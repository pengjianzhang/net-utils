#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define IPPROTO_TEST 253
#define MAGIC 0xA1B2C3D4u

#pragma pack(push, 1)
struct payload {
    uint32_t magic;
    uint32_t seq;
    uint64_t ts_us_be;   // gettimeofday() us, big-endian
};
#pragma pack(pop)

/* IPv4 header checksum */
static uint16_t ipv4_checksum(const void *buf, size_t len)
{
    uint32_t sum = 0;
    const uint16_t *data = buf;

    while (len > 1) {
        sum += *data++;
        len -= 2;
    }
    if (len == 1)
        sum += *(const uint8_t *)data;

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return (uint16_t)(~sum);
}

static uint64_t now_us(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ull + tv.tv_usec;
}

static int open_raw253_socket(void)
{
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_TEST);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    int one = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL,
                   &one, sizeof(one)) < 0) {
        perror("setsockopt(IP_HDRINCL)");
        close(fd);
        return -1;
    }
    return fd;
}

/* ================= server ================= */

static int run_server(void)
{
    int fd = open_raw253_socket();
    if (fd < 0)
        return 1;

    uint8_t buf[2048];
    printf("server: listening (ip proto %d)\n", IPPROTO_TEST);

    while (1) {
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, NULL, NULL);
        if (n < 0) {
            perror("recvfrom");
            break;
        }

        if ((size_t)n < sizeof(struct iphdr))
            continue;

        struct iphdr *ip = (struct iphdr *)buf;
        if (ip->version != 4 || ip->protocol != IPPROTO_TEST)
            continue;

        size_t ip_hlen = ip->ihl * 4;
        if ((size_t)n < ip_hlen + sizeof(struct payload))
            continue;

        struct payload pl;
        memcpy(&pl, buf + ip_hlen, sizeof(pl));
        if (ntohl(pl.magic) != MAGIC)
            continue;

        /* build echo reply */
        struct {
            struct iphdr ip;
            struct payload pl;
        } __attribute__((packed)) pkt;

        memset(&pkt, 0, sizeof(pkt));

        pkt.ip.version  = 4;
        pkt.ip.ihl      = 5;
        pkt.ip.ttl      = 64;
        pkt.ip.protocol = IPPROTO_TEST;
        pkt.ip.tot_len  = htons(sizeof(pkt));
        pkt.ip.saddr    = ip->daddr;
        pkt.ip.daddr    = ip->saddr;

        pkt.pl = pl;  // 原样 echo

        pkt.ip.check = 0;
        pkt.ip.check = ipv4_checksum(&pkt.ip, sizeof(struct iphdr));

        struct sockaddr_in dst = {
            .sin_family = AF_INET,
            .sin_addr.s_addr = pkt.ip.daddr,
        };

        sendto(fd, &pkt, sizeof(pkt), 0,
               (struct sockaddr *)&dst, sizeof(dst));
    }

    close(fd);
    return 0;
}

/* ================= client ================= */

static int run_client(const char *src_ip_str,
                      const char *dst_ip_str,
                      int count)
{
    int fd = open_raw253_socket();
    if (fd < 0)
        return 1;

    uint32_t src_ip = inet_addr(src_ip_str);
    uint32_t dst_ip = inet_addr(dst_ip_str);

    struct sockaddr_in dst = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = dst_ip,
    };

    uint8_t rbuf[2048];

    for (int i = 0; i < count; i++) {
        uint64_t ts_us = now_us();

        struct {
            struct iphdr ip;
            struct payload pl;
        } __attribute__((packed)) pkt;

        memset(&pkt, 0, sizeof(pkt));

        pkt.ip.version  = 4;
        pkt.ip.ihl      = 5;
        pkt.ip.ttl      = 64;
        pkt.ip.protocol = IPPROTO_TEST;
        pkt.ip.tot_len  = htons(sizeof(pkt));
        pkt.ip.saddr    = src_ip;
        pkt.ip.daddr    = dst_ip;

        pkt.pl.magic    = htonl(MAGIC);
        pkt.pl.seq      = htonl((uint32_t)i);
        pkt.pl.ts_us_be = htobe64(ts_us);

        pkt.ip.check = 0;
        pkt.ip.check = ipv4_checksum(&pkt.ip, sizeof(struct iphdr));

        /* send */
        sendto(fd, &pkt, sizeof(pkt), 0,
               (struct sockaddr *)&dst, sizeof(dst));

        /* blocking recv */
        while (1) {
            ssize_t n = recvfrom(fd, rbuf, sizeof(rbuf), 0, NULL, NULL);
            if (n < 0) {
                perror("recvfrom");
                close(fd);
                return 1;
            }

            struct iphdr *rip = (struct iphdr *)rbuf;
            if (rip->version != 4 || rip->protocol != IPPROTO_TEST)
                continue;

            size_t ip_hlen = rip->ihl * 4;
            if ((size_t)n < ip_hlen + sizeof(struct payload))
                continue;

            if (rip->saddr != dst_ip || rip->daddr != src_ip)
                continue;

            struct payload rpl;
            memcpy(&rpl, rbuf + ip_hlen, sizeof(rpl));
            if (ntohl(rpl.magic) != MAGIC)
                continue;

            uint32_t seq = ntohl(rpl.seq);
            if ((int)seq != i)
                continue;

            uint64_t sent_us = be64toh(rpl.ts_us_be);
            uint64_t rtt_us = now_us() - sent_us;

            printf("seq=%u rtt_us=%lu\n", seq, rtt_us);
            break;
        }
    }

    close(fd);
    return 0;
}

/* ================= main ================= */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage:\n"
        "  Server:\n"
        "    sudo %s -s\n"
        "  Client:\n"
        "    sudo %s -c <src_ip> <dst_ip> <count>\n",
        prog, prog);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (!strcmp(argv[1], "-s")) {
        return run_server();
    }

    if (!strcmp(argv[1], "-c")) {
        if (argc != 5) {
            usage(argv[0]);
            return 1;
        }
        return run_client(argv[2], argv[3], atoi(argv[4]));
    }

    usage(argv[0]);
    return 1;
}

