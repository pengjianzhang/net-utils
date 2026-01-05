#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define IPPROTO_TEST 253
#define MAGIC 0xA1B2C3D4u

/* ---------------- payload header (16 bytes) ---------------- */

#pragma pack(push, 1)
struct payload_hdr {
    uint32_t magic;      /* 4 */
    uint32_t seq;        /* 4 */
    uint64_t ts_us_be;   /* 8 */
};                       /* = 16 bytes */
#pragma pack(pop)

/* ---------------- utils ---------------- */

static uint64_t now_us(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ull + tv.tv_usec;
}

/* IPv4 header checksum (one's complement) */
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

static int open_raw253_socket(void)
{
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_TEST);
    if (fd < 0) {
        perror("socket(AF_INET,SOCK_RAW,253)");
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

/* ---------------- server ---------------- */

static int run_server(void)
{
    int fd = open_raw253_socket();
    if (fd < 0)
        return 1;

    uint8_t buf[2048];
    printf("server: listening (IP protocol %d)\n", IPPROTO_TEST);

    while (1) {
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, NULL, NULL);
        if (n < 0) {
            perror("recvfrom");
            break;
        }

        if ((size_t)n < sizeof(struct iphdr) + sizeof(struct payload_hdr))
            continue;

        struct iphdr *ip = (struct iphdr *)buf;
        if (ip->version != 4 || ip->protocol != IPPROTO_TEST)
            continue;

        size_t ip_hlen = ip->ihl * 4;
        if ((size_t)n < ip_hlen + sizeof(struct payload_hdr))
            continue;

        struct payload_hdr *hdr =
            (struct payload_hdr *)(buf + ip_hlen);

        if (ntohl(hdr->magic) != MAGIC)
            continue;

        /* swap src / dst */
        uint32_t tmp = ip->saddr;
        ip->saddr = ip->daddr;
        ip->daddr = tmp;

        ip->check = 0;
        ip->check = ipv4_checksum(ip, sizeof(struct iphdr));

        struct sockaddr_in dst = {
            .sin_family = AF_INET,
            .sin_addr.s_addr = ip->daddr,
        };

        /* echo back entire packet */
        sendto(fd, buf, n, 0,
               (struct sockaddr *)&dst, sizeof(dst));
    }

    close(fd);
    return 0;
}

/* ---------------- client ---------------- */

static int run_client(const char *src_ip_str,
                      const char *dst_ip_str,
                      int count,
                      int payload_size)
{
    int fd = open_raw253_socket();
    if (fd < 0)
        return 1;

    uint32_t src_ip = inet_addr(src_ip_str);
    uint32_t dst_ip = inet_addr(dst_ip_str);

    if (payload_size < 16)
        payload_size = 16;

    int pkt_len = sizeof(struct iphdr) + payload_size;

    struct sockaddr_in dst = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = dst_ip,
    };

    uint8_t rbuf[2048];

    for (int i = 0; i < count; i++) {
        uint8_t *pkt = calloc(1, pkt_len);
        if (!pkt) {
            perror("calloc");
            break;
        }

        struct iphdr *ip = (struct iphdr *)pkt;
        struct payload_hdr *hdr =
            (struct payload_hdr *)(pkt + sizeof(struct iphdr));

        /* IPv4 header */
        ip->version  = 4;
        ip->ihl      = 5;
        ip->ttl      = 64;
        ip->protocol = IPPROTO_TEST;
        ip->tot_len  = htons(pkt_len);
        ip->saddr    = src_ip;
        ip->daddr    = dst_ip;

        /* payload header */
        hdr->magic    = htonl(MAGIC);
        hdr->seq      = htonl((uint32_t)i);
        hdr->ts_us_be = htobe64(now_us());

        ip->check = 0;
        ip->check = ipv4_checksum(ip, sizeof(struct iphdr));

        sendto(fd, pkt, pkt_len, 0,
               (struct sockaddr *)&dst, sizeof(dst));

        free(pkt);

        /* blocking recv */
        while (1) {
            ssize_t n = recvfrom(fd, rbuf, sizeof(rbuf), 0, NULL, NULL);
            if (n < 0) {
                perror("recvfrom");
                close(fd);
                return 1;
            }

            if ((size_t)n < sizeof(struct iphdr) + sizeof(struct payload_hdr))
                continue;

            struct iphdr *rip = (struct iphdr *)rbuf;
            if (rip->version != 4 || rip->protocol != IPPROTO_TEST)
                continue;

            size_t ip_hlen = rip->ihl * 4;
            if ((size_t)n < ip_hlen + sizeof(struct payload_hdr))
                continue;

            if (rip->saddr != dst_ip || rip->daddr != src_ip)
                continue;

            struct payload_hdr *rhdr =
                (struct payload_hdr *)(rbuf + ip_hlen);

            if (ntohl(rhdr->magic) != MAGIC)
                continue;

            uint32_t seq = ntohl(rhdr->seq);
            if ((int)seq != i)
                continue;

            uint64_t sent_us = be64toh(rhdr->ts_us_be);
            uint64_t rtt_us  = now_us() - sent_us;

            printf("seq=%u rtt_us=%lu payload=%d\n",
                   seq, rtt_us, payload_size);
            break;
        }
        sleep(1);
    }

    close(fd);
    return 0;
}

/* ---------------- main ---------------- */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage:\n"
        "  Server:\n"
        "    sudo %s -s\n"
        "  Client:\n"
        "    sudo %s -c <src_ip> <dst_ip> <count> [-S payload_size]\n"
        "\n"
        "Options:\n"
        "  -S <size>   payload size (min 16 bytes)\n"
        "\n"
        "Examples:\n"
        "  sudo %s -s\n"
        "  sudo %s -c 127.0.0.1 127.0.0.1 10 -S 512\n",
        prog, prog, prog, prog);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    int payload_size = 16;

    if (!strcmp(argv[1], "-s")) {
        return run_server();
    }

    if (!strcmp(argv[1], "-c")) {
        if (argc < 5) {
            usage(argv[0]);
            return 1;
        }

        for (int i = 5; i < argc; i++) {
            if (!strcmp(argv[i], "-S") && i + 1 < argc) {
                payload_size = atoi(argv[++i]);
            }
        }

        return run_client(
            argv[2],
            argv[3],
            atoi(argv[4]),
            payload_size
        );
    }

    usage(argv[0]);
    return 1;
}

