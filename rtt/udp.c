
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define MAGIC 0xA1B2C3D4u
#define BUF_SIZE 1500

#pragma pack(push, 1)
struct payload {
    uint32_t magic;
    uint32_t seq;
    uint64_t ts_us_be;
};
#pragma pack(pop)

/* gettimeofday -> microseconds */
static uint64_t now_us(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ull + tv.tv_usec;
}

/* ================= server ================= */

static int run_server(uint16_t listen_port)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(listen_port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(fd);
        return 1;
    }

    printf("server: UDP listen on port %u\n", listen_port);

    uint8_t buf[BUF_SIZE];

    while (1) {
        struct sockaddr_in peer;
        socklen_t peer_len = sizeof(peer);

        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&peer, &peer_len);
        if (n < (ssize_t)sizeof(struct payload))
            continue;

        struct payload pl;
        memcpy(&pl, buf, sizeof(pl));
        if (ntohl(pl.magic) != MAGIC)
            continue;

        /* echo back */
        sendto(fd, buf, n, 0,
               (struct sockaddr *)&peer, peer_len);
    }

    close(fd);
    return 0;
}

/* ================= client ================= */

static int run_client(const char *src_ip,
                      uint16_t src_port,
                      const char *dst_ip,
                      uint16_t dst_port,
                      int count,
                      int interval_us)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    /* bind source IP + port */
    struct sockaddr_in src;
    memset(&src, 0, sizeof(src));
    src.sin_family = AF_INET;
    src.sin_port   = htons(src_port);
    if (inet_pton(AF_INET, src_ip, &src.sin_addr) != 1) {
        fprintf(stderr, "invalid src ip\n");
        close(fd);
        return 1;
    }

    if (bind(fd, (struct sockaddr *)&src, sizeof(src)) < 0) {
        perror("bind(src)");
        close(fd);
        return 1;
    }

    /* destination */
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port   = htons(dst_port);
    if (inet_pton(AF_INET, dst_ip, &dst.sin_addr) != 1) {
        fprintf(stderr, "invalid dst ip\n");
        close(fd);
        return 1;
    }

    uint8_t buf[BUF_SIZE];

    for (int i = 0; i < count; i++) {
        struct payload pl;
        pl.magic    = htonl(MAGIC);
        pl.seq      = htonl((uint32_t)i);
        pl.ts_us_be = htobe64(now_us());

        /* send */
        if (sendto(fd, &pl, sizeof(pl), 0,
                   (struct sockaddr *)&dst, sizeof(dst)) < 0) {
            perror("sendto");
            break;
        }

        /* blocking recv */
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, NULL, NULL);
        if (n < (ssize_t)sizeof(struct payload)) {
            printf("seq=%d short packet\n", i);
            continue;
        }

        struct payload rpl;
        memcpy(&rpl, buf, sizeof(rpl));
        if (ntohl(rpl.magic) != MAGIC)
            continue;

        uint32_t seq = ntohl(rpl.seq);
        uint64_t sent_us = be64toh(rpl.ts_us_be);
        uint64_t rtt_us  = now_us() - sent_us;

        printf("seq=%u rtt_us=%lu\n", seq, rtt_us);

        if (interval_us > 0) {
            if (interval_us < 1000000) {
                usleep(interval_us);
            } else {
                sleep(interval_us/1000000);
            }
        } else {
            sleep(1);
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
        "    %s -s <listen_port>\n"
        "  Client:\n"
        "    %s -c <src_ip> <src_port> <dst_ip> <dst_port> <count> [interval_us]\n"
        "\n"
        "Examples:\n"
        "  %s -s 9000\n"
        "  %s -c 192.168.1.10 40000 192.168.1.20 9000 10 100000\n",
        prog, prog, prog, prog);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (!strcmp(argv[1], "-s")) {
        if (argc != 3) {
            usage(argv[0]);
            return 1;
        }
        return run_server((uint16_t)atoi(argv[2]));
    }

    if (!strcmp(argv[1], "-c")) {
        if (argc < 8 || argc > 9) {
            usage(argv[0]);
            return 1;
        }
        int interval_us = (argc == 9) ? atoi(argv[8]) : 0;
        return run_client(
            argv[2], (uint16_t)atoi(argv[3]),
            argv[4], (uint16_t)atoi(argv[5]),
            atoi(argv[6]),
            interval_us
        );
    }

    usage(argv[0]);
    return 1;
}

