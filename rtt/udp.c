#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define MAGIC 0xA1B2C3D4u
#define BUF_SIZE 2048

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

/* ---------------- server ---------------- */

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
        if (n < (ssize_t)(sizeof(struct payload_hdr)))
            continue;

        struct payload_hdr *hdr = (struct payload_hdr *)buf;
        if (ntohl(hdr->magic) != MAGIC)
            continue;

        /* echo back exactly what we got */
        sendto(fd, buf, n, 0,
               (struct sockaddr *)&peer, peer_len);
    }

    close(fd);
    return 0;
}

/* ---------------- client ---------------- */

static int run_client(const char *src_ip,
                      uint16_t src_port,
                      const char *dst_ip,
                      uint16_t dst_port,
                      int count,
                      int payload_size,
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

    if (payload_size < 16)
        payload_size = 16;

    uint8_t *buf = calloc(1, payload_size);
    if (!buf) {
        perror("calloc");
        close(fd);
        return 1;
    }

    for (int i = 0; i < count; i++) {
        struct payload_hdr *hdr = (struct payload_hdr *)buf;

        hdr->magic    = htonl(MAGIC);
        hdr->seq      = htonl((uint32_t)i);
        hdr->ts_us_be = htobe64(now_us());

        /* send */
        if (sendto(fd, buf, payload_size, 0,
                   (struct sockaddr *)&dst, sizeof(dst)) < 0) {
            perror("sendto");
            break;
        }

        /* blocking recv */
        ssize_t n = recvfrom(fd, buf, payload_size, 0, NULL, NULL);
        if (n < (ssize_t)(sizeof(struct payload_hdr))) {
            printf("seq=%d short packet\n", i);
            continue;
        }

        struct payload_hdr *rhdr = (struct payload_hdr *)buf;
        if (ntohl(rhdr->magic) != MAGIC)
            continue;

        uint32_t seq = ntohl(rhdr->seq);
        if ((int)seq != i)
            continue;

        uint64_t sent_us = be64toh(rhdr->ts_us_be);
        uint64_t rtt_us  = now_us() - sent_us;

        printf("seq=%u rtt_us=%lu payload=%d\n",
               seq, rtt_us, payload_size);

        if (interval_us > 0)
            usleep(interval_us);
    }

    free(buf);
    close(fd);
    return 0;
}

/* ---------------- main ---------------- */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage:\n"
        "  Server:\n"
        "    %s -s <listen_port>\n"
        "  Client:\n"
        "    %s -c <src_ip> <src_port> <dst_ip> <dst_port> <count> "
        "[-S payload_size] [interval_us]\n"
        "\n"
        "Options:\n"
        "  -S <size>   payload size (min 16 bytes)\n"
        "\n"
        "Examples:\n"
        "  %s -s 9000\n"
        "  %s -c 127.0.0.1 40000 127.0.0.1 9000 10 -S 512 100000\n",
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
        if (argc < 8) {
            usage(argv[0]);
            return 1;
        }

        int payload_size = 16;
        int interval_us  = 0;

        for (int i = 8; i < argc; i++) {
            if (!strcmp(argv[i], "-S") && i + 1 < argc) {
                payload_size = atoi(argv[++i]);
            } else {
                interval_us = atoi(argv[i]);
            }
        }

        return run_client(
            argv[2], (uint16_t)atoi(argv[3]),
            argv[4], (uint16_t)atoi(argv[5]),
            atoi(argv[6]),
            payload_size,
            interval_us
        );
    }

    usage(argv[0]);
    return 1;
}

