#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#define IGMP_REPORT 0x16
#define IGMP_LEAVE  0x17

struct igmp {
    uint8_t type;
    uint8_t ttl;
    uint16_t csum;
    uint32_t group;
};

static uint16_t igmp_checksum(uint16_t *buf, int len)
{
    uint64_t sum = 0;

    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(uint8_t *)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

static void igmp_init(struct igmp *p, uint8_t type, uint32_t group)
{
    p->type =type;
    p->ttl = 0;
    p->csum = 0;
    p->group = group;
    p->csum = igmp_checksum((uint16_t *)p, sizeof(struct igmp));
}

static int igmp_set_sockopt(int sk)
{
    uint8_t opt[4] = {148, 4, 0, 0};
    int ttl = 1;

    if (setsockopt(sk, IPPROTO_IP, IP_OPTIONS, opt, 4) < 0) {
        return -1;
    }

    if (setsockopt(sk, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0) {
        return -1;
    }

    return 0;
}

static void addr_init(struct sockaddr_in *addr, uint32_t ip, uint16_t port)
{
    memset(addr, 0, sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = ip;
    addr->sin_port = port;
}

static int igmp_socket(void)
{
    return socket(AF_INET, SOCK_RAW|SOCK_NONBLOCK, IPPROTO_IGMP);
}

static int igmp_send(uint32_t dest, uint32_t group, uint8_t type)
{
    int sk = -1;
    struct igmp igmp;
    struct sockaddr_in addr;

    igmp_init(&igmp, type, group);
    addr_init(&addr, dest, 0);

    if ((sk = igmp_socket()) < 0) {
        return -1;
    }

    if (igmp_set_sockopt(sk) < 0) {
        goto err;
    }

    if (sendto(sk, &igmp, sizeof(struct igmp), 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        goto err;
    }
    close(sk);
    return 0;
err:
    close(sk);
    return -1;
}

static int igmp_send_report(uint32_t group)
{
    return igmp_send(group, group, IGMP_REPORT);
}

static int igmp_send_leave(uint32_t group)
{
    uint32_t router = inet_addr("224.0.0.2");

    return igmp_send(router, group, IGMP_LEAVE);
}

static int igmp_recv(int sk, uint32_t group)
{
    int len;
    char buf[1024];
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    len = recvfrom(sk, buf, sizeof(buf), 0, (struct sockaddr *)&addr, &addr_len);
    if (len > 0) {
        igmp_send_report(group);
    }

    return len;
}

int main(int argc, char **argv)
{
    int i = 0;
    uint16_t port = 0;
    uint32_t group = 0;
    int sk_igmp = 0;
    int n = 0;

    if (argc != 3) {
        printf("usage: %s group-ip port\n", argv[0]);
        return -1;
    }

    group = inet_addr(argv[1]);
    port = htons(atoi(argv[2]));

    if ((sk_igmp = igmp_socket()) < 0) {
        goto out;
    }

    igmp_send_report(group);
    sleep(1);
    igmp_send_report(group);

    for (i = 0; i < 100000; i++) {
        igmp_recv(sk_igmp, group);
        usleep(1000);
    }

    igmp_send_leave(group);
out:
    if (sk_igmp >= 0) {
        close(sk_igmp);
    }

    return 0;
}
