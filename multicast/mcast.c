#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

static struct timeval tv_last;
static struct timeval tv;

static void client_request_start(void)
{
    gettimeofday(&tv_last, NULL);
}

static int client_request_end(int n)
{
    unsigned long us;
    gettimeofday(&tv, NULL);

    us = (tv.tv_sec - tv_last.tv_sec)* 1000 * 1000 + (tv.tv_usec - tv_last.tv_usec);
    printf("%f ms\n", us * 1.0/(n * 1000));

    us = (us / 1000) * 1000;
    return us;
}

static int addr_init(struct sockaddr_in *addr, const char *ip_str, const char *port_str)
{
    int port =  0;

    port = atoi(port_str);
    if ((port <= 0) || (port >= 65536)) {
        return -1;
    }

    memset(addr, 0, sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr(ip_str);
    addr->sin_port = htons(port);

    return 0;
}

static void multicast_no_loop(int sk)
{
    int loop = 0;

    setsockopt(sk, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(int));
}

static void multicast_iface(int sk, const char *ip_str)
{
    struct in_addr addr;

    addr.s_addr = inet_addr(ip_str);
    setsockopt(sk, IPPROTO_IP, IP_MULTICAST_IF, &addr, sizeof(struct in_addr));
}

static int socket_bind(int sk, const char *ip_str, const char *port_str)
{
    int one = 1;
    struct sockaddr_in addr;

    if (addr_init(&addr, ip_str, port_str) != 0) {
        return -1;
    }

    setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    bind(sk, (struct sockaddr*)&addr, sizeof(struct sockaddr_in));
    return 0;
}

#define BUF_SIZE    128
static void sender(const char *mip, const char *lip, const char *port)
{
    int sk = 0;
    struct sockaddr_in maddr;
    char buf[BUF_SIZE];
//    int len = 0;
    int i = 0;
    int n = 100000;

    if (addr_init(&maddr, mip, port) != 0) {
        return;
    }

    sk = socket(AF_INET, SOCK_DGRAM, 0);
    socket_bind(sk, lip, port);
    multicast_no_loop(sk);
    multicast_iface(sk, lip);

    client_request_start();
    for (i = 0; i < n; i++) {
        sendto(sk, "aaa", 3, 0, (struct sockaddr *)&maddr, sizeof(struct sockaddr_in));
        recvfrom(sk, buf, BUF_SIZE, 0, NULL, NULL);
/*
        if (len > 0) {
            buf[len] = 0;
            printf("%s\n", buf);
        }
*/
    }
    client_request_end(n);
    close(sk);
}

static void multicast_join(int sk, const char *mip, const char *lip)
{
    struct ip_mreq group;

    group.imr_multiaddr.s_addr = inet_addr(mip);
    group.imr_interface.s_addr = inet_addr(lip);

    setsockopt(sk, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&group, sizeof(group));
}

static void receiver(const char *mip, const char *lip, const char *port_str)
{
    char buf[BUF_SIZE + 1];
//    int len = 0;
    int sk = -1;
    struct sockaddr_in peer;
    socklen_t slen;

    slen = sizeof(struct sockaddr_in);
    sk = socket(AF_INET, SOCK_DGRAM, 0);
    socket_bind(sk, mip, port_str);
    multicast_join(sk, mip, lip);

    while (1) {
        recvfrom(sk, buf, BUF_SIZE, 0, (struct sockaddr *)&peer, &slen);
        sendto(sk, "bbb", 3, 0,  (struct sockaddr*)&peer, slen);
/*
        if (len > 0) {
            buf[len] = 0;
            printf("%s\n", buf);
        }
*/
    }
}

static void usage(void)
{
    printf("mcast send|recv multicast-ip local-ip port\n");
}

int main (int argc, char *argv[])
{
    char *lip = NULL;
    char *mip = NULL;
    char *port = NULL;

    if (argc != 5) {
        usage();
        return 1;
    }

    mip = argv[2];
    lip = argv[3];
    port = argv[4];

    if (strcmp(argv[1], "send") == 0) {
        sender(mip, lip, port);
    } else if (strcmp(argv[1], "recv") == 0) {
        receiver(mip, lip, port);
    } else {
        usage();
        return 1;
    }

    return 0;
}
