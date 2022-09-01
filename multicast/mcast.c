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


#define BUF_SIZE	(1024 * 2)
static char g_req[BUF_SIZE];
static char g_rsp[BUF_SIZE];
static int g_req_len = 0;

static void client_request_start(void)
{
    gettimeofday(&tv_last, NULL);
}

static int client_request_end(long n)
{
    unsigned long us;

    gettimeofday(&tv, NULL);

    us = (tv.tv_sec - tv_last.tv_sec)* 1000 * 1000 + (tv.tv_usec - tv_last.tv_usec);
    printf("%f ms PPS %ld\n", us * 1.0/(n * 1000), n*1000*1000/us);

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

static int multicast_ip_check(const char *ip)
{
    char c0 = ip[0];
    char c1 = ip[1];
    char c2 = ip[2];

    if (c0 == '2') {
        if (c1 == '2') {
            if (c2 >= '4') {
                return 0;
            }
        } else if (c1 == '3') {
            return 0;
        }
    }

    return -1;
}

static void sender(const char *mip, const char *lip, const char *port, int n)
{
    int sk = 0;
    struct sockaddr_in maddr;
    int i = 0;

    if (n == 0) {
        n = 1;
    }

    if (addr_init(&maddr, mip, port) != 0) {
        return;
    }

    sk = socket(AF_INET, SOCK_DGRAM, 0);
    socket_bind(sk, lip, port);

    if (multicast_ip_check(mip) == 0) {
        multicast_no_loop(sk);
        multicast_iface(sk, lip);
    }
    client_request_start();
    for (i = 0; i < n; i++) {
        sendto(sk, g_req, g_req_len, 0, (struct sockaddr *)&maddr, sizeof(struct sockaddr_in));
        recvfrom(sk, g_rsp, BUF_SIZE, 0, NULL, NULL);
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

static void receiver(const char *mip, const char *lip, const char *port_str, int output)
{
    int sk = -1;
    socklen_t slen = 0;
    struct sockaddr_in peer;

    slen = sizeof(struct sockaddr_in);
    sk = socket(AF_INET, SOCK_DGRAM, 0);
    socket_bind(sk, mip, port_str);

    if (multicast_ip_check(mip) == 0) {
        multicast_join(sk, mip, lip);
    }

    while (1) {
        recvfrom(sk, g_rsp, BUF_SIZE, 0, (struct sockaddr *)&peer, &slen);
        sendto(sk, g_req, g_req_len, 0,  (struct sockaddr*)&peer, slen);
    }
}

static void usage(void)
{
    printf("mcast send size multicast-ip local-ip port [number]\n");
    printf("mcast recv size multicast-ip local-ip port [output]\n");
}

int main (int argc, char *argv[])
{
    char *type = NULL;
    char *lip = NULL;
    char *mip = NULL;
    char *port = NULL;
    int size = 0;
    int n = 0;
    int output = 0;

    if (argc < 6) {
        usage();
        return 1;
    }

    type = argv[1];
    size = atoi(argv[2]);
    if ((size <= 0) || (size > (1500 - 20 - 8))) {
        printf("bad size\n");
        return 1;
    }
    mip = argv[3];
    lip = argv[4];
    port = argv[5];

    if (argc >= 7) {
        if (strcmp(argv[6], "output") == 0) {
            output = 0;
        } else {
            n = atoi(argv[6]);
            if (n <= 0) {
                usage();
                return -1;
            }
        }
    }
    g_req_len = size;
    if (strcmp(type, "send") == 0) {
        memset(g_req, 'a', size);
        sender(mip, lip, port, n);
    } else if (strcmp(type, "recv") == 0) {
        memset(g_req, 'b', size);
        receiver(mip, lip, port, output);
    } else {
        usage();
        return 1;
    }

    return 0;
}
