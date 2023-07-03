#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <event2/event.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

struct stats {
    struct timeval start;
    struct timeval end;
    uint64_t bytes;
    uint64_t count;
    uint64_t max_size;
    uint64_t min_size;
};

struct stats g_stats = {
    .min_size = 10000000,
};

static void stats_start(void)
{
    gettimeofday(&g_stats.start, NULL);
}

static inline void stats_inc(uint64_t byte)
{
    g_stats.bytes += byte;
    g_stats.count++;
    if (byte > g_stats.max_size) {
        g_stats.max_size = byte;
    }

    if (byte < g_stats.min_size) {
        g_stats.min_size = byte;
    }
}

static void stats_end(void)
{
    uint64_t us;
    uint64_t ms;
    uint64_t sec;
    struct timeval tv;
    struct timeval *last;
    uint64_t tps = 0;
    uint64_t pps = 0;
    uint64_t avg_size = 0;
    uint64_t rtt = 0;

    gettimeofday(&tv, NULL);
    last = &g_stats.start;

    us = (tv.tv_sec - last->tv_sec) * 1000 * 1000 + tv.tv_usec - last->tv_usec;
    ms = us / 1000;
    sec = ms / 1000;
    if (sec == 0) {
        sec = 1;
    }
    if (sec) {
        tps = g_stats.bytes / sec;
        pps = g_stats.count / sec;
    }

    if (g_stats.count) {
        avg_size = g_stats.bytes / g_stats.count;
        rtt = us / g_stats.count;
    }

    printf("count %lu rtt %luus tps %5.1fk pps %lu pkt-size max %lu avg %lu min %lu\n",
            g_stats.count, rtt, tps*1.0/1024, pps, g_stats.max_size, avg_size, g_stats.min_size);
}

static int cpu_bind(int cpu)
{
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);
    if(sched_setaffinity(0, sizeof(cpuset), &cpuset) == -1) {
        return -1;
    }
    return 0;
}

static int g_stop = 0;
static void signal_handler(int signum)
{
    if (signum == SIGINT) {
        g_stop = 1;
    }
}

static inline void socket_set_option(int fd, int type)
{
    int one = 1;
    socklen_t size = 16 * 1024 * 1024;

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int));
    if (type == SOCK_STREAM) {
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(int));
    }

    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
}

static int socket_open(int type)
{
    int fd = -1;

    fd = socket(AF_INET, type, 0);
    if (fd < 0) {
        return -1;
    }

    fcntl(fd, F_SETFL, O_NONBLOCK);
    socket_set_option(fd, type);

    return fd;
}

static int open_client(struct sockaddr_in *laddr, struct sockaddr_in *addr)
{
    int ret = 0;
    int fd = -1;
    socklen_t len = 0;
    int type = SOCK_STREAM;

    fd = socket_open(type);
    if (fd < 0) {
        return -1;
    }

    len = sizeof(struct sockaddr_in);
    if (laddr->sin_addr.s_addr) {
        if (bind(fd, (struct sockaddr *)laddr, len) < 0) {
            close(fd);
            return -1;
        }
    }
    ret = connect(fd, (const struct sockaddr *)addr, len);
    if (ret < 0) {
        if ((type == SOCK_STREAM) && (errno == EINPROGRESS)) {
            return fd;
        }
        close(fd);
        return -1;
    }

    return fd;
}

#define BUF_SIZE (1024 *4)
static char g_rcv_buf[BUF_SIZE];
static char g_snd_buf[BUF_SIZE];
static int g_snd_len = 0;
int g_num = 0;
int g_rcv = 0;

static inline void tcp_send(int fd)
{
    send(fd, g_snd_buf, g_snd_len, 0);
}

static void do_term(int sig, short events, void *arg)
{
    g_stop = 0;
    struct event_base *base = arg;
    event_base_loopbreak(base);
}

void read_cb(evutil_socket_t fd, short what, void *arg)
{
    int ret = -1;
    struct event_base *base = arg;

    ret = recv(fd, g_rcv_buf, BUF_SIZE, 0);
    if (ret > 0) {
        stats_inc(ret);
        g_rcv++;
        if (g_rcv < g_num) {
            tcp_send(fd);
            if (g_stop == 0) {
                return;
            }
        }
    }

    event_base_loopbreak(base);
}

static int addr_init(const char *str, struct sockaddr_in *addr)
{
    int val = 0;
    uint32_t ip = 0;
    uint16_t port = 0;
    char *p = NULL;

    p = strchr(str, ':');
    if (p == NULL) {
        return -1;
    }

    *p = 0;
    p++;
    if (inet_pton(AF_INET, str, &ip) != 1) {
        return -1;
    }

    val = atoi(p);
    if ((val <= 0) || (val > 65535)) {
        return -1;
    }
    port = htons(val);

    memset(addr, 0, sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = ip;
    addr->sin_port = port;
    return sizeof(struct sockaddr_in);
}

int main(int argc, char **argv)
{
    struct event_base *base = NULL;
    struct event *ev = NULL;
    struct event *term = NULL;
    int ret = -1;
    int fd = -1;
    int val = 0;
    int cpu = 0;
    struct sockaddr_in addr;
    struct sockaddr_in laddr;
    struct timeval tval;

    tval.tv_sec = 0;
    tval.tv_usec = 100 * 1000;

    if (argc != 6) {
        printf("usage: lip:lport ip:port path num cpu\n");
        return 1;
    }

    if (addr_init(argv[1], &laddr) < 0) {
        return -1;
    }

    if (addr_init(argv[2], &addr) < 0) {
        return -1;
    }

    sprintf(g_snd_buf, "GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: curl/7.79.1\r\nAccept: */*\r\n\r\n", argv[3]);
    g_snd_len = strlen(g_snd_buf);

    val = atoi(argv[4]);
    if(val <= 0) {
        return -1;
    }
    g_num = val;

    cpu = atoi(argv[5]);
    if (cpu < 0) {
        return -1;
    }
    cpu_bind(cpu);

    signal(SIGINT, signal_handler);
    base = event_base_new();
    if (!base) {
        goto err;
    }

    fd = open_client(&laddr, &addr);
    if (fd < 0) {
        goto err;
    }

    /* wait connected */
    sleep(1);
    ev = event_new(base, fd, EV_READ|EV_PERSIST, read_cb, base);
    if (event_add(ev, NULL)) {
        goto err;
    }

    stats_start();
    tcp_send(fd);
    event_base_dispatch(base);
    stats_end();
    ret = 0;

err:
    if (fd >= 0) {
        close(fd);
    }

    if (ev) {
        event_free(ev);
    }

    if (base) {
        event_base_free(base);
    }

    return ret;
}
