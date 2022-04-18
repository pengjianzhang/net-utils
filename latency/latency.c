#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <getopt.h>

struct timeval tv_last;
struct timeval tv;


#define BUF_SIZE    2048
char req_buf[BUF_SIZE] =
"GET / HTTP/1.1\r\n"
"User-Agent: curl/7.29.0\r\n"
"Host: 172.16.199.175\r\n"
"Accept: */*\r\n"
"\r\n";

char rsp_buf[BUF_SIZE] =
"HTTP/1.1 200 OK\r\n"
"Server: nginx/1.20.1\r\n"
"Date: Sun, 17 Apr 2022 07:12:08 GMT\r\n"
"Content-Type: application/octet-stream\r\n"
"Content-Length: 13\r\n"
"Connection: keep-alive\r\n"
"\r\n"
"nginx server\n";

int socket_addr(struct sockaddr_storage *addr, const char *str)
{
    struct sockaddr_un *un = (struct sockaddr_un *)addr;
    struct sockaddr_in  *p4 = (struct sockaddr_in *)addr;
    struct sockaddr_in6 *p6 = (struct sockaddr_in6 *)addr;

    bzero(addr, sizeof(struct sockaddr_storage));
    if (strchr(str, '/') != NULL) {
        if (strlen(str) >= sizeof(un->sun_path)) {
            return -1;
        }

        un = (struct sockaddr_un *)addr;
        un->sun_family = AF_UNIX;
        strcpy(un->sun_path, str);
        return AF_UNIX;
    } else if (strchr(str, ':') != NULL) {
        p6->sin6_family = AF_INET6;
        p6->sin6_port = htons(80);
        inet_pton(AF_INET6, str, &(p6->sin6_addr));
        return AF_INET6;
    } else {
        p4->sin_family = AF_INET;
        p4->sin_port = htons(80);
        p4->sin_addr.s_addr = inet_addr(str);
        return AF_INET;
    }
}

static int server_listen(const char *addr, int udp)
{
    int fd = 0;
    int af = 0;
    int ret = 0;
    struct sockaddr_storage saddr;
    int len = sizeof(struct sockaddr_storage);

    af = socket_addr(&saddr, addr);
    if (af == AF_UNIX) {
        len = sizeof(struct sockaddr_un);
    }

    if (udp) {
        fd = socket(af, SOCK_DGRAM, 0);
    } else {
        fd = socket(af, SOCK_STREAM, 0);
    }

    if (fd < 0) {
        printf("create socket error\n");
        return -1;
    }

    ret = bind(fd, (struct sockaddr *)&saddr, len);
    if (ret != 0) {
        printf("bind error\n");
        close(fd);
        return -1;
    }

    if (udp == 0) {
        ret = listen(fd, 5);
        if (ret != 0) {
            close(fd);
            printf("listen error\n");
            return -1;
        }
    }
    return fd;
}

void server_loop(int fd)
{
    int cfd = 0;
    int ret = 0;

    int len = strlen(rsp_buf);
    while ((cfd = accept(fd, NULL, NULL)) > 0) {
        while((ret = recv(cfd, req_buf, BUF_SIZE, 0)) > 0) {
            send(cfd, rsp_buf, len, 0);
        }
        close(cfd);
    }
}

static void udp_server_loop(int fd)
{
    struct sockaddr_storage guest;
    socklen_t slen;
    int len = 0;
    int ret = 0;

    len = strlen(rsp_buf);
    slen = sizeof(struct sockaddr_storage);

    while(1){
        ret = recvfrom(fd, req_buf, BUF_SIZE, 0,  (struct sockaddr*)&guest, &slen);
        if (ret > 0) {
            sendto(fd, rsp_buf, len, 0,  (struct sockaddr*)&guest, slen);
        }
    }
}

void server_run(const char *addr, int udp)
{
    int fd = 0;
    int un = 0;

    if (strchr(addr, '/') != NULL) {
        un = 1;
    }

    if (un) {
        unlink(addr);
    }

    fd = server_listen(addr, udp);
    if (udp) {
        udp_server_loop(fd);
    } else {
        server_loop(fd);
    }

    if (un) {
        unlink(addr);
    }
}

static int client_connect(const char *addr, int udp)
{
    int fd = 0;
    int af = 0;
    struct sockaddr_storage saddr;
    int len = sizeof(struct sockaddr_storage);

    af = socket_addr(&saddr, addr);
    if (af == AF_UNIX) {
        len = sizeof(struct sockaddr_un);
    }

    if (udp) {
        fd = socket(af, SOCK_DGRAM, 0);
    } else {
        fd = socket(af, SOCK_STREAM, 0);
    }

    if(connect(fd, (struct sockaddr *)&saddr, len) < 0)  {
        return -1;
    }

    return fd;
}

void client_loop(int fd, int n)
{
    int i;
    int len = 0;

    len = strlen(req_buf);
    for (i = 0; i < n; i++) {
        send(fd, req_buf, len, 0);
        recv(fd, rsp_buf, BUF_SIZE, 0);
    }
}

static void client_request_start(void)
{
    gettimeofday(&tv_last, NULL);
}

static void client_request_end(int n)
{
    unsigned long us;
    gettimeofday(&tv, NULL);

    us = (tv.tv_sec - tv_last.tv_sec)* 1000 * 1000 + (tv.tv_usec - tv_last.tv_usec);
    printf("%f ms\n", us * 1.0/(n * 1000));

}

void client_run(const char *addr, int n, int udp)
{
    int fd = 0;

    fd = client_connect(addr, udp);
    client_request_start();
    client_loop(fd, n);
    client_request_end(n);
    close(fd);
}


static void usage(void)
{
    printf("Usage:\n");
    printf("\tlatency  [--udp|-u] --server|-s ip/unix-socket-path \n");
    printf("\tlatency  [--udp|-u] --client|-c ip/unix-socket-path --number|-n number\n");
}

static struct option g_options[] = {
    {"help", no_argument, NULL, 'h'},
    {"udp", no_argument, NULL, 'u'},
    {"server", required_argument, NULL, 's'},
    {"client", required_argument, NULL, 'c'},
    {"number", required_argument, NULL, 'n'},
    {NULL, 0, NULL, 0}
};

#define ADDR_SIZE    108
int main(int argc, char *argv[])
{
    int udp = 0;
    int num = 0;
    int server = 0;
    int client = 0;
    int opt = 0;
    const char *optstr = "hus:c:n:";
    char addr[ADDR_SIZE];

    if (argc == 1) {
        usage();
        return -1;
    }

    while ((opt = getopt_long_only(argc, argv, optstr, g_options, NULL)) != -1) {
        switch (opt) {
            case 'c':
                client = 1;
                strncpy(addr, optarg, ADDR_SIZE);
                break;
            case 's':
                server = 1;
                strncpy(addr, optarg, ADDR_SIZE);
                break;
            case 'n':
                num = atoi(optarg);
                if (num <= 0) {
                    goto err;
                }
                break;
            case 'u':
                udp = 1;
                break;
            case 'h':
                usage();
                return 0;
            default:
                goto err;
        }
    }

    if (client == server) {
        goto err;
    }

    if (server && num) {
        goto err;
    }

    if (num == 0) {
        num = 100000;
    }

    if (client) {
        client_run(addr, num, udp);
    } else {
        server_run(addr, udp);
    }

    return 0;
err:
    usage();
    return -1;
}
