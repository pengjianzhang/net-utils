#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/un.h>

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

static int socket_addr(struct sockaddr_storage *addr, const char *str)
{
    struct sockaddr_un *un = (struct sockaddr_un *)addr;
    struct sockaddr_in  *p4 = (struct sockaddr_in *)addr;
    struct sockaddr_in6 *p6 = (struct sockaddr_in6 *)addr;

    bzero(addr, sizeof(struct sockaddr_storage));
    if (strchr(str, '/') != NULL) {
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

int server_listen(const char *addr)
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
    fd = socket(af, SOCK_STREAM, 0);
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
    ret = listen(fd, 5);
    if (ret != 0) {
        close(fd);
        printf("listen error\n");
        return -1;
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

void server_run(const char *addr)
{
    int fd = 0;
    int un = 0;

    if (strchr(addr, '/') != NULL) {
        un = 1;
    }

    if (un) {
        unlink(addr);
    }

    fd = server_listen(addr);
    server_loop(fd);

    if (un) {
        unlink(addr);
    }
}

int client_connect(const char *addr)
{
    int fd = 0;
    int af = 0;
    struct sockaddr_storage saddr;
    int len = sizeof(struct sockaddr_storage);

    af = socket_addr(&saddr, addr);
    if (af == AF_UNIX) {
        len = sizeof(struct sockaddr_un);
    }
    fd = socket(af, SOCK_STREAM, 0);
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

void client_run(const char *addr, int n)
{
    int fd = 0;
    struct timeval tv_last;
    struct timeval tv;
    unsigned long us;


    fd = client_connect(addr);

    gettimeofday(&tv_last, NULL);
    client_loop(fd, n);
    gettimeofday(&tv, NULL);
    close(fd);
    us = (tv.tv_sec - tv_last.tv_sec)* 1000 * 1000 + (tv.tv_usec - tv_last.tv_usec);
    printf("%f ms\n", us * 1.0/(n * 1000));
}

static void usage(void)
{
    printf("Usage:\n");
    printf("\tlatency -s ip/unix-socket-path\n");
    printf("\tlatency -c ip/unix-socket-path number\n");
}

int main(int argc, char *argv[])
{
    if ((argc == 3) && (strcmp(argv[1], "-s") == 0)) {
        server_run(argv[2]);
    } else if ((argc == 4) && (strcmp(argv[1], "-c") == 0)) {
        client_run(argv[2], atoi(argv[3]));
    } else {
        usage();
    }

    return 0;
}
