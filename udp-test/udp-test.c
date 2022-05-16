#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/time.h>
#include <getopt.h>

struct sockaddr_storage g_addr;

#define BUF_LEN (1024*128)

char buf[BUF_LEN + 1];
char msg[BUF_LEN];
int msg_len = 0;
int g_show;
int g_list;

void msg_set(int size)
{
    int i = 0;
    int j = 0;
    int line = 0;
    char str[200];
    int col = 100;
    int pad = 0;

    if (size<2) {
        size = 2;
    }

    line = size / col;
    pad = size - line * col;

    for (i = 0; i < line; i++) {
        sprintf(str, "%-8d", i * col);
        for (j = 8; j < col; j++) {
            str[j] = 'a';
        }
        str[j - 1] = '\n';
        str[j] = 0;
        strcat(msg, str);
    }
    if (pad > 0) {
        for (i = 0; i < pad; i++) {
            str[i] = 'b';
        }
        str[i] = 0;
        strcat(msg, str);
    }

    if (size > 1) {
        msg[size -1] = '=';
    }

    msg_len = size;
}

static void show_info(char *b, int len)
{
    if (len > 0) {
        if (g_list) {
            printf("recv %d\n", len);
        }
        if (g_show) {
            b[len] = 0;
            printf("%s\n", b);
        }
    }
}

static inline void client_request(int fd)
{
    int len = 0;

    sendto(fd, msg, msg_len, 0,(struct sockaddr *)&g_addr, sizeof(g_addr));
    len = recv(fd, buf, BUF_LEN, 0);
    show_info(buf, len);
}

void client_run(int fd, int size)
{
    msg_set(size);
    client_request(fd);
}

void server_run(int fd)
{
    struct sockaddr_storage guest;
    socklen_t slen;
    int len = 0;

    while(1){
        slen = sizeof(struct sockaddr_storage);
        len = recvfrom(fd, buf, BUF_LEN, 0,  (struct sockaddr*)&guest, &slen);

        if (len > 0) {
            show_info(buf, len);
            sendto(fd, buf, len, 0,  (struct sockaddr*)&guest, slen);
        }
    }
}

int set_socket_opt(int fd, int level)
{
    int one = 1;
    int ret;

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    #ifndef SO_REUSEPORT
    #define SO_REUSEPORT 15
    #endif

   ret = setsockopt(fd, level, SO_REUSEPORT, &one, sizeof(one));
    if(ret != 0) {
        printf("setsockopt REUSEPORT ERROR\n");
        return 0;
    } else {
        printf("bind ok\n");
    }

    return 1;
}

int sock_addr_set(struct sockaddr_storage *addr, char * ip,  int port)
{
    struct sockaddr_in      *p4 = (struct sockaddr_in *)addr;
    struct sockaddr_in6     *p6 = (struct sockaddr_in6 *)addr;

    port = htons(port);

    bzero(addr, sizeof(struct sockaddr_storage));
    if(strchr(ip,'.')){
        p4->sin_family = AF_INET;
        p4->sin_port = port;
        p4->sin_addr.s_addr = inet_addr(ip);
        return AF_INET;
    } else {
        p6->sin6_family = AF_INET6;
        p6->sin6_port = port;
        inet_pton(AF_INET6, ip, &(p6->sin6_addr));
        return AF_INET6;
    }
}

int socket_set_server(int fd)
{
    int socklen,level;
    int domain = g_addr.ss_family;

    if(domain == AF_INET) {
        level = SOL_SOCKET;
        socklen = sizeof(struct sockaddr_in);
    } else {
        level = SOL_IPV6;
        socklen = sizeof(struct sockaddr_in6);
    }

    if (!set_socket_opt(fd, level)) {
        goto err;
    }

    if (bind(fd, (struct sockaddr *)&g_addr, socklen) == -1) {
        goto err;
    }

    return fd;
err:
    close(fd);
    return -1;
}

void usage()
{
    printf("usage:\n\t./udp-test --client|--server --ip|-i IP  --port|-p PORT --size|-n SIZE [--show|-o] [--list|-l] [--daemon|-d]\n");
}

static struct option g_options[] = {
    {"help", no_argument, NULL, 'h'},
    {"server", required_argument, NULL, 's'},
    {"client", required_argument, NULL, 'c'},
    {"size", required_argument, NULL, 'n'},
    {"ip", required_argument, NULL, 'i'},
    {"port", required_argument, NULL, 'p'},
    {"show", no_argument, NULL, 'o'},
    {"daemon", no_argument, NULL, 'd'},
    {"list", no_argument, NULL, 'l'},
    {NULL, 0, NULL, 0}
};

int main(int argc, char **argv)
{
    int fd = 0;
    int domain = 0;
    int client = 0;
    int server = 0;
    int d = 0;
    int port = 0;
    int opt = 0;
    int size = 0;
    char addr[128] = {0};

    const char *optstr = "hdoscn:i:p:";

    if (argc == 1) {
        usage();
        return 1;
    }

    while ((opt = getopt_long_only(argc, argv, optstr, g_options, NULL)) != -1) {
        switch (opt) {
            case 'c':
                client = 1;
                break;
            case 's':
                server = 1;
                break;
            case 'n':
                size = atoi(optarg);
                if ((size <= 0) || (size >= BUF_LEN)) {
                    return 1;
                }
                break;
            case 'p':
                port = atoi(optarg);
                if ((port <= 0) || (port >= 65536)) {
                    return 1;
                }
                break;
            case 'i':
                strcpy(addr, optarg);
                break;
            case 'o':
                g_show = 1;
                break;
            case 'l':
                g_list = 1;
                break;
            case 'h':
                usage();
                return 0;
            case 'd':
                d = 1;
                break;
            default:
                return 1;
        }
    }

    if (client == server) {
        return 1;
    }

    if (port == 0) {
        return 1;
    }

    if (size == 0) {
        size = 10;
    }

    domain = sock_addr_set(&g_addr, addr, port);

    if (d) {
        daemon(0, 0);
    }

    fd = socket(domain, SOCK_DGRAM, 0);

    if(fd >= 0) {
        if(client) {
            client_run(fd, size);
        } else {
            if(socket_set_server(fd) > 0) {
                server_run(fd);
            }
        }

        close(fd);
    }
    return 0;
}
