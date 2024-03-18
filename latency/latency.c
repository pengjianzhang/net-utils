#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/time.h>
#include <getopt.h>
#include <pthread.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#define ADDR_SIZE   108
#define THREAD_MAX  128
#define PATH_SIZE   128

int g_rtt_min_us = 1000 * 1000;
__thread struct timeval tv_last;
__thread struct timeval tv;
int g_alarm = 0;
int g_show = 0;
int g_wait = 0;
int g_repeat = 1;
int g_first = 1;
int g_ping = 0;
int g_thread = 1;
int g_port = 80;
int g_lport = 0;
int g_udp = 0;
int g_num = 0;
int g_ssl_enable = 0;
int g_time = 0;
int g_timestamp = 0;
char g_path[PATH_SIZE];
char g_addr[ADDR_SIZE];
char g_laddr[ADDR_SIZE];

#define BUF_SIZE    65536
__thread char req_buf[BUF_SIZE + 1] =
"GET / HTTP/1.1\r\n"
"User-Agent: curl/7.29.0\r\n"
"Host: 172.16.199.175\r\n"
"Accept: */*\r\n"
"\r\n";
int req_buf_len = 0;

#define REQ_FMT "GET %s HTTP/1.1\r\n"   \
    "User-Agent: curl/7.29.0\r\n"       \
    "Host: localhost\r\n"               \
    "Accept: */*\r\n"                   \
    "\r\n"

char rsp_buf[BUF_SIZE + 1] =
"HTTP/1.1 200 OK\r\n"
"Server: nginx/1.20.1\r\n"
"Date: Sun, 17 Apr 2022 07:12:08 GMT\r\n"
"Content-Type: application/octet-stream\r\n"
"Content-Length: 13\r\n"
"Connection: keep-alive\r\n"
"\r\n"
"nginx server\n";
int rsp_buf_len = 0;

static __thread SSL_CTX *g_ctx = NULL;
static __thread SSL *g_ssl = NULL;

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

static void ssl_init(void)
{
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ERR_load_crypto_strings();
}

static int ssl_client_init(int sk)
{
    SSL *ssl = NULL;
    SSL_CTX *ctx = NULL;

    ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL) {
        goto err;
    }
    SSL_CTX_set_options(ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);

    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        goto err;
    }

    SSL_set_fd(ssl, sk);
    if(SSL_connect(ssl) == -1) {
        goto err;
    }

    g_ssl = ssl;
    g_ctx = ctx;
    return 0;

err:
    if (ssl) {
        SSL_free(ssl);
    }

    if (ctx) {
        SSL_CTX_free(ctx);
    }

    return -1;
}

static inline void show(char *buf, int len)
{
    if (g_show && (len > 0)) {
        buf[len] = 0;
        printf("%s\n", buf);
    }
}

static void msg_set(char *msg, int size)
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

    msg[0] = 0;
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
}

int socket_addr(struct sockaddr_storage *addr, const char *str, int port)
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
        p6->sin6_port = htons(port);
        inet_pton(AF_INET6, str, &(p6->sin6_addr));
        return AF_INET6;
    } else if (str[0]) {
        p4->sin_family = AF_INET;
        p4->sin_port = htons(port);
        p4->sin_addr.s_addr = inet_addr(str);
        return AF_INET;
    } else {
        return -1;
    }
}

static int server_listen(const char *addr, int port, int udp)
{
    int fd = 0;
    int af = 0;
    int ret = 0;
    int one = 1;
    struct sockaddr_storage saddr;
    int len = sizeof(struct sockaddr_storage);

    af = socket_addr(&saddr, addr, port);
    if (af < 0) {
        return -1;
    }

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

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

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

    while ((cfd = accept(fd, NULL, NULL)) > 0) {
        while((ret = recv(cfd, req_buf, BUF_SIZE, 0)) > 0) {
            show(req_buf, ret);
            send(cfd, rsp_buf, rsp_buf_len, 0);
        }
        close(cfd);
    }
}

static void udp_server_loop(int fd)
{
    struct sockaddr_storage guest;
    socklen_t slen;
    int ret = 0;
    int i = 0;


    slen = sizeof(struct sockaddr_storage);

    if (g_repeat && g_first) {
        while(1){
            for (i = 0; i < g_repeat; i++) {
                ret = recvfrom(fd, req_buf, BUF_SIZE, 0,  (struct sockaddr*)&guest, &slen);
            }
            if (ret > 0) {
                show(req_buf, ret);
                sendto(fd, rsp_buf, rsp_buf_len, 0,  (struct sockaddr*)&guest, slen);
            }
        }
    } else {
        while(1){
            ret = recvfrom(fd, req_buf, BUF_SIZE, 0,  (struct sockaddr*)&guest, &slen);
            if (ret > 0) {
                show(req_buf, ret);
                sendto(fd, rsp_buf, rsp_buf_len, 0,  (struct sockaddr*)&guest, slen);
            }
        }
    }
}

void server_run(void *data)
{
    int fd = 0;
    int un = 0;

    if (strchr(g_addr, '/') != NULL) {
        un = 1;
    }

    if (un) {
        unlink(g_addr);
    }

    fd = server_listen(g_addr, g_port, g_udp);
    if (g_udp) {
        udp_server_loop(fd);
    } else {
        server_loop(fd);
    }

    if (un) {
        unlink(g_addr);
    }
}

static int client_connect(const char *addr, int port, const char *laddr, int lport, int udp)
{
    int fd = 0;
    int af = 0;
    int af2 = 0;
    struct sockaddr_storage saddr;
    struct sockaddr_storage laddr2;
    int len = sizeof(struct sockaddr_storage);

    af = socket_addr(&saddr, addr, port);
    if (af < 0) {
        return -1;
    }

    if (af == AF_UNIX) {
        len = sizeof(struct sockaddr_un);
    }

    if (udp) {
        fd = socket(af, SOCK_DGRAM, 0);
    } else {
        fd = socket(af, SOCK_STREAM, 0);
    }

    af2 = socket_addr(&laddr2, laddr, lport);
    if (af2 == af) {
        bind(fd, (struct sockaddr *)&laddr2, len);
    }

    if(connect(fd, (struct sockaddr *)&saddr, len) < 0)  {
        close(fd);
        return -1;
    }

    if (g_ssl_enable) {
        if (ssl_client_init(fd) < 0) {
            close(fd);
            return -1;
        }
    }

    return fd;
}

static void client_request_start(void)
{
    gettimeofday(&tv_last, NULL);
}

static int client_request_end(int n)
{
    unsigned long us;
    time_t t;
    struct tm *tm;

    gettimeofday(&tv, NULL);

    us = (tv.tv_sec - tv_last.tv_sec)* 1000 * 1000 + (tv.tv_usec - tv_last.tv_usec);
    if (g_time) {
        time(&t);
        tm = localtime(&t);
        printf("%04d-%02d-%02d %02d:%02d:%02d\t", tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);
    }

    if (g_timestamp) {
        printf("%lu\t", tv.tv_sec);
    }
    printf("%f ms\n", us * 1.0/(n * 1000));
    fflush(stdout);

    us = (us / 1000) * 1000;
    return us;
}

static void alarm_cb(int sig)
{
    g_alarm = 1;
}

static void alarm_init(void)
{
    struct sigaction alarmact;

    bzero(&alarmact,sizeof(alarmact));
    alarmact.sa_handler = alarm_cb;
    alarmact.sa_flags = SA_NOMASK;
    sigaction(SIGALRM,&alarmact,NULL);
}

static void alarm_add(int sec)
{
    g_alarm = 0;
    alarm(sec);
}

static void alarm_del(void)
{
    alarm(0);
}

void client_loop(int fd, int n)
{
    int i = 0;
    int j = 0;
    int ret = 0;
    int rcv_num = 0;
    int us = 0;
    int large = 0;
    int timeout = 0;

    timeout = g_wait / (1000*1000);
    timeout += 1;

    alarm_init();
    if (g_first) {
        rcv_num = 1;
    } else {
        rcv_num = g_repeat;
    }

    for (i = 0; i < n; i++) {
        alarm_add(timeout);
        if (g_ping) {
            client_request_start();
        }
        if (g_ssl_enable) {
            for (j = 0; j < g_repeat; j++) {
                SSL_write(g_ssl, req_buf, req_buf_len);
            }

            for (j = 0; j < rcv_num; j++) {
                ret = SSL_read(g_ssl, rsp_buf, BUF_SIZE);
            }
        } else {
            for (j = 0; j < g_repeat; j++) {
                send(fd, req_buf, req_buf_len, 0);
            }

            for (j = 0; j < rcv_num; j++) {
                ret = recv(fd, rsp_buf, BUF_SIZE, 0);
            }
        }
/*
        if (g_alarm) {
            continue;
        }
*/
        if (g_ping) {
            client_request_end(1);
        }
        show(rsp_buf, ret);
        if (g_wait) {
            if (g_wait <= 1000*1000) {
                usleep(g_wait);
            } else {
                sleep(g_wait/(1000*1000));
            }
        }
    }
}

void *client_run(void *data)
{
    int fd = 0;

    fd = client_connect(g_addr, g_port, g_laddr, g_lport, g_udp);
    if (!g_ping) {
        client_request_start();
    }
    client_loop(fd, g_num);

    if (!g_ping) {
        client_request_end(g_num);
    }

    if (g_ssl_enable) {
        SSL_shutdown(g_ssl);
        SSL_free(g_ssl);
        SSL_CTX_free(g_ctx);
    }
    close(fd);
    return NULL;
}

void client_run_threads(void)
{
    int i = 0;
    pthread_t t[THREAD_MAX];

    if (g_thread <= 1) {
        client_run(NULL);
        return;
    }

    for (i = 0; i < g_thread; i++) {
        pthread_create(&t[i], NULL, client_run, NULL);
    }

    for (i = 0; i < g_thread; i++) {
        pthread_join(t[i], NULL);
    }
}

static void usage(void)
{
    char *opts =
        "\t--udp|-u\n"
        "\t--server|-s ip/unix-socket-path\n"
        "\t--client|-c ip/unix-socket-path\n"
        "\t--laddr|-L ip\n"
        "\t--lport|-R port\n"
        "\t--port|-p port\n"
        "\t--show|-o\n"
        "\t--daemon|-D\n"
        "\t--size|-S Size\n"
        "\t--wait|-w w(us)\n"
        "\t--repeat|-r Repeat\n"
        "\t--first|-f\n"
        "\t--ping|-P\n"
        "\t--time|-T\n"
        "\t--timestamp|-m\n"
        "\t--path|-a PATH\n"
        "\t--ssl|-l\n"
        "\t--thread|-t threads\n"
        "\t--bind_cpu|-b CPU\n"
        "\t--number|-n number\n";

    printf("Usage:\n");
    printf("\tlatency options\n");
    printf("options:\n%s", opts);
}

static struct option g_options[] = {
    {"help", no_argument, NULL, 'h'},
    {"udp", no_argument, NULL, 'u'},
    {"server", required_argument, NULL, 's'},
    {"client", required_argument, NULL, 'c'},
    {"laddr", required_argument, NULL, 'L'},
    {"first", required_argument, NULL, 'f'},
    {"number", required_argument, NULL, 'n'},
    {"path", required_argument, NULL, 'a'},
    {"wait", required_argument, NULL, 'w'},
    {"size", required_argument, NULL, 'S'},
    {"bind_cpu", required_argument, NULL, 'b'},
    {"port", required_argument, NULL, 'p'},
    {"lport", required_argument, NULL, 'R'},
    {"repeat", required_argument, NULL, 'r'},
    {"thread", required_argument, NULL, 't'},
    {"show", no_argument, NULL, 'o'},
    {"daemon", no_argument, NULL, 'D'},
    {"ping", no_argument, NULL, 'P'},
    {"time", no_argument, NULL, 'T'},
    {"timestamp", no_argument, NULL, 'm'},
    {"ssl", no_argument, NULL, 'l'},
    {NULL, 0, NULL, 0}
};

int main(int argc, char *argv[])
{
    int len = 0;
    int server = 0;
    int client = 0;
    int opt = 0;
    int size = 0;
    int run_daemon = 0;
    int cpu = -1;
    const char *optstr = "hufolTmPDb:s:c:L:n:p:R:S:w:r:t:a:";

    if (argc == 1) {
        usage();
        return -1;
    }

    while ((opt = getopt_long_only(argc, argv, optstr, g_options, NULL)) != -1) {
        switch (opt) {
            case 'a':
                if (strlen(optarg) >= PATH_SIZE) {
                    return -1;
                }
                strcpy(g_path, optarg);
                break;
            case 'c':
                client = 1;
                strncpy(g_addr, optarg, ADDR_SIZE);
                break;
            case 's':
                server = 1;
                strncpy(g_addr, optarg, ADDR_SIZE);
                break;
            case 'L':
                strncpy(g_laddr, optarg, ADDR_SIZE);
                break;
            case 'R':
                g_lport = atoi(optarg);
                if ((g_lport <= 0) || (g_lport >= 65536)) {
                    goto err;
                }
                break;
            case 'n':
                g_num = atoi(optarg);
                if (g_num <= 0) {
                    goto err;
                }
                break;
            case 'p':
                g_port = atoi(optarg);
                if ((g_port <= 0) || (g_port >= 65536)) {
                    goto err;
                }
                break;
            case 'w':
                g_wait = atoi(optarg);
                if (g_wait <= 0) {
                    goto err;
                }
                len = strlen(optarg);
                if (len >= 2) {
                    if (optarg[len - 1] == 's') {
                        if (optarg[len - 2] == 'u') {
                            ;
                        } else if (optarg[len - 2] == 'm') {
                            g_wait *= 1000;
                        } else if ((optarg[len - 2] < '0') || (optarg[len - 2] > '9')){
                            goto err;
                        } else {
                            g_wait *= 1000 * 1000;
                        }
                    }
                }
                break;
            case 'r':
                g_repeat = atoi(optarg);
                if (g_repeat < 1) {
                    goto err;
                }
                break;
            case 't':
                g_thread = atoi(optarg);
                if ((g_thread < 1) || (g_thread > THREAD_MAX)) {
                    goto err;
                }
                break;
            case 'S':
                size = atoi(optarg);
                if ((size <= 0) || (size > BUF_SIZE)) {
                    goto err;
                }
                msg_set(req_buf, size);
                msg_set(rsp_buf, size);
                break;
            case 'b':
                cpu = atoi(optarg);
                if (cpu < 0) {
                    return -1;
                }
                break;
            case 'f':
                g_first = 1;
                break;
            case 'o':
                g_show = 1;
                break;
            case 'D':
                run_daemon = 1;
                break;
            case 'u':
                g_udp = 1;
                break;
            case 'P':
                g_ping = 1;
                break;
            case 'l':
                g_ssl_enable = 1;
                break;
            case 'T':
                g_time = 1;
                break;
            case 'm':
                g_timestamp = 1;
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

    if (server && g_num) {
        goto err;
    }

    if (strlen(g_path) > 0) {
        if (server || (size > 0)) {
            goto err;
        }

        sprintf(req_buf, REQ_FMT, g_path);
    }

    if (run_daemon) {
        if (daemon(1, 1) != 0) {
            printf("daemon error\n");
            return 1;
        }
    }

    if (g_ssl_enable) {
        if (server || g_udp) {
            printf("bad args\n");
            return -1;
        }
        ssl_init();
    }

    if (cpu >= 0) {
        cpu_bind(cpu);
    }
    req_buf_len = strlen(req_buf);
    rsp_buf_len = strlen(rsp_buf);


    if (client) {
        if (g_num == 0) {
            g_num = 1;
        }
        client_run_threads();
    } else {
        server_run(NULL);
    }

    return 0;
err:
    usage();
    return -1;
}
