#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define HOSTNAME_MAX    128
#define PATH_SIZE        128
#define REQ_MAX         512
#define RSP_MAX         (1024*2)

struct https_client {
    int fd;
    SSL *ssl;
    SSL_CTX *ctx;
    uint32_t dip;
    uint16_t dport;
    uint32_t sip;
    uint16_t sport;
    char hostname[HOSTNAME_MAX];
    char path[PATH_SIZE];

    char req[REQ_MAX];
    int req_len;

    char rsp[RSP_MAX];
    int rsp_len;
};

struct https_client g_client;

static void addr_init(struct sockaddr_in *addr, uint32_t ip, uint16_t port)
{
    memset(addr, 0, sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = ip;
    addr->sin_port = port;
}

static int socket_open(struct https_client *c)
{
    int fd = -1;
    int one = 1;
    struct sockaddr_in remote;
    struct sockaddr_in local;
    socklen_t len = sizeof(struct sockaddr_in);

    addr_init(&remote, c->dip, c->dport);
    addr_init(&local, c->sip, c->sport);
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int));
    if (c->sip) {
        if (bind(fd, (struct sockaddr *)&local, len) < 0) {
            printf("bind error\n");
            close(fd);
            return -1;
        }
    }

    if (connect(fd, (const struct sockaddr *)&remote, len) < 0) {
        printf("bind error\n");
        close(fd);
        return -1;
    }

    printf("socket open ok\n");
    c->fd = fd;
    return fd;
}

static int ssl_open(struct https_client *c)
{
    const SSL_METHOD *m = NULL;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;

    m = SSLv23_client_method();
    if (m == NULL) {
        printf("no method\n");
        return -1;
    }

    ctx = SSL_CTX_new(m);
    if (ctx == NULL) {
        printf("no ssl ctx\n");
        return -1;
    }

    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        goto err;
    }

    SSL_set_tlsext_host_name(ssl, c->hostname);
    SSL_set_fd(ssl, c->fd);
	if(SSL_connect(ssl) == -1) {
        printf("ssl connect fail\n");
        goto err;
    }

    c->ssl = ssl;
    c->ctx = ctx;
    printf("ssl open ok\n");
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

static int client_init(struct https_client *c, char *hostname, char *path, uint32_t dip, uint16_t dport, uint32_t sip, uint16_t sport)
{
    memset(c, 0, sizeof(struct https_client));
    c->fd = -1;
    if (strlen(hostname) >= HOSTNAME_MAX) {
        return -1;
    }
    strcpy(c->hostname, hostname);

    if (strlen(path) >= PATH_SIZE) {
        return -1;
    }
    strcpy(c->path, path);

    c->dip = dip;
    c->dport = dport;
    c->sip = sip;
    c->sport = sport;
    sprintf(c->req, "GET %s HTTP/1.1\r\nHost: %s\r\nuser-agent: curl\r\naccept: */*\r\n\r\n", path, hostname);
    c->req_len = strlen(c->req);

    if (socket_open(c) < 0) {
        return -1;
    }

    if (ssl_open(c) < 0) {
        return -1;
    }

    return 0;
}

static int client_request(struct https_client *c, int show)
{
    int len = 0;
    struct timeval tv0;
    struct timeval tv1;
    uint64_t us = 0;

    if (show) {
        printf("%s", c->req);
    }
    gettimeofday(&tv0, NULL);
    SSL_write(c->ssl, c->req, c->req_len);
    len = SSL_read(c->ssl, c->rsp, RSP_MAX - 1);
    gettimeofday(&tv1, NULL);
    us = (tv1.tv_sec - tv0.tv_sec) * 1000 * 1000 + tv1.tv_usec - tv0.tv_usec;

    c->rsp[len] = 0;
    if (show) {
        printf("%s\n", c->rsp);
    }
    printf("latency %lu ms %lu us\n", us / 1000, us % 1000);
}

int client_run(struct https_client *c, int n, int wait_ms, int show)
{
    int i = 0;

    for (i = 0; i < n; i++) {
        client_request(c, show);
        if (wait_ms > 0) {
            usleep(wait_ms * 1000);
        }
    }
    return 0;
}

int client_close(struct https_client *c)
{
    if (c->ssl) {
        SSL_free(c->ssl);
        c->ssl = NULL;
    }

    if (c->ctx) {
        SSL_CTX_free(c->ctx);
        c->ctx = NULL;
    }

    if (c->fd > 0) {
        close(c->fd);
        c->fd = -1;
    }
    return 0;
}

static void usage(char *name)
{
    printf("usage:\n\t%s hostname path dip dport sip sport num [wait(ms) show(0|1)]\n", name);
}

int main(int argc, char *argv[])
{
    char *hostname = NULL;
    char *path = NULL;
    uint32_t dip = 0;
    uint16_t dport = 0;
    uint32_t sip = 0;
    uint16_t sport = 0;
    int num = 0;
    int wait_ms = 1000;
    int show = 0;
    struct https_client *c = &g_client;

    if (argc < 8) {
        usage(argv[0]);
        return 1;
    }
    hostname = argv[1];
    path = argv[2];
    dip = inet_addr(argv[3]);
    dport = htons(atoi(argv[4]));

    sip = inet_addr(argv[5]);
    sport = htons(atoi(argv[6]));
    num = atoi(argv[7]);

    if (argc >= 9) {
        wait_ms = atoi(argv[8]);
    }
    if (argc >= 10) {
        show = atoi(argv[9]);
    }

	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

    if (client_init(c, hostname, path, dip, dport, sip, sport) < 0) {
        goto out;
    }

    client_run(c, num, wait_ms, show);
out:
    client_close(c);
    return 0;
}
