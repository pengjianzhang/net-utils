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
#define PATH_SIZE       128
#define REQ_MAX         512
#define RSP_MAX         (1024*2)
#define QUERY_MAX       512
#define METHOD_MAX      16
#define SKEY_MAX        128
#define HEADER_MAX      256
#define ID_MAX          64

struct https_client {
    int num;
    int wait_ms;
    int show;

    int fd;
    SSL *ssl;
    SSL_CTX *ctx;
    uint32_t dip;
    uint16_t dport;
    uint32_t sip;
    uint16_t sport;

    int timestamp;

    char skey[SKEY_MAX];
    int skey_len;

    char method[METHOD_MAX];

    char hostname[HOSTNAME_MAX];
    char path[PATH_SIZE];

    char query[QUERY_MAX];
    int query_len;

    char id[ID_MAX];
    int id_len;

    char header[HEADER_MAX];
    int header_len;

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
        printf("connect error\n");
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

static int client_open(struct https_client *c)
{
    if (socket_open(c) < 0) {
        return -1;
    }

    if (ssl_open(c) < 0) {
        return -1;
    }

    return 0;
}

static uint64_t get_ms()
{
    struct timeval tv0;

    gettimeofday(&tv0, NULL);
    return (tv0.tv_sec * 1000) + (tv0.tv_usec / 1000);
}

int signature(char *data, int dlen, char *key, int klen, char *out)
{
    int slen = SHA256_DIGEST_LENGTH;
    uint8_t *p = NULL;
    uint8_t md[256];
    int md_len;
    int i = 0;

    HMAC(EVP_sha256(), key, klen, (unsigned char*)data, dlen, md, &md_len);
    p = out;
    for(i = 0; i < md_len; i++) {
        sprintf(p, "%02x", md[i]);
        p+= 2;
    }
    return 0;
}

static int client_request(struct https_client *c)
{
    int len = 0;
    struct timeval tv0;
    struct timeval tv1;
    uint64_t us = 0;
    uint64_t ms = 0;
    char query1[QUERY_MAX];
    char query2[QUERY_MAX];
    char query3[QUERY_MAX];
    char query4[QUERY_MAX];
    char *q = "";
    char *header = "";

    uint8_t sig[128];

    if (c->query_len) {
        q = c->query;
        ms = get_ms();
        if (c->timestamp) {
            sprintf(query1, "%s&timestamp=%lu", q, ms);
            q = query1;
        }

        if (c->id_len) {
            sprintf(query2, "%s&%s=%lu", q, c->id, ms);
            q = query2;
        }

        if (c->skey_len) {
            signature(q, strlen(q), c->skey, c->skey_len, sig);
            sprintf(query3, "%s&signature=%s", q, sig);
            q = query3;
        }

        sprintf(query4, "?%s", q);
        q = query4;
    }

    if (c->header_len) {
        header = c->header;
    }

    sprintf(c->req, "%s %s%s HTTP/1.1\r\nHost: %s\r\nuser-agent: curl\r\naccept: */*\r\nContent-Length: 0\r\n%s\r\n",
        c->method, c->path, q, c->hostname, header);
    c->req_len = strlen(c->req);

    if (c->show) {
        printf("%s", c->req);
    }
    gettimeofday(&tv0, NULL);

    SSL_write(c->ssl, c->req, c->req_len);
    len = SSL_read(c->ssl, c->rsp, RSP_MAX - 1);
    gettimeofday(&tv1, NULL);
    us = (tv1.tv_sec - tv0.tv_sec) * 1000 * 1000 + tv1.tv_usec - tv0.tv_usec;

    c->rsp[len] = 0;
    if (c->show) {
        printf("%s\n", c->rsp);
    }
    printf("latency %lu ms %lu us\n", us / 1000, us % 1000);
}

int client_run(struct https_client *c)
{
    int i = 0;

    for (i = 0; i < c->num; i++) {
        client_request(c);
        if (c->wait_ms > 0) {
            usleep(c->wait_ms * 1000);
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
    printf("usage:\n\t%s method hostname path query id header ts(0|1) skey  dip dport sip sport num wait(ms) show(0|1)\n", name);
}

static int set_str(char *src, char *dst, int dst_size, int *dst_len)
{
    int len = strlen(src);

    if (len >= dst_size) {
        return -1;
    }

    if (len > 1) {
        strcpy(dst, src);
        if (dst_len) {
            *dst_len = len;
        }
    }

    return 0;
}

int config(int argc, char *argv[], struct https_client *c)
{
    char *method = NULL;
    char *hostname = NULL;
    char *path = NULL;
    char *query = NULL;
    char *skey = NULL;
    int n = 0;
    char *header = NULL;

    if (argc != 16) {
        return -1;
    }
    memset(c, 0, sizeof(struct https_client));
    c->fd = -1;

    n = 1;

    if (set_str(argv[n++], c->method, METHOD_MAX, NULL) < 0) {
        return -1;
    }

    if (set_str(argv[n++], c->hostname, HOSTNAME_MAX, NULL) < 0) {
        return -1;
    }

    if (set_str(argv[n++], c->path, PATH_SIZE, NULL) < 0) {
        return -1;
    }

    if (set_str(argv[n++], c->query, QUERY_MAX, &c->query_len) < 0) {
        return -1;
    }

    if (set_str(argv[n++], c->id, ID_MAX, &c->id_len) < 0) {
        return -1;
    }

    if (set_str(argv[n++], c->header, HEADER_MAX, &c->header_len) < 0) {
        return -1;
    }

    c->timestamp = atoi(argv[n++]);

    if (set_str(argv[n++], c->skey, SKEY_MAX, &c->skey_len) < 0) {
        return -1;
    }

    c->dip = inet_addr(argv[n++]);
    c->dport = htons(atoi(argv[n++]));

    c->sip = inet_addr(argv[n++]);
    c->sport = htons(atoi(argv[n++]));


    c->num = atoi(argv[n++]);
    c->wait_ms = atoi(argv[n++]);
    c->show = atoi(argv[n++]);

    if (c->header_len) {
        c->header[c->header_len++] = '\r';
        c->header[c->header_len++] = '\n';
    }

    return 0;
}

int main(int argc, char *argv[])
{
    struct https_client *c = &g_client;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    if (config(argc, argv, c) < 0) {
        usage(argv[0]);
        return 1;
    }

    if (client_open(c) < 0) {
        goto out;
    }

    client_run(c);
out:
    client_close(c);
    return 0;
}
