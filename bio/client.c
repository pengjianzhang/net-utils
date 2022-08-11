/*
 * Copyright (c) jianzhang peng
 * A simple demo for openssl bio programming
 * */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <event2/event.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>


#define BUF_LEN 4096
struct ssl_session
{
    int sk;
    int peer_close;
    SSL *ssl;
    SSL_CTX *ctx;

    BIO *rbio;
    BIO *wbio;
    struct event_base *base;
    struct event *ev_stdin;
    struct event *ev_socket;
};

static void usage(void)
{
    printf("ssl_client ip port [hostname]\n");
}

static int addr_init(struct sockaddr_in *addr, const char *ip_str, const char *port_str)
{
    int port = 0;

    port = atoi(port_str);
    if ((port <= 0) || (port >= 65536)) {
        return -1;
    }

    memset(addr, 0, sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);

    if (inet_pton(AF_INET, ip_str, &(addr->sin_addr)) <= 0) {
        return -1;
    }

    return 0;
}

static int socket_init(struct sockaddr_in *addr)
{
    int sk = -1;

    sk = socket(AF_INET, SOCK_STREAM, 0);
    if (sk < 0) {
        return -1;
    }

    if (connect(sk, (struct sockaddr *)addr, sizeof(struct sockaddr_in)) < 0) {
        return -1;
    }

    return sk;
}

static void ssl_init(void)
{
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ERR_load_crypto_strings();
}

static SSL_CTX *ssl_client_ctx_new(void)
{
    SSL_CTX *ctx = NULL;

    ctx = SSL_CTX_new(SSLv23_client_method());
    SSL_CTX_set_options(ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);
    return ctx;
}

static SSL *ssl_client_new(SSL_CTX *ctx)
{
    SSL *ssl = NULL;

    ssl = SSL_new(ctx);
    SSL_set_connect_state(ssl);
    return ssl;
}

static int ssl_client_init_session(struct ssl_session *sess, int sk, const char *hostname)
{
    BIO *rbio = NULL;
    BIO *wbio = NULL;
    SSL *ssl = NULL;
    SSL_CTX *ctx = NULL;

    memset(sess, 0, sizeof(struct ssl_session));
    ctx = ssl_client_ctx_new();
    ssl = ssl_client_new(ctx);
    rbio = BIO_new(BIO_s_mem());
    wbio = BIO_new(BIO_s_mem());
    SSL_set_bio(ssl, rbio, wbio);
    if (hostname) {
        SSL_set_tlsext_host_name(ssl, hostname);
    }

    sess->ctx = ctx;
    sess->ssl = ssl;
    sess->sk = sk;
    sess->rbio = rbio;
    sess->wbio = wbio;

    return 0;
}

static int ssl_handshake(struct ssl_session *sess)
{
    char buf[BUF_LEN];
    int ret = 0;
    int status = 0;
    int sk = -1;
    int n = 0;
    BIO *wbio = NULL;
    BIO *rbio = NULL;
    SSL *ssl = NULL;

    ssl = sess->ssl;
    wbio = sess->wbio;
    rbio = sess->rbio;
    sk = sess->sk;

retry:
    ret = SSL_do_handshake(ssl);
    status = SSL_get_error(ssl, ret);
    if ((status == SSL_ERROR_WANT_WRITE) || (status == SSL_ERROR_WANT_READ)) {
        do {
            n = BIO_read(wbio, buf, BUF_LEN);
            if (n > 0) {
                send(sk, buf, n, 0);
            }
        } while (n > 0);
    }

    if (SSL_is_init_finished(ssl)) {
        printf("ssl init ok\n");
        return 0;
    }

    n = recv(sk, buf, BUF_LEN, 0);
    if (n > 0) {
        n = BIO_write(rbio, buf, n);
        if (SSL_is_init_finished(ssl)) {
            printf("ssl init ok\n");
            return 0;
        } else {
            goto retry;
        }
    }

    return status;
}

static void ssl_client_cleanup(struct ssl_session *sess)
{
    /* SSL_free will free bio */
    SSL_free(sess->ssl);
    SSL_CTX_free(sess->ctx);
}

static void process_stdin_cb(evutil_socket_t fd, short what, void *arg)
{
    ssize_t n = 0;
    char buf[BUF_LEN];
    struct ssl_session *sess = NULL;

    sess = (struct ssl_session *)arg;
    n = read(STDIN_FILENO, buf, BUF_LEN);
    if (n > 0) {
        SSL_write(sess->ssl, buf, n);
        n = BIO_read(sess->wbio, buf, BUF_LEN);
        send(sess->sk, buf, n, 0);
    } else {
        event_del(sess->ev_stdin);
    }
}

static void process_socket_cb(evutil_socket_t fd, short what, void *arg)
{
    int ret = 0;
    ssize_t n = 0;
    char buf[BUF_LEN];
    struct ssl_session *sess = NULL;

    sess = (struct ssl_session *)arg;
    n = recv(sess->sk, buf, BUF_LEN, 0);
    if (n > 0) {
        BIO_write(sess->rbio, buf, n);
        n = SSL_read(sess->ssl, buf, BUF_LEN);
        if (n > 0) {
            buf[n] = 0;
            printf("%s\n", buf);
        } else {
            ret = SSL_get_error(sess->ssl, n);
            if ((ret == SSL_ERROR_ZERO_RETURN) || ( ret == SSL_ERROR_SSL)) {
                sess->peer_close = 1;
                event_base_loopbreak(sess->base);
            }
        }
    }
}

static void ssl_client_close(struct ssl_session *sess)
{
    ssize_t n = 0;
    char buf[BUF_LEN];

    if (sess->peer_close) {
        return;
    }
    SSL_shutdown(sess->ssl);
    n = BIO_read(sess->wbio, buf, BUF_LEN);
    if (n > 0) {
        send(sess->sk, buf, n, 0);
    }
    n = recv(sess->sk, buf, BUF_LEN, 0);
    if (n > 0) {
        BIO_write(sess->rbio, buf, n);
    }
}

static void sig_handler(int signal, short events, void *base)
{
    event_base_loopbreak(base);
}

static void ssl_client_run(struct ssl_session *sess)
{
    struct event *ev0;
    struct event_base *base = NULL;
    struct event_config *cfg = NULL;

    cfg = event_config_new();
    event_config_avoid_method(cfg, "epoll");
    base = event_base_new_with_config(cfg);
    event_config_free(cfg);

    ssl_handshake(sess);
    sleep(5);
    sess->ev_stdin = event_new(base, STDIN_FILENO, EV_READ|EV_PERSIST, process_stdin_cb, sess);
    event_add(sess->ev_stdin, NULL);

    sess->ev_socket = event_new(base, sess->sk, EV_READ|EV_PERSIST, process_socket_cb, sess);
    event_add(sess->ev_socket, NULL);

    ev0 = evsignal_new(base, SIGINT, sig_handler, base);
    event_add(ev0, NULL);

    sess->base = base;
    event_base_dispatch(base);

    event_del(sess->ev_stdin);
    event_del(sess->ev_socket);
    event_del(ev0);
    event_free(ev0);
    event_free(sess->ev_stdin);
    event_free(sess->ev_socket);

    event_base_free(base);
    ssl_client_close(sess);
}

int main(int argc, char **argv)
{
    int sk = -1;
    struct sockaddr_in addr;
    struct ssl_session sess;
    const char *ip = NULL;
    const char *port = NULL;
    const char *hostname = NULL;

    if ((argc < 3) || (argc > 4)) {
        usage();
        return 1;
    }

    ip = argv[1];
    port = argv[2];
    if (argc >= 4) {
        hostname = argv[3];
    }

    ssl_init();
    if (addr_init(&addr, ip, port) < 0) {
        return -1;
    }

    if ((sk = socket_init(&addr)) < 0) {
        return -1;
    }

    ssl_client_init_session(&sess, sk, hostname);

    ssl_client_run(&sess);

    ssl_client_cleanup(&sess);
    close(sk);

  return 0;
}
