#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAXBUF 1024


int main(int argc, char **argv)
{
	int sockfd,len;
	struct sockaddr_in dest;
	char buffer[MAXBUF + 1];
	SSL_CTX *ctx;
	SSL *ssl;
    char *hostname = "fstream.binance.com";
//"Accept-Language: en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7\r\n"
//"Cache-Control: no-cache\r\n"
//"User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36\r\n"
//"Pragma: no-cache\r\n"

    const char *msg =
"GET /stream HTTP/1.1\r\n"
"Connection: Upgrade\r\n"
"Host: fstream.binance.com\r\n"
"Sec-WebSocket-Key: ROfq82nUTxdKCovHSmM1+w==\r\n"
"Sec-WebSocket-Version: 13\r\n"
"Upgrade: websocket\r\n"
"\r\n"
;

    char *req = "{\"method\":\"SUBSCRIBE\",\"params\":[\"btcusdt@depth20\"],\"id\":101}";

    printf("%s\nlen %d\n", req, strlen(req));
	if(argc !=3){
		printf("./client serverIP serverPort\n");
		exit(-1);
	}


	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();


	printf("init.\n");
	ctx = SSL_CTX_new(SSLv23_client_method());
	if(ctx==NULL) {
		ERR_print_errors_fp(stdout);
		exit(1);
	}
	printf("ctx new.\n");
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("Socket");
		exit(errno);
	}
	printf("sockfd created.\n");
	bzero(&dest, sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_port = htons(atoi(argv[2]));
	dest.sin_addr.s_addr = inet_addr(argv[1]);
	if (connect(sockfd, (struct sockaddr *) &dest, sizeof(dest)) != 0) {
		perror("Connect");
		exit(errno);
	}
	printf("server connected.\n");
	ssl=SSL_new(ctx);
	SSL_set_fd(ssl,sockfd);
    SSL_set_tlsext_host_name(ssl, hostname);
	if(SSL_connect(ssl)==-1) {
		ERR_print_errors_fp(stderr);
        goto finish;
    } else {
		printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
	}

	len = SSL_write(ssl, msg, strlen(msg));
	if (len > 0) {
		printf("writing message:%s\nlen=%d\n",buffer,len);
	} else {
		printf("SSL_write faild,errno:%d\nerror:%s\n",errno,strerror(errno));
		goto finish;
	}
	len = SSL_read(ssl, buffer, MAXBUF);
	if (len > 0) {
        buffer[len] = 0;
		printf("server message:%s\nlen=%d\n",buffer,len);
	} else {
		printf("SSL_read faild,errno:%d\nerror:%s\n",errno,strerror(errno));
		goto finish;
	}

    uint8_t head[6];
    uint8_t plen = strlen(req);
    head[0] = 0x01;
    head[1] = 0x80|plen;
    head[2] = 0;
    head[3] = 0;
    head[4] = 0;
    head[5] = 0;
	len = SSL_write(ssl, head, 6);
	len = SSL_write(ssl, req, strlen(req));

    while(1) {
        len = SSL_read(ssl, buffer, MAXBUF);
        if (len > 0) {
            buffer[len] = 0;
            printf("server message:%s\nlen=%d\n",buffer,len);
        } else {
            printf("SSL_read faild,errno:%d\nerror:%s\n",errno,strerror(errno));
            goto finish;
        }
    }

	finish:
		SSL_shutdown(ssl);
		SSL_free(ssl);
		close(sockfd);
		SSL_CTX_free(ctx);
		return 0;
}
