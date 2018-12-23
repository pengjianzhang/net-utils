
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/time.h>

#include <openssl/ssl.h> 
#include <openssl/err.h>





#define RSP_LEN 4096

char    rsp[RSP_LEN];
char   *req = "GET / HTTP/1.1\r\nHost:127.0.0.1\r\nContent-Length: 0\r\n\r\n";


struct sockaddr_in  g_addr;
int                 g_req_num;





static void 
addr_init(struct sockaddr_in *srv_addr, char * ip, char* port)
{
    struct sockaddr_in * p = srv_addr;

    bzero(srv_addr, sizeof(struct sockaddr_in));  

    p->sin_family = PF_INET;
    p->sin_port = htons(atoi(port));    
    p->sin_addr.s_addr = inet_addr(ip);  
}

int connect_server(struct sockaddr_in * addr)
{
    int fd ;
    SSL_CTX *ctx;
    SSL *ssl;
    int len;
  
    fd = socket(addr->sin_family, SOCK_STREAM,0);

    if (connect(fd, (struct sockaddr *)addr, sizeof(struct sockaddr_in)) != 0) {
        close(fd);
        return -1;
    }
     
    ctx = SSL_CTX_new(SSLv23_client_method());

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl,fd);

    if(SSL_connect(ssl)==-1) {
        printf("ssl connect error\n");
        goto out;            
    }

    len = SSL_write(ssl, req, strlen(req));
    len = SSL_read(ssl, rsp, RSP_LEN);

    if(g_req_num == 1){
        if(len > 0) {
            rsp[len] = 0;
            printf("%s\n",rsp);    
        } else {
            printf("error\n");    
        }
    }
    
out:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(fd);
    SSL_CTX_free(ctx);

    return fd;
}

void* bench(void *s)
{
    int i;

    for(i = 0; i < g_req_num; i++) {
        connect_server(&g_addr);
    }
    
    return NULL;   
}

#define MAX_THREAD  128


int main(int argc, char ** argv)
{
    int thread;
    int num;
    int i;
    struct timeval start,end;
    float rps;
    float sec, ms;
    pthread_t tid[MAX_THREAD];


    if(argc != 5) {
        printf("%s ip port thread num \n",argv[0]);
        return  0;    
    }

    thread = atoi(argv[3]);
    num = atoi(argv[4]);
    g_req_num = num;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    addr_init(&g_addr, argv[1], argv[2]);

    gettimeofday(&start, NULL);
    if(thread > 1){
        for(i = 0; i < thread; i++) {
            pthread_create(&tid[i], NULL, bench, NULL);
        }
        
        for(i = 0; i < thread; i++) {
            pthread_join(tid[i],NULL);
        }
    } else {
        bench(NULL);     
    }
 
    gettimeofday(&end, NULL);

    num = thread*num;
    ms = ((end.tv_sec * 1000 + end.tv_usec/1000) - (start.tv_sec * 1000 + start.tv_usec/1000))*1.0;
    sec = ms/1000.0;
    rps = num/sec;

    printf("%d sec %f  %f\n",num,sec,rps);


    return 0;
}

