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
//function used to change int to string
void itoa(unsigned long val,char *buf, unsigned radix)
{
	char   *p;
       	char   *firstdig;
       	char   temp;
        unsigned   digval;
      	p = buf;
        firstdig = p;
        do{
       		digval = (unsigned)(val % radix);
                val /= radix;
                if(digval > 9)
                	*p++ = (char)(digval-10+ 'a');
                else
                        *p++ = (char)(digval+'0');
      	}while(val > 0);
        *p-- = '\0';
        do{
        	temp = *p;
               	*p = *firstdig;
                *firstdig = temp;
                --p;
                ++firstdig;
       	}while(firstdig < p);
}
void ShowCerts(SSL * ssl)
{
	X509 *cert;
	char *line;
	cert = SSL_get_peer_certificate(ssl);


	if (cert != NULL) {
		printf("user certificate information:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("certificate:%s\n",line);
		free(line);
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("inventor:%s\n",line);
		free(line);
		X509_free(cert);
	}
	else{
		printf("no certificate.\n");
	}
}

int main(int argc, char **argv)
{
	int sockfd,len;
	struct sockaddr_in dest;
	char buffer[MAXBUF + 1];
	SSL_CTX *ctx;
	SSL *ssl;



	if(argc !=3){
		printf("./client serverIP serverPort\n");
		exit(-1);
	}


	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();




	printf("init.\n");
	ctx = SSL_CTX_new(SSLv23_client_method());
	if(ctx==NULL)
	{
		ERR_print_errors_fp(stdout);
		exit(1);
	}
	printf("ctx new.\n");
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("Socket");
		exit(errno);
	}
	printf("sockfd created.\n");
	bzero(&dest, sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_port = htons(atoi(argv[2]));
	dest.sin_addr.s_addr = inet_addr(argv[1]);
	if (connect(sockfd, (struct sockaddr *) &dest, sizeof(dest)) != 0)
	{
		perror("Connect");
		exit(errno);
	}
	printf("server connected.\n");
	ssl=SSL_new(ctx);
	SSL_set_fd(ssl,sockfd);
	if(SSL_connect(ssl)==-1)
		ERR_print_errors_fp(stderr);
	else
	{
		printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
		ShowCerts(ssl);
	}
	bzero(buffer, MAXBUF + 1);
	//printf("input sending message:");
	//scanf("%s",buffer);
	strcat(buffer,"hello server");
	//create random number
	int i =0;
	srand((unsigned)time(NULL));
	i=rand();
	//change to string
	char str[25];
	bzero(str,25);
	itoa(i,str,10);
	//strcat
	strcat(buffer,str);
	len = SSL_write(ssl, buffer, strlen(buffer));
	if (len > 0)
	{
		printf("writing message:%s\nlen=%d\n",buffer,len);
	}
	else
	{
		printf("SSL_write faild,errno:%d\nerror:%s\n",errno,strerror(errno));
		goto finish;
	}
	bzero(buffer, MAXBUF + 1);
	len = SSL_read(ssl, buffer, MAXBUF);
	if (len > 0)
	{
		printf("server message:%s\nlen=%d\n",buffer,len);
	}
	else
	{
		printf("SSL_read faild,errno:%d\nerror:%s\n",errno,strerror(errno));
		goto finish;
	}
	finish:
		SSL_shutdown(ssl);
		SSL_free(ssl);
		close(sockfd);
		SSL_CTX_free(ctx);
		return 0;
}
	





	
	
