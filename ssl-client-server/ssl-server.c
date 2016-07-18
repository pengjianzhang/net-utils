#include <stdio.h>   
#include <stdlib.h> 
#include <errno.h>   
#include <string.h>   
#include <sys/types.h>   
#include <netinet/in.h>   
#include <sys/socket.h>   
#include <sys/wait.h>   
#include <unistd.h>   
#include <arpa/inet.h>   
#include <openssl/ssl.h>   
#include <openssl/err.h>  
#define MAXNUM 6
#define MAXBUF 1024 
//function used to change int into string 
void itoa(unsigned long val,char *buf, unsigned radix)
{
	char *p;
	char *firstdig;
	char temp;
	unsigned digval;
	p = buf;
	firstdig = p;
	do{
		digval = (unsigned)(val % radix);
		val /= radix;
		if(digval > 9)
			*p++ = (char)(digval-10+'a');
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
//there will be 2 arguments:certificate,private_key
int main(int argc, char **argv)  
{
	
	int sockfd, new_fd;
	socklen_t len;
	struct sockaddr_in my_addr, their_addr;
	char buf[MAXBUF + 1];  
	SSL_CTX *ctx; 


	if(argc != 4){
		printf("Usage:./server certFile privateKeyFile port\n");
		exit(-1);
	}
 	//init
	SSL_library_init();  
	OpenSSL_add_ssl_algorithms();  
	SSL_load_error_strings(); 
	//ssl content text
	ctx = SSL_CTX_new(SSLv23_server_method());  
	if (ctx == NULL) {  
        	ERR_print_errors_fp(stdout);  
       		exit(1);  
        }
	printf("ctx new.\n");  
	if (SSL_CTX_use_certificate_file(ctx, argv[1], SSL_FILETYPE_PEM) <= 0) {  
	        ERR_print_errors_fp(stdout);  
	        exit(1);  
	}
	printf("user certificate loaded.\n");
	if (SSL_CTX_use_PrivateKey_file(ctx, argv[2], SSL_FILETYPE_PEM) <= 0) {  
	        ERR_print_errors_fp(stdout);  
	        exit(1);  
        } 
	printf("user privatekey loaded.\n");
	if (!SSL_CTX_check_private_key(ctx)) {  
	        ERR_print_errors_fp(stdout);  
	        exit(1);  
    	} 
	printf("user privatekey checked.\n");
	if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1){  
	        perror("socket");  
	        exit(1);  
       	}  
     	else  
       		printf("socket created.\n");  

	int port = atoi(argv[3]);
        bzero(&my_addr, sizeof(my_addr));  
    	my_addr.sin_family = PF_INET;  
    	my_addr.sin_port = htons(port);    
        my_addr.sin_addr.s_addr = inet_addr("0.0.0.0");  
    	if (bind(sockfd, (struct sockaddr *) &my_addr, sizeof(struct sockaddr)) == -1) {  
        	perror("bind");  
        	exit(1);  
    	} 
	else  
        	printf("socket binded.\n");  
    	if (listen(sockfd, MAXNUM) == -1) {  
        	perror("listen");  
        	exit(1);  
    	} 
	else  
        	printf("begin listenning.\n");  
    	while (1) {  
        	SSL *ssl;  
        	len = sizeof(struct sockaddr);  
		if ((new_fd = accept(sockfd, (struct sockaddr *) &their_addr, &len)) == -1) 
		{  
            		perror("accept");  
            		exit(errno);  
        	} 
		else
		{  
       printf("server: got connection from %s, port %d, socket %d\n",inet_ntoa(their_addr.sin_addr),ntohs(their_addr.sin_port), new_fd);  
		}
		ssl = SSL_new(ctx);  
		printf("ssl based on ctx created.\n");
		SSL_set_fd(ssl, new_fd);  
		printf("ssl set to fd.\n");
		if (SSL_accept(ssl) == -1) 
		{  
	            perror("accept");  
        	    close(new_fd);  
            	    break;  
       		 } 
		printf("ssl accept.\n");
		bzero(buf, MAXBUF + 1);  
        	//read client data  
        	len = SSL_read(ssl, buf, MAXBUF);  
        	if (len > 0)  
		{
            		printf("ssl read:buf=%s,len=%d\n", buf, len);  
		}
       	 	else
		{
            		printf("errno=%d,error=%s\n",  errno, strerror(errno));  
		}
 		bzero(buf, MAXBUF + 1);  
		strcat(buf,"hello client");
		//create random number
		int i;
	//the function below is to create a seed,based on time,so we will see that the returned number by server equal to the number by client
   		srand((unsigned)time(NULL));
		i = rand();
		printf("i = %d\n",i);
		// change to string 
		char str[25];
		bzero(str,25);
		printf("string:%s\n",str);
		itoa(i,str,10);
		//strcat
		strcat(buf,str);
		printf("string:%s\n",str);
		len = SSL_write(ssl, buf, strlen(buf));  
		if (len <= 0) 
		{  
            		printf("buf=%s,errno=%d,error=%s\n",buf, errno, strerror(errno));  
            		goto finish;  
        	} 
		else
		{  
            		printf("ssl write:buf=%s,len=%d\n", buf, len);   
		}
      	       	//finish
      		finish:    
        	SSL_shutdown(ssl); 
       		SSL_free(ssl);  
        	close(new_fd);  
    	}  
   	close(sockfd);    
    	SSL_CTX_free(ctx);  
    	return 0;  
}  
  
 



  
 
  


