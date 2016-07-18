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



void read_html(SSL * ssl)
{

	#define BUF_LEN	1024
	char buf[BUF_LEN];

	int len = SSL_read(ssl, buf, BUF_LEN);  

       	if (len > 0)  
	{
		buf[len] = 0;
		printf("%s\n", buf);  
	}
	else
	{
		printf("Error\n");
	}
}

//function used to change int into string 
void write_html( SSL *ssl)
{
	char * body = "hello from ssl server\n\n";

	char * html = "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s";

	char buf[1024];

	sprintf(buf,html,strlen(body),body);

	SSL_write(ssl, buf, strlen(buf));  
} 


void start_openssl()
{
	SSL_library_init();  
	OpenSSL_add_ssl_algorithms();  
	SSL_load_error_strings(); 
}


void add_ca_crl_path( SSL_CTX * ctx,char * path)
{

	printf("%s\n",path);
	X509_STORE * trusted_store = X509_STORE_new();

//	X509_STORE_set_flags(trusted_store , X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
	X509_STORE_set_flags(trusted_store , X509_V_FLAG_CRL_CHECK );
//	X509_STORE_set_flags(trusted_store ,X509_V_FLAG_CRL_CHECK_ALL);

//	X509_LOOKUP* lookup_ca = X509_STORE_add_lookup(trusted_store, X509_LOOKUP_file());
//	X509_LOOKUP_load_file(lookup_ca, path, X509_FILETYPE_PEM);

	X509_LOOKUP* lookup_crls = X509_STORE_add_lookup(trusted_store, X509_LOOKUP_hash_dir());
	X509_LOOKUP_add_dir(lookup_crls, path, X509_FILETYPE_PEM);

	SSL_CTX_set_cert_store(ctx, trusted_store);

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); 
}





void add_ca_crl_file( SSL_CTX * ctx,char * path)
{
	int len = 5;
	char *  names[] = {
	"rootCA.pem",
	"crl_rootcase3.pem",
	"crl_rootcase4.pem",
	"l1ca.pem",
	"l2ca.pem",
	};

	int i;
	int ret;
	char t[100];

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); 

	printf("%s\n",path);
	X509_STORE * trusted_store = X509_STORE_new();


	X509_LOOKUP* lookup_ca = X509_STORE_add_lookup(trusted_store, X509_LOOKUP_file());

	for(i = 0; i < len; i++){	

		sprintf(t,"%s%s",path,names[i]);

//		SSL_CTX_load_verify_locations(ctx,t,NULL); 

		//X509_FILETYPE_ASN1 

		ret = X509_LOOKUP_load_file(lookup_ca, t, X509_FILETYPE_PEM  );

		ERR_print_errors_fp(stderr);
		printf("%s	%d\n",t,ret);
	}
//	X509_LOOKUP* lookup_crls = X509_STORE_add_lookup(trusted_store, X509_LOOKUP_hash_dir());
//	X509_LOOKUP_add_dir(lookup_crls, path, X509_FILETYPE_PEM);

//	X509_STORE_set_flags(trusted_store , X509_V_FLAG_CRL_CHECK );
	X509_STORE_set_flags(trusted_store , X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
//	X509_STORE_set_flags(trusted_store , X509_V_FLAG_X509_STRICT|  X509_V_FLAG_CRL_CHECK_ALL);
	SSL_CTX_set_cert_store(ctx, trusted_store);

}


SSL_CTX * start_ctx(char * cert, char * key, char * ca, char * caPath, char * crl, int type)
{
	SSL_CTX *ctx = NULL;
	X509_STORE  *store = NULL;
	X509_LOOKUP *lookup = NULL;

	if(type == 0){
		ctx = SSL_CTX_new(SSLv23_server_method());
	}else{
		ctx = SSL_CTX_new(TLSv1_server_method());
	}
	
	if(caPath){
		add_ca_crl_file(ctx,caPath);
	//	add_ca_crl_path(ctx,caPath);
	}
/*

	if(crl){
		store = X509_STORE_new();

		X509_STORE_set_flags(store,X509_V_FLAG_CRL_CHECK);
 
  		lookup = X509_STORE_add_lookup(store,X509_LOOKUP_file());

		if(X509_load_crl_file(lookup, crl, X509_FILETYPE_PEM)<=0){
			printf("load crl error\n");
			exit(1);
		}

		SSL_CTX_set_cert_store(ctx,store);
	
	}

	if(ca || caPath){
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); 
		if(ca){
			printf("use ca check client:%s\n",ca);
			SSL_CTX_load_verify_locations(ctx,ca,NULL); 
		}else{
			printf("use ca PATH  check client:%s\n",caPath);
			if(!SSL_CTX_load_verify_locations(ctx,NULL,caPath)){
				fprintf(stderr, "Error loading trust store\n");
			        ERR_print_errors_fp(stderr);
				exit(-1);
			}
		}
	}
*/

//	if (SSL_CTX_use_certificate_file(ctx, cert , SSL_FILETYPE_PEM) <= 0) {
	if (SSL_CTX_use_certificate_chain_file(ctx, cert) <= 0) {
		printf("load chain file error %s\n",cert);
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx,key, SSL_FILETYPE_PEM) <= 0) {
		printf("load key file error %s\n",key);
		ERR_print_errors_fp(stderr);
		exit(1);
	}



	return ctx;
}



int start_server(int port)
{

	struct sockaddr_in my_addr;
	int sockfd = socket(PF_INET, SOCK_STREAM, 0);

        bzero(&my_addr, sizeof(my_addr));  
    	my_addr.sin_family = PF_INET;  
    	my_addr.sin_port = htons(port);    
        my_addr.sin_addr.s_addr = inet_addr("0.0.0.0");  
    	if (bind(sockfd, (struct sockaddr *) &my_addr, sizeof(struct sockaddr)) == -1) {  
        	perror("bind");  
        	exit(1);  
    	} 
    	if (listen(sockfd, MAXNUM) == -1) {  
        	perror("listen");  
        	exit(1);  
    	} 

	return sockfd;
}


int check_client(SSL * ssl)
{
	int ret = 1;

	if ( X509_V_OK != SSL_get_verify_result( ssl ) ){
		ret = 0;
		printf("check error++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
	}else{
		printf("check OK\n");

	}


	ERR_print_errors_fp(stdout);

	return ret;
}


//there will be 2 arguments:certificate,private_key
int main(int argc, char **argv)  
{
	
	int sockfd, new_fd;
	socklen_t len;
	struct sockaddr_in my_addr, their_addr;
	SSL_CTX *ctx; 


	if( !((argc == 5 ) || (argc == 6) || (argc == 7)) ){
		printf("Usage:./server -ssl|-tls port certFile privateKeyFile [ ca [ crl]]\n");
		exit(-1);
	}

	int type = 0;

	if(strcmp(argv[1],"-tls") == 0){
		type = 1;
	}else{
		type = 0;
	}

	int port = atoi(argv[2]);
	char * cert = argv[3];
	char * key = argv[4];
	char * ca = NULL;;
	char * caPath = NULL;
	char * crl = NULL;

	char * p;
	if(argc >= 6  ){
		p = argv[5];
		int len = strlen(p);

		printf("%c\n",p[len -1]);
		if( p[len -1] == '/'){
			caPath = argv[5];
		}else{
			ca = argv[5];
		}
	}


	if(argc == 7){
		crl = argv[6];
	}

	start_openssl();
	 
	ctx = start_ctx(cert, key,ca,caPath, crl, type);

	sockfd = start_server(port);


    	while (1) {  
		int ret;
        	SSL *ssl;  
        	len = sizeof(struct sockaddr);  
		new_fd = accept(sockfd, (struct sockaddr *) &their_addr, &len);


		printf("accept\n");
		ssl = SSL_new(ctx);  
		SSL_set_fd(ssl, new_fd);  
		ret = SSL_accept(ssl);

		ERR_print_errors_fp(stdout);
		check_client(ssl);

		if(ret != -1)
		{  

			printf("read\n");
			read_html(ssl);
			printf("write\n");
			write_html(ssl);
		} 
		printf("close\n");

        	SSL_shutdown(ssl); 
       		SSL_free(ssl);  
        	close(new_fd);  
    	}  
   	close(sockfd);    
    	SSL_CTX_free(ctx);  
    	return 0;  
}  
  
 



  
 
  


