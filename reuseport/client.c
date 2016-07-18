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
#define MAXNUM 6
#define MAXBUF 1024 
#define BUF_LEN	1024



#include <stdio.h>
#include <unistd.h>

char  hostname[128] = {0};
int pid;
int is_tcp = 1;
int is_ipv4 = 1;
int is_daemon = 0;
int is_hole = 0;



int start(char * ip, int port, int is_tcp, int is_ipv4)
{
	struct sockaddr_storage addr;
	int sockfd ;
	int type;
	int domain;
	int socklen;
	
	port = htons(port);

	if(is_tcp)
	{
		type = SOCK_STREAM;
	}
	else
	{
		type = SOCK_DGRAM; 
	}

	if(is_ipv4)
	{
		domain = PF_INET;
	}
	else
	{
		domain = PF_INET6;
	}

    bzero(&addr, sizeof(addr));  

	if(is_ipv4)
	{	
	    struct sockaddr_in * p = (struct sockaddr_in *)&addr;
    	p->sin_family = domain  ;
	    p->sin_port = port;    
       	p->sin_addr.s_addr = inet_addr(ip);  
		socklen = sizeof(struct sockaddr_in);
	}
	else
	{
		struct sockaddr_in6 * p = (struct sockaddr_in6 *)&addr;
		p->sin6_family = AF_INET6;      
		p->sin6_port = port;      
		inet_pton(AF_INET6, ip, &(p->sin6_addr));
		socklen = sizeof(struct sockaddr_in6);
	}

	sockfd = socket(domain,type,0);
    if(connect(sockfd, (struct sockaddr *)&addr,socklen) != 0)
    {
        perror("connect");
        exit(1);
    }    


	return sockfd;
}

void usage()
{
	printf("usage:\n\t./server -tcp|-udp -ipv4|-ipv6 [-d] [-hole]  ip port\n");
	printf("usage:\n\t./client -tcp|-udp -ipv4|-ipv6 [-d] [-hole]  ip port\n");
	printf("\nclient examples:\n");
	printf("url -g [1111::2222]:3333\n");
	printf("url  192.168.111.222:3333\n");
	printf("echo \"hello\" | socat - UDP6:[1111::2222]3333\n");
	printf("echo \"hello\" | socat - UDP4:192.168.111.222:3333\n");
}

int arg_contain(int argc, char **argv, char * str)  
{
    int i;

    for(i = 0; i < argc; i++)
    {
        if(strcmp(argv[i],str) == 0)
        {
            return 1;
        }
    }

    return 0;
}

//there will be 2 arguments:certificate,private_key
int main(int argc, char **argv)  
{
	int sockfd, new_fd;
	char * str;
    char * request = "GET / HTTP/1.0\r\nHost: 192.168.4.22\r\nAccept: */*\r\n\r\n";
    char buf[BUF_LEN +1];
    int size;

	if(argc < 5)
	{
		usage();
		return 1;
	}
  
	str = argv[1];
    is_tcp = arg_contain(argc, argv, "-tcp");
    is_ipv4 = arg_contain(argc, argv, "-ipv4");
    is_hole = arg_contain(argc, argv, "-hole");
    is_daemon = arg_contain(argc, argv, "-d");

    if(is_daemon)
    {    
        daemon(0,0);
    }

    pid = getpid();
	sockfd = start(argv[argc - 2],atoi(argv[argc - 1]),is_tcp,is_ipv4);

    
    send(sockfd,request,strlen(request),0);
    
    while((size = recv(sockfd,buf,BUF_LEN,0)) > 0)
    {
        buf[size] = 0;
        printf("%s",buf);
    }

   	close(sockfd);    
    	return 0;  
}  
  
 



  
 
  


