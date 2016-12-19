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


int start(char * ip, int port)
{
	struct sockaddr_storage addr;
	int sockfd ;
	int type;
	int domain;
	int socklen;
	
	port = htons(port);
    type = SOCK_STREAM;
    domain = PF_INET;
	
    bzero(&addr, sizeof(addr));  

    struct sockaddr_in * p = (struct sockaddr_in *)&addr;
    p->sin_family = domain  ;
    p->sin_port = port;    
    p->sin_addr.s_addr = inet_addr(ip);  
    socklen = sizeof(struct sockaddr_in);


	sockfd = socket(domain,type,0);
    if(connect(sockfd, (struct sockaddr *)&addr,socklen) != 0)
    {
        perror("connect error");
        exit(1);
    }    


	return sockfd;
}

void usage()
{
	printf("usage:\n\t./invalid-encode  ip [port]\n");
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

int main(int argc, char **argv)  
{
	int sockfd;
    char * b = " HTTP/1.0\r\nHost: 192.168.4.22\r\nAccept: */*\r\n\r\n";
    char buf[BUF_LEN +1];
    int size;
    int port = 80;
    char request[2048] = { 'G','E','T',' ', '/','1','.','t','x','t','?',
        0x26, 0x63, 0x6d, 0x64, 0x3d, 0xb2, 0xe9, 0xd1,  0xaf, 0x2f, 0xb4, 0xa6, 0xbc, 0xb6, 0xb2, 0xe9,
        0xd1, 0xaf, 0x2f, 0xb7, 0xa2, 0xcb, 0xcd, 0xa1,  0xb6, 0xbd, 0xf8, 0xc8, 0xeb, 0xd6, 0xd0, 0xb9,
        0xfa, 0xb9, 0xfa, 0xbc, 0xd2, 0xbd, 0xd7, 0xb6,  0xce, 0xcd, 0xa8, 0xd6, 0xaa, 0xca, 0xe9, 0xa1, 
        0xb7, 0xb2, 0xe9, 0xd1, 0xaf, 0x26, 0x5f, 0x47,  0x47, 0x45, 0x41, 0x52, 0x53, 0x3d, 0x74, 0x72,
        0};

    strcat(request,b);
	if((argc != 2) && (argc != 3))
	{
		usage();
		return 1;
	}
  
    if(argc == 3)
    {
        port = atoi(argv[2]);
    }
    
	sockfd = start(argv[1],port);

    
    send(sockfd,request,strlen(request),0);
    
    while((size = recv(sockfd,buf,BUF_LEN,0)) > 0)
    {
        buf[size] = 0;
        printf("%s",buf);
    }

   	close(sockfd);    
    return 0;  
}  
  
 



  
 
  


