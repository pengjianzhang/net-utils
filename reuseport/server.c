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
#define BUF_LEN 1024



#include <stdio.h>
#include <unistd.h>

char  hostname[128] = {0};
int pid;
int is_tcp = 1;
int is_ipv4 = 1;
int is_daemon = 0;
int is_hole = 0;


char *  get_hostname()
{
    if(hostname[0] ==  0)
    {    
        gethostname(hostname, sizeof(hostname));
    }

    return hostname;
}


void handle(int fd)
{
    char buf[BUF_LEN];
    struct sockaddr_storage guest;
    char guest_ip[60];
    int len;
    int port;
    socklen_t server_alen = sizeof(struct sockaddr_storage);
    server_alen = sizeof(struct sockaddr);
        
     socklen_t slen = sizeof(struct sockaddr_storage);

    if(is_tcp)  
    {
        getpeername(fd,(struct sockaddr *)&guest , &slen);
        len = recv(fd,buf,BUF_LEN,0);
    }
    else
    {
        len = recvfrom(fd,buf,BUF_LEN,0,  (struct sockaddr*)&guest,&slen);
    }   

    if(is_ipv4)
    {   
        socklen_t slen = 60;
        struct sockaddr_in * p = (struct sockaddr_in *)&guest;
        inet_ntop(AF_INET, (void *)&p->sin_addr, guest_ip, slen);
        port = p->sin_port;
    }
    else
    {
        struct sockaddr_in6 * p = (struct sockaddr_in6 *)&guest;
        inet_ntop(AF_INET6, &(p->sin6_addr), guest_ip, 60);
        port = p->sin6_port;
    }

    char * name = get_hostname();
    sprintf(buf,"hostname=%s client-ip=%s client-port=%d pid=%d recv size = %d\n",name,guest_ip, ntohs(port),pid,len);   
    if(is_hole)
    {
        printf("%s",buf);    
    }
    else
    {    
        sendto(fd,buf,strlen(buf),0,  (struct sockaddr*)&guest,slen);    
    }
}



int set_reuse_ip_port(int fd, int is_ipv4)
{
    int one = 1;
    int ret;

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    #ifndef SO_REUSEPORT
    #define SO_REUSEPORT 15 
    #endif  

    if(1)
    {
        ret = setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
    }
    else
    {
        ret = setsockopt(fd, SOL_IPV6, SO_REUSEPORT, &one, sizeof(one));
    }

    if(ret != 0)
    {
        printf("setsockopt REUSEPORT ERROR\n");
        return 0;
    }
    else
    {
        printf("bind ok\n");
    }

    return 1;
}


int start_server(char * ip, int port, int is_tcp, int is_ipv4)
{
    struct sockaddr_storage my_addr;
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

    bzero(&my_addr, sizeof(my_addr));  

    if(is_ipv4)
    {   
        struct sockaddr_in * p = (struct sockaddr_in *)&my_addr;
        p->sin_family = domain  ;
        p->sin_port = port;    
        p->sin_addr.s_addr = inet_addr(ip);  
        socklen = sizeof(struct sockaddr_in);
    }
    else
    {
        struct sockaddr_in6 * p = (struct sockaddr_in6 *)&my_addr;
        p->sin6_family = AF_INET6;      
        p->sin6_port = port;      
        inet_pton(AF_INET6, ip, &(p->sin6_addr));
        socklen = sizeof(struct sockaddr_in6);
    }

    sockfd = socket(domain,type,0);

    set_reuse_ip_port(sockfd,is_ipv4);

    if (bind(sockfd, (struct sockaddr *) &my_addr, socklen) == -1) {  
        perror("bind");  
        exit(1);  
    } 

    if(is_tcp)
    {
        if (listen(sockfd, MAXNUM) == -1) {  
            perror("listen");  
            exit(1);  
        } 
    }
    return sockfd;
}

void usage()
{
    printf("usage:\n\t./server -tcp|-udp -ipv4|-ipv6 [-d] [-hole]  ip port\n");
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
    sockfd = start_server(argv[argc - 2],atoi(argv[argc - 1]),is_tcp,is_ipv4);


    while (1) {  

        if(is_tcp)
        {
            new_fd = accept(sockfd, NULL,NULL);
        }
        else
        {
            new_fd = sockfd;
        }

        if(new_fd > 0)
        {
            handle(new_fd);
            if(new_fd != sockfd )
            {
                if(is_hole == 0)
                {    
                    close(new_fd);  
                }
            }
        }
    }  
    close(sockfd);    
        return 0;  
}  
  
 
