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
#include <fcntl.h>

struct sockaddr_storage g_addr;

#define BUF_LEN (1024*2)

char buf[BUF_LEN + 1];

void client_func(int fd)
{
    char * msg = "hello,server~~";
    int len;

    sendto(fd, msg, strlen(msg), 0,(struct sockaddr *)&g_addr, sizeof(g_addr));
    len = recv(fd, buf, BUF_LEN, 0);

    if(len > 0){
        buf[len] = 0;
        printf("%s\n",buf);
    }
}

void server_loop(int fd)
{
    struct sockaddr_storage guest;
    socklen_t slen;
    int len;

    while(1){
        slen = sizeof(struct sockaddr_storage);
        len = recvfrom(fd,buf,BUF_LEN,0,  (struct sockaddr*)&guest,&slen);
        
        if (len > 0) {
            sendto(fd,buf, len,0,  (struct sockaddr*)&guest,slen);    
        }
    }
}



int set_socket_opt(int fd, int level)
{
    int one = 1;
    int ret;

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

/*
    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
        return 0;
    }
*/
    #ifndef SO_REUSEPORT
    #define SO_REUSEPORT 15 
    #endif  

   ret = setsockopt(fd, level, SO_REUSEPORT, &one, sizeof(one));
    if(ret != 0) {
        printf("setsockopt REUSEPORT ERROR\n");
        return 0;
    } else {
        printf("bind ok\n");
    }

    return 1;
}

int sock_addr_set(struct sockaddr_storage *addr, char * ip, char * port_str)
{
    struct sockaddr_in      *p4 = (struct sockaddr_in *)addr;
    struct sockaddr_in6     *p6 = (struct sockaddr_in6 *)addr;
    int port;

    port = htons(atoi(port_str));

    bzero(addr, sizeof(struct sockaddr_storage));  
    if(strchr(ip,'.')){   
        p4->sin_family = AF_INET;
        p4->sin_port = port;    
        p4->sin_addr.s_addr = inet_addr(ip);  
        return AF_INET;
    } else {
        p6->sin6_family = AF_INET6;      
        p6->sin6_port = port;      
        inet_pton(AF_INET6, ip, &(p6->sin6_addr));
        return AF_INET6; 
    }
}

int socket_set_server(int fd)
{
    int socklen,level;
    int domain = g_addr.ss_family;
    
    if(domain == AF_INET) {
        level = SOL_SOCKET;
        socklen = sizeof(struct sockaddr_in);
    } else {
        level = SOL_IPV6;
        socklen = sizeof(struct sockaddr_in6);
    }

    if (!set_socket_opt(fd, level)) {
        goto err;
    }

    if (bind(fd, (struct sockaddr *)&g_addr, socklen) == -1) {  
        goto err;
    } 

   
    return fd;
err:
    close(fd);
    return -1;
}

void usage()
{
    printf("usage:\n\t./server ip port [-d|-c]\n");
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
    int fd,domain;
    int client = 0;

    if(argc < 2)
    {
        usage();
        return 1;
    }
 
    if(arg_contain(argc, argv, "-c")) {    
        client = 1;
    } else if(arg_contain(argc, argv, "-d")) {    
        daemon(0,0);
    }

    domain = sock_addr_set(&g_addr, argv[1], argv[2]);
    fd = socket(domain,SOCK_DGRAM,0);

    if(fd >= 0) {
        if(client) {
            client_func(fd);
        } else {
            if(socket_set_server(fd) > 0) {
                server_loop(fd);
            }
        }

        close(fd);  
    }
    return 0;  
}  
  
 
