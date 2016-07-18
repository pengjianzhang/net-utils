
#include <fcntl.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netdb.h>
#include <setjmp.h>
#include <errno.h>
#include <strings.h>
#include <string.h>
#include <sys/time.h>

#define EVENT_NUM (1024*4)
#define BACKLOG   1024  


char g_state[EVENT_NUM];
struct epoll_event epoll_events[EVENT_NUM];
int g_sfd;
int epoll_fd;


static inline int event_new(int fd)
{
	struct epoll_event epEv;
    int op;

	if( (fd >=  EVENT_NUM) || (fd < 0))
    {
        return  0;
    }
    
	epEv.events =  EPOLLIN;
	epEv.data.fd = fd;

    op = EPOLL_CTL_ADD;

    if(epoll_ctl(epoll_fd, op, fd, &epEv) == -1)
    {
        return 0;
    }

    g_state[fd] = 1;
    return 1;
}



static inline void event_free(int fd)
{
    if(g_state[fd])
    {
        g_state[fd] = 0;
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
        close(fd);
    }
}



static inline void process_connect(int sfd)
{
    int fd;

    while(1)
    {
        fd = accept4(sfd, NULL,NULL,SOCK_NONBLOCK);
        if(fd < 0)
        {
            break;
        }
        event_new(fd);
    }
}

#define BUF_LEN 4096

char rbuf[4096];
char * sbuf = "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Type: text/html; charset=UTF-8\r\n\r\nA";
int sbuf_len ;

void sbuf_set()
{
    sbuf_len = strlen(sbuf);
}

static inline void process_request(int fd)
{
    int len = recv(fd,rbuf,BUF_LEN,0);

    if(len > 0)
    {
        len = send(fd,sbuf,sbuf_len,0);
        event_free(fd);
    }
}


int event_run_loop(int wait_ms)
{
    int fd;
    int i;
    int event_num = 0;
    int flags;

    while(1)
    {     
        event_num = epoll_wait(epoll_fd, epoll_events, EVENT_NUM,wait_ms);

        for(i = 0; i < event_num; i++)
        {
            fd = epoll_events[i].data.fd;
            flags = epoll_events[i].events;
            if(g_state[fd])
            {
                if(flags & EPOLLIN)
                {
                    if(fd == g_sfd)
                    {
                        process_connect(fd);        
                    }
                    else
                    {
                        process_request(fd);
                    }    
                }
                else
                {
                    event_free(fd);
                }    
            }
            else
            {
                close(fd);
            }    
        }
    }
    return event_num;
}



int __start_server(char * ip, int port)
{
    struct sockaddr_storage my_addr;
    int fd ;
    int type = SOCK_STREAM;
    int domain = PF_INET;
    int socklen = sizeof(struct sockaddr_in);
    struct sockaddr_in * p = (struct sockaddr_in *)&my_addr;

    bzero(&my_addr, sizeof(my_addr));  

    p->sin_family = domain  ;
    p->sin_port = htons(port);    
    p->sin_addr.s_addr = inet_addr(ip);  

    fd = socket(domain,type,0);

    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1)
    {
        close(fd);
        return -1;
    }

    if (bind(fd, (struct sockaddr *) &my_addr, socklen) == -1) {  
        perror("bind");  
        exit(1);  
    } 

    if (listen(fd, BACKLOG) == -1)
    {  
        perror("listen");  
        exit(1);  
    } 
    return fd;
}


int start_server(char * ip, char * port)
{
    g_sfd = __start_server(ip, atoi(port));
    event_new(g_sfd);

    return g_sfd;
}

void event_init()
{    
    epoll_fd = epoll_create(EVENT_NUM);
    bzero(g_state,EVENT_NUM);
}

int main(int argc, char ** argv)
{
    if(argc == 3)
    {     
        sbuf_set();
        event_init();
        start_server(argv[1], argv[2]);
        event_run_loop(5);
    }
    else
    {
        printf("%s ip port\n",argv[0]);
    } 

    return 0;
}

