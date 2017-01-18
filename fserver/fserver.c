
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



static inline void process_accept(int sfd)
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

int fsize(const char* path) 
{ 
    struct stat buff; 
    if(stat(path, &buff) == 0) 
    { 
        return buff.st_size; 
    } 
    else 
    { 
        return -1; 
    } 
} 

char * g_dir = NULL;

static inline void process_sendfile(int fd, char * path)
{
    int rfd = open(path,O_RDONLY);
    int len;
    off_t offset = 0;
    int count = fsize(path);
    int num;

    if(rfd < 0)
    {
        return ;
    }
    while(count > 0)
    {    
        num = sendfile(fd, rfd, &offset, count);
        if(num > 0)
        {
            count -= num;
        }
        else
        {
            if(errno ==  EAGAIN )
            {
                usleep(10000);
            }
            else
            {    
                break;
            }
        }    
    }

}

static int http_get_path(char * req, int size, char * path)
{
    int i;
    char * p;

    if((g_dir != NULL) &&  ((p = strstr(req, g_dir)) != NULL))
    {
        for(i = 0; i < size; i++)
        {
            path[i] = p[i];
            if(isspace(path[i]))
            {
                path[i] = 0;
                return 1;
            }
        }    
    }        

    return 0;
}


static inline void process_request(int fd)
{
    int rlen = recv(fd,rbuf,BUF_LEN,0);
    char path[128];

    if(rlen > 0)
    {
        rbuf[rlen] = 0;


        if(http_get_path(rbuf, rlen, path))
        {
            process_sendfile(fd, path);
        }
        else
        {
            send(fd,sbuf,sbuf_len,0);
        }    
    }

    event_free(fd);
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
                        process_accept(fd);        
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
    int one = 1;

    bzero(&my_addr, sizeof(my_addr));  

    p->sin_family = domain  ;
    p->sin_port = htons(port);    
    p->sin_addr.s_addr = inet_addr(ip);  

    fd = socket(domain,type,0);

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

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
    if(argc >= 3)
    {   
        if(argc >= 4)
        {    
            g_dir = argv[3];
        }

        sbuf_set();
        event_init();
        start_server(argv[1], argv[2]);
        event_run_loop(5);
    }
    else
    {
        printf("%s ip port [dir]\n",argv[0]);
    } 

    return 0;
}

