/*
 * pengjianzhang@gmail.com
 * */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>



static inline uint32_t ipv4_get(const char * ip)
{
    struct in_addr addr;

    if(inet_aton(ip, &addr) != 0)
    {    
        return addr.s_addr;
    }

    return 0;
}    




static inline void sockaddr_init(struct sockaddr_in * addr, uint32_t ip,uint16_t port) 
{
    bzero(addr,sizeof(struct sockaddr_in));	
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = ip;
    addr->sin_port = port;
}




int socket_init(uint32_t sip, uint32_t dip, uint16_t dport, int type, int proto)
{
    int fd ;
    struct sockaddr_in saddr;
    struct sockaddr_in daddr;


	if((fd = socket(AF_INET,type,proto)) < 0)
	{
        printf("socket error\n");
        return -1;
	}

    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1)
    {
        close(fd);
        printf("fcntl error\n");
        return -2;
    }

    sockaddr_init(&saddr, sip,0);
    if(bind(fd,(struct sockaddr *)&saddr, sizeof(struct sockaddr_in)) != 0)
    {
        close(fd);
        return -3;
    }

    
    sockaddr_init(&daddr, dip,dport);
    if(connect(fd, (struct sockaddr *)&daddr,sizeof(struct sockaddr_in)) != 0)
    {
        if(errno != EINPROGRESS)
        {    
            close(fd);
            return -4;
        }
    }

    return fd;
}

uint32_t rand_ip()
{
    struct      timeval    tv; 
    uint32_t    ip;

    gettimeofday(&tv,NULL);
    ip = tv.tv_sec + tv.tv_sec >> 32  + tv.tv_usec + tv.tv_usec >> 32;


    return ip;
}


#define SELFIP_MAX  10

int main(int argc, char ** argv)
{
    uint8_t dport;
    int i,j,fd,type;
    int c = 0;
    uint32_t selfip[SELFIP_MAX];
    uint32_t ip;
    int selfip_num = 0;
    char * msg = "hello123456789";
    uint32_t dip = rand_ip();

    if(argc < 2)
    {
        printf("usage:\n\t%s selfip0 selfip1 ...\n",argv[0]);
        return 1;
    }


    for(i = 1; i < argc  ; i++)
    {    
        if(((ip = ipv4_get(argv[i])) > 0) && (selfip_num < SELFIP_MAX))
        {
            selfip[selfip_num] =  ip;
            selfip_num++;
        }
    }

    if(selfip_num == 0)
    {
        printf("Error: no alilable selip\n");
        return 1;
    }


    while(1)
    {    
        for(i = 0; i < selfip_num; i++)
        {
            dip++;
            if(dip %2 == 0)
            {    
                type = SOCK_DGRAM;
            }
            else
            {
                type = SOCK_STREAM;
            }    

            for(j = 10; j < 20; j++)
            {
                dport = j;
                if(fd = socket_init(selfip[i], dip, dport, type, 0) > 0)
                {
                    if(type == SOCK_DGRAM)
                    {    
                        send(fd,msg,strlen(msg),0);
                    }    
                    close(fd);
                }

                c++;
                if(c >= 800)
                {
                    sleep(1);
                    c = 0;    
                }

            } 
        }
    }

    return 0;
}

