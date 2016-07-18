#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include "mc.h"



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




int mcast_server(char * local_addr, int id)
{
    int sk,ret,size;
    int ttl=1;
    int loop=0;
    char buffer[1024];
    struct sockaddr_in localaddr,fromaddr;//多播地址结构
    struct ip_mreq mreq;
    socklen_t  len;

    printf("server %d start\n",id);
    if((sk = socket(AF_INET,SOCK_DGRAM,0)) < 0)
    {
        perror("socket error");
        return -1;
    }

    set_reuse_ip_port(sk, 1);

    localaddr.sin_family = AF_INET;
    localaddr.sin_port = htons(MCAST_PORT);
    localaddr.sin_addr.s_addr = htonl(INADDR_ANY);
//    localaddr.sin_addr.s_addr = inet_addr(local_addr);


    if((ret = bind(sk,(struct sockaddr*)&localaddr,sizeof(localaddr))) < 0)    
    {
        perror("bind error");
        return -1;
    }

    if(setsockopt(sk,IPPROTO_IP,IP_MULTICAST_TTL,&ttl,sizeof(ttl))<0)
    {
        perror("IP_MULTICAST_TTL");
        return -1;
    }

    if(setsockopt(sk,IPPROTO_IP,IP_MULTICAST_LOOP,&loop,sizeof(loop))<0)
    {
        perror("IP_MULTICAST_LOOP");
        return -1;
    }

    mreq.imr_multiaddr.s_addr = inet_addr(MCAST_ADDR);
    mreq.imr_interface.s_addr = inet_addr(local_addr);
    
    if(setsockopt(sk,IPPROTO_IP,IP_ADD_MEMBERSHIP,&mreq,sizeof(mreq))<0)
    {
        perror("IP_ADD_MEMBERSHIP");
        return -1;
    }


    while(1) 
    {
        len = sizeof(fromaddr);
        size = recvfrom(sk,buffer,1024,0,(struct sockaddr*)&fromaddr,&len);
        
        if(size < 0)
        {
            perror("recvfrom ");
            return -1;
        }
        buffer[size] = 0;
        printf("%d recv:%s\n",id,buffer);
        sprintf(buffer,"hello-from server %d\n",id);
        size=sendto(sk,buffer,strlen(buffer),0,(struct sockaddr*)&fromaddr,sizeof(fromaddr));
        printf("reply %d\n",size);
    }

    ret=setsockopt(sk,IPPROTO_IP,IP_DROP_MEMBERSHIP,&mreq,sizeof(mreq));

    if(ret<0){
        perror("IP_DROP_MEMBERSHIP");
        return -1;
    }
    close(sk);
    return 0;

}


int main(int argc,char*argv[])
{
    int id;
    char * local_addr;
    int num;
    int i;

    if(argc != 3)
    {
        printf("Usage:\t%s local-ip server-num\n",argv[0]);
        return -1;
    }

    local_addr = argv[1];
    num = atoi(argv[2]);

    for(i = 1; i< num; i++)
    {     
        if(fork() == 0)
        {
            break;
        }    
    }

    id = getpid();
    mcast_server(local_addr,id);

    return  0;
}
