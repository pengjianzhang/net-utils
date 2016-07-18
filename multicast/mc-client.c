#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include "mc.h"


int main(int argc,char*argv[])
{
    int sk;
    int ret = -1;    
    struct sockaddr_in Multi_addr;
    struct sockaddr_in client_addr;
    char buffer[1024];
    int size;
    socklen_t  len;
    int i, num;

    if(argc != 2)
    {
        printf("Usage:\t%s recv-num\n",argv[0]);
        return -1;
    }

    num = atoi(argv[1]);


    if((sk = socket(AF_INET,SOCK_DGRAM,0)) < 0)
    {
        perror("socket error");
        goto out;
    }

    Multi_addr.sin_family=AF_INET;
    Multi_addr.sin_port=htons(MCAST_PORT);
    Multi_addr.sin_addr.s_addr=inet_addr(MCAST_ADDR);

    sprintf(buffer,"hello~~ \n");

    size = sendto(sk,buffer,strlen(buffer),0,(struct sockaddr*)&Multi_addr,sizeof(Multi_addr));
    if(size<0){
        perror("sendto error");
        return -1;
    }
    
    for(i = 0; i < num; i++)
    {
        size=recvfrom(sk,buffer,1024,0,(struct sockaddr*)&client_addr,&len);

        if(size)
        {
            buffer[size] = 0;
            printf("%s\n",buffer);
        }    
    }
out:
    if(sk > 0)
    {    
        close(sk);
    }

    return ret;
}

