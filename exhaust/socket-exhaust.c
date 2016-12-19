
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

int main(int argc, char **argv)  
{
    int num,fd,i;
    int type = SOCK_STREAM;
    int domain = PF_INET;

    if(argc != 2)
    {
        printf("%s sk-num\n",argv[0]);
        return 1;
    }

    num = atoi(argv[1]);
    for(i = 0; i < num; i++)
    {
        fd = socket(domain,type,0);
        printf("%d\t%d\n",i,fd);
    }

    while(1)
    {
        sleep(1);
    }

    return 0;  
}  
  
 



  
 
  


