#include <stdio.h>   
#include <stdlib.h> 
#include <unistd.h>

int main(int argc, char **argv)  
{
    char * data;
    int num;
    int i;
    int size = 16*1024*1024;

    if(argc != 2)
    {
        printf("%s alloc-num\n",argv[0]);
        return 1;
    }

    num = atoi(argv[1]);
    for(i = 0; i < num; i++)
    {
        data = calloc(size,1);
        if(data == NULL)
        {
            printf("%d fail\n",i);
        }    
        else 
        {
            printf("%d ok\n",i);
        }    
    }

    while(1)
    {
        sleep(1);
    }

    return 0;  
}  
  
 



  
 
  


