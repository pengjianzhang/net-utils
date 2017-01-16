#include <stdio.h>


char * common = "HTTP/1.1 200 OK\r\nDate: Fri, 23 Sep 2016 09:13:40 GMT\r\nServer: Fserver\r\nLast-Modified: Fri, 31 Jul 2015 00:06:58 GMT\r\nAccept-Ranges: bytes\r\nContent-Type: text/html; charset=UTF-8\r\n";
int colum = 50;
char buf[1024]; 

void gen_small(int len)
{
    int i;

    if(len <= 0)
    {
        return;
    }

    if(len == 1)
    {
        printf("1");
        return;
    }
    
    if(len == 2)
    {
        printf("2\n");
        return;
    }

    printf("%02d",len);
    len -= 3;
    for(i = 0; i < len; i++)
    {
        printf("=");
    }
    printf("\n");
}


int gen_body(int len, int end)
{
    int i,j;
    int line = 0;
    int left;
    

    if(len < colum)
    {
        gen_small(len);
        return;
    }

    for(i = 0; i < colum - 11; i++)
    {
        buf[i] = 'a';
    }

    if(end)
    {
        len -= 4;
    }

    line = len / colum;
    left = len % colum;
    
    for(i =0; i < line; i++)
    {
        printf("%010d%s\n",i,buf);
    }

    if(left > 0)
    {
        gen_small(left);
    }

    if(end)
    {
        printf("end\n");
    }
}


void gen_chunk(int len)
{
    printf("%08x\r\n",len);
    gen_body(len, 0);
    printf("\r\n");
/*
    printf("0\r\n");
    printf("\r\n");
  */ 
}


void gen_html_chunked(int chunk_num, int chunk_len)
{
    int a[10] = {1,3,5,7,11,13,17,23,31,111};
    char * head = "Transfer-Encoding: chunked\r\n";
    int i;
    int num;
    int len;


    printf("%s%s\r\n",common,head);

    if(chunk_len == 0)
    {
        gen_chunk(chunk_len);
    }
    else if(chunk_len > 0)
    {
        for(i = 0; i < chunk_num; i++)    
        {
            gen_chunk(chunk_len);
        }
    }
    else
    {
        for(i = 0; i < chunk_num; i++)    
        {
            len = a[i % 10];
            gen_chunk(len);
        }
    }
}

int gen_html_content_length(int len)
{
    printf("%sContent-Length: %d\r\n\r\n",common,len);
    gen_body(len, 1);
}


void gen_html_no_length(int len)
{
    printf("%sConnection: close\r\n\r\n",common);
    gen_body(len, 1);

}


void usage()
{
    printf(" -c chunk-num chunk-len\n");
    printf(" -l content-lenth\n");
    printf(" -b body-lenth\n");
    printf("if chunk-len < 0, chunk-len is range(1,3,5,7,11,13,17,23,31,111)\n");
}



int main(int argc, char ** argv)
{
    int chunk_num, len;

    if(argc < 3)
    {
        usage();
        return 1;
    }	

    if((strcmp(argv[1],"-c") == 0) && (argc == 4))    
    {
        chunk_num = atoi(argv[2]);
        len = atoi(argv[3]);
        gen_html_chunked(chunk_num, len);
    }
    else if((strcmp(argv[1],"-l") == 0) && (argc == 3))    
    {
        len = atoi(argv[2]);
        gen_html_content_length(len);
    }   
    else if((strcmp(argv[1],"-b") == 0) && (argc == 3))    
    {
        len = atoi(argv[2]);
        gen_html_no_length(len);
    }   
    else
    {
        usage();
        return 1; 
    } 

    return 0;
}

