#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
 
char *UPATH = "/tmp/foo.socket";
 
int recvfd(int sockfd, char buf[], int buflen, int fds_num){
    int newfd, nr;
    struct cmsghdr *cmptr = NULL;//OUT
    int cmsghdrlen = 0;
    struct iovec iov[1];
    struct msghdr msg;
    int i;
    int len;
    int *fds;
 
    if(buf){
        bzero(buf, buflen);
        iov[0].iov_base = buf;
        iov[0].iov_len = buflen;
        msg.msg_iov = iov;
        msg.msg_iovlen = 1;
    } else {
        msg.msg_iov = NULL;
        msg.msg_iovlen = 0;
            
    }

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
 
    if(fds_num) {
        cmsghdrlen = CMSG_LEN(sizeof(int)*fds_num);
        cmptr = (struct cmsghdr *)calloc(1, cmsghdrlen);
    }
    msg.msg_control = cmptr;
    msg.msg_controllen = cmsghdrlen;
 
    if((nr = recvmsg(sockfd, &msg, 0)) < 0){
        perror("recvmsg error");
        return 0;
    }

    if(buf) {
        printf("%s\n", buf);    
    }

    if(fds_num > 0) {
        fds = (int *)CMSG_DATA(cmptr);
        for(i = 0; i < fds_num; i++) {
            if(fds[i] > 0) {
                printf("%d\n", fds[i]);
                bzero(buf, buflen);
                len = read(fds[i], buf, 10);
                printf("%s\n",buf);
            }
        }
    }
 
    return -1;
}

 
void client_socketun(){
    int sockfd, newfd, len, nr;
    struct sockaddr_un un;
    char buf[100]={0};
 
    un.sun_family = AF_UNIX;
    strcpy(un.sun_path, UPATH);
 
    len = sizeof(un);
    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
 
    if(connect(sockfd, (struct sockaddr *)&un, len) < 0)  {
        printf("connect error\n");
        return;   
    }
/*
    sleep(4);
    len = recv(sockfd, buf, 100, 0);//接收普通数据
    printf("recv %d\n", len);
    if(len > 0) {
        printf("%s\n",buf);
    } else {
        return;    
    }
    printf("======\n\n");
    recvfd(sockfd, NULL,0, 10);
    //recvfd(sockfd, buf,100, 10);
    printf("======\n\n");
    */
    recvfd(sockfd, buf,100, 10);
   


    close(sockfd);
}
 
int main(){
 
    client_socketun();
 
    return 0;
}

