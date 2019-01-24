#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
 
char *UPATH = "/tmp/foo.socket";

 
void send_fd(int cfd, char * data, int *fd, int fdnum){
    struct iovec iov[1];
    struct msghdr msg;
    struct cmsghdr *cmptr = NULL;
    int i, *p;      
    int size = 0;


    msg.msg_name = NULL;
    msg.msg_namelen = 0;

    if(data != NULL) {
        iov[0].iov_base = data;
        iov[0].iov_len = strlen(data);
    } else {
        iov[0].iov_base = NULL;
        iov[0].iov_len = 0;
    }


    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    if (fdnum > 0) {
        size = CMSG_LEN(sizeof(int)*fdnum);
        cmptr = (struct cmsghdr *)calloc(1, size);
        cmptr->cmsg_level = SOL_SOCKET;
        cmptr->cmsg_type = SCM_RIGHTS;
        cmptr->cmsg_len = size;
        p = (int *)CMSG_DATA(cmptr);
        for(i = 0; i < fdnum; i++) {
            p[i] = fd[i];   
        }
    }
    msg.msg_control         = cmptr;
    msg.msg_controllen      = size;
 
    if(sendmsg(cfd, &msg, 0) == -1){
        perror("send error");
    }
}
 
void server() {
    int sfd,cfd, size;
    int fds[3];
    struct sockaddr_un un;
    struct sockaddr_un caddr;
    socklen_t len = sizeof(caddr);
    char * data = "hello, world\n";
 
    un.sun_family = AF_UNIX;
    strcpy(un.sun_path, UPATH);
 
    sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    bind(sfd, (struct sockaddr *) &un, sizeof(un));
    listen(sfd, 5);
    cfd = accept(sfd, (struct sockaddr *) &caddr, &len);
 
    printf("accept %d\n", cfd);
//    send(cfd, data, strlen(data), 0);
//    send(cfd, data, strlen(data), 0);
 
    fds[0] = open("/tmp/1.txt", O_CREAT | O_RDWR, 0666);
    fds[1] = open("/tmp/2.txt", O_CREAT | O_RDWR, 0666);
    fds[2] = open("/tmp/3.txt", O_CREAT | O_RDWR, 0666);
    printf("%d %d %d\n",fds[0],fds[1],fds[2]);

    send_fd(cfd,"sendmsg\n", fds, 3);
    printf("after send_fd\n");
    sleep(100);
    close(cfd);
    close(sfd);
    unlink(un.sun_path);
}

 
int main() {
 
    server(); 
    return 0;
}

