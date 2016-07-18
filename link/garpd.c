#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <asm/types.h> 
#include <ifaddrs.h>
#include <netinet/in.h> 
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h> 
#include <linux/if.h> 
#include <linux/if_arp.h> 
#include <linux/netlink.h> 
#include <linux/rtnetlink.h> 



#define BUF_SIZE 4096 

#define for_each_nlmsghdr(nh,size) for (;NLMSG_OK(nh, size) && (nh->nlmsg_type != NLMSG_DONE); nh = NLMSG_NEXT(nh, size)) 

#define for_each_rtattr(rta,len) for (; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) 



static void __arping_send(const char * name, const char * ip)
{
    int pid;
    char cmd[256];

    sprintf(cmd,"arping -q -c 10 -s %s -I %s %s",ip,name,ip);
    printf("%s\n",cmd);

    pid = fork();

    if(pid < 0)
    {
        return;
    }
    else if(pid == 0)
    {
    
        pid = fork();

        if(pid < 0)
        {
            exit(1);
        }
        else if(pid > 0)
        {
            exit(0);
        }
        else
        {     
            execlp("arping" ,"arping","-q", "-c","10","-s",ip,"-I",name,ip,NULL);
        }
    }
    
    waitpid(pid,NULL,0);
}


static void arping_send(const char * name)
{
    struct ifaddrs * ifaddr=NULL;
    void * ptr=NULL;
    char buf[128];
    getifaddrs(&ifaddr);

    while (ifaddr!=NULL) 
    {
        if (ifaddr->ifa_addr->sa_family==AF_INET) 
        { 
            ptr = &((struct sockaddr_in *)ifaddr->ifa_addr)->sin_addr;
            inet_ntop(AF_INET, ptr, buf, INET_ADDRSTRLEN);

            if(strcmp(name,ifaddr->ifa_name) == 0)
            {
                __arping_send(name, buf);
            }

        } 
        else if (ifaddr->ifa_addr->sa_family==AF_INET6) 
        { 
            /*
            ptr=&((struct sockaddr_in *)ifaddr->ifa_addr)->sin_addr;
            inet_ntop(AF_INET6, ptr, buf, INET6_ADDRSTRLEN);
            printf("%s IP Address %s\n", ifaddr->ifa_name, buf); 
            */
        } 
        
        ifaddr=ifaddr->ifa_next;
    }
}




/*RTM_NEWADDR, RTM_DELADDR*/
static void ip_detect(struct nlmsghdr *nh)
{
    char * act = NULL;
    struct ifaddrmsg *ifa;
    struct rtattr *rta;
    int rtl;
    char name[IFNAMSIZ];

    if (nh->nlmsg_type == RTM_NEWADDR) 
    {
        ifa = (struct ifaddrmsg *) NLMSG_DATA(nh);
        rta = IFA_RTA(ifa);
        rtl = IFA_PAYLOAD(nh);

        for_each_rtattr(rta,rtl)
        {
            if (rta->rta_type == IFA_LOCAL) 
            {
                if_indextoname(ifa->ifa_index, name);
                arping_send(name);
            }
        }
    }
}



static int link_request(int fd)
{
    struct 
    {
        struct nlmsghdr  nh;
        struct ifinfomsg ifimsg;
    } req;

    memset(&req, 0, sizeof(req));
    req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)); 
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP; 
    req.nh.nlmsg_type = RTM_GETLINK; 
    req.ifimsg.ifi_family = AF_UNSPEC; 
    req.ifimsg.ifi_index = 0; 
    req.ifimsg.ifi_change = 0xFFFFFFFF; 

    if (send(fd, &req, req.nh.nlmsg_len, 0) < 0) {
        return -1;
    }

    return 1;
}



static char * ifname(struct ifinfomsg *ifimsg,int len)
{
    struct rtattr *rta = IFLA_RTA(ifimsg);

    for_each_rtattr(rta,len) 
    {
        if (IFLA_IFNAME == rta->rta_type) 
        { 
            return (char*)RTA_DATA(rta); 
        }
    }

    return NULL;
}


static void link_detect(struct nlmsghdr * nh)
{    
    struct ifinfomsg *ifimsg;
    char * name;
    int attrlen;

    if((RTM_NEWLINK == nh->nlmsg_type) || (RTM_DELLINK == nh->nlmsg_type)) 
    {

        ifimsg = (struct ifinfomsg *)NLMSG_DATA(nh);

        if (ifimsg->ifi_type == ARPHRD_LOOPBACK) 
        {
            return;
        }

        attrlen = nh->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg)); 

        if((name = ifname(ifimsg,attrlen)) != NULL)
        {
            if (IFF_RUNNING & ifimsg->ifi_flags)
            {    
            //    printf("%s link up\n",name);
                arping_send(name);
            }    
            else
            {    
            //    printf("%s link down\n",name);
            }

        }
    }

}


static int netlink_process(int fd)
{
    char buf[BUF_SIZE];
    ssize_t nread = -1;
    struct nlmsghdr *nh;

    while((nread = recv(fd,buf,BUF_SIZE, 0) ) > 0 )
    {
        nh = (struct nlmsghdr *)buf;

        for_each_nlmsghdr(nh,nread)
        { 
            if (NLMSG_ERROR == nh->nlmsg_type) 
            {
                continue;
            }

            link_detect(nh);
            ip_detect(nh);

        }
    }

    return 1;
}




static int  netlink_socket(uint32_t groups)
{
    struct sockaddr_nl addr;
    int fd;
    
    if ((fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) == -1) 
    {
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = groups ;

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) 
    {
        return -1;
    }

    return fd;
}


static void usage(char * name)
{
    printf("Usage:\n\t %s -D|-H|--help\n",name);
    printf("Send gratuitous ARP by arping when adding new IPs or link up.\n");

}    

int main (int argc, char *argv[])
{
    int fd = 0;

    if(argc >= 2)
    {
        if(strcmp(argv[1],"-D") ==0)
        {
            daemon(0,0); 
        }
        else
        {
            usage(argv[0]);
            return 0;
        }    
    }

    fd = netlink_socket(RTMGRP_IPV4_IFADDR | RTMGRP_LINK);

    if(fd > 0)
    {    
        link_request(fd);
        netlink_process(fd);
    }

    return 0;
}


