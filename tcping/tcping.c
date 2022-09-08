#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/if.h>

#define BUF_LEN 2048

struct tcp_pkt {
	struct iphdr iph;
	struct tcphdr th;
} __attribute__((__packed__));

struct tcp_syn_pkt {
    struct tcp_pkt pkt;
    struct {
        uint8_t kind;   //2
        uint8_t len;    //4
        uint16_t mss;   //1460
    };
} __attribute__((__packed__));

static uint16_t g_ip_id = 0;
static struct timeval tv_last;
static struct timeval tv;

static void client_request_start(void)
{
    gettimeofday(&tv_last, NULL);
}

static int client_request_end(int n)
{
    unsigned long us;
    gettimeofday(&tv, NULL);

    us = (tv.tv_sec - tv_last.tv_sec)* 1000 * 1000 + (tv.tv_usec - tv_last.tv_usec);
    printf("%f ms\n", us * 1.0/(n * 1000));

    us = (us / 1000) * 1000;
    return us;
}

static uint16_t tcp_csum_pseudo(uint8_t proto, uint32_t sip, uint32_t dip, uint16_t len)
{
    uint32_t csum = 0;

    csum = (sip & 0x0000ffffUL) + (sip >> 16);
    csum += (dip & 0x0000ffffUL) + (dip >> 16);

    csum += (uint16_t)proto << 8;
    csum += len;

    csum = (csum & 0x0000ffffUL) + (csum >> 16);
    csum = (csum & 0x0000ffffUL) + (csum >> 16);

    return csum;
}

uint16_t checksum(uint16_t *buf, int size, uint16_t csum)
{
    uint32_t cksum = 0;

    cksum = csum;
    while (size > 1) {
        cksum += *buf++;
        size -= 2;
    }

    if (size) {
        cksum += *((uint8_t *)buf);
    }

    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16);
    return (uint16_t)(~cksum);
}

static void tcp_pkt_init(struct tcp_pkt *pkt, uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport, uint32_t seq, uint32_t ack, int syn)
{
    uint16_t csum = 0;
	struct iphdr *iph = NULL;
	struct tcphdr *th = NULL;
    struct tcp_syn_pkt *syn_pkt = NULL;

    memset(pkt, 0, sizeof(struct tcp_pkt));
    syn_pkt = (struct tcp_syn_pkt *)pkt;
	iph = &(pkt->iph);
	th = &(pkt->th);

	iph->ihl = 5;
	iph->version = 4;
    if (syn) {
	    iph->tot_len = htons(sizeof(struct tcp_syn_pkt));
    } else {
	    iph->tot_len = htons(sizeof(struct tcp_pkt));
    }
	iph->id = htons(g_ip_id++);
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->saddr = sip;
	iph->daddr = dip;
    iph->check = checksum((uint16_t *)iph, 20, 0);

	th->source = sport;
	th->dest = dport;
	th->seq = seq;
	th->ack_seq = ack;
	th->window = htons(60000);

    if (syn) {
	    th->doff = 6;
	    th->syn = 1;
        syn_pkt->kind = 2;
        syn_pkt->len = 4;
        syn_pkt->mss = htons(1460);
        csum = tcp_csum_pseudo(IPPROTO_TCP, sip, dip, htons(24));
        th->check = checksum((uint16_t *)th, 24, csum);
    } else {
        th->doff = 5;
        th->rst = 1;
        th->ack = 1;
        csum = tcp_csum_pseudo(IPPROTO_TCP, sip, dip, htons(20));
        th->check = checksum((uint16_t *)th, 24, csum);
    }
}

static void tcp_rst_init(struct tcp_pkt *pkt, struct tcp_pkt *rst)
{
	struct iphdr *iph = NULL;
	struct tcphdr *th = NULL;
    uint32_t seq = 0;
    uint32_t ack = 0;
    uint32_t sip = 0;
    uint32_t dip = 0;
    uint16_t sport = 0;
    uint16_t dport = 0;

    iph = &(pkt->iph);
	th = &(pkt->th);
    seq = th->ack;
    ack = htonl(ntohl(th->seq) + 1);
    sip = iph->daddr;
    dip = iph->saddr;
    sport = th->dest;
    dport = th->source;

    tcp_pkt_init(rst, sip, dip, sport, dport, seq, ack, 0);
}

static void tcp_syn_init(struct tcp_syn_pkt *pkt, uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport, uint32_t seq)
{
    tcp_pkt_init((struct tcp_pkt *)pkt, sip, dip, sport, dport, seq, 0, 1);
}

static int tcp_raw_socket(const char *dev)
{
	int one = 1;
	int sk = - 1;
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(struct ifreq));
    strcpy(ifr.ifr_name, dev);
    sk = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sk < 0) {
        return -1;
	}

    if (setsockopt(sk, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
        printf("bind %s error\n", dev);
    }

	if (setsockopt(sk, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) == -1) {
        close(sk);
        return -1;
	}

    return sk;
}

static int recv_pkt(int sk, uint8_t *buf, int buf_len, uint16_t port)
{
	int n = 0;
    struct tcp_pkt *pkt = NULL;
	struct iphdr *iph = NULL;
	struct tcphdr *th = NULL;

	while (1) {
		n = recvfrom(sk, buf, buf_len, 0, NULL, NULL);
		if (n < 0) {
            return -1;
        }
        pkt = (struct tcp_pkt *)buf;
        th = &(pkt->th);
        iph = &(pkt->iph);

        if (th->dest == port) {
            break;
        }
	}

    return n;
}

static void sockaddr_init(struct sockaddr_in *addr, uint32_t ip, uint16_t port)
{
    memset(addr, 0, sizeof(struct sockaddr_in));

	addr->sin_family = AF_INET;
	addr->sin_port = port;
    addr->sin_addr.s_addr = ip;
}

int main(int argc, char* argv[])
{
    int sk = -1;
    uint32_t sip = 0;
    uint32_t dip = 0;
    uint16_t sport = 0;
    uint16_t dport = 0;
    uint32_t seq = 0;
    struct tcp_syn_pkt syn;
    struct tcp_pkt *pkt;
    struct tcp_pkt rst;
    struct sockaddr_in addr;
    uint8_t buf[BUF_LEN];
    int n = 1;
    int i = 0;

	if (argc < 6) {
		printf("%s dev sip sport dip dport [num]\n", argv[0]);
		return 1;
	}

	srand(time(NULL));

    if (inet_pton(AF_INET, argv[2], &sip) != 1) {
        return -1;
    }
    sport = htons(atoi(argv[3]));
    if (inet_pton(AF_INET, argv[4], &dip) != 1) {
        return -1;
    }
    dport = htons(atoi(argv[5]));
    sockaddr_init(&addr, dip, dport);

    if (argc >= 7) {
        n = atoi(argv[6]);
    }

    sk = tcp_raw_socket(argv[1]);
    seq = htonl(12345);
    tcp_syn_init(&syn, sip, dip, sport, dport, seq);

    client_request_start();
    for (i = 0; i < n; i++) {
	    sendto(sk, &syn, sizeof(syn), 0, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
        recv_pkt(sk, buf, BUF_LEN, sport);
    }
    client_request_end(n);
    pkt = (struct tcp_pkt *)buf;
    tcp_rst_init(pkt, &rst);
	sendto(sk, &rst, sizeof(rst), 0, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
	close(sk);
	return 0;
}
