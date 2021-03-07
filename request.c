#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <stdlib.h>

#define ICMP_HDRLEN 8 
static int p_count = 1;
static char filter_exp[] = "icmp";
static char capture_device[] = "br-1a9996b508c9";
static char ip_to_spoof_icmp[] = "1.2.3.4";

unsigned short calculate_checksum(unsigned short * paddress, int len) {
	int nleft = len;
	int sum = 0;
	unsigned short * w = paddress;
	unsigned short answer = 0;
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}
	if (nleft == 1) {
		*((unsigned char *)&answer) = *((unsigned char *)w);
		sum += answer;
	}
	// add back carry outs from top 16 bits to low 16 bits
	sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
	sum += (sum >> 16);                 // add carry
	answer = ~sum;                      // truncate to 16 bits
	return answer;
}

void main() {
    printf("################################\n");
    printf("       Spoofing ICMP Packet\n");
    printf("################################\n\n");
    int sock;
    struct sockaddr_in sin;
    char buf[1024];
    int on = 1;

    // Create the IP/ICMP headers and attach to the buffer
    struct ip *ip = (struct ip *)buf;
    struct icmp *icmp = (struct icmp *) (ip + 1);
    // Allocate buffer size
    bzero(buf, sizeof(buf)); 

    ip->ip_v = 4;
    ip->ip_hl = 5;
    ip->ip_tos = 0;
    ip->ip_len = htons(sizeof(buf));
    ip->ip_id = 0;
    ip->ip_off = htons(0);
    ip->ip_ttl = 128;
    ip->ip_p = 1;
    ip->ip_sum = 0; 
    ip->ip_src.s_addr = inet_addr("10.9.0.5");
    ip->ip_dst.s_addr = inet_addr("8.8.8.8");
    sin.sin_family = AF_INET;
	sin.sin_addr = ip->ip_dst;

    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_id = htons(50179);
    icmp->icmp_seq = htons(0x0);
    icmp->icmp_cksum = calculate_checksum((unsigned short *)icmp, 8);

/* Create a raw socket with IP protocol. The IPPROTO_RAW parameter
* tells the sytem that the IP header is already included;
* this prevents the OS from adding another IP header.  */
sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
if (sd < 0) {
perror("socket() error"); exit(-1);
}

/* This data structure is needed when sending the packets
* using sockets. Normally, we need to fill out several
* fields, but for raw sockets, we only need to fill out
* this one field */
sin.sin_family = AF_INET;
sin.sin_addr.s_addr = ip->ip_dst.s_addr;


/* Send out the IP packet.
* ip_len is the actual size of the packet. */
if (sendto(sd, buf, sizeof(buf), 0, (struct sockaddr *)&sin, 
        sizeof(sin)) < 0)  {
perror("sendto() error"); exit(-1);
}

return 0;
}