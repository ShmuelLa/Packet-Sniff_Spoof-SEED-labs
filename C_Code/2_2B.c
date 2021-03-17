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

int main()
{
    printf("################################\n");
    printf("       Spoofing ICMP Packet\n");
    printf("################################\n\n");
    int ip_header_len = sizeof(struct iphdr) ;
    const char buffer[1500];
    memset((char *) buffer, 0, 1500);
    struct iphdr * ip = (struct iphdr*) buffer;
    struct icmp *icmp= (struct icmp*) (buffer + ip_header_len);
    int sockflag =1;

    icmp->icmp_type = 8 ;
    icmp->icmp_cksum = 0;
    icmp->icmp_cksum = calculate_checksum((unsigned short *)icmp,sizeof(struct icmp));
    
    ip->ihl =5;
    ip->check=0;
    ip->frag_off =0;
    ip->id =0;
    ip->protocol= IPPROTO_ICMP;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmp));
    ip->ttl = 20;
    ip->version = 4;
    ip->daddr = inet_addr("8.8.8.8");
    ip->saddr = inet_addr("10.9.0.5");

    struct sockaddr_in d_addr;
    d_addr.sin_family = AF_INET;
    d_addr.sin_addr= *(struct in_addr *) &ip->daddr;

    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sd < 0) {
        perror("failed to create socket");
    }
    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &sockflag, sizeof(sockflag)) != 0) {
        perror("failed to set option");
    }
    if (sendto(sd, ip, ntohs(ip->tot_len), 0, (struct sockaddr *) &(d_addr), sizeof(d_addr)) <= 0) {
        perror("failed to sendto");
    } 
    close(sd);


    return 0;
}