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

static int p_count = 1;
static char filter_exp[] = "icmp";
static char capture_device[] = "br-1a9996b508c9"; 

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
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;
	return answer;
}

void spoof_icmp(struct iphdr *sniffed_ip_packet) {
    printf("################################\n");
    printf("       Spoofing ICMP Response\n");
    printf("################################\n");
    int ip_header_len = sniffed_ip_packet->ihl * 4;
    const char buffer[1024];
    int sockflag = 1; //raw socket
    struct sockaddr_in d_addr; //destination address
    memset((char *) buffer, 0, 1024); //set buffer
    /**Set the IP Header in the spoofed packet**/
    memcpy((char *) buffer, sniffed_ip_packet, ntohs(sniffed_ip_packet->tot_len));
    struct iphdr *spoofed_ip = (struct iphdr *) buffer; //create spoofed ip header 
    struct icmp *spoofed_icmp = (struct icmp *) (buffer + ip_header_len); //create spoofed icmp header add 
    spoofed_icmp->icmp_type = 0;
    spoofed_icmp->icmp_cksum = 0;
    spoofed_icmp->icmp_cksum = calculate_checksum((unsigned short *)spoofed_icmp,(ntohs(sniffed_ip_packet->tot_len)- ip_header_len));
    spoofed_ip->saddr = sniffed_ip_packet->daddr;
    spoofed_ip->daddr = sniffed_ip_packet->saddr;
    spoofed_ip->ttl = 128;
    bzero(&d_addr, sizeof(d_addr));
    d_addr.sin_family = AF_INET; //set destination address for the raw socket
    d_addr.sin_addr = *(struct in_addr *) &spoofed_ip->daddr;
    int sd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW); //create raw socket for IP protocols 
    if (sd < 0) perror("failed to create socket");
    /** configure the raw socket **/
    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &sockflag, sizeof(sockflag)) != 0) perror("failed to set option");
    if (sendto(sd,spoofed_ip,ntohs(spoofed_ip->tot_len),0,(struct sockaddr *) &(d_addr),sizeof(d_addr)) <= 0) perror("failed to sendto"); 
    close(sd);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)args;
    (void)header;
    struct iphdr *ip = (struct iphdr*)(packet + sizeof(struct ethhdr)); 
    int ip_hdr_len = ip->ihl*4;
    struct tcphdr *tcph = (struct tcphdr*)(packet + ip_hdr_len + sizeof(struct ethhdr));
    struct sockaddr_in src_ip, dst_ip;
    src_ip.sin_addr.s_addr = ip->saddr;
    dst_ip.sin_addr.s_addr = ip->daddr;
    switch (ip->protocol) {
        case 1:
            p_count++;
            struct icmphdr *icmph = (struct icmphdr *)(packet + sizeof(struct ethhdr) + ip_hdr_len);
            int icmp_header_len =  sizeof(struct ethhdr) + ip_hdr_len + sizeof icmph;
            printf("[+] No.: %d | Protocol: ICMP | ", p_count);
            printf("SRC_IP: %s | ", inet_ntoa(src_ip.sin_addr)); 
            printf("DST_IP: %s | \n", inet_ntoa(dst_ip.sin_addr));
            if ((unsigned int)(icmph->type) == ICMP_ECHOREPLY) printf("[+] Type: Reply");
            if ((unsigned int)(icmph->type) == ICMP_ECHO) printf("[+] Type: Request");
            printf(" | Code: %d | ", (unsigned int)(icmph->code));
            printf("Checksum: %d | Seq: %d \n", ntohs(icmph->checksum), ntohs(icmph->un.echo.sequence));
            printf("[+] Payload: %s \n\n", packet + icmp_header_len);
            if (icmph->type == 8) {
                spoof_icmp(ip);
            }
            break;
        case 6:
            p_count++;
            printf("[+] No.: %d | Protocol: TCP | ", p_count);
            printf("SRC_PORT %u | DST_PORT %u \n", ntohs(tcph->source), ntohs(tcph->dest));
            printf("[+] SRC_IP: %s | ", inet_ntoa(src_ip.sin_addr));  
            printf("DST_IP: %s | ", inet_ntoa(dst_ip.sin_addr));
            printf("Checksum %d \n", ntohs(tcph->check));
            printf("[+] Payload: %s \n\n", packet + sizeof(struct ethhdr) + ip_hdr_len + tcph->doff*4);
            break;
        default:
            break;
    }
}

int main() {
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 net = 0;
    char errbuf[PCAP_ERRBUF_SIZE]; 
    handle = pcap_open_live(capture_device, 65536, 1, 100, errbuf); //open capture device
    if (handle == NULL) {
        perror("Live session opening error");
    }
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);
    pcap_loop(handle, -1, got_packet, NULL);                
    pcap_close(handle);
    return 0;
}