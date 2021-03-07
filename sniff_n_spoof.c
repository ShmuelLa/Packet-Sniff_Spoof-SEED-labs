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

void spoof_icmp(char target_ip[], struct icmphdr *target_icmp_hdr) {
    printf("################################\n");
    printf("       Spoofing ICMP Packet\n");
    printf("################################\n\n");

    int sd;
    struct sockaddr_in sin;
    char buf[1024];

    // Create the IP/ICMP headers and attach to the buffer
    struct ip *ip = (struct ip *)buf;
    struct icmp *icmp = (struct icmp *) (ip + 1);
    const int on = 1;

    // Allocate buffer size
    bzero(buf, sizeof(buf)); 

    // IP header
    ip->ip_v = 4;
    ip->ip_hl = 5;
    ip->ip_tos = 0;
    ip->ip_len = htons(sizeof(buf));
    ip->ip_id = 0;
    ip->ip_off = htons(0);
    ip->ip_ttl = 128; // 255 TTL
    ip->ip_p = 1; // ICMP
    ip->ip_sum = 0; // Don't care about this
    ip->ip_src.s_addr = inet_addr(ip_to_spoof_icmp);
    ip->ip_dst.s_addr = inet_addr(target_ip);

    // ICMP header
    icmp->icmp_type = 0;
    icmp->icmp_code = 0;
    icmp->icmp_id = target_icmp_hdr->un.echo.id;
    icmp->icmp_seq = target_icmp_hdr->un.echo.sequence;
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
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)args;
    (void)header;
    //int size = header->len;
    struct iphdr *ip = (struct iphdr*)(packet + sizeof(struct ethhdr)); 
    //struct ethheader *eth = (struct ethheader *)packet;
    int ip_hdr_len = ip->ihl*4;
    struct tcphdr *tcph = (struct tcphdr*)(packet + ip_hdr_len + sizeof(struct ethhdr));
    //struct udphdr *udph = (struct udphdr*)(packet + ip_hdr_len  + sizeof(struct ethhdr));
    struct sockaddr_in src_ip, dst_ip;
    src_ip.sin_addr.s_addr = ip->saddr;
    dst_ip.sin_addr.s_addr = ip->daddr;
    switch (ip->protocol) {
        case 1:
            p_count++;
            struct icmphdr *icmph = (struct icmphdr *)(packet + sizeof(struct ethhdr) + ip_hdr_len);
            int icmp_header_len =  sizeof(struct ethhdr) + ip_hdr_len + sizeof icmph;
            printf("[+] No.: %d | Protocol: ICMP | ", p_count);
            printf("SRC_IP: %s | DST_IP: %s \n", inet_ntoa(src_ip.sin_addr), inet_ntoa(dst_ip.sin_addr));  
            if ((unsigned int)(icmph->type) == ICMP_ECHOREPLY) printf("[+] Type: Reply");
            if ((unsigned int)(icmph->type) == ICMP_ECHO) printf("[+] Type: Request");
            printf(" | Code: %d | ", (unsigned int)(icmph->code));
            printf("Checksum: %d | Seq: %d \n", ntohs(icmph->checksum), ntohs(icmph->un.echo.sequence));
            printf("[+] Payload: %s \n\n", packet + icmp_header_len);
            if (strcmp(inet_ntoa(dst_ip.sin_addr),ip_to_spoof_icmp) == 0) {
                //send_ping_response(ip->ip_dst, ip->ip_src, data_bk, data_size, icmp->checksum, icmp->id, icmp->seq);
                spoof_icmp(inet_ntoa(src_ip.sin_addr) ,icmph);
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
    handle = pcap_open_live(capture_device, 65536, 1, 100, errbuf);
    if (handle == NULL) {
        perror("Live session opening error");
    }
    pcap_compile(handle, &fp, filter_exp, 0, net);      
    pcap_setfilter(handle, &fp);
    pcap_loop(handle, -1, got_packet, NULL);                
    pcap_close(handle);
    return 0;
}
