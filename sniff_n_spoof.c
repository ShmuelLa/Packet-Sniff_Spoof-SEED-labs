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

    char buffer[1500];
    memset(buffer, 0, 1500);
    struct icmphdr *icmp_hdr = (struct icmphdr *) (buffer + sizeof(struct iphdr));
    struct iphdr *ip_hdr = (struct iphdr *) buffer;
    icmp_hdr->type = 0;
    icmp_hdr->un.echo.sequence= target_icmp_hdr->un.echo.sequence;
    icmp_hdr->checksum = 0;
    icmp_hdr->checksum = calculate_checksum((unsigned short *)icmp_hdr, sizeof(struct icmphdr));
    ip_hdr->version = 4;
    ip_hdr->ihl = 5;
    ip_hdr->ttl = 20;
    ip_hdr->saddr = inet_addr(ip_to_spoof_icmp);
    ip_hdr->daddr = inet_addr(target_ip);
    ip_hdr->protocol = IPPROTO_ICMP;
    ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
    struct sockaddr_in dest_in;
    int enable = 1;
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));
    dest_in.sin_family = AF_INET;
    dest_in.sin_addr = inet_aton(ip_hdr->daddr);
    sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&dest_in, sizeof(dest_in));
    close(sock);
    return 0;









    /**
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    int sock = -1;
    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
        perror("socket() failed");
        return;
    }
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, capture_device, strnlen(capture_device, 20)) == -1) {
        perror("setsockopt() failed");
    }
    char data[] = "SPOOFED!\n";
    struct iphdr* ip_hdr = (struct iphdr*) (sizeof(struct icmphdr));
    struct icmp icmphdr;
    int datalen = strlen(data);
    char *packet = datalen + sizeof(struct iphdr) + sizeof(struct icmphdr);
    ip_hdr->version = 4;
    ip_hdr->ihl = (sizeof(struct iphdr)) / 4;
    ip_hdr->tos = 0;
    ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(data));
	ip_hdr->id = htons(111);
	ip_hdr->frag_off = 0;
	ip_hdr->ttl = 128;
	ip_hdr->protocol = IPPROTO_ICMP;
	ip_hdr->check = calculate_checksum((unsigned short *) &ip_hdr, ip_hdr->tot_len);
	ip_hdr->saddr = inet_addr(ip_to_spoof_icmp);
	ip_hdr->daddr = inet_addr(target_ip);
    icmphdr.icmp_type = 0;
    icmphdr.icmp_code = 0;
    icmphdr.icmp_id = id; 
    icmphdr.icmp_seq = seq;
    //icmphdr.icmp_cksum = 0;
    icmphdr.icmp_cksum = calculate_checksum((unsigned short *) (packet +ip_hdr->tot_len), ICMP_HDRLEN + datalen);
    if (sendto (sock, packet, ip_hdr->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) == -1) {
        perror("sendto() failed");
        return;
    }
    close(sock);
    return;
    */
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
