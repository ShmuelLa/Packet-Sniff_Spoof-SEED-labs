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

void spoof_icmp(struct iphdr *target_ip_hdr) {
    printf("################################\n");
    printf("       Spoofing ICMP Packet\n");
    printf("################################\n\n");
    int ip_header_len = target_ip_hdr->ihl * 4;
    struct icmp *icmp = (struct icmp *) ((u_char *) target_ip_hdr + ip_header_len);
    if (icmp->icmp_type == 8) {
        const char buffer[1500];
        memset((char *) buffer, 0, 1500);
        memcpy((char *) buffer, target_ip_hdr, ntohs(target_ip_hdr->tot_len));
        struct iphdr *new_ip = (struct iphdr *) buffer;
        struct icmp *new_icmp = (struct icmp *) (buffer + ip_header_len);
        char *data = (char *) new_icmp + sizeof(struct icmp);
        new_icmp->icmp_type = 0;
   	    new_icmp->icmp_cksum = 0;
   	    new_icmp->icmp_cksum = calculate_checksum((unsigned short *)new_icmp,(ntohs(target_ip_hdr->tot_len)- ip_header_len));
        new_ip->saddr = target_ip_hdr->daddr;
        new_ip->daddr = target_ip_hdr->saddr;
        new_ip->ttl = 50;
        struct sockaddr_in d_addr;
        bzero(&d_addr, sizeof(d_addr));
        d_addr.sin_family = AF_INET;
        d_addr.sin_addr = *(struct in_addr *) &new_ip->daddr;
        int sd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sd < 0) {
            perror("failed to create socket");
        }
        int flag = 1;
        if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &flag, sizeof(flag)) != 0) {
            perror("failed to set option");
        }
        if (sendto(sd, new_ip, ntohs(new_ip->tot_len), 0, (struct sockaddr *) &(d_addr), sizeof(d_addr)) <= 0) {
            perror("failed to sendto\n");
        } 
        close(sd);
    }
    /**
    ip->ip_v = target_ip_hdr->ip_v;
    ip->ip_hl = target_ip_hdr->ip_hl;
    ip->ip_tos = target_ip_hdr->ip_tos;
    ip->ip_len = target_ip_hdr->ip_len;
    ip->ip_id = target_ip_hdr->ip_id;
    ip->ip_off = target_ip_hdr->ip_off;
    ip->ip_ttl = target_ip_hdr->ip_ttl; // 255 TTL
    ip->ip_p = target_ip_hdr->ip_p; // ICMP
    ip->ip_sum = 0; // Don't care about this
    ip->ip_src = target_ip_hdr->ip_dst;
    ip->ip_dst = target_ip_hdr->ip_src;

    sin.sin_family = AF_INET;
	sin.sin_addr = ip->ip_dst;

    icmp->icmp_type = 0;
    icmp->icmp_code = 0;
    //icmp->icmp_id = target_icmp_hdr->un.echo.id;
    icmp->icmp_seq = target_icmp_hdr->un.echo.sequence;
    icmp->icmp_cksum = calculate_checksum((unsigned short *)icmp, (ntohs(ip->ip_hl)-ip_hdr_len));

    sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("socket() error");
        return;
    }
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
	{
		perror("setsockopt() for IP_HDRINCL error");
        return;
	}
    if (sendto(sock, buf, ntohs(ip->ip_len) - 28, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		perror("sendto() error");
        return;
	}
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
            printf("SRC_IP: %s | ", inet_ntoa(src_ip.sin_addr)); 
            printf("DST_IP: %s | \n", inet_ntoa(dst_ip.sin_addr));
            if ((unsigned int)(icmph->type) == ICMP_ECHOREPLY) printf("[+] Type: Reply");
            if ((unsigned int)(icmph->type) == ICMP_ECHO) printf("[+] Type: Request");
            printf(" | Code: %d | ", (unsigned int)(icmph->code));
            printf("Checksum: %d | Seq: %d \n", ntohs(icmph->checksum), ntohs(icmph->un.echo.sequence));
            printf("[+] Payload: %s \n\n", packet + icmp_header_len);
            if (strcmp(inet_ntoa(dst_ip.sin_addr),ip_to_spoof_icmp) == 0) {
                //struct ip *target_ip = (struct ip *) ip;
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