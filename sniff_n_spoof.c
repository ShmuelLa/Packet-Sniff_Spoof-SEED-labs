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
#define IP4_HDRLEN 20
static int p_count = 1;
static char filter_exp[] = "icmp";
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

void spoof_icmp(char target_ip[], int seq) {
    printf("################################\n");
    printf("       Spoofing ICMP Packet\n");
    printf("################################\n\n");
    char data[IP_MAXPACKET] = "SPOOFED!\n";
    int datalen = strlen(data) + 1;
    struct ip iphdr;
    struct icmp icmphdr;
    iphdr.ip_v = 4;
    // IP header length (4 bits): Number of 32-bit words in header = 5
    iphdr.ip_hl = IP4_HDRLEN / 4; // not the most correct
    // Type of service (8 bits) - not using, zero it.
    iphdr.ip_tos = 0;
    // Total length of datagram (16 bits): IP header + ICMP header + ICMP data
    iphdr.ip_len = htons (IP4_HDRLEN + ICMP_HDRLEN + datalen);
    // ID sequence number (16 bits): not in use since we do not allow fragmentation
    iphdr.ip_id = 0;
    // Fragmentation bits - we are sending short packets below MTU-size and without 
    int ip_flags[4];
    // Reserved bit
    ip_flags[0] = 0;
    // "Do not fragment" bit
    ip_flags[1] = 0;
    // "More fragments" bit
    ip_flags[2] = 0;
    // Fragmentation offset (13 bits)
    ip_flags[3] = 0;
    iphdr.ip_off = htons ((ip_flags[0] << 15) + (ip_flags[1] << 14)
                      + (ip_flags[2] << 13) +  ip_flags[3]);
    // TTL (8 bits): 128 - you can play with it: set to some reasonable number
    iphdr.ip_ttl = 128;
    // Upper protocol (8 bits): ICMP is protocol number 1
    iphdr.ip_p = IPPROTO_ICMP;
    if (inet_pton (AF_INET, ip_to_spoof_icmp, &(iphdr.ip_src)) <= 0) {
        perror("inet_pton() failed");
        return;
    }
    if (inet_pton (AF_INET, target_ip, &(iphdr.ip_dst)) <= 0) {
        perror("inet_pton() failed");
        return;
    }
    iphdr.ip_sum = 0;
    iphdr.ip_sum = calculate_checksum((unsigned short *) &iphdr, IP4_HDRLEN);
    // Message Type (8 bits): ICMP_ECHO_REQUEST
    icmphdr.icmp_type = ICMP_ECHO;
    // Message Code (8 bits): echo request
    icmphdr.icmp_code = 0;
    // Identifier (16 bits): some number to trace the response.
    // It will be copied to the response packet and used to map response to the request sent earlier.
    // Thus, it serves as a Transaction-ID when we need to make "ping"
    icmphdr.icmp_id = 18; 
    icmphdr.icmp_seq = seq;
    // ICMP header checksum (16 bits): set to 0 not to include into checksum calculation
    icmphdr.icmp_cksum = 0;
    // Combine the packet 
    char packet[IP_MAXPACKET];
    // First, IP header.
    memcpy (packet, &iphdr, IP4_HDRLEN);
    // Next, ICMP header
    memcpy ((packet + IP4_HDRLEN), &icmphdr, ICMP_HDRLEN);
    // After ICMP header, add the ICMP data.
    memcpy (packet + IP4_HDRLEN + ICMP_HDRLEN, data, datalen);
    // Calculate the ICMP header checksum
    icmphdr.icmp_cksum = calculate_checksum((unsigned short *) (packet + IP4_HDRLEN), ICMP_HDRLEN + datalen);
    memcpy ((packet), &icmphdr, ICMP_HDRLEN);
    struct sockaddr_in dest_in;
    memset (&dest_in, 0, sizeof (struct sockaddr_in));
    dest_in.sin_family = AF_INET;
    dest_in.sin_addr.s_addr = iphdr.ip_dst.s_addr;
    //dest_in.sin_addr.s_addr = inet_addr("8.8.8.8");
    // Create raw socket for IP-RAW (make IP-header by yourself)
    int sock = -1;
    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
        perror("socket() failed");
        return;
    }
    // This socket option IP_HDRINCL says that we are building IPv4 header by ourselves, and
    // the networking in kernel is in charge only for Ethernet header.
    // Send the packet using sendto() for sending datagrams.
    const int flagOne = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL,&flagOne,sizeof(flagOne)) == -1) {
        perror("setsockopt() failed");
    }
    if (sendto (sock, packet, IP4_HDRLEN + ICMP_HDRLEN + datalen, 0, (struct sockaddr *) &dest_in, sizeof (dest_in)) == -1) {
        perror("sendto() failed with error: %d");
        return;
    }
    /**
    if (recvfrom (sock, &packet, ICMP_HDRLEN+datalen , 0, NULL, (socklen_t*)sizeof (struct sockaddr)) < 0)  {
        perror("recvfrom() failed with error: %d");
        return; 
    }
    */
    close(sock);
    return;
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
                spoof_icmp(inet_ntoa(src_ip.sin_addr) ,ntohs(icmph->un.echo.sequence));
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
    handle = pcap_open_live("br-1a9996b508c9", 65536, 1, 100, errbuf);
    if (handle == NULL) {
        perror("Live session opening error");
    }
    pcap_compile(handle, &fp, filter_exp, 0, net);      
    pcap_setfilter(handle, &fp);
    pcap_loop(handle, -1, got_packet, NULL);                
    pcap_close(handle);
    return 0;
}
