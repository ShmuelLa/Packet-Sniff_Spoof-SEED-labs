#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include<netinet/udp.h>

static int p_count = 1;
static char filter_exp[] = "icmp";
char ip_to_spoof_icmp[] = "1.2.3.4";

void spoof_icmp() {
    printf("\n\n################################");
    printf("       Spoofing ICMP Packet");
    printf("################################\n\n ");
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)args;
    int size = header->len;
    struct iphdr *ip = (struct iphdr*)(packet + sizeof(struct ethhdr)); 
    struct ethheader *eth = (struct ethheader *)packet;
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
            if (strcmp(inet_ntoa(dst_ip.sin_addr),ip_to_spoof_icmp)) {
                spoof_icmp();
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
