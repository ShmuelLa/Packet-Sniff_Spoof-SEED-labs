#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>

static int p_count = 1;

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)args;
    int size = header->len;
    struct iphdr *ip = (struct iphdr*)(packet + sizeof(struct ethhdr)); 
    struct ethheader *eth = (struct ethheader *)packet;
    int ip_hdr_len = ip->ihl*4;
    struct icmphdr *icmph = (struct icmphdr *)(packet + sizeof(struct ethhdr) + ip_hdr_len);
    switch (ip->protocol) {
        case 1: ;
            int icmp_header_len =  sizeof(struct ethhdr) + ip_hdr_len + sizeof icmph;
            struct tcphdr *tcph = (struct tcphdr*)(packet + ip_hdr_len + sizeof(struct ethhdr));
            printf("No.: %d | Protocol: ICMP | ", p_count);
            printf("SRC_PORT %u | ",ntohs(tcph->source));
            printf("DST_PORT %u ",ntohs(tcph->dest));
            printf("\n");
            p_count++;
            uint32_t src_ip = ip->saddr;
            uint32_t dst_ip = ip->daddr;
            printf("SRC_IP: %d | ", src_ip);  
            printf("DST_IP: %d | ", dst_ip); 
            if ((unsigned int)(icmph->type) == ICMP_ECHOREPLY) {
                printf("Type: Reply");
            }
            if ((unsigned int)(icmph->type) == ICMP_ECHO) {
                printf("Type: Request");
            }
            printf("Code: %d | ", (unsigned int)(icmph->code));
            printf("Checksum %d \n",ntohs(icmph->checksum));
            printf("Data: ");
            printf("%s", packet + icmp_header_len);
            printf("\n");
            return;
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
    char filter_exp[] = "icmp";    
    handle = pcap_open_live("enp0s3", 65536, 1, 0, errbuf);
    if (handle == NULL) {
        perror("Live session opening error");
    }
    pcap_compile(handle, &fp, filter_exp, 0, net);      
    pcap_setfilter(handle, &fp);
    pcap_loop(handle, -1, got_packet, NULL);                
    pcap_close(handle);
    return 0;
}
