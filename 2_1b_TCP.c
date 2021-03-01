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

struct ethheader {
  u_char  ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char  ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type;                  /* IP? ARP? RARP? etc */
};

struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address 
  struct  in_addr    iph_destip;   //Destination IP address 
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)args;
    (void)header;
    struct ethheader *eth = (struct ethheader *)packet;
    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 or 2048 is IP type
        struct ipheader * ip = (struct ipheader *)(packet + sizeof(struct ethheader)); 
        int ip_hdr_len = ip->iph_ihl * 4;
        struct icmphdr *icmph = (struct icmphdr *)(packet + sizeof(struct ethheader) + ip_hdr_len);
        int icmp_header_len =  sizeof(struct ethhdr) + ip_hdr_len + sizeof icmph;
        struct tcphdr *tcph = (struct tcphdr*)(packet + ip_hdr_len + sizeof(struct ethhdr));
        if (ip->iph_protocol == IPPROTO_TCP) {
            printf("No.: %d | Protocol: ICMP | ", p_count);
            printf("SRC_PORT %u | ",ntohs(tcph->source));
            printf("DST_PORT %u ",ntohs(tcph->dest));
            printf("\n");
            p_count++;
            printf("SRC_IP: %s | ", inet_ntoa(ip->iph_sourceip));  
            printf("DST_IP: %s | ", inet_ntoa(ip->iph_destip)); 
            /**
            if ((unsigned int)(icmph->type) == ICMP_ECHOREPLY) {
                printf("Type: Reply");
            }
            if ((unsigned int)(icmph->type) == ICMP_ECHO) {
                printf("Type: Request");
            }
            */
            printf("Code: %d | ", (unsigned int)(icmph->code));
            printf("Checksum %d \n",ntohs(icmph->checksum));
            printf("Data: ");
            printf("%s", packet + icmp_header_len);
            printf("\n");
            return;
        }
    }
}


int main() {
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 net = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    char filter_exp[] = "tcp portrange dst 10-100";    
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        perror("Live session opening error");
    }
    pcap_compile(handle, &fp, filter_exp, 0, net);      
    pcap_setfilter(handle, &fp);
    pcap_loop(handle, -1, got_packet, NULL);                
    pcap_close(handle);
    return 0;
}
