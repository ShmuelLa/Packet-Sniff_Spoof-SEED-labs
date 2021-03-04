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

void PrintData (unsigned char* data , int Size)
{
    int i , j;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            printf("         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    printf("%c",(unsigned char)data[j]); //if its a number or alphabet
                 
                else printf("."); //otherwise print a dot
            }
            printf("\n");
        } 
         
        if(i%16==0) printf("   ");
            printf(" %02X",(unsigned int)data[i]);
                 
        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++) 
            {
              printf("   "); //extra spaces
            }
             
            printf("         ");
             
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) 
                {
                  printf("%c",(unsigned char)data[j]);
                }
                else
                {
                  printf(".");
                }
            }
    
            printf( "\n" );
        }
    }
}

void print_tcp_packet(unsigned char* Buffer, int Size)
{
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));  
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
    printf("\n\n***********************TCP Packet*************************\n");  
    printf("\n");
    printf("TCP Header\n");
    printf("   |-Source Port      : %u\n",ntohs(tcph->source));
    printf("   |-Destination Port : %u\n",ntohs(tcph->dest));
    printf("   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    printf("   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    printf("   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    printf("   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    printf("   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    printf("   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    printf("   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    printf("   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    printf("   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    printf("   |-Window         : %d\n",ntohs(tcph->window));
    printf("   |-Checksum       : %d\n",ntohs(tcph->check));
    printf("   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    printf("\n");
    printf("                        DATA Dump                         ");
    printf("\n");
    printf("IP Header\n");
    PrintData(Buffer,iphdrlen);
    printf("TCP Header\n");
    PrintData(Buffer+iphdrlen,tcph->doff*4);
    printf("Data Payload\n");    
    PrintData(Buffer + header_size , Size - header_size );
    printf("\n###########################################################");
}

void print_content(const u_char* data , int Size) {
    int i , j;
    for(i=0 ; i < Size ; i++) {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            for(j=i-16 ; j<i ; j++) {
                if(data[j]>=32 && data[j]<=128) printf("%c", (unsigned char)data[j]); //if its a number or alphabet
                else printf("."); //otherwise print a dot
            }
            printf("\n");
        } 
        if(i%16==0) printf("   ");
            printf(" %02X",(unsigned int)data[i]);      
        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++) {
              printf("   "); //extra spaces
            }
            printf("         ");
            for(j=i-i%16 ; j<=i ; j++) {
                if(data[j]>=32 && data[j]<=128) {
                  printf("%c",(unsigned char)data[j]);
                }
                else {
                  printf(".");
                }
            }
            printf("\n" );
        }
    }
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)args;
    (void)header;
    struct ethheader *eth = (struct ethheader *)packet;
    print_tcp_packet(packet , sizeof(packet));
    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 or 2048 is IP type
        struct ipheader * ip = (struct ipheader *)(packet + sizeof(struct ethheader)); 
        int ip_hdr_len = ip->iph_ihl * 4;
        struct tcphdr *tcph = (struct tcphdr*)(packet + ip_hdr_len + sizeof(struct ethhdr));
        int tcp_hdr_len = sizeof(struct ethhdr) + ip_hdr_len + tcph->doff*4;
        if (ip->iph_protocol == IPPROTO_TCP) {
            printf("No.: %d | Protocol: ICMP | ", p_count);
            printf("SRC_PORT %u | ",ntohs(tcph->source));
            printf("DST_PORT %u ",ntohs(tcph->dest));
            printf("\n");
            p_count++;
            printf("SRC_IP: %s | ", inet_ntoa(ip->iph_sourceip));  
            printf("DST_IP: %s | ", inet_ntoa(ip->iph_destip)); 
            printf("Data: ");
            printf("\n");
            print_content(packet + tcp_hdr_len, sizeof(packet) - tcp_hdr_len);
            return;
        }
    }
}

int main() {
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 net = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    char filter_exp[] = "tcp port 23";    
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
