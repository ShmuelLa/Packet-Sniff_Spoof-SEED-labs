#include<pcap.h>
#include<stdio.h>
#include<arpa/inet.h>
#include<string.h>
#include<sys/socket.h>
#include<netinet/ether.h>//ETHER_ADDR_LEN
#include<netinet/ip.h>
#include<stdlib.h>

/* Ethernet header */
struct ethheader {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
    u_short ether_type;                  /* IP? ARP? RARP? etc */
};

/* IP Header */
struct ipheader {
    unsigned char iph_ihl: 4, //IP header length
    iph_ver: 4; //IP version
    unsigned char iph_tos; //Type of service
    unsigned short int iph_len; //IP Packet length (data + header)
    unsigned short int iph_ident; //Identification
    unsigned short int iph_flag: 3, //Fragmentation flags
    iph_offset: 13; //Flags offset
    unsigned char iph_ttl; //Time to Live
    unsigned char iph_protocol; //Protocol type
    unsigned short int iph_chksum; //IP datagram checksum
    struct in_addr iph_sourceip; //Source IP address
    struct in_addr iph_destip;   //Destination IP address
};
/* ICMP Header */
struct icmpheader {
#define    ICMP_ECHO_REQ 8
#define    ICMP_ECHO_RES 0
#define    ICMP_HDR_LEN 4
    unsigned char icmp_type;
    unsigned char icmp_code;
    unsigned short icmp_cksum;        /* icmp checksum */
    unsigned short icmp_id;                /* icmp identifier */
    unsigned short icmp_seq;            /* icmp sequence number */
};

/**********************************************
  Calculating Internet Checksum
 **********************************************/

unsigned short in_cksum (unsigned short *buf, int length)
{
   unsigned short *w = buf;
   int nleft = length;
   int sum = 0;
   unsigned short temp=0;

   /*
    * The algorithm uses a 32 bit accumulator (sum), adds
    * sequential 16 bit words to it, and at the end, folds back all 
    * the carry bits from the top 16 bits into the lower 16 bits.
    */
   while (nleft > 1)  {
       sum += *w++;
       nleft -= 2;
   }

   /* treat the odd byte at the end, if any */
   if (nleft == 1) {
        *(u_char *)(&temp) = *(u_char *)w ;
        sum += temp;
   }

   /* add back carry outs from top 16 bits to low 16 bits */
   sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16 
   sum += (sum >> 16);                  // add carry 
   return (unsigned short)(~sum);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void sent_ip(struct ipheader *ip, size_t size);

void spoof_reply(struct ipheader *ip);

#define ICMP 1

int main() {

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    memset((void *) &fp, 0, sizeof(fp));
    char filter_exp[] = "icmp";//filter
    bpf_u_int32 net;
    handle = pcap_open_live("br-1a9996b508c9", BUFSIZ, 1, 1000, errbuf);
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);   //Close the handle
    return 0;
}

/*
 function that recieve a packet and if the protocol type is ICMP request- spoot reply
*/
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet) {
    struct ethheader *eth = (struct ethheader *) packet;
    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
        struct ipheader *ip = (struct ipheader *) (packet + sizeof(struct ethheader));
        printf("protocol number: %d\n", ip->iph_protocol);
        // print information from IP header
        printf("IP SOURCE: %s\n", inet_ntoa(ip->iph_sourceip));
        printf("IP DESTINATION: %s\n", inet_ntoa(ip->iph_destip));
        spoof_reply(ip);
        printf("\n_________________________\n");
    }
}
void spoof_reply(struct ipheader *ip) {
    int ip_header_len = ip->iph_ihl * 4;
    struct icmpheader *icmp = (struct icmpheader *) ((u_char *) ip + ip_header_len);

    printf("ICMP TYPE: %d\n", icmp->icmp_type);

    if (icmp->icmp_type == ICMP_ECHO_REQ) {
        const char buffer[1500];
	//  Make a copy from the original packet
        memset((char *) buffer, 0, 1500);
        memcpy((char *) buffer, ip, ntohs(ip->iph_len));
        struct ipheader *new_ip = (struct ipheader *) buffer;
        struct icmpheader *new_icmp = (struct icmpheader *) (buffer + ip_header_len);
        char *data = (char *) new_icmp + sizeof(struct icmpheader);

	//  Construct the ICMP header
        new_icmp->icmp_type = ICMP_ECHO_RES;
        // Calculate the checksum for integrity
   	new_icmp->icmp_cksum = 0;
   	new_icmp->icmp_cksum = in_cksum((unsigned short *)new_icmp,(ntohs(ip->iph_len)- ip_header_len));

	// Construct the IP header 
        new_ip->iph_sourceip = ip->iph_destip;
        new_ip->iph_destip = ip->iph_sourceip;
        new_ip->iph_ttl = 50; // Rest the TTL field
        /****************************
*** initialize the socket ****
******************************/
    struct sockaddr_in d_addr;// address for sendto
    bzero(&d_addr, sizeof(d_addr));
    d_addr.sin_family = AF_INET;
    d_addr.sin_addr = new_ip->iph_destip;


    int sd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sd < 0) {
        perror("failed to create socket");
        exit(-1);
    }

    int enable = 1;
    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)) != 0)//not nessesary for short distance
        perror("failed to set option");


    // sent reply
    if (sendto(sd, new_ip, ntohs(new_ip->iph_len), 0, (struct sockaddr *) &(d_addr), sizeof(d_addr)) <= 0) {
        perror("failed to sendto\n");
        exit(EXIT_FAILURE);
    } else {
        printf("reply sent succesfully\n");
    }
    close(sd);
    }
}




