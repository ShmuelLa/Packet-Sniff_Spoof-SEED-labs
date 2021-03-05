#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>
#include <time.h>
#include <sys/time.h>

#define ICMP_HDRLEN 8 
unsigned short calculate_checksum(unsigned short * paddress, int len);

int main () {
    struct timespec start, end;
    struct icmp icmphdr; // ICMP-header
    char data[IP_MAXPACKET] = "This is a custom Gidon_Shmuel Ping :) \n";
    int datalen = strlen(data) + 1;
    icmphdr.icmp_type = ICMP_ECHO;
    icmphdr.icmp_code = 0;
    icmphdr.icmp_id = 18; // hai
    icmphdr.icmp_seq = 0;
    icmphdr.icmp_cksum = 0;
    char packet[IP_MAXPACKET];
    memcpy ((packet), &icmphdr, ICMP_HDRLEN);
    memcpy (packet + ICMP_HDRLEN, data, datalen);
    icmphdr.icmp_cksum = calculate_checksum((unsigned short *) (packet), ICMP_HDRLEN + datalen);
    memcpy ((packet), &icmphdr, ICMP_HDRLEN);
    struct sockaddr_in dest_in;
    memset (&dest_in, 0, sizeof (struct sockaddr_in));
    dest_in.sin_family = AF_INET;
    dest_in.sin_addr.s_addr = inet_addr("8.8.8.8");
    int sock = -1;
    if ((sock = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
        fprintf (stderr, "socket() failed with error: %d", errno);
        fprintf (stderr, "To create a raw socket, the process needs to be run by Admin/root user.\n\n");
        return -1;
    }
    if (sendto (sock, packet, ICMP_HDRLEN+datalen, 0, (struct sockaddr *) &dest_in, sizeof (dest_in)) == -1) {
        fprintf (stderr, "sendto() failed with error: %d", errno);
        return -1;
    }
    if (recvfrom (sock, &packet, ICMP_HDRLEN+datalen , 0, NULL, (socklen_t*)sizeof (struct sockaddr)) < 0)  {
        fprintf (stderr, "recvfrom() failed with error: %d", errno);
        return -1; 
    }
    close(sock);
    return 0;
}

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
	sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
	sum += (sum >> 16);                 // add carry
	answer = ~sum;                      // truncate to 16 bits
	return answer;
}