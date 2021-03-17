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
    //===================
    // ICMP header
    //===================
    // Message Type (8 bits): ICMP_ECHO_REQUEST
    icmphdr.icmp_type = ICMP_ECHO;
    // Message Code (8 bits): echo request
    icmphdr.icmp_code = 0;
    // Identifier (16 bits): some number to trace the response.
    // It will be copied to the response packet and used to map response to the request sent earlier.
    // Thus, it serves as a Transaction-ID when we need to make "ping"
    icmphdr.icmp_id = 18; // hai
    // Sequence Number (16 bits): starts at 0
    icmphdr.icmp_seq = 0;
    // ICMP header checksum (16 bits): set to 0 not to include into checksum calculation
    icmphdr.icmp_cksum = 0;
    // Combine the packet 
    char packet[IP_MAXPACKET];
    // Next, ICMP header
    memcpy ((packet), &icmphdr, ICMP_HDRLEN);
    // After ICMP header, add the ICMP data.
    memcpy (packet + ICMP_HDRLEN, data, datalen);
    // Calculate the ICMP header checksum
    icmphdr.icmp_cksum = calculate_checksum((unsigned short *) (packet), ICMP_HDRLEN + datalen);
    memcpy ((packet), &icmphdr, ICMP_HDRLEN);
    struct sockaddr_in dest_in;
    memset (&dest_in, 0, sizeof (struct sockaddr_in));
    dest_in.sin_family = AF_INET;
    dest_in.sin_addr.s_addr = inet_addr("8.8.8.8");
    // Create raw socket for IP-RAW (make IP-header by yourself)
    int sock = -1;
    if ((sock = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
        fprintf (stderr, "socket() failed with error: %d", errno);
        fprintf (stderr, "To create a raw socket, the process needs to be run by Admin/root user.\n\n");
        return -1;
    }
    // This socket option IP_HDRINCL says that we are building IPv4 header by ourselves, and
    // the networking in kernel is in charge only for Ethernet header.
    // Send the packet using sendto() for sending datagrams.
    clock_gettime(CLOCK_MONOTONIC, &start);
    if (sendto (sock, packet, ICMP_HDRLEN+datalen, 0, (struct sockaddr *) &dest_in, sizeof (dest_in)) == -1) {
        fprintf (stderr, "sendto() failed with error: %d", errno);
        return -1;
    }
    if (recvfrom (sock, &packet, ICMP_HDRLEN+datalen , 0, NULL, (socklen_t*)sizeof (struct sockaddr)) < 0)  {
        fprintf (stderr, "recvfrom() failed with error: %d", errno);
        return -1; 
    }
    else {
        clock_gettime(CLOCK_MONOTONIC, &end);
        uint64_t start_nsec = start.tv_nsec;
        uint64_t end_nsec = end.tv_nsec;
        double operation_time_micros = (end_nsec - start_nsec) * 0.001;
        double operation_time_ms = (end_nsec - start_nsec) * 1e-6;
        printf("Ping received with RTT:");
        printf (" %1.1f ", operation_time_ms);
        printf("milliseconds | ");
        printf (" %1.1f ", operation_time_micros);
        printf("microsoeconds \n");

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
	// add back carry outs from top 16 bits to low 16 bits
	sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
	sum += (sum >> 16);                 // add carry
	answer = ~sum;                      // truncate to 16 bits
	return answer;
}