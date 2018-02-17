#include<stdio.h>
#include<stdlib.h>
#include<sys/time.h>
#include<sys/socket.h>
#include<features.h>
#include<linux/if_packet.h>
#include<linux/if_ether.h>
#include<errno.h>
#include<sys/ioctl.h>
#include<net/if.h>
#include<net/ethernet.h>
#include<linux/ip.h>
#include<linux/tcp.h>
#include<arpa/inet.h>
#include<string.h>
#include <unistd.h>
#include<netinet/in.h>
#include<netdb.h>
#include <limits.h>
#include <netdb.h>
#include <sys/types.h>
#include <math.h>

int BindRawSocketToInterface(char *device, int rawsock, int protocol)
{
	struct sockaddr_ll sll;
	struct ifreq ifr;
	bzero(&sll, sizeof(sll));
	bzero(&ifr, sizeof(ifr));
	/* First Get the Interface Index */
	strncpy((char *)ifr.ifr_name, device, IFNAMSIZ);
	if((ioctl(rawsock, SIOCGIFINDEX, &ifr)) == -1)
	{
	printf("Error getting Interface index !\n");
	exit(-1);
	}
	/* Bind our raw socket to this interface */
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;
	sll.sll_protocol = htons(protocol);
	if((bind(rawsock, (struct sockaddr *)&sll, sizeof(sll)))== -1)
	{
	perror("Error binding raw socket to interface\n");
	exit(-1);
	}
	return 1;
}

int CreateRawSocket(int protocol_to_sniff)
{
	int rawsock;
	if((rawsock = socket(PF_PACKET, SOCK_RAW, htons(protocol_to_sniff)))== -1)
	{
	perror("Error creating raw socket: ");
	exit(-1);
	}
	return rawsock;
}

int main(int argv, char* argc[])
{	int x = inet_addr("127.0.0.1");
	int raw = CreateRawSocket(ETH_P_ALL);
	BindRawSocketToInterface("wlan0", raw, ETH_P_ALL);
	unsigned char pkt[66] = {0x12,0xdd,0xb1,0xdc,0xc1,0x64,0x00,0x26,0xc6,0x6c,0x15,0x1a,0x08,0x00,0x45,0x00,0x00,0x34,0x0d,0x86,
							0x40,0x00,0x40,0x06,0xf2,0xf2,0xc0,0xa8,0x02,0x68,0x2d,0x3a,0x4a, 0x01,0x95,0x10,0x01,0xbb,0x31,
							0x68,0xc0,0x40,0xbc,0x08,0x52,0x95,0x80,0x10,0x00,0x0a,0xe3,0x0c,0x00,0x00,0x01,0x01,0x08,0x0a,0x00,0xf4,
							0x61,0x59,0xac,0x9f,0xb3,0x5b};
	int i;
	for(i=0; i<30000; i++){
		write(raw, pkt, 66);
		usleep(10);
		printf("packet sent");
	}
	//printf("%08x", x);
	return 0;
}
