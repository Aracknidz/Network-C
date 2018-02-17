#include <stdio.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include "network.h"
#include "utils.h"

struct network{
	char iface[10];
	unsigned char ip[4];  //hex
	unsigned char ipv6[16];//hex
	unsigned char mac[6];
	unsigned char broadcast[4];
	unsigned char netmask[4];
	unsigned char network[4];
	unsigned char gateway[4];
	unsigned char gtwmac[6];
	unsigned char extip[4];
	unsigned char spoof_ip[4];
	unsigned char spoof_ipv6[16];
	unsigned char spoof_mac[6];
	int MTU;
} netlan;
   
inline void parse_inet6(const char *ifname) {
	FILE *f;
	int ret, scope, prefix;
	unsigned char ipv6[16];
	char dname[IFNAMSIZ];
	char address[INET6_ADDRSTRLEN];
	char scopestr[20];

	f = fopen("/proc/net/if_inet6", "r");
	if (f == NULL) {
	    return;
	}

	while (19 == fscanf(f,
		            "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx %*x %x %x %*x %s",
		            &netlan.ipv6[0],
		            &netlan.ipv6[1],
		            &netlan.ipv6[2],
		            &netlan.ipv6[3],
		            &netlan.ipv6[4],
		            &netlan.ipv6[5],
		            &netlan.ipv6[6],
		            &netlan.ipv6[7],
		            &netlan.ipv6[8],
		            &netlan.ipv6[9],
		            &netlan.ipv6[10],
		            &netlan.ipv6[11],
		            &netlan.ipv6[12],
		            &netlan.ipv6[13],
		            &netlan.ipv6[14],
		            &netlan.ipv6[15],
		            &prefix,
		            &scope,
		            dname)) {
	   
	    if (strcmp(ifname, dname) != 0) {
			continue;
	    }

	    if (inet_ntop(AF_INET6, ipv6, address, sizeof(address)) == NULL) {
			continue;
	    }
	}

	fclose(f);
}

inline void parse_ioctl(const char *ifname)
{
	int sock, i;
	struct ifreq ifr;
	struct sockaddr_in *ipaddr;
	char address[INET_ADDRSTRLEN];
	size_t ifnamelen;

	/* copy ifname to ifr object */
	ifnamelen = strlen(ifname);
	if (ifnamelen >= sizeof(ifr.ifr_name)) {
	    return ;
	}
	memcpy(ifr.ifr_name, ifname, ifnamelen);
	ifr.ifr_name[ifnamelen] = '\0';

	/* open socket */
	sock = socket(PF_INET, SOCK_DGRAM, htons(IPPROTO_IP));
	if (sock < 0) {
	    return;
	}

	/* process mac */
	if (ioctl(sock, SIOCGIFHWADDR, &ifr) != -1) {
		for(i=0; i<6; i++)
			netlan.mac[i] = (unsigned char)ifr.ifr_hwaddr.sa_data[i];
	}

	/* process mtu */
	if (ioctl(sock, SIOCGIFMTU, &ifr) != -1) {
	    netlan.MTU = ifr.ifr_mtu;
	}

	/* die if cannot get address */
	if (ioctl(sock, SIOCGIFADDR, &ifr) == -1) {
	    return;
	}

	/* process ip */
	ipaddr = (struct sockaddr_in *)&ifr.ifr_addr;
	if (inet_ntop(AF_INET, &ipaddr->sin_addr, address, sizeof(address)) != NULL) {
		for(i=0; i<4; i++)
	   		netlan.ip[i] = ( inet_addr(address) >> (8U * (i)) ) & 0xff;
	}

	/* try to get broadcast */
	if (ioctl(sock, SIOCGIFBRDADDR, &ifr) != -1) {
	    ipaddr = (struct sockaddr_in *)&ifr.ifr_broadaddr;
	    if (inet_ntop(AF_INET, &ipaddr->sin_addr, address, sizeof(address)) != NULL) {
			for(i=0; i<4; i++)
		   		netlan.broadcast[i] = ( inet_addr(address) >> (8U * (i)) ) & 0xff;
	    }
	}

	/* try to get mask */
	if (ioctl(sock, SIOCGIFNETMASK, &ifr) != -1) {
	    ipaddr = (struct sockaddr_in *)&ifr.ifr_netmask;
	    if (inet_ntop(AF_INET, &ipaddr->sin_addr, address, sizeof(address)) != NULL) {
			for(i=0; i<4; i++)
			   		netlan.netmask[i] = ( inet_addr(address) >> (8U * (i)) ) & 0xff;
	    }
	}
}

inline void getGateway(const char* iface) 
{
	char address[30];
    char cmd [1000] = {0x0};
    sprintf(cmd,"route -n | grep %s  | grep 'UG[ \t]' | awk '{print $2}'", iface);
    FILE* fp = popen(cmd, "r");
    char line[256]={0x0};

    if(fgets(line, sizeof(line), fp) != NULL)
        strcpy(address, line);

	pclose(fp);
	int i;
	for(i=0; i<4; i++)
		netlan.gateway[i] = ( inet_addr(address) >> (8U * (i)) ) & 0xff;
}

inline void getInterface(char* iface)
{
    char cmd [1000] = {0x0};
    sprintf(cmd, "netstat -rn | awk {'print $8'} | sed -n 3p | tr -d '[[:space:]]'");
    FILE* fp = popen(cmd, "r");
    char line[256]={0x0};

    if(fgets(line, sizeof(line), fp) != NULL)
        strcpy(iface, line);

    pclose(fp);
}

inline void getNetwork(){
	char address[30];
	char cmd [1000] = {0x0};
    sprintf(cmd, "netstat -rn | awk {'print $1'} | sed -n 4p | tr -d '[[:space:]]'");
    FILE* fp = popen(cmd, "r");
    char line[256]={0x0};

    if(fgets(line, sizeof(line), fp) != NULL)
        strcpy(address, line);

    pclose(fp);
	int i;
	for(i=0; i<4; i++)
		netlan.network[i] = ( inet_addr(address) >> (8U * (i)) ) & 0xff;
}

inline void getFake(){
	rand_ip(netlan.spoof_ip);
	rand_mac(netlan.spoof_mac);
}

inline int getExternal() 
{
	char address[30];
    char cmd [1000] = {0x0};
    sprintf(cmd, "curl -s http://whatismijnip.nl |cut -d \" \" -f 5");
    FILE* fp = popen(cmd, "r");
    char line[256]={0x0};
    if(fgets(line, sizeof(line), fp) != NULL)
        strcpy(address, line);
	else
		return 1;

    pclose(fp);

	int i;
	for(i=0; i<4; i++)
		netlan.extip[i] = ( inet_addr(address) >> (8U * (i)) ) & 0xff;
	return 0;
}

void str_network(){
	printf("NETWORK CONFIGURATION\n");
	printf("iface:\t\t%s\nip:\t\t%s\nipv6:\t\t%s\nmac:\t\t%s\nbroadcast:\t%s\nnetmask:\t%s\nnetwork:\t%s\ngateway:\t%s\nexternip:\t%s\nspoof_ip:\t%s\nspoof_mac:\t%s\n", netlan.iface, ip_h2s(netlan.ip), ipv6_h2s(netlan.ipv6), mac_h2s(netlan.mac), 
									 ip_h2s(netlan.broadcast), ip_h2s(netlan.netmask), ip_h2s(netlan.network), 
									 ip_h2s(netlan.gateway), ip_h2s(netlan.extip), ip_h2s(netlan.spoof_ip), 
									 mac_h2s(netlan.spoof_mac));
}

int fill_network(){
	int i;
	getInterface(netlan.iface);
    parse_ioctl(netlan.iface);
    parse_inet6(netlan.iface);
	getGateway(netlan.iface);
	getNetwork();
	getFake();
	if(getExternal() > 0){
		for(i=0; i<4; i++)
				netlan.extip[i] = 0x00;
	}
	return 0;
}


