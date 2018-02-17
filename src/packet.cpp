/*

decortiquer les payloads des tcp 80/ https
modifier les cache dns
analyser les ip dun reseau ARP
router les ips
spoofer les ips
flooder quelquun
intercepter des communications
envoyer un fichier
executer un fichier
garder les mac dans ma DB
faire DB optimiser des ipv4
ping un range d'adresse ip

*/

#include <iostream>
#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <vector>
#include <string.h>

#include "packet.h"
#include "utils.h"

using namespace std;
using namespace xld;
using std::vector;

int strlen2(unsigned char* _2find){;}

//Part::pack
//remaster get_prop() -> ex: ip char[4]
//display 255.255.255.255

unsigned int pack_uint(unsigned char* _2pack, int len){
	int max = len;
	unsigned int packed = 0U;
	register int i;
	for(i=0; i<max; i++)
	{
		packed += _2pack[i] << ((max-i-1)*8U);
	}
	return packed;
}

char* Part::get_layer_name(){ return this->layer_name; }

/*}else if(strcmp((const char*)prot, "ipv6")==0){
			sprintf(ipv6, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
										ptr_fill[indx][0], ptr_fill[indx][1], ptr_fill[indx][2], ptr_fill[indx][3],
										ptr_fill[indx][4], ptr_fill[indx][5], ptr_fill[indx][6], ptr_fill[indx][7],
										ptr_fill[indx][8], ptr_fill[indx][9], ptr_fill[indx][10], ptr_fill[indx][11]);
			return ipv6;*/
int Part::get_proto_len(const unsigned int len, const unsigned char (*ptr_prop)[5][10]){
	int total = 0U;
	for(int i = 0; i < len; ++i){
		total += ptr_prop[i][2][0];
	}
	total /= 8;
	return total;
}

inline char* Part::get_prop(const char* p, const unsigned int len, unsigned char (*ptr_fill)[13], const unsigned char (*ptr_prop)[5][10]){
	const unsigned char* tofind;
	int indx = -1;
	char* ip = xalloc<char*>(20);
	char* mac = xalloc<char*>(30);
	char* value = xalloc<char*>(10);
	char* err = xalloc<char*>(8);
	strcpy(err, "error");
	for(int i = 0; i < len; ++i){
		tofind = ptr_prop[i][0];
		if (strcmp(p, (const char*)tofind) == 0){
			indx = i;
			break;		
		}	
	}
	if (indx == -1){
		return err;
	}else{
		//{"dst","ipv4" ,0x30}
		const unsigned char* prot = ptr_prop[indx][1];
		if (strcmp((const char*)prot,"mac")==0){
			sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x", 
										ptr_fill[indx][0], ptr_fill[indx][1], 
									    ptr_fill[indx][2], ptr_fill[indx][3],
									    ptr_fill[indx][4], ptr_fill[indx][5]);
			return mac;
		}else if(strcmp((const char*)prot, "ipv4")==0){
			sprintf(ip, "%d.%d.%d.%d",  ptr_fill[indx][0], ptr_fill[indx][1], 
									    ptr_fill[indx][2], ptr_fill[indx][3]);
			return ip;		
		}else if(strcmp((const char*)prot, "long")==0){
			int max = (int)(ceil((float)ptr_prop[indx][2][0] / 8));
			int i;
			for(i=0; i<max; i++)
			{
				value[i] = ptr_fill[indx][i];
			}
			value[i+1] = '\0';
			return (char*)value;
		}else{
			return err;		
		}
	}
	return err;
}

inline void Part::process(unsigned char* pkt, const unsigned int len, unsigned char (*ptr_fill)[13], const unsigned char (*ptr_prop)[5][10]){
	octet = 0;
	mask = 0x00;
	last = 0x00;
	max = 0;
	bytepush = 0x00;
	realmax = 0x00;
	int i, y;
	for(i=0; i<len; ++i){
		last = 0x00;
		realmax = (int)( ceil((float)ptr_prop[i][2][0]/8U) );
		max = realmax + (bytepush > 0x00 && ptr_prop[i][2][0]/8 > 0 ? (int)(ceil((ptr_prop[i][2][0]-(8U-bytepush))/8U)-1): 0);
		for (y = 0; y < max; ++y){
			if( (((ptr_prop[i][2][0] - last) % 8U != 0U) && (y == max-1)) || (mask ^ 0x0) ){
				if (mask ^ 0x0){
					if (y != 0 && ((((8U-bytepush)+((ptr_prop[i][2][0] - last) % 8U)) % 8U) ^ 0x0)){
						bytepush -= ptr_prop[i][2][0] % 8U;
						ptr_fill[i][y] = pkt[octet] & mask >> bytepush;
						mask -= (ptr_fill[i][y] << bytepush);
					}else{
						ptr_fill[i][y] = pkt[octet] & mask;
						if(y==0)
							last += 8U-bytepush;
						else
							last += ptr_prop[i][2][0] % 8;
						mask = 0U;
					}
				}else{
					bytepush = 8U - (ptr_prop[i][2][0] % 8U);
					ptr_fill[i][y] = pkt[octet] >> bytepush;
					mask = 0xff - (ptr_fill[i][y] << bytepush);
				}
			} else {
				ptr_fill[i][y] = pkt[octet];	
				last += 0x08;
			}
			//printf("%s, %02x | ", ptr_prop[i][0], ptr_fill[i][y]);
			if ( !(mask ^ 0x00) ){
				++octet;
				bytepush = 0x00;			
			}
		}
		ptr_fill[i][y+1] = ';'; 
	}
//04 - 0c
}

/* ************************************************[ Ether ]************************************************************* */

const unsigned char Ether::prop[][5][10]={{"dst",   "mac",  0x30},
										  {"src",   "mac",  0x30},
										  {"type", "long", 0x10}};

unsigned char* Ether::get(const char* p){
	register unsigned char* returned = (unsigned char*)this->get_prop(p, 3, fill, prop);
	return returned;
}

int Ether::get_prot_len(){
	register int returned = get_proto_len(3, prop);
	return returned;
}

Ether::Ether(unsigned char* eth){ 
	strcpy(layer_name, "Ether");
	this->process(eth, 3, fill, prop); 
}

int Ether::get_layer(){ return 0; }


/* ************************************************[ IP ]************************************************************* */

const unsigned char IP::prop[][5][10]=  {{"ver","long",  0x04},
										    {"ihl",	"long",  0x04},
										    {"tos",	"long",  0x08},
											{"len",	"long",  0x10},
											{"id",	"long",  0x10},
											{"flags","long", 0x04},
											{"frag", "long", 0x0c},
											{"ttl",	 "long", 0x08},
											{"proto","long", 0x08},
											{"chksum","long",0x10},
											{"src",	 "ipv4", 0x20},
											{"dst",	 "ipv4", 0x20}};
											/*{"opt","long", 0x1c}
											{"pad","long", 0x10}};*/

IP::IP(unsigned char* ip){ 
	strcpy(layer_name, "IP");
	this->process(ip, 12, fill, prop); 
}

int IP::get_prot_len(){
	register int returned = get_proto_len(12, prop);
	return returned;
}

unsigned char* IP::get(const char* p){ 
	unsigned char* returned = (unsigned char*)this->get_prop(p, 12, fill, prop); 
	return returned;
}

int IP::get_layer(){ return 1; }
/* ************************************************[ IPv6 ]************************************************************* */

const unsigned char IPv6::prop[][5][10]=  {{"ver","long",  0x04},
										    {"tc",	"long", 0x08},
										    {"fl",	"long", 0x14},
											{"plen","long", 0x10},
											{"nh",	"long", 0x08},
											{"hlim","long", 0x08},
											{"src", "ipv6", 0x80},
											{"dst",	 "ipv6", 0x80}};
											/*{"opt","long", 0x1c}
											{"pad","long", 0x10}};*/

IPv6::IPv6(unsigned char* ip){ 
	strcpy(layer_name, "IPv6");
	this->process(ip, 8, fill, prop); 
}

int IPv6::get_prot_len(){
	register int returned = get_proto_len(8, prop);
	return returned;
}

unsigned char* IPv6::get(const char* p){ 
	register unsigned char* returned = (unsigned char*)this->get_prop(p, 8, fill, prop); 
	return returned;
}

int IPv6::get_layer() { return 1; }


/* ************************************************[ TCP ]************************************************************* */

const unsigned char TCP::prop[][5][10]=  {{"sport","long",  0x10},
										    {"dport","long", 0x10},
										    {"seq",	"long", 0x20},
											{"ack","long", 0x20},
											{"dataofs",	"long", 0x04},
											{"reserved", "long", 0x03},
											{"flags", "long", 0x09},
											{"window", "long", 0x10},
											{"chksum", "long", 0x10},
											{"urgptr", "long", 0x10}};
											/*{"opt","long", 0x1c}
											{"pad","long", 0x10}};*/

TCP::TCP(unsigned char* ip){
	strcpy(layer_name, "TCP");
	this->process(ip, 10, fill, prop);
}

int TCP::get_prot_len(){
	register int returned = get_proto_len(10, prop);
	return returned;
}

unsigned char* TCP::get(const char* p){ 
	register unsigned char* returned = (unsigned char*)this->get_prop(p, 10, fill, prop); 
	return returned;
}

int TCP::get_layer() { return 2; }
/* ************************************************[ UDP ]************************************************************* */

const unsigned char UDP::prop[][5][10]=  {{"sport","long",  0x10},
										    {"dport", "long", 0x10},
										    {"len",	"long", 0x10},
											{"chksum","long", 0x10}};
											/*{"opt","long", 0x1c}
											{"pad","long", 0x10}};*/

UDP::UDP(unsigned char* ip){ 
	strcpy(layer_name, "UDP");
	this->process(ip, 4, fill, prop); 
}

int UDP::get_prot_len(){
	register int returned = get_proto_len(4, prop);
	return returned;
}

unsigned char* UDP::get(const char* p){ 
	register unsigned char* returned = (unsigned char*)this->get_prop(p, 4, fill, prop); 
	return returned;
}

int UDP::get_layer(){ return 2; }

/* ************************************************[ ICMP ]************************************************************* */

const unsigned char ICMP::prop[][5][10]=  {{"type","long",  0x08},
										    {"code", "long", 0x08},
										    {"chksum",	"long", 0x10},
											{"id","long", 0x10},
											{"seq",	"long", 0x10}};
											/*{"opt","long", 0x1c}
											{"pad","long", 0x10}};*/

ICMP::ICMP(unsigned char* ip){
	strcpy(layer_name, "ICMP"); 
	this->process(ip,5, fill, prop); 
}

int ICMP::get_prot_len(){
	int returned = get_proto_len(5, prop);
	return returned;
}

unsigned char* ICMP::get(const char* p){ 
	unsigned char* returned = (unsigned char*)this->get_prop(p, 5, fill, prop); 
	return returned;
}

int ICMP::get_layer(){ return 2; }

/* ************************************************[ ARP ]************************************************************* */

const unsigned char ARP::prop[][5][10]=  {{"hwtype","long",  0x10},
										    {"ptype","long", 0x10},
										    {"hwlen", "long", 0x08},
											{"plen","long", 0x08},
											{"op",	"long", 0x10},
											{"hwsrc","mac", 0x30},
											{"psrc", "ipv4", 0x20},
											{"hwdst","mac", 0x30},
											{"pdst","ipv4", 0x20}};

ARP::ARP(unsigned char* ip){ 
	strcpy(layer_name, "ARP");
	this->process(ip, 9, fill, prop); 
}

int ARP::get_prot_len(){
	int returned = get_proto_len(9, prop);
	return returned;
}

unsigned char* ARP::get(const char* p){ 
	unsigned char* returned = (unsigned char*)this->get_prop(p, 9, fill, prop); 
	return returned;
}

int ARP::get_layer(){ return 1; }
/* ************************************************[ DHCP ]************************************************************* */

const unsigned char DHCP::prop[][5][10]=  {{"options","long",  0x20}};

DHCP::DHCP(unsigned char* ip){ 
	strcpy(layer_name, "DHCP");
	this->process(ip, 1, fill, prop); 
}

int DHCP::get_prot_len(){
	int returned = get_proto_len(1, prop);
	return returned;
}

unsigned char* DHCP::get(const char* p){ 
	unsigned char* returned = (unsigned char*)this->get_prop(p, 1, fill, prop); 
	return returned;
}

int DHCP::get_layer(){ return 4; }
/* ************************************************[ BOOTP ]************************************************************* */

const unsigned char BOOTP::prop[][5][10]=  {{"op","long",  0x08},
										    {"htype","long", 0x08},
										    {"hlen", "long", 0x08},
											{"hops","long", 0x08},
											{"xid",	"long", 0x20},
											{"secs","long", 0x10},
											{"flags", "long", 0x10},
											{"ciaddr","ipv4", 0x20},
											{"yiaddr","ipv4", 0x20},
											{"siaddr", "ipv4", 0x20},
											{"giaddr","ipv4", 0x20},
											{"chaddr","ipv4", 0x20},
											{"sname", "ipv4", 0x20},
											{"file","long", 0x20},
											{"options","long", 0x20}};

BOOTP::BOOTP(unsigned char* ip){ 
	strcpy(layer_name, "BOOTP");
	this->process(ip, 15, fill, prop); 
}

int BOOTP::get_prot_len(){
	int returned = get_proto_len(15, prop);
	return returned;
}

unsigned char* BOOTP::get(const char* p){ 
	unsigned char* returned = (unsigned char*)this->get_prop(p, 15, fill, prop); 
	return returned;
}

int BOOTP::get_layer(){ return 3; }

/* ************************************************[ DNS ]************************************************************* */

const unsigned char DNS::prop[][5][10]=  {{"id","long",  0x10},
										    {"qr","long", 0x01},
										    {"opcode", "long", 0x04},
											{"aa","long", 0x01},
											{"tc",	"long", 0x01},
											{"rd","long", 0x01},
											{"ra", "long", 0x01},
											{"z","long", 0x01},
											{"ad","long", 0x01},
											{"cd", "long", 0x01},
											{"rcode","long", 0x04},
											{"qdcount","long", 0x10},
											{"ancount", "long", 0x10},
											{"nscount","long", 0x10},
											{"arcount","long", 0x10},
											{"qd","long", 0x20},
											{"an", "long", 0x20},
											{"ns","long", 0x20},
											{"ar","long", 0x20}};

DNS::DNS(unsigned char* ip){ 
	strcpy(layer_name, "DNS");
	this->process(ip, 19, fill, prop); 
}

int DNS::get_prot_len(){
	int returned = get_proto_len(19, prop);
	return returned;
}

unsigned char* DNS::get(const char* p){ 
	unsigned char* returned = (unsigned char*)this->get_prop(p, 19, fill, prop); 
	return returned;
}

int DNS::get_layer(){ return 3; }

/* ************************************************[ PACKET ]************************************************************* */

Packet::~Packet(){
	int i;
	for(i = 0; i < this->parts.size(); i++){
		this->parts.pop_back();	
	}
}

int Packet::get_nb_layer(){ return parts.size(); }

Part* Packet::get_layer(int name){
	register Part* part = NULL;
	if(name <= this->get_nb_layer()){
		part = this->parts[name];
	}
	return part;
}

Packet::Packet(unsigned char* pkt, int size){
	register int len = 0;
	this->payload = NULL;
	this->pkt = pkt;
	this->sport = 0;
	this->packet_size = 0;
	this->payload_size = 0;
	this->size = size;
	//layer ether
	if(size >= Ether::get_prot_len()){
		Ether* ether = new Ether(pkt);
		this->parts.push_back(ether);
		this->type = pack_uint(((Ether*)this->parts[Ether::get_layer()])->get("type"), 2);
		len+=Ether::get_prot_len();
		Part* part2;
		Part* part3;
		Part* part4;
		//layer 2
		switch(this->type){
			case ETH_IPv4:
				part2 = new IP(&pkt[len]);
				this->parts.push_back(part2);
				len+=IP::get_prot_len();
				this->subtype = pack_uint(((IP*)this->parts[IP::get_layer()])->get("proto"), 1);
				//layer 3
				switch(this->subtype){
					case IP_TCP:
						part3 = new TCP(&pkt[len]);
						this->parts.push_back(part3);
						this->sport = pack_uint(((TCP*)this->parts[IP::get_layer()])->get("sport"), 2);
						len+=TCP::get_prot_len();
						break;
					case IP_UDP:
						part3 = new UDP(&pkt[len]);
						this->parts.push_back(part3);
						len+=UDP::get_prot_len();
						this->sport = pack_uint(((UDP*)this->parts[UDP::get_layer()])->get("sport"), 2);
						switch(this->sport){
							case UDP_DNS:
								part4 = new DNS(&pkt[len]);
								this->parts.push_back(part4);
								len+=DNS::get_prot_len();
								break;
							case UDP_BOOTP_SEND:
							case UDP_BOOTP_RECV:
								part4 = new BOOTP(&pkt[len]);
								this->parts.push_back(part4);
								len+=BOOTP::get_prot_len();
								break;
						}
						break;
					case IP_ICMP:
						part3 = new ICMP(&pkt[len]);
						this->parts.push_back(part3);
						len+=ICMP::get_prot_len();
						break;
					default:
						break;
				}
				break;
			case ETH_IPv6:
				part2 = new IPv6(&pkt[Ether::get_prot_len()]);
				this->parts.push_back(part2);
				len+=IPv6::get_prot_len();
				break;
			case ETH_ARP:
				part2 = new ARP(&pkt[Ether::get_prot_len()]);
				this->parts.push_back(part2);
				len+=ARP::get_prot_len();
				break;	
			default:
				break;
		}
	}else{
		len=0;
	}
	//take the payload
	this->packet_size = len;
	this->payload_size = size - len;
	if(this->payload_size > 0){
		this->payload = &pkt[len];
	}
}

void Packet::tostr(){
	register char subtype[20];
	if(this->packet_size > 0){
		switch(type)
		{
			case ETH_IPv4:
				printf("%s > ", ((IP*)this->parts[IP::get_layer()])->get("src"));
				printf("%s ", ((IP*)this->parts[IP::get_layer()])->get("dst"));
				if(this->get_nb_layer() > 2){
					strcpy(subtype, this->get_layer(this->get_nb_layer()-1)->get_layer_name());
					printf("type: %s", subtype);
				}
				break;
			case ETH_ARP:
				printf("%s > ", ((ARP*)this->parts[ARP::get_layer()])->get("psrc"));
				printf("%s ", ((ARP*)this->parts[ARP::get_layer()])->get("pdst"));
				printf("Arp request");
				break;
			case ETH_IPv6:
				printf("IPv6");
				break;
		}
		if(this->payload != NULL){
				printf(" & loads");
		}
	}else{
		printf("raw");
	}
	printf("\n");
}

