#ifndef __PACKET_H_INCLUDED__
#define __PACKET_H_INCLUDED__

#include <iostream>
#include <vector>

using std::vector;

#define ETH_NO_IP 0x9000
#define ETH_IPv4 0x0800
#define ETH_ARP 0x0806
#define ETH_IPv6 0x86dd
#define ETH_UNDEFINED 0x0040

#define IP_TCP 0x06
#define IP_UDP 0x11
#define IP_ICMP 0x01

#define UDP_DNS 0x0035
#define UDP_BOOTP_SEND 0x0043
#define UDP_BOOTP_RECV 0x0044

#define BOOTP_MAGIC 0x63825363

#define TCP_HTTPS 0x01bb
#define TCP_HTTP 0x0050

unsigned int pack_uint(unsigned char*, int);

class Part{
protected:
	void process(unsigned char*, const unsigned int, unsigned char (*)[13], const unsigned char (*)[5][10]);
	char layer_name[20];
	char* get_prop(const char*, const unsigned int, unsigned char (*)[13], const unsigned char (*)[5][10]);
	static int get_proto_len(const unsigned int, const unsigned char (*)[5][10]);
private:
	char octet;
	char mask;
	char last;
	int bytepush;
	int size;
	int realmax;
	int max;
public:
	char* get_layer_name();
};

class Ether: public Part{
private:
	unsigned char fill[3][13];
	static const unsigned char prop[][5][10];
public:
	Ether(unsigned char*);
	unsigned char* get(const char*);
	static int get_prot_len();
	static int get_layer();
};

class IP: public Part{
private:
	unsigned char fill[12][13];
	static const unsigned char prop[][5][10];
public:
	IP(unsigned char*);
	unsigned char* get(const char*);
	static int get_prot_len();
	static int get_layer();
};

class IPv6: public Part{
private:
	unsigned char fill[8][13];
	static const unsigned char prop[][5][10];
public:
	IPv6(unsigned char*);
	unsigned char* get(const char*);
	static int get_prot_len();
	static int get_layer();
};

class TCP: public Part{
private:
	unsigned char fill[10][13];
	static const unsigned char prop[][5][10];
public:
	TCP(unsigned char*);
	unsigned char* get(const char*);
	static int get_prot_len();
	static int get_layer();
};

class UDP: public Part{
private:
	unsigned char fill[4][13];
	static const unsigned char prop[][5][10];
public:
	UDP(unsigned char*);
	unsigned char* get(const char*);
	static int get_prot_len();
	static int get_layer();
};

class ICMP: public Part{
private:
	unsigned char fill[5][13];
	static const unsigned char prop[][5][10];
public:
	ICMP(unsigned char*);
	unsigned char* get(const char*);
	static int get_prot_len();
	static int get_layer();
};

class ARP: public Part{
private:
	unsigned char fill[9][13];
	static const unsigned char prop[][5][10];
public:
	ARP(unsigned char*);
	unsigned char* get(const char*);
	static int get_prot_len();
	static int get_layer();
};

class DHCP: public Part{
private:
	unsigned char fill[1][13];
	static const unsigned char prop[][5][10];
public:
	DHCP(unsigned char*);
	unsigned char* get(const char*);
	static int get_prot_len();
	static int get_layer();
};

class BOOTP: public Part{
private:
	unsigned char fill[15][13];
	static const unsigned char prop[][5][10];
public:
	BOOTP(unsigned char*);
	unsigned char* get(const char*);
	static int get_prot_len();
	static int get_layer();
};

class DNS: public Part{
private:
	unsigned char fill[19][13];
	static const unsigned char prop[][5][10];
public:
	DNS(unsigned char*);
	unsigned char* get(const char*);
	static int get_prot_len();
	static int get_layer();
};

class Packet{
private:
	unsigned char* pkt;
	unsigned char* payload;
	int size;
	int packet_size;
	int payload_size;
	unsigned int type;
	unsigned int subtype;
	unsigned int sport;
	vector<Part*> parts;
public:
	Packet(unsigned char*,int);
	~Packet();
	void tostr();
	int get_nb_layer();
	Part* get_layer(int);
};

#endif 
