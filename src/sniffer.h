#ifndef __SNIFFER_H_INCLUDED__
#define __SNIFFER_H_INCLUDED__

#include <iostream>
#include<netinet/in.h>
#include<net/ethernet.h>
#include<net/if.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<stdio.h>
#include<stdlib.h> 
#include "packet.h"

class Sniffer{
private:
	struct ifreq ifr;
	struct sockaddr saddr;
	bool view_s, view_x;
	unsigned char *buffer;
	int sock_raw;
	int saddr_size, ret, nbpks;	
	vector<Packet*> pks;
public:
	Sniffer();
	~Sniffer();
	void execute(float, int);
	void view(bool);
	void view_hex(bool);
	void close_raw();
};

#endif
