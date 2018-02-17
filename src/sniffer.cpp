#include <netinet/in.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h> 
#include <string.h> 
#include <time.h>


#include <iostream>
#include <vector>

using namespace std;
using std::vector;

#include "sniffer.h"
#include "packet.h"
#include "utils.h"

#define PKTSIZE 65536

Sniffer::Sniffer(){
	nbpks = 0;
	view_s = false;
	view_x = false;
	sock_raw = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL));
	if(sock_raw < 0) {
        perror("Socket error\n");
       	exit(1);
    }
}

void Sniffer::close_raw(){
	int i;
	for(i = pks.size(); i>0; i--){
		free(pks[i]);
		pks.pop_back();
	}
	free(buffer);
	close(sock_raw);
}

Sniffer::~Sniffer(){ close_raw(); }

void Sniffer::view(bool activate){ this->view_s = activate; }
void Sniffer::view_hex(bool activate){ this->view_x = activate; }

void Sniffer::execute(float ms_time = 0, int count = 1){
	double t1 = 0;
	int cpks = 0;
	int data_size = 0;
	unsigned char* ptr;
	char _2str[PKTSIZE*2];

	if(ms_time > 0)
		t1 = timer();

	while(1){
		buffer = (unsigned char *) malloc(PKTSIZE);
		saddr_size = sizeof saddr;
		data_size = recvfrom(sock_raw , buffer , PKTSIZE , 0 , &saddr , (socklen_t*)&saddr_size);
		nbpks++; cpks++;
		ptr = buffer;
		ptr = (unsigned char*) realloc(ptr, data_size);
		
		Packet* pkt = new Packet(ptr, data_size);
		pks.push_back(pkt);
		
		if(view_s == true){
			pkt->tostr();
		}
		
		if(view_x == true){
			pkt_x2s(ptr, data_size, _2str);
			printf("%d)%s\n", nbpks, _2str);
		}
		//end sniff
		if(count > 0 && cpks >= count){
			break;
		}

		if(ms_time > 0 && timer()-t1 >= ms_time){
			break;
		}
	}
}

