#include <iostream>
#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/time.h>
#include "utils.h"
namespace xld{
	struct pcontain
	{
		struct _private
		{
			void** ptr;
			long unsigned int size;
			bool buffing;
			unsigned int buff_size;
		} priv;

		bool initialise(){
			if(!priv.ptr){
				priv.ptr = (void**)malloc(1 * sizeof(void*));
				priv.size = 1;
				priv.buffing = false;
				priv.buff_size = 0;
				return true;
			}else{
				return false;
			}
		}

		void add(void* obj){
			++priv.size;
			priv.ptr = (void**)realloc(priv.ptr, priv.size * sizeof(void*));
			priv.ptr[priv.size - 1] = obj;
			if(priv.buffing){
				++priv.buff_size;
			}
		}
		
		void release(){
			int i;
			for(i = 0; i < priv.size; ++i){
				free(priv.ptr[i]);
			}
			free(priv.ptr);
			priv.size = 0;
		}

		void free_buff(){
			register int i;
			priv.buffing = false;
			for(i=priv.size-1; i>=(priv.size-priv.buff_size); i--){
				free(priv.ptr[i]);
				priv.size--;
				priv.buff_size--;
			}
			priv.ptr = (void**)realloc(priv.ptr, priv.size * sizeof(void*));
		}

		void start_buff(){ priv.buffing = true; }
		long unsigned int size(){ return priv.size; }

	} pcont;

	template<typename T>
	T xalloc(int size){
		pcont.initialise();
		long int len = sizeof(T);
		T obj = NULL;
		obj = (T)malloc(size);
		if(obj == NULL){
			perror("bad malloc");
			exit(1);	
		}
		pcont.add(obj);
		return obj;
	}

	void lock_xbuff(){ pcont.start_buff(); }
	void free_xbuff(){ pcont.free_buff(); }
	void free_xalloc(){ pcont.release(); }
}

void ip_s2h(const char* str, unsigned char* hex){
	register int i;
	for(i=0; i<4; i++){
		hex[i] = ( inet_addr(str) >> (8U * (i)) ) & 0xff;
	}
}

const char* ip_h2s(const unsigned char* hex){
	register char* ip = xld::xalloc<char*>(20);
	sprintf(ip, "%d.%d.%d.%d", hex[0], hex[1], hex[2], hex[3]);
	return(ip);
}

const char* ipv6_h2s(const unsigned char* hex){
	register char* ipv6 = xld::xalloc<char*>(20);
	sprintf(ipv6, "%02x%02x::%02x%02x", hex[0], hex[1], hex[14], hex[15]);
	return ipv6;
}

const char* mac_h2s(const unsigned char* hex){
	register char* mac = xld::xalloc<char*>(20);
	sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x", hex[0], hex[1], hex[2], hex[3], hex[4], hex[5]);
	return mac;
}

void load_2s(const unsigned char* load, int len){
	register int i;	
	for(i=0; i<len; i++){
		if(load[i] > CHAR_START && load[i] < CHAR_END)
			printf("%c", load[i]);	
		else
			printf("\\x%02x", load[i]);
	}
}

void pkt_x2s(const unsigned char* pkt, int len, char* str){
	register int i;
	for(i=0; i<len; i++){
		sprintf(str+i, "%02x", pkt[i]);
	}
}

void rand_mac(unsigned char* hex){
	int i;
	unsigned char rnd;
	for(i=0; i<6; i++)
	{
		rnd = rand() % 256;
		sprintf((char*)hex+i, "%c", rnd);
		hex[i] &= 0xff;
	}
}

void rand_ip(unsigned char* hex){
	int i;
	unsigned char rnd;
	for(i=0; i<4; i++)
	{
		rnd = rand() % 256;
		sprintf((char*)hex+i, "%c", rnd);
		hex[i] &= 0xff;
	}
}

void rand_ipv6(char* hex, const char* mask = "*::*"){;}

double timer() {
	register double time_in_mill;
	register struct timeval  tv;
	gettimeofday(&tv, NULL);
	time_in_mill = (tv.tv_sec) * 1000 + (tv.tv_usec) / 1000;
	return time_in_mill;
}

