#ifndef __UTILS_H_INCLUDED__
#define __UTILS_H_INCLUDED__

#define CHAR_START 0xb0
#define CHAR_END 0xff

#include <iostream>
#include <stdlib.h>
#include <stdio.h>

extern double timer();
extern void ip_s2h(const char*, unsigned char*);
extern const char* ip_h2s(const unsigned char*);
extern const char* ipv6_h2s(const unsigned char*);
extern const char* mac_h2s(const unsigned char*);
extern void load_2s(const unsigned char*, int);
extern void pkt_x2s(const unsigned char*, int, char*);
extern void rand_mac(unsigned char*);
extern void rand_ip(unsigned char*);
extern void rand_ipv6(char*, const char*);

namespace xld 
{
	template<typename T>
	extern T xalloc(int size);
	void lock_xbuff();
	void free_xbuff();
	extern void free_xalloc();
}
#endif 

