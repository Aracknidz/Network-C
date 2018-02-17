//g++ sniffer.cpp packet.cpp network.cpp utils.cpp main.cpp -o sniffer

//#include<sys/ioctl.h>
//#include<sys/types.h>
//#include <errno.h> 
//#include <limits.h>
//#include <sys/types.h>
//#include<netdb.h>

#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include <iostream>

#include "network.h"
#include "utils.h"
#include "packet.h"
#include "sniffer.h"

int main( int argc, const char* argv[]) 
{
	srand(time(NULL));
	fill_network();
	str_network();
	Sniffer* sniff = new Sniffer();
	sniff->view(true);
	sniff->view_hex(true);
	sniff->execute(10000, 100);
	xld::free_xalloc();
	delete sniff;
    return 0;
}
