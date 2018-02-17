#ifndef __NETWORK_H_INCLUDED__
#define __NETWORK_H_INCLUDED__

#define CHAR_START 0xb0
#define CHAR_END 0xff

#define IPV6_ADDR_GLOBAL        0x0000U
#define IPV6_ADDR_LOOPBACK      0x0010U
#define IPV6_ADDR_LINKLOCAL     0x0020U
#define IPV6_ADDR_SITELOCAL     0x0040U
#define IPV6_ADDR_COMPATv4      0x0080U

int fill_network();
void str_network();

#endif 

