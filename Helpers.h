//
//  Helpers.h
//

#ifndef demo_Helpers_h
#define demo_Helpers_h

#include "PCH.h"
#include "Globals.h"


unsigned short in_cksum(unsigned short *addr, int len);
unsigned short in_cksum_tcp(int src, int dst, unsigned short *addr, int len);
unsigned short in_cksum_udp(int src, int dst, unsigned short *addr, int len);

devAndIp getMyIpAddress();
bool isIpV6(const char *add);


void logUDPHeader(struct udphdr *header);
void logIpHeader(struct ip *kIpHdr);
//void logIpHeader2(struct ip kIpHdr);
void logTCPHeader(struct tcphdr *kHeader);
void logICMPHeader(struct icmp *header);
void logIP6Header(struct ip6_hdr *hdr);
void logICMP6Header(struct icmp6_hdr *khdr);

bool islocalhost(char *kip);

srcDesIpv4 getIpPairForIpHeader(struct ip *kIpHdr);
srcDesIpv6 getIpPairForIp6Header(struct ip6_hdr *kIpHdr);
void scanWellKnownServices(char *ipAddress,int portNumber);
//void getV6Addr();

#endif
