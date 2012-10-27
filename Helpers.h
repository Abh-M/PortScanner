//
//  Helpers.h
//  demo
//
//  Created by Abhineet on 19/10/12.
//  Copyright (c) 2012 Abhineet. All rights reserved.
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

srcDesIpv4 getIpPairForIpHeader(struct ip *kIpHdr);


#endif
