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
void logIpHeader(struct ip *kIpHdr);
void logTCPHeader(struct tcphdr *kHeader);
void logICMPHeader(struct icmp *header);
unsigned short in_cksum_udp(int src, int dst, unsigned short *addr, int len);
devAndIp getMyIpAddress();
void scanHTTP(char *ipAddress);


#endif
