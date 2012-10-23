//
//  Helpers.c
//  demo
//
//  Created by Abhineet on 19/10/12.
//  Copyright (c) 2012 Abhineet. All rights reserved.
//

#include <stdio.h>
#include "Helpers.h"
#include "Globals.h"

using namespace std;

struct psd_udp {
	struct in_addr src;
	struct in_addr dst;
	unsigned char pad;
	unsigned char proto;
	unsigned short udp_len;
	struct udphdr udp;
};
unsigned short in_cksum(unsigned short *addr, int len)

{
	int nleft = len;
	int sum = 0;
	unsigned short *w = addr;
	unsigned short answer = 0;
    
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}
    
	if (nleft == 1) {
		*(unsigned char *) (&answer) = *(unsigned char *) w;
		sum += answer;
	}
	
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	answer = ~sum;
	return (answer);
}

unsigned short in_cksum_tcp(int src, int dst, unsigned short *addr, int len)
{
	struct psd_tcp buf;
	u_short ans;
    
	memset(&buf, 0, sizeof(buf));
	buf.src.s_addr = src;
	buf.dst.s_addr = dst;
	buf.pad = 0;
	buf.proto = IPPROTO_TCP;
	buf.tcp_len = htons(len);
	memcpy(&(buf.tcp), addr, len);
	ans = in_cksum((unsigned short *)&buf, 12 + len);
	return (ans);
}

unsigned short in_cksum_udp(int src, int dst, unsigned short *addr, int len)
{
	struct psd_udp buf;
    
	memset(&buf, 0, sizeof(buf));
	buf.src.s_addr = src;
	buf.dst.s_addr = dst;
	buf.pad = 0;
	buf.proto = IPPROTO_UDP;
	buf.udp_len = htons(len);
	memcpy(&(buf.udp), addr, len);
	return in_cksum((unsigned short *)&buf, 12 + len);
}

void logIpHeader(struct ip *kIpHdr)
{
    cout<<"---------IP HEADER-----------"<<endl;
    cout<<"SRC  IP          : "<<inet_ntoa(kIpHdr->ip_src)<<endl;
    cout<<"DEST IP          : "<<inet_ntoa(kIpHdr->ip_dst)<<endl;
    cout<<"HEADER LENGTH    : "<<(kIpHdr->ip_hl)<<endl;
    cout<<"TOTAL LENGTH     : "<<ntohs(kIpHdr->ip_len)<<endl;
    cout<<"PROTOCOL         : "<<(unsigned int)kIpHdr->ip_p<<endl;
    cout<<"---------IP HEADER-----------"<<endl;
    
}

void logTCPHeader(struct tcphdr *kHeader){
    cout<<"---------TCP HEADER-----------"<<endl;
    cout<<"SOURCE PORT      : "<<ntohs(kHeader->th_sport)<<endl;
    cout<<"DESTINATION PORT : "<<ntohs(kHeader->th_dport)<<endl;
    cout<<"FLAGS            : ";
    if (kHeader->th_flags & TH_SYN)
        putchar('S');
    if(kHeader->th_flags & TH_ACK)
        putchar('.');
    if(kHeader->th_flags & TH_FIN)
        putchar('F');
    if (kHeader->th_flags & TH_RST)
        putchar('R');
    
    cout<<endl;
    cout<<"ACK              : "<<(unsigned int)ntohl(kHeader->th_ack)<<endl;
    cout<<"SEQ              : "<<ntohl(kHeader->th_seq)<<endl;
    
    cout<<"---------TCP HEADER-----------"<<endl;
}


void logICMPHeader(struct icmp *header)
{
    cout<<"---------ICMP HEADER-----------"<<endl;
    cout<<"CODE :"<<(unsigned int)(header->icmp_code)<<endl;
    cout<<"TYPE :"<<(unsigned int)(header->icmp_type)<<endl;
    cout<<"---------ICMP HEADER-----------"<<endl;
    
    
}



void getMyIpAddress()
{
    char errBuff[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    int result = pcap_findalldevs(&alldevs, errBuff);
    if(result==0)
    {
        //success
        while(alldevs!=NULL)
        {
            cout<<"DEV : "<<alldevs->name<<endl;
            //print all addresses
            pcap_addr_t *addrr = alldevs->addresses;
            while (addrr!=NULL) {
                
                struct sockaddr *adr = addrr->addr;
                
                cout<<inet_ntoa(*(struct in_addr*)adr)<<endl;
                addrr=addrr->next;
            }
            alldevs=alldevs->next;
        }
    }
    else{
        //failure
    }
}



