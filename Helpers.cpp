//
//  Helpers.c
//  demo
//
//  Created by Abhineet on 19/10/12.
//  Copyright (c) 2012 Abhineet. All rights reserved.
//

#include <stdio.h>
#include "Helpers.h"

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
    
    cout<<"\nIP  "<<" | src: "<<inet_ntoa(kIpHdr->ip_src)
    <<" | des: "<<inet_ntoa(kIpHdr->ip_dst)
    <<" | total length: "<<ntohs(kIpHdr->ip_len)
    <<" | protocol: "<<(unsigned int)kIpHdr->ip_p
    <<" | header length : "<<(kIpHdr->ip_hl);
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
    cout<<"CSUM :"<<(unsigned int)(header->icmp_cksum)<<endl;
    cout<<"---------ICMP HEADER-----------"<<endl;
}

void print_byte(uint8_t byte)
{
    uint8_t         i;
    for (i = 0; i < 8; i++)
        if (byte & (1 << i))
            printf("1");
        else
            printf("0");
}


void logIP6Header(struct ip6_hdr *hdr)
{
    char src[INET6_ADDRSTRLEN];
    char des[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(hdr->ip6_src), src, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(hdr->ip6_dst), des, INET6_ADDRSTRLEN);
    cout<<"\nIPV6 "<<" | src = "<<src<<" | des = "<<des<<" | nxt = "<<(unsigned short)(hdr->ip6_ctlun.ip6_un1.ip6_un1_plen);
//    print_byte((uint8_t)ntohs((hdr->ip6_vfc)));    //unsigned int x : 2;
    

}


devAndIp getMyIpAddress()
{
    devAndIp result;
    
    char ipaddr[15];
    
    const char *dummyDest = "74.125.225.209";
    const char *localHostIp = "127.0.0.1";
    int dummySocket;
    struct  sockaddr_in desAdd;
    struct sockaddr_in srcAdd;
    desAdd.sin_family = AF_INET;
    desAdd.sin_port = htons(80);
    inet_aton(dummyDest, &desAdd.sin_addr);
    
    dummySocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    
    if(dummySocket>-1)
    {
        //socket created
        socklen_t socklen = sizeof(desAdd);
        int res = connect(dummySocket, (struct sockaddr*)&desAdd, socklen);
        if(res==0)
        {
            //connected
            socklen_t srcLen = sizeof(srcAdd);
            int result = getsockname(dummySocket, (struct sockaddr*)&srcAdd, &srcLen);
            if(result==0)
                strcpy(ipaddr, inet_ntoa(srcAdd.sin_addr));
            
        }
        close(dummySocket);
        
    }
    
    
    struct ifaddrs *adrs;
    int res =getifaddrs(&adrs);
    if(res==0)
    {
        while (1) {
            adrs=adrs->ifa_next;
            
            if(adrs==NULL)
                break;
            else
            {
                struct sockaddr_in *so = (struct sockaddr_in*)adrs->ifa_addr;
                const char* ipp = inet_ntoa(so->sin_addr);
                int cmpres =strcmp(ipaddr,ipp);
                if(cmpres==0)
                {
                    strcpy(result.dev, adrs->ifa_name);
                    strcpy(result.ip, ipaddr);
                    //cout<<"\n--"<<adrs->ifa_name<<"--"<<inet_ntoa(so->sin_addr);
                }
                cmpres = strcmp(localHostIp, ipp);
                if(cmpres==0)
                {
                    strcpy(result.localhost_dev, adrs->ifa_name);
                    strcpy(result.localHost_ip, localHostIp);
                }
            }
        }
    }
    else
    {
        //failure
    }
    
    
    
    return result;
}



bool isIpV6(const char *add)
{
    bool isIpv6;
    struct sockaddr_in ipv4;
    struct sockaddr_in6 ipv6;
    
    //check if ipv4
    int ipv4res = inet_pton(AF_INET, add, &ipv4);
    int ipv6res = inet_pton(AF_INET6, add, &ipv6);
    
    
    isIpv6 = (ipv6res==1 && ipv4res == 0)?true:false;
    
    return isIpv6;


}


