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


void logIpHeader2(struct ip kIpHdr)
{
    
    char des[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(kIpHdr.ip_dst), des, INET_ADDRSTRLEN);

    cout<<".............."<<des;
    cout<<"\nIP  "<<" | src: "<<inet_ntoa(kIpHdr.ip_src)
    <<" | des: "<<inet_ntoa(kIpHdr.ip_dst);
    //    <<" | total length: "<<ntohs(kIpHdr->ip_len)
    //    <<" | protocol: "<<(unsigned int)kIpHdr->ip_p
    //    <<" | header length : "<<(kIpHdr->ip_hl);
}
void logIpHeader(struct ip *kIpHdr)
{
    
    srcDesIpv4 ipPair;
    char src[INET_ADDRSTRLEN];
    char des[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &kIpHdr->ip_src, src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &kIpHdr->ip_dst, des, INET_ADDRSTRLEN);
    strcpy(ipPair.src, src);
    strcpy(ipPair.des, des);
    cout<<"\nIP  "<<" | src: "<<src
    <<" | des: "<<des
    <<" | total length: "<<ntohs(kIpHdr->ip_len)
    <<" | protocol: "<<(unsigned int)kIpHdr->ip_p
    <<" | header length : "<<(kIpHdr->ip_hl);
}

srcDesIpv4 getIpPairForIpHeader(struct ip *kIpHdr)
{
    
    srcDesIpv4 ipPair;
    char src[INET_ADDRSTRLEN];
    char des[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &kIpHdr->ip_src, src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &kIpHdr->ip_dst, des, INET_ADDRSTRLEN);
    strcpy(ipPair.src, src);
    strcpy(ipPair.des, des);

    return ipPair;
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

    cout<<"\nICMP |CODE: "<<(unsigned int)(header->icmp_code)
        <<" |TYPE: "<<(unsigned int)(header->icmp_type)
        <<" |CSUM:"<<(unsigned int)(header->icmp_cksum);

}

void logUDPHeader(struct udphdr *header)
{
    cout<<"\nUDP |src port: "<<ntohs(header->uh_sport)<<" |des port: "<<ntohs(header->uh_dport);
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
    cout<<"\nIPV6 "<<" | src = "<<src<<" | des = "<<des<<" | payload = "<<(unsigned short)htons(hdr->ip6_ctlun.ip6_un1.ip6_un1_plen);
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

void getAllIPV6AddressesInSubnet(char *address, char* maskv6)
{
    //truncateFile(SUBNET_IP_FILE);
    char addr [100];
    strcpy(addr,address);
    cout<<"IPV6 address-->"<<addr<<"Mask:"<<maskv6<<endl;
    
    char* word1 = strtok((char*)addr,":");
    char* word2 = strtok((char *)NULL, ":");
    char* word3 = strtok((char *)NULL, ":");
    char* word4 = strtok((char *)NULL, ":");
    char* word5 = strtok((char *)NULL, ":");
    char* word6 = strtok((char *)NULL, ":");
    char* word7 = strtok((char *)NULL, ":");
    char* word8 = strtok((char *)NULL, ":");
    
    int mask = atoi(maskv6);
    float totalBitsChangedFloat = 128 - mask;
    int totalBitsChanged = (int)totalBitsChangedFloat;
    
    cout<<"Total Bits changed: "<<totalBitsChanged<<endl;
    char *number;
    
    long int wrd1 = strtol(word1,&number,16);
    cout<<"===="<<wrd1;
    long int wrd2 = strtol(word2,&number,16);
    cout<<"====>"<<wrd2;
    long int wrd3 = strtol(word3,&number,16);
    long int wrd4 = strtol(word4,&number,16);
    cout<<"Word 4===>"<<wrd4;
    long int wrd5 = strtol(word5,&number,16);
    cout<<"Word 5====>"<<wrd5;
    long int wrd6 = strtol(word6,&number,16);
    long int wrd7 = strtol(word7,&number,16);
    long int wrd8 = strtol(word8,&number,16);
    
    int bitsChangedinWord1,bitsChangedinWord2,bitsChangedinWord3,bitsChangedinWord4,bitsChangedinWord5,bitsChangedinWord6,bitsChangedinWord7,bitsChangedinWord8;
    
    if((totalBitsChangedFloat/16)>7)
    {
        if(totalBitsChanged%16==0)
            bitsChangedinWord1 = 16;
        else bitsChangedinWord1 = totalBitsChanged%16;
        bitsChangedinWord2 = 16;
        bitsChangedinWord3 = 16;
        bitsChangedinWord4 = 16;
        bitsChangedinWord5 = 16;
        bitsChangedinWord6 = 16;
        bitsChangedinWord7 = 16;
        bitsChangedinWord8 = 16;
    }else if((totalBitsChangedFloat/16)>6 && (totalBitsChangedFloat/16)<=7)
    {
        bitsChangedinWord1 = 0;
        if(totalBitsChanged%16==0)
            bitsChangedinWord2 = 16;
        else bitsChangedinWord2 = totalBitsChanged%16;
        bitsChangedinWord2 = 16;
        bitsChangedinWord3 = 16;
        bitsChangedinWord4 = 16;
        bitsChangedinWord5 = 16;
        bitsChangedinWord6 = 16;
        bitsChangedinWord7 = 16;
        bitsChangedinWord8 = 16;
    }else if((totalBitsChangedFloat/16)>5 && (totalBitsChangedFloat/16)<=6)
    {
        bitsChangedinWord1 = 0;
        bitsChangedinWord2 = 0;
        if(totalBitsChanged%16==0)
            bitsChangedinWord3 = 16;
        else bitsChangedinWord3 = totalBitsChanged%16;
        bitsChangedinWord4 = 16;
        bitsChangedinWord5 = 16;
        bitsChangedinWord6 = 16;
        bitsChangedinWord7 = 16;
        bitsChangedinWord8 = 16;
    }else if((totalBitsChangedFloat/16)>4 && (totalBitsChangedFloat/16)<=5)
    {
        bitsChangedinWord1 = 0;
        bitsChangedinWord2 = 0;
        bitsChangedinWord3 = 0;
        if(totalBitsChanged%16==0)
            bitsChangedinWord4 = 16;
        else bitsChangedinWord4 = totalBitsChanged%16;
        bitsChangedinWord5 = 16;
        bitsChangedinWord6 = 16;
        bitsChangedinWord7 = 16;
        bitsChangedinWord8 = 16;
    }else if((totalBitsChangedFloat/16)>3 && (totalBitsChangedFloat/16)<=4)
    {
        bitsChangedinWord1 = 0;
        bitsChangedinWord2 = 0;
        bitsChangedinWord3 = 0;
        bitsChangedinWord4 = 0;
        if(totalBitsChanged%16==0)
            bitsChangedinWord5 = 16;
        else bitsChangedinWord5 = totalBitsChanged%16;
        bitsChangedinWord6 = 16;
        bitsChangedinWord7 = 16;
        bitsChangedinWord8 = 16;
    }else if((totalBitsChangedFloat/16)>2 && (totalBitsChangedFloat/16)<=3)
    {
        bitsChangedinWord1 = 0;
        bitsChangedinWord2 = 0;
        bitsChangedinWord3 = 0;
        bitsChangedinWord4 = 0;
        bitsChangedinWord5 = 0;
        if(totalBitsChanged%16==0)
            bitsChangedinWord6 = 16;
        else bitsChangedinWord6 = totalBitsChanged%16;
        bitsChangedinWord7 = 16;
        bitsChangedinWord8 = 16;
    }else if((totalBitsChangedFloat/16)>1 && (totalBitsChangedFloat/16)<=2)
    {
        bitsChangedinWord1 = 0;
        bitsChangedinWord2 = 0;
        bitsChangedinWord3 = 0;
        bitsChangedinWord4 = 0;
        bitsChangedinWord5 = 0;
        bitsChangedinWord6 = 0;
        if(totalBitsChanged%16==0)
            bitsChangedinWord7 = 16;
        else bitsChangedinWord7 = totalBitsChanged%16;
        bitsChangedinWord8 = 16;
    }else if((totalBitsChangedFloat/16)>0 && (totalBitsChangedFloat/16)<=1)
    {
        
        bitsChangedinWord1 = 0;
        bitsChangedinWord2 = 0;
        bitsChangedinWord3 = 0;
        bitsChangedinWord4 = 0;
        bitsChangedinWord5 = 0;
        bitsChangedinWord6 = 0;
        bitsChangedinWord7 = 0;
        if(totalBitsChanged%16==0)
            bitsChangedinWord8 = 16;
        else bitsChangedinWord8 = totalBitsChanged%16;
        cout<<"===bitsChangedinWord8 ="<<bitsChangedinWord8;
    }
    char addr6[100];
    for(int i=0;i<pow(2,bitsChangedinWord1);i++)
    {
        if(wrd1>65535)
        {
            break;
        }
        for(int j=0;j<pow(2,bitsChangedinWord2);j++)
        {
            if(wrd2>65535)
            {
                wrd2=0;
                wrd1 = wrd1+1; 
                break; 
            } 
            for(int k=0;k<pow(2,bitsChangedinWord3);k++)
            { 
                if(wrd3>65535) 
                { 
                    wrd3=0; 
                    wrd2 = wrd2+1; 
                    break; 
                } 
                for(int l=0;l<pow(2,bitsChangedinWord4);l++) 
                { 
                    if(wrd4>65535) 
                    { 
                        wrd4=0; 
                        wrd3 = wrd3+1; 
                        break; 
                    } 
                    for(int m=0;m<pow(2,bitsChangedinWord5);m++) 
                    { 
                        if(wrd5>65535) 
                        { 
                            wrd5=0; 
                            wrd4 = wrd4+1; 
                            break; 
                        } 
                        for(int n=0;n<pow(2,bitsChangedinWord6);n++) 
                        { 
                            if(wrd6>65535) 
                            { 
                                wrd6=0; 
                                wrd5 = wrd5+1; 
                                break; 
                            } 
                            for(int p=0;p<pow(2,bitsChangedinWord7);p++) 
                            { 
                                if(wrd7>65535) 
                                { 
                                    wrd7=0; 
                                    wrd6 = wrd6+1; 
                                    break; 
                                } 
                                for(int q=0;q<pow(2,bitsChangedinWord8);q++) 
                                { 
                                    //convert to hex and then append to create entire ip address. 
                                    sprintf(addr6,"%x:%x:%x:%x:%x:%x:%x:%x",(unsigned int)wrd1,(unsigned int)wrd2,(unsigned int)wrd3,(unsigned int)wrd4,(unsigned int)wrd5,(unsigned int)wrd6,(unsigned int)wrd7,(unsigned int)wrd8); 
                                    //writeToFile(SUBNET_IP_FILE,addr6); 
                                    wrd8 = wrd8+1; 
                                    if(wrd8>65535) 
                                    { 
                                        wrd8=0; 
                                        wrd7 = wrd7+1; 
                                        break; 
                                    } 
                                } 
                            } 
                        } 
                    } 
                } 
            } 
        } 
    } 
}
