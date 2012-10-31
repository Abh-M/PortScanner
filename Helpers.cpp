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



//move this int main
bool islocalhost(char *kip)
{
    bool result= false;
    if(strcmp(kip, "127.0.0.1")==0 || strcmp(kip, "0.0.0.0")==0 || strcmp("::1", kip)==0 )
        result = true;
    
    
    return result;
}

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

//comment
    
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

srcDesIpv6 getIpPairForIp6Header(struct ip6_hdr *kIpHdr)
{
    
    srcDesIpv6 ipPair;
    char src[INET6_ADDRSTRLEN];
    char des[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &kIpHdr->ip6_src, src, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &kIpHdr->ip6_dst, des, INET6_ADDRSTRLEN);
    strcpy(ipPair.src, src);
    strcpy(ipPair.des, des);
    
    return ipPair;
}



void logTCPHeader(struct tcphdr *kHeader){
        cout<<"\nTCP  |SOURCE PORT: "<<ntohs(kHeader->th_sport)
        <<" |DESTINATION PORT: "<<ntohs(kHeader->th_dport)
        <<" |FLAGS: ";
    if (kHeader->th_flags & TH_SYN)
        putchar('S');
    if(kHeader->th_flags & TH_ACK)
        putchar('.');
    if(kHeader->th_flags & TH_FIN)
        putchar('F');
    if (kHeader->th_flags & TH_RST)
        putchar('R');
    

    cout<<" |ACK :"<<(unsigned int)ntohl(kHeader->th_ack)
        <<" |SEQ :"<<ntohl(kHeader->th_seq)<<endl;
    
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


void logICMP6Header(struct icmp6_hdr *khdr)
{
    cout<<"\nICMP6 |code :"<<(unsigned short)(khdr->icmp6_code)<<" |type: "<<(unsigned short)(khdr->icmp6_type);
}

void logIP6Header(struct ip6_hdr *hdr)
{
    char src[INET6_ADDRSTRLEN];
    char des[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(hdr->ip6_src), src, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(hdr->ip6_dst), des, INET6_ADDRSTRLEN);
    cout<<"\nIPV6 "<<" | src = "<<src<<" | des = "<<des<<" | payload = "<<(unsigned short)ntohs(hdr->ip6_ctlun.ip6_un1.ip6_un1_plen);
    if(hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_ICMPV6)
        cout<<" | Protocol : ICMPV6";
//    print_byte((uint8_t)ntohs((hdr->ip6_vfc)));    //unsigned int x : 2;
    

}


devAndIp getMyIpAddress()
{
    devAndIp result;
    
    const char *v6 ="2001:18e8:2:28a6:462a:60ff:fef3:c6ae";
    const char *ll = "::1";

    strcpy(result.localHost_ipv6, ll);
    char ipaddr[15];
    char des[INET6_ADDRSTRLEN];

    
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
    
    struct sockaddr_in6 v6addr;
    v6addr.sin6_family = AF_INET6;
    v6addr.sin6_port = htons(80);
    inet_pton(AF_INET6,v6, &v6addr.sin6_addr);
    int v6socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if(v6socket>-1)
    {
        socklen_t socklen = sizeof(v6addr);
        int res = connect(v6socket,(struct sockaddr*)&v6addr , socklen);
        if(res == 0)
        {
            socklen_t srcLen = sizeof(v6addr);
            int result = getsockname(v6socket, (struct sockaddr*)&v6addr, &srcLen);
            if(result==0)
            {
                
                inet_ntop(AF_INET6, &(v6addr.sin6_addr), des, INET6_ADDRSTRLEN);
                cout<<des;
            }
            
        }
    }

    const char *dd = "2001:18e8:2:28a6:80ee:3e23:720d:37ec";
    strcpy(result.ipv6,dd);

    struct ifaddrs *adrs;
    struct ifaddrs *adrs2;
    int res =getifaddrs(&adrs);
    adrs2 = adrs;

    if(res==0)
    {
        while (1) {
            adrs=adrs->ifa_next;
            
            
            if(adrs==NULL)
                break;
            else
            {
//                if(adrs->ifa_addr->sa_family==AF_INET6)
//                {
//                    char name[IF_NAMESIZE];
//                    char *d = if_indextoname(((sockaddr_in6 *)(adrs->ifa_addr))->sin6_scope_id, name);
//                    cout<<"\n "<<name;
//                    inet_ntop(AF_INET6, &((sockaddr_in6 *)(adrs->ifa_addr))->sin6_addr, des, INET6_ADDRSTRLEN);
//                    cout<<" : "<<des;
//
//
//                }
//                

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
        
        
        
        //v6
        adrs = adrs2;
        while (1)
        {
        
            
            
            if(adrs==NULL)
                break;
            else
            {
                if(adrs->ifa_addr->sa_family==AF_INET6)
                {
                    char name[IF_NAMESIZE];
                    char *d = if_indextoname(((sockaddr_in6 *)(adrs->ifa_addr))->sin6_scope_id, name);
//                    cout<<"\n "<<name;
                    inet_ntop(AF_INET6, &((sockaddr_in6 *)(adrs->ifa_addr))->sin6_addr, des, INET6_ADDRSTRLEN);
//                    cout<<" : "<<des;
                    if(d==NULL && strcmp(name, result.localhost_dev)==0)
                        strcpy(result.localHost_ipv6,des);
                    if(strcmp(name,result.dev)==0)
                        strcpy(result.ipv6, des);

                }
            }
            adrs=adrs->ifa_next;

        }
        
    }
    else
    {
        //failure
    }
    
    
    
    return result;
}


//void getV6Addr()
//{
//    vector<string> ipv4localhosts;
//    vector<string> ipv4s;
//    vector<string> ipv6s;
//    vector<string> ipv6localhosts;
//    char errBuff[PCAP_ERRBUF_SIZE];
//    pcap_if_t *alldevs;
//    pcap_findalldevs(&alldevs, errBuff);
//    if(alldevs!=NULL)
//    {
//        //success
//        while (alldevs!=NULL) {
//            
//            cout<<"\n "<<alldevs->name;
//            pcap_addr_t *addr = alldevs->addresses;
//            while (addr!=NULL) {
//                //cout<<alldevs->description;
//                if(addr->addr->sa_family == AF_INET)
//                {
//                    char ipv4addr[INET_ADDRSTRLEN];
//                    struct sockaddr_in *saddr = (struct sockaddr_in*)addr->addr;
//                    inet_ntop(AF_INET, &saddr->sin_addr, ipv4addr, INET_ADDRSTRLEN);
//                    cout<<"\n v4: "<<ipv4addr;
//
//                    if(addr->broadaddr==NULL)
//                        cout<<" N";
//                    else
//                        cout<<" Y";
//                    
//                    if(alldevs->flags == PCAP_IF_LOOPBACK)
//                    {
//                        
//                        
//                    }
//                    
//                }
//                else if(addr->addr->sa_family== AF_INET6)
//                {
//                    
//                    char ipv6addr[INET6_ADDRSTRLEN];
//                    struct sockaddr_in6 *saddr = (struct sockaddr_in6*)addr->addr;
//                    inet_ntop(AF_INET6, &saddr->sin6_addr, ipv6addr, INET6_ADDRSTRLEN);
//                    cout<<"\n V6 :"<<ipv6addr;
//                    if(addr->broadaddr==NULL)
//                        cout<<" N";
//                    else
//                        cout<<" Y";
//
//                    
//
//                    if(alldevs->flags == PCAP_IF_LOOPBACK)
//                    {
//                        
//                        
//                    }
//
//                }
//                
//                addr = addr->next;
//            }
//
//            if(alldevs->flags == PCAP_IF_LOOPBACK)
//            {
//            }
//            
//            alldevs=alldevs->next;
//        }
//    }
//    else
//    {
//        //fails
//    }
//
//}

bool isIpV6(const char *add)
{
    bool isIpv6;
    struct sockaddr_in ipv4;
    struct sockaddr_in6 ipv6;
    memset(&ipv4, 0, (size_t)sizeof(struct sockaddr_in));
    memset(&ipv6, 0, (size_t)sizeof(struct sockaddr_in6));
    //check if ipv4
    int ipv4res = inet_pton(AF_INET, add, &ipv4);
    int ipv6res = inet_pton(AF_INET6, add, &ipv6);
    
    
    isIpv6 = (ipv6res==1 && ipv4res == 0)?true:false;
    
    return isIpv6;


}




void scanWellKnownServices(char *ipAddress,int portNumber)
{
    cout<<"Scanning: "<<ipAddress<<" port: "<<portNumber<<endl;
    
    int port_no = portNumber;
    
    //Create client stream socket of type TCP for IPV4
    int clientFD = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in sockAddr;
    void *rstatus = NULL;
    
    //If client socket is successfully created
    if (clientFD!=-1) {
        memset(&sockAddr, 0, sizeof(sockAddr));
        sockAddr.sin_family = AF_INET;
        //Convert port no to network byte order
        sockAddr.sin_port = htons(port_no);
        inet_pton(AF_INET,ipAddress,&(sockAddr.sin_addr.s_addr));
        sockAddr.sin_addr.s_addr = inet_addr(ipAddress);
        //cout<<"Socket created"<<endl;
    }
    else
    {
        exit(1);
    }
    
    //connect to server
    int res = connect(clientFD, (struct sockaddr*)&sockAddr, sizeof(sockAddr));
    if(res>=0)
    {
        //Send
        //char *getRequest = new char[100] ;
        char getRequest[100];
        //request to get HTTP version, connect to 80
        if(port_no == 80)
        {
            strcpy(getRequest,"GET / HTTP/1.1\r\n");
            strcat(getRequest,"HOST: 140.182.225.222\r\n\r\n"); //replace with own ip address !
            //cout<<"Request: "<<getRequest;
            //getRequest[strlen(getRequest)-1]='\0';
            ssize_t len = (ssize_t)sizeof(getRequest);
            ssize_t res = send(clientFD,&getRequest,len,0);
            if(res==-1){printf("\nError in sending");}
        }else if(port_no==43)
        {
            strcpy(getRequest,"google.com\r\n");
            cout<<"Request: "<<getRequest;
            // getRequest[strlen(getRequest)-1]='\0';
            ssize_t len = (ssize_t)sizeof(getRequest);
            ssize_t res = send(clientFD,&getRequest,len,0);
            if(res==-1){printf("\nError in sending");}
        }
        
        //Receive
        char buff[1024];
        int byte_count = -1;
        memset(buff, 0, sizeof(buff));
        //Check if data is received correctly
        if( (byte_count = recv (clientFD, buff, sizeof(buff), 0)) == -1)
        {
            cout<<"Error receiving msg";
        }
        else
        {
            buff[byte_count]='\0';
            if(portNumber==80)
            {
                if(strstr(buff,"HTTP/1.1")!=NULL)
                {
                    cout<<"----------------------------------"<<endl;
                    cout<<"HTTP 1.1 running on port 80 of host "<<ipAddress<<endl;
                    cout<<"----------------------------------"<<endl;
                }else if(strstr(buff,"HTTP/1.0")!=NULL)
                {
                    cout<<"----------------------------------"<<endl;
                    cout<<"HTTP 1.0 running on port 80 of host: "<<ipAddress<<endl;
                    cout<<"----------------------------------"<<endl;
                }else
                {
                    cout<<"----------------------------------"<<endl;
                    cout<<"HTTP service not found on port 80 of host: "<<ipAddress<<endl;
                    cout<<"----------------------------------"<<endl;
                }
            }else if(port_no==25||port_no==587) //check SMTP version
            {
                cout<<"-----------------Mail Server Details---------------------"<<endl;
                cout<<buff<<endl;
                strcpy(getRequest,"EHLO ");
                strcat(getRequest,ipAddress);
                strcat(getRequest,"\r\n");
                // cout<<"--------------Request-------------------"<<endl<<getRequest<<endl;
                ssize_t len = (ssize_t)sizeof(getRequest);
                ssize_t res = send(clientFD,&getRequest,len,0);
                if(res==-1){printf("\nError in sending");}
                
                int byte_count = -1;
                memset(buff, 0, sizeof(buff));
                
                if( (byte_count = recv (clientFD, buff, sizeof(buff), 0)) == -1)
                {
                    cout<<"Error receiving response";
                }else
                {
                    if(strstr(buff,"pleased to meet you"))
                    {
                        cout<<"------------------ESMTP-------------------"<<endl;
                        cout<<"ESMTP running on port: "<<port_no<<" of host: "<<ipAddress<<endl;
                        cout<<"Details: "<<buff<<endl;
                    }else
                    {
                        cout<<"-----------------SMTP-------------------"<<endl;
                        cout<<"SMTP running on port: "<<port_no<<" of host: "<<ipAddress<<endl;
                        cout<<"Details: "<<buff<<endl;
                    }
                }
                cout<<"--------------------------------------------------"<<endl;
            }else if(port_no==43) //whois
            {
                cout<<"WHOIS Result: "<<buff<<endl;
            }else if(port_no==110) //check SMTP version
            {
                // cout<<"--------------------POP Details---------------------"<<endl;
                // cout<<buff<<endl; 
                strcpy(getRequest,"capa\r\n"); 
                // cout<<"--------------Request-------------------"<<endl<<getRequest<<endl; 
                ssize_t len = (ssize_t)sizeof(getRequest); 
                ssize_t res = send(clientFD,&getRequest,len,0); 
                if(res==-1){printf("\nError in sending");} 
                
                int byte_count = -1; 
                memset(buff, 0, sizeof(buff)); 
                
                if( (byte_count = recv (clientFD, buff, sizeof(buff), 0)) == -1) 
                { 
                    cout<<"Error receiving response"; 
                }else 
                { 
                    if(strstr(buff,"UIDL")) 
                    { 
                        cout<<"------------------POP3-------------------"<<endl; 
                        cout<<"POP3 running on port: "<<port_no<<" of host: "<<ipAddress<<endl; 
                        cout<<"Available options: "<<buff<<endl; 
                    }else 
                    { 
                        cout<<"--------------POP-------------------"<<endl; 
                        cout<<"POP running on port: "<<port_no<<" of host: "<<ipAddress<<endl; 
                        cout<<"Available options: "<<buff<<endl; 
                    } 
                    cout<<"--------------------------------------------------"<<endl; 
                } 
                
            }else if(port_no==143) //check IMAP version 
            { 
                cout<<"------------------IMAP-------------------"<<endl; 
                cout<<"IMAP Version: "<<buff<<endl; 
                cout<<"-----------------------------------------"<<endl; 
                
            }else if(port_no==22) //check SSH version 
            { 
                cout<<"------------------SSH-------------------"<<endl; 
                cout<<"SSH Version: "<<buff<<endl; 
                cout<<"----------------------------------------"<<endl; 
            } 
        } 
    } 
    else 
    { 
        cout<<"Error in connection!!"<<endl; 
    } 
    
    //Close connection from client side. 
    close(clientFD); 
}
