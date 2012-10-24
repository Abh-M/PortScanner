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

    struct ifaddrs *adrs;
    int res =getifaddrs(&adrs);
    if(res==0)
    {
        while (1) {
            adrs=adrs->ifa_next;
            
            if(adrs==NULL)
                return;
            else
            {
                struct sockaddr_in *so = (struct sockaddr_in*)adrs->ifa_addr;
                struct sockaddr_in *da = (struct sockaddr_in*)adrs->ifa_dstaddr;
                struct sockaddr_in *ba = (struct sockaddr_in*)adrs->ifa_netmask;

                if(da && so && ba && adrs->ifa_flags)
                    cout<<"\n--"<<adrs->ifa_name<<"--"<<inet_ntoa(so->sin_addr)<<"--"<<inet_ntoa(da->sin_addr)<<"--"<<inet_ntoa(ba->sin_addr)<<"--"<<adrs->ifa_flags;
            }
        }
    }
    else
    {
        //failure
    }
}


//void scanHTTP(char *ipAddress)
//{
//	cout<<"Scanning: "<<ipAddress<<" port 80";
//	int port_no = 80;
//	int use_localhost = 1;
//    
//	char *dev, errBuff[50];
//	//dev = pcap_lookupdev(errBuff);
//	dev="en0";
//	cout<<dev;
//    
//	pcap_t *handle;
//    
//	struct bpf_program fp;
//    
//	//set filter exp depending upon source port
//	char filter_exp[100];
//    
//	sprintf(filter_exp,"src %s",ipAddress);
//	printf("\n FILTER EXP: %s",filter_exp);
//    
//	bpf_u_int32 mask;
//	bpf_u_int32 net;
//    
//	if (pcap_lookupnet(dev, &net, &mask, errBuff) == -1) {
//		fprintf(stderr, "Can't get netmask for device %s\n", dev);
//		net = 0;
//		mask = 0;
//	}
//	handle = pcap_open_live(dev, 65535, 0, 2000, errBuff);
//	if (handle == NULL) {
//		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errBuff);
//	}
//	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
//		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
//	}
//	if (pcap_setfilter(handle, &fp) == -1) {
//		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
//	}
//    
//	//The seperator is "=" as parameters are supplied in the form param=value
//	const char *seperator = "=";
//	int i;
//    
//	//Create client stream socket of type TCP for IPV4
//	int clientFD = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
//	struct sockaddr_in sockAddr;
//	pthread_t rthread,sthread;
//	void *rstatus = NULL;
//    
//	//If client socket is successfully created
//	if (clientFD!=-1) {
//		memset(&sockAddr, 0, sizeof(sockAddr));
//		sockAddr.sin_family = AF_INET;
//		//Convert port no to network byte order
//		sockAddr.sin_port = htons(port_no);
//		inet_pton(AF_INET,ipAddress,&(sockAddr.sin_addr.s_addr));
//		sockAddr.sin_addr.s_addr = inet_addr(ipAddress);
//		cout<<"Socket created";
//	}
//	else
//	{
//		exit(1);
//	}
//    
//	//connect to server
//	int res = connect(clientFD, (struct sockaddr*)&sockAddr, sizeof(sockAddr));
//	if(res>=0)
//	{
//		printf("\nConnected to server");
//        
//		//Send
//		const char *getRequest;
//		getRequest = "GET /index.html HTTP/1.1";
//        
//		//memset(&getRequest, 0, sizeof(getRequest));
//        
//		//getRequest[strlen(getRequest)-1]='\0';
//        
//		ssize_t len = (ssize_t)sizeof(getRequest);
//		ssize_t res = send(clientFD,getRequest,len,0);
//		if(res==-1){printf("\nError in sending");}
//        
//        
//		//Receive
//		char buff[1024];
//		ssize_t bytes = 0;
//		int byte_count = -1;
//        
//		memset(buff, 0, sizeof(buff));
//        
//        cout<<"\nRECV";
//		//Check if data is received correctly
//		if( (byte_count = recv (clientFD, buff, sizeof(buff), MSG_WAITALL)) == -1)
//		{
//			printf("Error receiving msg");
//		}
//		else
//		{
//			buff[byte_count]='\0';
//            
//			struct pcap_pkthdr header;
//			const u_char *recPakcet = pcap_next(handle, &header);
//			if(recPakcet!=NULL)
//			{
//				struct ip *iph = (struct ip*)(recPakcet + 14);
//				logIpHeader(iph);
//                
//				//check is protocol is TCP
//				struct tcphdr *tcpHdr = (struct tcphdr*)(recPakcet + 34);
//				logTCPHeader(tcpHdr);
//                
//				//check if src and destination ports are valid
//				//get which flags are set in the response
//				unsigned char flags = tcpHdr->th_flags;
//                
//				close(clientFD);
//				pcap_close(handle);
//                
//				cout<<"Returned Data: "<<buff<<endl;
//                
//			}
//		}
//        
//		if(strstr(buff,"http/1.1")!=NULL)
//		{
//			cout<<"HTTP 1.1 running on port 80 of host "<<ipAddress;
//		}else if(strstr(buff,"http/1.0")!=NULL)
//		{
//			cout<<"HTTP 1.0 running on port 80 of host "<<ipAddress;
//		}else
//		{
//			cout<<"HTTP service not found on port 80 of host "<<ipAddress;
//		}
//        
//		//Close connection from client side.
//		close(clientFD);
//	}
//}


