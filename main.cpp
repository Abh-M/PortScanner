//
//  main.cpp
//  demo
//
//  Created by Abhineet on 10/10/12.
//  Copyright (c) 2012 Abhineet. All rights reserved.
//

//#include <pcap/pcap.h>
//#include <unistd.h>
//#include <iostream>
//#include <stdlib.h>
//#include <sys/socket.h>
//#include <sys/types.h>
//#include <netinet/in.h>
//#include <pthread.h>
//#include <errno.h>
//#include <netinet/tcp.h>
//#include <arpa/inet.h>
//#include <unistd.h>
//#include <sys/protosw.h>
//#include "Globals.h"
//#include <netinet/ip.h>
//#include <netinet/udp.h>
//#include <netinet/if_ether.h>
//#include <netinet/ip_icmp.h>

#include "PCH.h"
#include "ScanController.h"
#include "Helpers.h"


#include "Utils.h"

using namespace std;


//struct psd_tcp {
//	struct in_addr src;
//	struct in_addr dst;
//	unsigned char pad;
//	unsigned char proto;
//	unsigned short tcp_len;
//	struct tcphdr tcp;
//};

//int sd;
//    pcap_t *handle;
//unsigned short in_cksum(unsigned short *addr, int len)
//
//{
//	int nleft = len;
//	int sum = 0;
//	unsigned short *w = addr;
//	unsigned short answer = 0;
//    
//	while (nleft > 1) {
//		sum += *w++;
//		nleft -= 2;
//	}
//    
//	if (nleft == 1) {
//		*(unsigned char *) (&answer) = *(unsigned char *) w;
//		sum += answer;
//	}
//	
//	sum = (sum >> 16) + (sum & 0xFFFF);
//	sum += (sum >> 16);
//	answer = ~sum;
//	return (answer);
//}
//
//unsigned short in_cksum_tcp(int src, int dst, unsigned short *addr, int len)
//{
//	struct psd_tcp buf;
//	u_short ans;
//    
//	memset(&buf, 0, sizeof(buf));
//	buf.src.s_addr = src;
//	buf.dst.s_addr = dst;
//	buf.pad = 0;
//	buf.proto = IPPROTO_TCP;
//	buf.tcp_len = htons(len);
//	memcpy(&(buf.tcp), addr, len);
//	ans = in_cksum((unsigned short *)&buf, 12 + len);
//	return (ans);
//}

int main(int argc, const char * argv[])
{



//    getMyIpAddress();
    
    ScanController *con =  ScanController::shared();
    //con->populateProtocolNumberToScan();
    //con->runProtocolScan();

    con->scanPorts();
    
//    char *dev, errBuff[50];
//    dev = pcap_lookupdev(errBuff);
//    cout<<dev;
//    
//    
//    pcap_t *handle;
//    
//    
//    struct bpf_program fp;		/* The compiled filter expression */
//    char filter_exp[] = "dst port 5678";	/* The filter expression */
//    bpf_u_int32 mask;		/* The netmask of our sniffing device */
//    bpf_u_int32 net;		/* The IP of our sniffing device */
//    
//    if (pcap_lookupnet(dev, &net, &mask, errBuff) == -1) {
//        fprintf(stderr, "Can't get netmask for device %s\n", dev);
//        net = 0;
//        mask = 0;
//    }
//    handle = pcap_open_live(dev, 65535, 10, 1000, errBuff);
//    if (handle == NULL) {
//        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errBuff);
//        return(2);
//    }
//    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
//        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
//        return(2);
//    }
//    if (pcap_setfilter(handle, &fp) == -1) {
//        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
//        return(2);
//    }
    
//    tcpscan(445, 445, SRC_IP, DEST_IP);

//    pcap_loop(handle, 2, (pcap_handler)my_callback, NULL);
//    cout<<"Works";
    
#pragma mark - protocol scan
    
//        struct ip ip;
//        const int on = 1;
//        struct sockaddr_in sin;
//
//        u_char *packet;
//        packet = (u_char *)malloc(20);
//
//    if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
//		perror("raw socket");
//		exit(1);
//	}
//        ip.ip_hl = 0x5;
//        ip.ip_v = 0x4;
//        ip.ip_tos = 0x0;
//        ip.ip_len = sizeof(struct ip);
//        ip.ip_id = htons(12830);
//        ip.ip_off = 0x0;
//        ip.ip_ttl = 64;
//        ip.ip_p = 41;
//        ip.ip_sum = 0x0;
//        ip.ip_src.s_addr = inet_addr(SRC_IP);
//        ip.ip_dst.s_addr = inet_addr(DEST_IP);
//        ip.ip_sum = in_cksum((unsigned short *)&ip, sizeof(ip));
//        memcpy(packet, &ip, sizeof(ip));
//
//
//        memset(&sin, 0, sizeof(sin));
//        sin.sin_family = AF_INET;
//        sin.sin_addr.s_addr = ip.ip_dst.s_addr;
//
//        if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
//		perror("setsockopt");
//		exit(1);
//        }
//    
//        if (sendto(sd, packet, 20, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0)  {
//            perror("sendto");
//            exit(1);
//        }

    
    
#pragma mark - send packet
//    
//        struct ip ip;
//        struct tcphdr tcp;
//        const int on = 1;
//        struct sockaddr_in sin;
//        
//        u_char *packet;
//        packet = (u_char *)malloc(60);
//        
//    if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
//		perror("raw socket");
//		exit(1);
//	}
//        ip.ip_hl = 0x5;
//        ip.ip_v = 0x4;
//        ip.ip_tos = 0x0;
//        ip.ip_len = sizeof(struct ip) + sizeof(struct tcphdr);
//        ip.ip_id = htons(12830);
//        ip.ip_off = 0x0;
//        ip.ip_ttl = 64;
//        ip.ip_p = IPPROTO_TCP;
//        ip.ip_sum = 0x0;
//        ip.ip_src.s_addr = inet_addr(SRC_IP);
//        ip.ip_dst.s_addr = inet_addr(DEST_IP);
//        ip.ip_sum = in_cksum((unsigned short *)&ip, sizeof(ip));
//        memcpy(packet, &ip, sizeof(ip));
//        
//        tcp.th_sport = htons(SRC_PORT);
//        tcp.th_dport = htons(DEST_PORT);
//        tcp.th_seq = htonl(0x131123);
//        tcp.th_off = sizeof(struct tcphdr) / 4;
//        tcp.th_flags = TH_SYN;
//        tcp.th_win = htons(32768);
//        tcp.th_sum = 0;
//        tcp.th_sum = in_cksum_tcp(ip.ip_src.s_addr, ip.ip_dst.s_addr, (unsigned short *)&tcp, sizeof(tcp));
//        memcpy((packet + sizeof(ip)), &tcp, sizeof(tcp));
//        
//        memset(&sin, 0, sizeof(sin));
//        sin.sin_family = AF_INET;
//        sin.sin_addr.s_addr = ip.ip_dst.s_addr;
//    
//    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
//		perror("setsockopt");
//		exit(1);
//	}
//    
//        if (sendto(sd, packet, 60, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0)  {
//            perror("sendto");
//            exit(1);
//        }
    
    
#pragma mark - send UDP packet
//    struct ip ip;
//	struct udphdr udp;
//	int sd;
//	const int on = 1;
//	struct sockaddr_in sin;
//	u_char *packet;
//    
//    packet = (u_char *)malloc(60);
//
//    
//    ip.ip_hl = 0x5;
//	ip.ip_v = 0x4;
//	ip.ip_tos = 0x0;
//	ip.ip_len = 60;
//	ip.ip_id = htons(12830);
//	ip.ip_off = 0x0;
//	ip.ip_ttl = 64;
//	ip.ip_p = IPPROTO_UDP;
//	ip.ip_sum = 0x0;
//	ip.ip_src.s_addr = inet_addr(SRC_IP);
//	ip.ip_dst.s_addr = inet_addr(DEST_IP);
//	ip.ip_sum = in_cksum((unsigned short *)&ip, sizeof(ip));
//	memcpy(packet, &ip, sizeof(ip));
//    
//    udp.uh_sport = htons(SRC_PORT);
//    udp.uh_dport = htons(DEST_PORT);
//    udp.uh_ulen = htons(8);
//    
//    udp.uh_sum = 0;
//	udp.uh_sum = in_cksum_tcp(ip.ip_src.s_addr, ip.ip_dst.s_addr, (unsigned short *)&udp, sizeof(udp));
//	memcpy(packet + 20, &udp, sizeof(udp));
//    
//    if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
//		perror("raw socket");
//		exit(1);
//	}
//    
//	if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
//		perror("setsockopt");
//		exit(1);
//	}
//	memset(&sin, 0, sizeof(sin));
//	sin.sin_family = AF_INET;
//	sin.sin_addr.s_addr = ip.ip_dst.s_addr;
//    
//	if (sendto(sd, packet, 60, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0)  {
//		perror("sendto");
//		exit(1);
//	}



    
//#pragma mark - rev packet
//    struct pcap_pkthdr header;
//    const u_char *recPakcet = pcap_next(handle, &header);
//    printf("\nJacked a packet with length of [%d]\n", header.len);
//    
//    struct ip *iph = (struct ip*)(recPakcet + 14);
//    cout<<inet_ntoa(iph->ip_src);
    
    
    return 0;
}



