/*
 * ScanController.cpp
 *
 *  Created on: Oct 13, 2012
 *      Author: raj
 */

#include "ScanController.h"

////
#include <stdio.h>
#include <unistd.h>
#include <iostream>
#include <stdlib.h>
#include <cstring>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <pthread.h>
#include <errno.h>
//#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
//#include <linux/types.h>
#include <netdb.h>
#include "Helpers.h"
#include "PCH.h"
using namespace std;

#include "Utils.h"

static ScanController *sharedInstance;
ScanController::ScanController() {

	//by default scan 0-1024;
	this->startPort = 1;
	this->endPort = 1;
	this->isRange = true;
	memset(&this->portsToScan,-1,sizeof(this->portsToScan));
	this->totalPortsToScan = this->startPort - this->endPort;


	//by default run all type of scans
    //knobs to configure type of scans
	this->typeOfScans[SYN_SCAN]=0;
	this->typeOfScans[NULL_SCAN]=0;
	this->typeOfScans[FIN_SCAN]=0;
	this->typeOfScans[XMAS_SCAN]=0;
	this->typeOfScans[ACK_SCAN]=0;
	this->typeOfScans[PROTO_SCAN]=0;


	//by default scan loccalhost
	this->targetIP = new char[15]();
	strcpy(this->targetIP,DEST_IP);
	this->sourceIP = new char[15]();
	strcpy(this->sourceIP,SRC_IP);


    //ignore this
	this->scanLocalhost = true;

	this->speed = false;
	this->fileName = false;
    
    populatePortsList();

}

void ScanController::setTargetIPAddress(char *kTargetIp)
{


}

void ScanController::populatePortsList()
{
    int index =0;
    int port = this->startPort;
    this->totalPortsToScan = 0;
    for(port = this->startPort,index = 0;port<=this->endPort;port++)
    {
        this->portsToScan[index++]=port;
        this->totalPortsToScan++;
    }
        
}




void ScanController::scanPort(ScanRequest kRequest)
{

}


ScanResult ScanController::runUDPScan(ScanRequest kRequest)
{
	ScanResult status;
    status.srcPort = ntohs(kRequest.srcPort);
    status.destPort = ntohs(kRequest.destPort);
    status.srcIp = inet_ntoa(kRequest.src.sin_addr);
    status.destIp = inet_ntoa(kRequest.dest.sin_addr);
    status.udp_portState = kUnkown;
    
    
#pragma mark - set pcap for UDP
    //// Set pcap parameters
    
    char *dev, errBuff[50];
    dev = pcap_lookupdev(errBuff);
    cout<<dev;
    
    
    pcap_t *handle;
    
    
    struct bpf_program fp;
    
    //set filter exp depending upon source port
    char filter_exp[] = "icmp || dst port ";
    sprintf(filter_exp,"dst port %d",5678);
    cout<<"\n FILTER EXP "<<filter_exp;
    
    bpf_u_int32 mask;
    bpf_u_int32 net;
    
    if (pcap_lookupnet(dev, &net, &mask, errBuff) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }
    handle = pcap_open_live(dev, 65535, 0, 5000, errBuff);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errBuff);
    }
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    }
    ////
    
    struct ip ip;
	struct udphdr udp;
	int sd;
	const int on = 1;
	struct sockaddr_in sin;
	u_char *packet;

    packet = (u_char *)malloc(60);

#pragma mark - set ip header for UDP packet
    ip.ip_hl = 0x5;
	ip.ip_v = 0x4;
	ip.ip_tos = 0x0;
	ip.ip_len = 60;
	ip.ip_id = htons(12830);
	ip.ip_off = 0x0;
	ip.ip_ttl = 64;
    //imp
	ip.ip_p = IPPROTO_UDP;
    //
	ip.ip_sum = 0x0;
    //IMP
	ip.ip_src.s_addr = inet_addr(SRC_IP);
	ip.ip_dst.s_addr =  inet_addr(DEST_IP);
	ip.ip_sum = in_cksum((unsigned short *)&ip, sizeof(ip));
    //IMP
	memcpy(packet, &ip, sizeof(ip));


#pragma mark - set UDP header
    //IMP
    udp.uh_sport = htons(SRC_PORT);
    udp.uh_dport = htons(kRequest.destPort);
    udp.uh_ulen = htons(8);

    udp.uh_sum = 0;
	udp.uh_sum = in_cksum_tcp(ip.ip_src.s_addr, ip.ip_dst.s_addr, (unsigned short *)&udp, sizeof(udp));
	memcpy(packet + 20, &udp, sizeof(udp));

    if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror("raw socket");
		exit(1);
	}

	if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
		perror("setsockopt");
		exit(1);
	}
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = ip.ip_dst.s_addr;

	if (sendto(sd, packet, 60, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0)  {
		perror("sendto");
		exit(1);
	}
//	if (sendto(sd, packet, 60, 0, (struct sockaddr *)&kRequest.dest, sizeof(struct sockaddr)) < 0)  {
//		perror("sendto");
//		exit(1);
//	}

    
    //close socket
    //close pcap session
    
    close(sd);
    pcap_close(handle);
	return status;
}




ScanResult ScanController::runTCPscan(ScanRequest kRequest)
{
    
    

    ScanResult status;
    status.srcPort = ntohs(kRequest.srcPort);
    status.destPort = ntohs(kRequest.destPort);
    status.srcIp = inet_ntoa(kRequest.src.sin_addr);
    status.destIp = inet_ntoa(kRequest.dest.sin_addr);
    status.tcp_portState = kUnkown;

    
    //// Set pcap parameters
    
    char *dev, errBuff[50];
    dev = pcap_lookupdev(errBuff);
    cout<<dev;
    
    
    pcap_t *handle;
    

    struct bpf_program fp;
    
    //set filter exp depending upon source port
    char filter_exp[] = "icmp || dst port ";
    sprintf(filter_exp,"dst port %d",5678);
    cout<<"\n FILTER EXP "<<filter_exp;
    
    bpf_u_int32 mask;
    bpf_u_int32 net;
    
    if (pcap_lookupnet(dev, &net, &mask, errBuff) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }
    handle = pcap_open_live(dev, 65535, 0, 5000, errBuff);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errBuff);
    }
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    }
    ////
    
    
    
    
    struct ip ip;
    struct tcphdr tcp;
    const int on = 1;
   // struct sockaddr_in sin;
    int sd;
    u_char *packet;
    packet = (u_char *)malloc(60);
    
    if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
		perror("raw socket");
		exit(1);
	}
    ip.ip_hl = 0x5;
    ip.ip_v = 0x4;
    ip.ip_tos = 0x0;
    ip.ip_len = sizeof(struct ip) + sizeof(struct tcphdr);
    ip.ip_id = htons(12830);
    ip.ip_off = 0x0;
    ip.ip_ttl = 64;
    ip.ip_p = IPPROTO_TCP;
    ip.ip_sum = 0x0;
    ip.ip_src.s_addr = inet_addr(SRC_IP);
    ip.ip_dst.s_addr = inet_addr(DEST_IP);
    ip.ip_sum = in_cksum((unsigned short *)&ip, sizeof(ip));
    memcpy(packet, &ip, sizeof(ip));
    
    tcp.th_sport = htons(SRC_PORT);
    //Set dest port
    tcp.th_dport = htons(kRequest.destPort);
    tcp.th_seq = htonl(0x131123);
    tcp.th_off = sizeof(struct tcphdr) / 4;
//    tcp.th_flags = TH_SYN;
    
    //set flag depending upon type of scan
    switch (kRequest.scanType) {
        case SYN_SCAN:
            tcp.th_flags = TH_SYN;
            break;
        case ACK_SCAN:
            tcp.th_flags = TH_ACK;
            break;
        case NULL_SCAN:
            tcp.th_flags = 0x00;
            break;
        case FIN_SCAN:
            tcp.th_flags = TH_FIN;
            break;
        case XMAS_SCAN:
            tcp.th_flags = (TH_FIN | TH_PUSH |TH_URG);
            break;
    
        default:
            break;
    }
    //
    
    tcp.th_win = htons(32768);
    tcp.th_sum = 0;
    tcp.th_sum = in_cksum_tcp(ip.ip_src.s_addr, ip.ip_dst.s_addr, (unsigned short *)&tcp, sizeof(tcp));
    memcpy((packet + sizeof(ip)), &tcp, sizeof(tcp));
    
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ip.ip_dst.s_addr;
    
    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
		perror("setsockopt");
		exit(1);
	}
    
    if (sendto(sd, packet, 60, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0)  {
        perror("sendto");
        exit(1);
    }

    
	
    

    
    
    struct pcap_pkthdr header;
    const u_char *recPakcet = pcap_next(handle, &header);
    if(recPakcet!=NULL)
    {
        printf("\nJacked a packet with length of [%d]\n", header.len);
        struct ip *iph = (struct ip*)(recPakcet + 14);
        logIpHeader(iph);
        struct tcphdr *tcpHdr = (struct tcphdr*)(recPakcet + 34);
        logTCPHeader(tcpHdr);
        
        //check is protocol is TCP
        if((unsigned int)iph->ip_p == IPPROTO_TCP)
        {
            //check if src and destination ports are valid
            //get which flags are set in the response
            unsigned char flags = tcpHdr->th_flags;
            
            if(kRequest.scanType == SYN_SCAN)
            {
                if( (flags & TH_SYN) && (flags & TH_ACK))
                    status.tcp_portState = kOpen;
                else if (flags & TH_SYN)
                    status.tcp_portState = kOpen;
                else if(flags & TH_RST)
                    status.tcp_portState = kClosed;
                else
                    status.tcp_portState = kClosedAndUnfiltered;
                
            }
            
            switch (kRequest.scanType) {
                case SYN_SCAN:
                {
                    if( (flags & TH_SYN) && (flags & TH_ACK))
                        status.tcp_portState = kOpen;
                    else if (flags & TH_SYN)
                        status.tcp_portState = kOpen;
                    else if(flags & TH_RST)
                        status.tcp_portState = kClosed;
                    else
                        status.tcp_portState = kClosedAndUnfiltered;
                    
                }
                    break;
                    
                case ACK_SCAN:
                {
                    if(flags & TH_RST)
                        status.tcp_portState = kUnFiltered;
                }
                    break;
                    
                case NULL_SCAN:
                {
                    if (flags & TH_RST) {
                        status.tcp_portState = kClosedAndUnfiltered;
                    }
                }
                    break;
                    
                case FIN_SCAN:
                {
                    if(flags & TH_RST)
                        status.tcp_portState = kClosedAndUnfiltered;
                }
                    break;
                    
                case XMAS_SCAN:
                {
                    if(flags & TH_RST)
                        status.tcp_portState = kClosedAndUnfiltered;
                }
                    
                default:
                    break;
            }
        }

        
    }
     else if(recPakcet==NULL)
     {
         if(kRequest.scanType==XMAS_SCAN)
             status.tcp_portState = kOpen;
         if(kRequest.scanType == NULL_SCAN)
             status.tcp_portState = kOpen;
         if(kRequest.scanType == FIN_SCAN)
             status.tcp_portState = kOpen;
         
//         if(kRequest.scanType == SYN_SCAN)
//             //need to retransmitt //needs to be done from the calling function
         
         
         if(kRequest.scanType == ACK_SCAN)
             status.tcp_portState = kFiltered;
         
         
     }
    
    //*TO DO if packet is icmp
    //close socket
    //close pcap session
    close(sd);
    pcap_close(handle);
  
    return status;


}



ScanRequest createScanRequestFor(int srcPort, int destPort, char *srcIp, char *destIp, int kScanType)
{
    ScanRequest newRequest;
    struct sockaddr_in src;
    struct sockaddr_in des;
    
    src.sin_family = AF_INET;
    src.sin_port = htons(srcPort);
    inet_aton(srcIp, (struct in_addr*)&src);
    
    des.sin_family = AF_INET;
    inet_aton(destIp, (struct in_addr*)&des);
    des.sin_port = htons(destPort);
    
    
    newRequest.srcPort = srcPort;
    newRequest.destPort = destPort;
    
    newRequest.scanType = kScanType;
    return newRequest;


}



void ScanController::scanPorts()
{


    
    //for each port run TCP and UDP scan
    for (int index = 0 ;index < this->totalPortsToScan; index++)
    {
        
        ScanResult syn_result;
        ScanResult ack_result;
        ScanResult null_result;
        ScanResult fin_result;
        ScanResult xmas_result;
        ScanResult udp_result;
        AllScanResult scanResults;
        scanResults.synState = kUnkown;
        scanResults.ackState = kUnkown;
        scanResults.nullState = kUnkown;
        scanResults.finState = kUnkown;
        scanResults.xmasState = kUnkown;

        
        int port = this->portsToScan[index];
        //check which types of scan to be carried out

        scanResults.portNo = port;
        
        if(this->typeOfScans[SYN_SCAN]==1)
        {
            //construct scan request
            cout<<"\n Scanning SYN "<<port<<endl;
            ScanRequest synRequest = createScanRequestFor(SRC_PORT, port, this->sourceIP, this->targetIP, SYN_SCAN);
            syn_result = runTCPscan(synRequest);
            scanResults.synState = syn_result.tcp_portState;
            

        }
        
        if(this->typeOfScans[ACK_SCAN] == 1)
        {
            ScanRequest ackReq = createScanRequestFor(SRC_PORT, port, this->sourceIP, this->targetIP, ACK_SCAN);
            ack_result = runTCPscan(ackReq);
            scanResults.ackState = ack_result.tcp_portState;
        }
        
        if(this->typeOfScans[NULL_SCAN] == 1)
        {
            ScanRequest ackReq = createScanRequestFor(SRC_PORT, port, this->sourceIP, this->targetIP, NULL_SCAN);
            null_result = runTCPscan(ackReq);
            scanResults.ackState = null_result.tcp_portState;
        }
        
        if(this->typeOfScans[FIN_SCAN] == 1)
        {

            ScanRequest finReq = createScanRequestFor(SRC_PORT, port, this->sourceIP, this->targetIP, FIN_SCAN);
            fin_result = runTCPscan(finReq);
            scanResults.finState = fin_result.tcp_portState;
        }
        
        if (this->typeOfScans[XMAS_SCAN]==1) {
            ScanRequest xmasReq = createScanRequestFor(SRC_PORT, port, this->sourceIP, this->targetIP, XMAS_SCAN);
            xmas_result = runTCPscan(xmasReq);
            scanResults.xmasState = fin_result.tcp_portState;
        }

        //Run UDP scan by default
        
            ScanRequest udpReq = createScanRequestFor(SRC_PORT, port, this->sourceIP, this->targetIP, UDP_SCAN);
            udp_result = runUDPScan(udpReq);

        
        
        
        
            
        
    }
    

}

ScanController::~ScanController() {
	// TODO Auto-generated destructor stub

}


ScanController* ScanController::shared()
{
	if(sharedInstance==NULL)
		sharedInstance = new ScanController();

	return sharedInstance;
}




