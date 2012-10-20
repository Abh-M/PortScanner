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
	this->endPort = 2;
	this->isRange = true;
	memset(&this->portsToScan,-1,sizeof(this->portsToScan));
	this->totalPortsToScan = this->startPort - this->endPort;


	//by default run all type of scans
	this->typeOfScans[SYN_SCAN]=1;
	this->typeOfScans[NULL_SCAN]=1;
	this->typeOfScans[FIN_SCAN]=1;
	this->typeOfScans[XMAS_SCAN]=1;
	this->typeOfScans[ACK_SCAN]=1;
	this->typeOfScans[PROTO_SCAN]=1;


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
    for(port = this->startPort,index = 0;port<=this->endPort;port++,index++)
    {
        this->portsToScan[index++]=port;
        this->totalPortsToScan++;
    }
        
}




ScanResult ScanController::scanPort(ScanRequest kRequest)
{
	ScanResult status;
	return status;
}




ScanResult ScanController::runTCPscan(ScanRequest kRequest)
{

    ScanResult status;
    status.srcPort = ntohs(kRequest.srcPort);
    status.destPort = ntohs(kRequest.destPort);
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
    tcp.th_dport = htons(DEST_PORT);
    tcp.th_seq = htonl(0x131123);
    tcp.th_off = sizeof(struct tcphdr) / 4;
//    tcp.th_flags = TH_SYN;
    
    //set flag depending upon type of scan
    switch (kRequest.scanType) {
        case SYN_SCAN:
            tcp.th_flags = TH_SYN;
            break;
        default:
            break;
    }
    //
    
    tcp.th_win = htons(32768);
    tcp.th_sum = 0;
    tcp.th_sum = in_cksum_tcp(ip.ip_src.s_addr, ip.ip_dst.s_addr, (unsigned short *)&tcp, sizeof(tcp));
    memcpy((packet + sizeof(ip)), &tcp, sizeof(tcp));
    
//    memset(&sin, 0, sizeof(sin));
//    sin.sin_family = AF_INET;
//    sin.sin_addr.s_addr = ip.ip_dst.s_addr;
    
    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
		perror("setsockopt");
		exit(1);
	}
    
    if (sendto(sd, packet, 60, 0, (struct sockaddr *)&kRequest.dest, sizeof(struct sockaddr)) < 0)  {
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

        
    }

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
    
    
    newRequest.scanType = kScanType;
    return newRequest;


}



void ScanController::scanPorts()
{


    ScanResult syn_result;

    
    //for each port run TCP and UDP scan
    for (int index = 0 ;index < this->totalPortsToScan; index++){
        
        int port = this->portsToScan[index];
        //check which types of scan to be carried out

        if(this->typeOfScans[SYN_SCAN]==1)
        {
            //construct scan request
            ScanRequest synRequest = createScanRequestFor(SRC_PORT, port, this->sourceIP, this->targetIP, SYN_SCAN);
            syn_result = runTCPscan(synRequest);
        
        }
            
        
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




