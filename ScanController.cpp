/*
 * ScanController.cpp
 *
 *  Created on: Oct 13, 2012
 *      Author: raj
 */

#include "ScanController.h"

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
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netdb.h>
#include "Helpers.h"
#include "PCH.h"
#include "Utils.h"
using namespace std;



Job allJobs[MAX_PORTS];
sem_t mutex_allJobs;
int totalJobs=0;
sem_t mutex_totalJobs;
int currentJob;
sem_t mutex_currJob;
Worker workers[MAX_WORKERS];
int workDistribution[MAX_WORKERS][3];
sem_t mutex_wrkD;
pthread_t allWorkerThreads[MAX_WORKERS];
//sem_t kMutex;
pthread_mutex_t kMutex;

static ScanController *sharedInstance;
ScanController::ScanController() {
    
    //by default scan 0-1024;
    this->startPort = 0;
    this->endPort = 1024;
    this->isRange = true;
    memset(&this->portsToScan,-1,sizeof(this->portsToScan));
    this->totalPortsToScan = this->startPort - this->endPort;
    
    
    //by default run all type of scans
    //knobs to configure type of scans
    this->typeOfScans[SYN_SCAN]=1;
    this->typeOfScans[NULL_SCAN]=0;
    this->typeOfScans[FIN_SCAN]=0;
    this->typeOfScans[XMAS_SCAN]=0;
    this->typeOfScans[ACK_SCAN]=0;
    this->typeOfScans[PROTO_SCAN]=0;
    this->typeOfScans[UDP_SCAN]=0;
    
    
    //by default scan loccalhost
    this->targetIP = new char[15]();
    //    strcpy(this->targetIP,DEST_IP);
    this->sourceIP = new char[15]();
    //    strcpy(this->sourceIP,SRC_IP);
    
    
    //ignore this
    this->scanLocalhost = true;
    
    this->speed = false;
    this->fileName = false;
    
    populatePortsList();
    
}

void ScanController::resetAllScanTypes()
{
    this->typeOfScans[SYN_SCAN]=0;
    this->typeOfScans[NULL_SCAN]=0;
    this->typeOfScans[FIN_SCAN]=0;
    this->typeOfScans[XMAS_SCAN]=0;
    this->typeOfScans[ACK_SCAN]=0;
    this->typeOfScans[PROTO_SCAN]=0;
    this->typeOfScans[UDP_SCAN]=0;
    
    
}


void ScanController::printScanTypeConf()
{
    for (int i=0; i<7; i++) {
        if(this->typeOfScans[i])
            cout<<"\n"<<scanNumToString(i);
    }
}

void ScanController::setTargetIPAddress(char *kSourceIp,char *kTargetIp)
{
    this->sourceIP = kSourceIp;
    this->targetIP = kTargetIp;
    
}

void ScanController::populatePortsList(int kStart, int kEnd)
{
    
    // cout<<kStart<<" "<<kEnd;
    this->totalPortsToScan = 0;
    for(int port = kStart; port<=kEnd;port++)
    {
        this->portsToScan[this->totalPortsToScan++]=port;
    }
    cout<<this->totalPortsToScan;
    for (int i=0; i<this->totalPortsToScan;i++) {
        cout<<"\n PORT : "<<this->portsToScan[i];
    }
    
}


void ScanController::populatePortsList(int kPortsList[MAX_PORTS])
{
    
    int index = 0;
    while (kPortsList[index]!=INVALID_PORT)
    {
        this->portsToScan[this->totalPortsToScan++]=kPortsList[index];
        index++;
    }
    
    
    for (int i=0; i<this->totalPortsToScan;i++) {
        cout<<"\n PORT : "<<this->portsToScan[i];
    }
    
    
}

void ScanController::flushPortsList()
{
    int port = 0;
    this->startPort =0;
    this->endPort = 0;
    this->totalPortsToScan = 0;
    for(port=0;port<MAX_PORTS;port++)
        this->portsToScan[port]= INVALID_PORT;
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



ProtocolScanResult ScanController::runScanForProtocol(ProtocolScanRequest req)
{
    ProtocolScanResult result;
    result.protocolNumber = req.protocolNumber;
    result.protocolSupported = false;
    
    //// Set pcap parameters
    
    char *dev, errBuff[50];
    if(LOCALHST == 0)
        dev = pcap_lookupdev(errBuff);
    else if(LOCALHST == 1 && APPLE ==1)
        dev = "lo0";
    else if(LOCALHST == 1 && APPLE ==0)
        dev = "lo";
    //#endif
    cout<<dev;
    
    
    pcap_t *handle;
    
    
    struct bpf_program fp;
    
    //set filter exp depending upon source port
    char filter_exp[100];
    
    sprintf(filter_exp,"icmp");
    cout<<"\n FILTER EXP "<<filter_exp;
    
    bpf_u_int32 mask;
    bpf_u_int32 net;
    
    if (pcap_lookupnet(dev, &net, &mask, errBuff) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }
    handle = pcap_open_live(dev, 65535, 0, 2000, errBuff);
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
    int sd;
    const int on = 1;
    struct sockaddr_in sin;
    u_char *packet;
    
    packet = (u_char *)malloc(60);
    
    ip.ip_hl = 0x5;
    ip.ip_v = 0x4;
    ip.ip_tos = 0x0;
    ip.ip_len = 60;
    ip.ip_id = htons(12830);
    ip.ip_off = 0x0;
    ip.ip_ttl = 64;
    //imp
    ip.ip_p = req.protocolNumber;
    //
    ip.ip_sum = 0x0;
    //IMP
    ip.ip_src.s_addr = inet_addr(SRC_IP);
    ip.ip_dst.s_addr =  inet_addr(DEST_IP);
    ip.ip_sum = in_cksum((unsigned short *)&ip, sizeof(ip));
    //IMP
    memcpy(packet, &ip, sizeof(ip));
    
    
    //    //IMP
    
    
    if(ip.ip_p == IPPROTO_ICMP)
    {
        struct icmp icmphd;
        icmphd.icmp_type = ICMP_ECHO;
        icmphd.icmp_code = 0;
        icmphd.icmp_id = 1000;
        icmphd.icmp_seq = 0;
        icmphd.icmp_cksum = 0;
        icmphd.icmp_cksum = in_cksum((unsigned short *)&icmphd, 8);
        memcpy(packet + 20, &icmphd, 8);
        cout<<"SCANNIN XXXX ICMP"<<endl;
    }
    else if(ip.ip_p == IPPROTO_TCP)
    {
        cout<<"SCANNIN XXXX TCP"<<endl;
        struct tcphdr tcp;
        tcp.th_sport = htons(SRC_PORT);
        tcp.th_dport = htons(DEST_PORT);
        tcp.th_seq = htonl(0x131123);
        tcp.th_off = sizeof(struct tcphdr) / 4;
        tcp.th_flags = TH_SYN;
        tcp.th_win = htons(32768);
        tcp.th_sum = 0;
        tcp.th_sum = in_cksum_tcp(ip.ip_src.s_addr, ip.ip_dst.s_addr, (unsigned short *)&tcp, sizeof(tcp));
        memcpy((packet + sizeof(ip)), &tcp, sizeof(tcp));
        
    }
    else if(ip.ip_p == IPPROTO_UDP)
    {
        struct udphdr udp;
        
        cout<<"SCANNIN XXXX UDP"<<endl;
        udp.uh_sport = htons(SRC_PORT);
        udp.uh_dport = htons(69);
        udp.uh_ulen = htons(8);
        udp.uh_sum = 0;
        udp.uh_sum = in_cksum_udp(ip.ip_src.s_addr, ip.ip_dst.s_addr, (unsigned short *)&udp, sizeof(udp));
        memcpy(packet + 20, &udp, sizeof(udp));
        
    }
    
    
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
    
    
    //RECV
    struct pcap_pkthdr header;
    const u_char *recPakcet =  pcap_next(handle, &header);
    
    if(recPakcet!=NULL)
    {
        printf("\nJacked a packet with length of [%d]\n", header.caplen);
        struct ip *iph = (struct ip*)(recPakcet+14);
        logIpHeader(iph);
        
        //char *srcip = inet_ntoa(iph->ip_src);
        //char *desip = inet_ntoa(iph->ip_dst);
        cout<<inet_ntoa(iph->ip_src)<<endl;
        cout<<inet_ntoa(iph->ip_dst)<<endl;
        unsigned int proto = (unsigned)iph->ip_p;
        if((strcmp(inet_ntoa(iph->ip_src), DEST_IP))==0)
        {
            cout<<"-----------VALID----------"<<endl;
            
            if(proto==IPPROTO_ICMP )
            {
                struct icmp *icmpHdr = (struct icmp*)(packet + 14 + 20);
                logICMPHeader(icmpHdr);
            }
            
        }
        else
            cout<<"-----------INVALID----------"<<endl;
        
    }
    else
    {
    }
    
    
    close(sd);
    pcap_close(handle);
    return result;
    
}

void ScanController::runProtocolScan()
{
    for(int i=0;i<totalProtocolsToScan;i++)
    {
        int protocolNumnber = this->protocolNumbersToScan[i];
        cout<<"Scanning Protocol :"<<protocolNumnber<<endl;
        ProtocolScanRequest newReq;
        newReq.protocolNumber = protocolNumnber;
        ProtocolScanResult res = runScanForProtocol(newReq);
    }
}




void ScanController::populateProtocolNumberToScan()
{
    this->totalPortsToScan = 0;
    for(int i=6;i<7;i++)
    {
        this->protocolNumbersToScan[this->totalProtocolsToScan++]=i;
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
    
    
    //// Set pcap parameters
    
    char *dev, errBuff[50];
    if(LOCALHST == 0)
        dev = pcap_lookupdev(errBuff);
    else if(LOCALHST == 1 && APPLE ==1)
        dev = "lo0";
    else if(LOCALHST == 1 && APPLE ==0)
        dev = "lo";
    //#endif
    cout<<dev;
    
    
    pcap_t *handle;
    
    
    struct bpf_program fp;
    
    //set filter exp depending upon source port
    char filter_exp[] = "adkjdw";
    sprintf(filter_exp,"icmp",SRC_IP);
    cout<<"\n FILTER EXP "<<filter_exp;
    
    bpf_u_int32 mask;
    bpf_u_int32 net;
    
    if (pcap_lookupnet(dev, &net, &mask, errBuff) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }
    handle = pcap_open_live(dev, 65535, 1, 2000, errBuff);
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
    
    
    //IMP
    udp.uh_sport = htons(SRC_PORT);
    udp.uh_dport = htons(kRequest.destPort);
    udp.uh_ulen = htons(8);
    
    udp.uh_sum = 0;
    udp.uh_sum = in_cksum_udp(ip.ip_src.s_addr, ip.ip_dst.s_addr, (unsigned short *)&udp, sizeof(udp));
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
    
    
    //RECV
    struct pcap_pkthdr header;
    const u_char *recPakcet ;//= pcap_next(handle, &header);
    
    while((recPakcet = pcap_next(handle, &header))!=NULL){
        if(recPakcet!=NULL)
        {
            cout<<"\nGOt UDP Packet response\n";
            printf("\nJacked a packet with length of [%d]\n", header.caplen);
            struct ip *iph = (struct ip*)(recPakcet+14);
            logIpHeader(iph);
            if((unsigned int)iph->ip_p == IPPROTO_ICMP)
            {
                struct icmp *icmpHeader = (struct icmp*)(recPakcet + 14 + 20);
                logICMPHeader(icmpHeader);
                //check is valid icmp is present
                status.udp_portState=   kFiltered;
                
                unsigned int code = (unsigned int)icmpHeader->icmp_code;
                unsigned int type = (unsigned int)icmpHeader->icmp_type;
                if(type==3 && (code==1 || code==2 || code==3 || code==9 || code ==10 || code==13))
                    status.udp_portState = kFiltered;
                
                //                struct ip* i_ip = (struct ip*)(packet + 14+20+8);
                //                logIpHeader(i_ip);
                
                
                
                
            }
            
            
        }
        else
        {
            status.udp_portState = kOpenORFiltered;
        }
        
        
    }
    
    
    
    
    
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
    if(LOCALHST == 0)
        dev = pcap_lookupdev(errBuff);
    else if(LOCALHST == 1 && APPLE ==1)
        dev = "lo0";
    else if(LOCALHST == 1 && APPLE ==0)
        dev = "lo";
    // cout<<dev;
    
    
    pcap_t *handle;
    
    
    struct bpf_program fp;
    
    //set filter exp depending upon source port
    char filter_exp[] = "icmp || dst port ";
    sprintf(filter_exp,"icmp || dst port %d",5678);
    // cout<<"\n FILTER EXP "<<filter_exp;
    
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
        struct ip *iph = (struct ip*)(recPakcet + 14);
        logIpHeader(iph);
        
        //check is protocol is TCP
        if((unsigned int)iph->ip_p == IPPROTO_TCP)
        {
            struct tcphdr *tcpHdr = (struct tcphdr*)(recPakcet + 34);
            logTCPHeader(tcpHdr);
            
            //check if src and destination ports are valid
            //get which flags are set in the response
            unsigned char flags = tcpHdr->th_flags;
            
            
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
        else if((unsigned int)iph->ip_p == IPPROTO_ICMP)
        {
            //Handle ICMP packets
            
            cout<<"\n.......GOT ICMP FOR TCP";
            struct icmp *icmph = (struct icmp*)(recPakcet + 14 + 20);
            unsigned int code = (unsigned int)icmph->icmp_code;
            unsigned int type = (unsigned int)icmph->icmp_type;
            logICMPHeader(icmph);
            switch (kRequest.scanType) {
                case SYN_SCAN:
                {
                    if(type==3 && (code==1 || code==2 || code==3 || code==9 || code==10 || code==13))
                        status.tcp_portState = kFiltered;
                }
                    break;
                    
                case ACK_SCAN:
                {
                    if(type==3 && (code==1 || code==2 || code==3 || code==9 || code==10 || code==13))
                        status.tcp_portState = kFiltered;
                }
                    break;
                    
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
        if(kRequest.scanType == SYN_SCAN)
            status.tcp_portState = kFiltered;
        if(kRequest.scanType == ACK_SCAN)
            status.tcp_portState = kFiltered;
        
    }
    
    //close socket
    close(sd);
    //close pcap session
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



char *getStringForPortState(portStates kState)
{
    
    char *str = "Not Used";
    switch (kState) {
        case kOpen:str="open";break;
        case kClosed:str="closed";break;
        case kCloedAndFiltered: str="closed and filtered";break;
        case kFiltered: str="filtered"; break;
        case kUnkown: str="unknown"; break;
        case kUnFiltered: str="unfiltered"; break;
        case kNoResposne: str="no response"; break;
        case kOpenORFiltered: str="open or filtered"; break;
        case kClosedAndUnfiltered: str="closed or filtered"; break;
        case kOpenAndFiltered: str="open and filtered"; break;
        case kOpenAndUnfiltered: str="open and unfiltered"; break;
        default:break;
    }
    return str;
}



void printScanResultForPort(AllScanResultForPort kResult)
{
    cout<<endl<<"-----------------------------------------"<<endl;
    cout<<"\nPORT : "<<kResult.portNo;
    cout<<"\nSYN  : "<<getStringForPortState(kResult.synState);
    cout<<"\nACK  : "<<getStringForPortState(kResult.ackState);
    cout<<"\nNULL : "<<getStringForPortState(kResult.nullState);
    cout<<"\nFIN  : "<<getStringForPortState(kResult.finState);
    cout<<"\nXMAS : "<<getStringForPortState(kResult.xmasState);
    cout<<endl<<"-----------------------------------------"<<endl;
    
    
}



void ScanController::scanPorts()
{
    
    
    
    //for each port run TCP and UDP scan
    this->allPortsScanResultIndex = 0;
    for (int index = 0 ;index < this->totalPortsToScan; index++)
    {
        
        ScanResult syn_result;
        ScanResult ack_result;
        ScanResult null_result;
        ScanResult fin_result;
        ScanResult xmas_result;
        ScanResult udp_result;
        AllScanResultForPort scanResults;
        scanResults.synState = kNotUsed;
        scanResults.ackState = kNotUsed;
        scanResults.nullState = kNotUsed;
        scanResults.finState = kNotUsed;
        scanResults.xmasState = kNotUsed;
        scanResults.udpState = kNotUsed;
        
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
        
        if(this->typeOfScans[UDP_SCAN]==1)
        {
            ScanRequest udpReq = createScanRequestFor(SRC_PORT, port, this->sourceIP, this->targetIP, UDP_SCAN);
            udp_result = runUDPScan(udpReq);
            scanResults.udpState = udp_result.udp_portState;
            
        }
        
        
        
        
        this->allPortsScanResult[this->allPortsScanResultIndex++] = scanResults;
        printScanResultForPort(scanResults);
        
        
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

void ScanController::setUpJobsAndJobDistribution()
{
    
    totalJobs = this->totalPortsToScan;
    
    for(int jobId=0;jobId<this->totalPortsToScan;jobId++)
    {
        
        int destport = this->portsToScan[jobId];
        
        Job newJob;
        newJob.jobId = jobId;
        newJob.type = kPortScan;
        newJob.srcPort = SRC_PORT;
        newJob.desPort = destport;
        newJob.srcIp = this->sourceIP;
        newJob.desIp = this->targetIP;
        newJob.scanTypeToUse[SYN_SCAN] = this->typeOfScans[SYN_SCAN];
        newJob.scanTypeToUse[ACK_SCAN] = this->typeOfScans[ACK_SCAN];
        newJob.scanTypeToUse[FIN_SCAN] = this->typeOfScans[FIN_SCAN];
        newJob.scanTypeToUse[NULL_SCAN] = this->typeOfScans[NULL_SCAN];
        newJob.scanTypeToUse[XMAS_SCAN] = this->typeOfScans[XMAS_SCAN];
        newJob.scanTypeToUse[UDP_SCAN] = this->typeOfScans[UDP_SCAN];
        newJob.scanTypeToUse[PROTO_SCAN] = this->typeOfScans[PROTO_SCAN];
        //        newJob.result
        
        allJobs[jobId]=newJob;
        
    }
    
    
    int jobsPerWorker = totalJobs/MAX_WORKERS;
    int temp_totalJobs = totalJobs;
    for (int workerId =0; workerId<MAX_WORKERS; workerId++) {
        
        
        Worker newWorker;
        newWorker.workerId = workerId;
        
        int startindex = workerId*jobsPerWorker;
        int endindex=-1;
        if(workerId==(MAX_WORKERS-1))//last worker check  remaining jobs
        {
            endindex = totalJobs-1;
            temp_totalJobs = temp_totalJobs - temp_totalJobs;
        }
        else{
            endindex = startindex + jobsPerWorker-1;
            temp_totalJobs = temp_totalJobs - jobsPerWorker;
        }
        
        
        
        workDistribution[workerId][JOB_START_INDEX] = startindex;
        workDistribution[workerId][JOB_END_INDEX] =  endindex;
        workDistribution[workerId][JOB_CURRENT_INDEX] = NOT_STARTED;
    }
    
    
    
    
}


Job* getBonusJobForWorker(int kWorkerId)
{
    Job nJob;
    Job *nextJob = NULL;
    for(int wkr=0;wkr<MAX_WORKERS;wkr++)
    {
        if(kWorkerId!=wkr)
            //look for pending jobs of other workers
        {
            int currJob = workDistribution[wkr][JOB_CURRENT_INDEX];
            int startJob = workDistribution[wkr][JOB_START_INDEX];
            int endJob = workDistribution[wkr][JOB_END_INDEX];
            if(currJob<endJob)
            {
                if(currJob==-1)
                    currJob = startJob;
                else
                    currJob++;
                nJob = allJobs[currJob];
                nextJob = &nJob;
                workDistribution[wkr][JOB_CURRENT_INDEX] = currJob;
                break;
            }
        }
    }
    return nextJob;
    
}


Job*  ScanController::getNextJob(int kWorkerId)
{
    Job nJob;
    Job *nextJob = NULL;

    pthread_mutex_lock(&kMutex);

    int curretJob = workDistribution[kWorkerId][JOB_CURRENT_INDEX];
    int startJob = workDistribution[kWorkerId][JOB_START_INDEX];
    int endJob = workDistribution[kWorkerId][JOB_END_INDEX];
    
    //when this is the first job
    if(!(curretJob == endJob))
    {
        if(curretJob==-1)
            curretJob = startJob;
        else
            curretJob++;

            workDistribution[kWorkerId][JOB_CURRENT_INDEX] = curretJob;
        nJob = allJobs[curretJob];
        nextJob = &nJob;
        
    }
    else if(curretJob == endJob)
    {
        //all jobs are complete look for additional job
        //nextJob =getBonusJobForWorker(kWorkerId);
    }
    pthread_mutex_unlock(&kMutex);

    return nextJob;
    
}


void submitJob(Job *)
{
    
}
void printJobInfo(Job *kJob, int wrk)
{
    //cout<<"\n-------Printing job info for worker :"<<wrk<<"---------------";
    cout<<"\n PORT : "<<kJob->desPort<<": "<<wrk;
    cout<<"\n----------------";

}

void* handleJob(void *arg)
{

    
    int myId = ((Worker *)arg)->workerId;
    cout<<"\nI am worker"<<myId<<endl;
    Job *nextJob = NULL;
    sleep(1);
    while (1) {
        nextJob = sharedInstance->getNextJob(myId);
        if(nextJob != NULL)
        printJobInfo(nextJob,myId);
        if(nextJob == NULL)
            break;
        

    }
    pthread_exit(arg);
}

void ScanController::scanPortsWithThread()
{
    
    pthread_mutex_init(&kMutex, NULL);
 //   kMutex = PTHREAD_MUTEX_INITIALIZER;
    int j[MAX_WORKERS];
    for (int i=0; i<MAX_WORKERS; i++) {
        j[i] = i;
        pthread_create(&allWorkerThreads[i], NULL, handleJob, (void*)&j[i]);
        
    }
    
    void *result;
    
    for(int i=0; i<MAX_WORKERS;i++)
    {
        pthread_join(allWorkerThreads[i], &result);
        cout<<"\n Exit : "<<*(int *)result;
    }
    
}