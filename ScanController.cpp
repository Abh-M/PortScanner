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



Job allJobs[MAX_PORTS+MAX_PROTOCOL_NUMBERS];
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
pthread_mutex_t k_syn_mutex;
pthread_mutex_t k_request_mutex;
pthread_mutex_t k_nextJob_mutex;
void submitJob(Job kJob);
void printProtocolScanResult(ProtocolScanResult kResult);



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
    this->sourceIP = new char[15]();
    
    
    //ignore this
    this->scanLocalhost = true;
    
    //by default no thread spawning
    this->spawnThreads = false;
    
    
    this->fileName = false;
    
    
    //get host ip address and dev string for localhost and other interface
    
    hostDevAndIp = getMyIpAddress();
    setTargetIPAddress(hostDevAndIp.localHost_ip);
    populatePortsList();
    
    
    
    //populate protocol numbers to scan by default
    populateProtocolNumberToScan();
    
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


void ScanController::setSrcAndDesAndDevString(bool islocalhost, char *kDestIp)
{
    if(islocalhost)
    {
        this->devString = hostDevAndIp.localhost_dev;
        this->sourceIP = hostDevAndIp.localHost_ip;
        this->targetIP = hostDevAndIp.localHost_ip;
    }
    else if(!islocalhost && kDestIp!=NULL)
    {
        this->devString = hostDevAndIp.dev;
        this->sourceIP = hostDevAndIp.ip;
        this->targetIP = kDestIp;
        
    }
    else
    {
        cout<<"\n Invalid Ip addresses";
    }
    
}

void ScanController::setTargetIPAddress(char *kTargetIp)
{
    if(strcmp(kTargetIp, hostDevAndIp.localHost_ip)==0)
    {
        //if localhost
        setSrcAndDesAndDevString(true, NULL);
        
    }
    else
    {
        setSrcAndDesAndDevString(false, kTargetIp);
        
    }
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
    int port = 0;
    this->totalPortsToScan = 0;
    for(port = 0,index = 0;port<=1024;port++)
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
    result.icmp_code = INVALID_CODE;
    result.icmp_type = INVALID_TYPE;
    //// Set pcap parameters
    
    char *dev, errBuff[50];
    dev=this->devString;
    //cout<<dev;
    
    
    pcap_t *handle;
    
    
    struct bpf_program fp;
    
    //set filter exp depending upon source port
    char filter_exp[100];
    
    sprintf(filter_exp,"icmp");
    //cout<<"\n FILTER EXP "<<filter_exp;
    
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
    int ip_id = rand()%100+1;
    const int on = 1;
    struct sockaddr_in sin;
    u_char *packet;
    
    packet = (u_char *)malloc(60);
    
    ip.ip_hl = 0x5;
    ip.ip_v = 0x4;
    ip.ip_tos = 0x0;
    ip.ip_len = 60;
    ip.ip_id = htons(ip_id);
    ip.ip_off = 0x0;
    ip.ip_ttl = 64;
    //imp
    ip.ip_p = req.protocolNumber;
    //
    ip.ip_sum = 0x0;
    //IMP
    ip.ip_src.s_addr = inet_addr(req.sourceIp);
    ip.ip_dst.s_addr =  inet_addr(req.destIp);
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
        //cout<<"SCANNIN XXXX ICMP"<<endl;
    }
    else if(ip.ip_p == IPPROTO_TCP)
    {
        //cout<<"SCANNIN XXXX TCP"<<endl;
        struct tcphdr tcp;
        tcp.th_sport = htons(req.srcPort);
        tcp.th_dport = htons(80);
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
        
        //cout<<"SCANNIN XXXX UDP"<<endl;
        udp.uh_sport = htons(req.srcPort);
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
        
        unsigned int proto = (unsigned)iph->ip_p;
        if((strcmp(inet_ntoa(iph->ip_src), req.destIp))==0)
        {
            if(proto==IPPROTO_ICMP )
            {
                cout<<"\n Protocol Number "<<req.protocolNumber<<endl;
                struct icmp *icmpHdr = (struct icmp*)(recPakcet  + 20 + 14);
                struct ip *p =(struct ip*)(recPakcet+14+20+8);
                cout<<"\n....."<<ntohs(p->ip_id)<<"----"<<ip_id;
                if(ntohs(p->ip_id)==ip_id)
                {
                    logICMPHeader(icmpHdr);
                    logIpHeader(p);
                    result.icmp_code = (unsigned int)icmpHdr->icmp_code;
                    result.icmp_type = (unsigned int)icmpHdr->icmp_type;
                }


            }
            else{
                cout<<"\n Other Protocol Number "<<proto;
            }
        }
        else
        {
            cout<<"\n Invalid  packet";
            result.protocolSupported = false;
        }
        
    }
    else //no packet recieved
    {
        cout<<"\n Did not recieve packet";
        result.protocolSupported = false;
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





void ScanController::populateProtocolNumberToScan(int kProtocolNumbersList[MAX_PROTOCOL_NUMBERS])
{
    this->totalProtocolsToScan=0;
    int index=0;
    int protocolNumber;
    while ((protocolNumber=kProtocolNumbersList[index])!=-1) {
        this->protocolNumbersToScan[index]=protocolNumber;
        index++;
        this->totalProtocolsToScan++;
    }
}

void ScanController::populateProtocolNumberToScan()
{
    
    //by default scan protocol number from 0-255
    this->totalProtocolsToScan = 0;
    for(int i=0;i<256;i++)
        this->protocolNumbersToScan[this->totalProtocolsToScan++]=i;
}
void ScanController::startScan()
{
    
    //set up jobs
    //route according to spawn threads flag
    if(this->spawnThreads==true)
    {
        this->totalWorkers = MAX_WORKERS;
        setUpJobsAndJobDistribution();
        scanPortsWithThread();
        
        //distribute work
        
    }
    else if(this->spawnThreads == false)
    {
        this->totalWorkers = NO_WORKERS;
        setUpJobsAndJobDistribution();
        scanPorts();
        //dont distribute work
        
    }
    
    
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
    //    if(LOCALHST == 0)
    //        dev = pcap_lookupdev(errBuff);
    //    else if(LOCALHST == 1 && APPLE ==1)
    //        dev = "lo0";
    //    else if(LOCALHST == 1 && APPLE ==0)
    //        dev = "lo";
    //#endif
    dev = this->devString;
    cout<<dev;
    
    
    pcap_t *handle;
    
    
    struct bpf_program fp;
    
    //set filter exp depending upon source port
    char filter_exp[] = "adkjdw";
    sprintf(filter_exp,"icmp",this->sourceIP);
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
    ip.ip_src.s_addr = inet_addr(this->sourceIP);
    ip.ip_dst.s_addr =  inet_addr(this->targetIP);
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
    status.srcPort = kRequest.srcPort;
    status.destPort = kRequest.destPort;
    status.srcIp = kRequest.sourceIp;
    status.destIp = kRequest.destIp;
    status.tcp_portState = kUnkown;
    
    
    //// Set pcap parameters
    
    char *dev, errBuff[50];
    //    if(LOCALHST == 0)
    //        dev = pcap_lookupdev(errBuff);
    //    else if(LOCALHST == 1 && APPLE ==1)
    //        dev = "lo0";
    //    else if(LOCALHST == 1 && APPLE ==0)
    //        dev = "lo";
    // cout<<dev;
    
    dev=this->devString;
    
    
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
    int tcp_seq = rand()%100+1;
    int ip_id = rand()%100+1;
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
    ip.ip_id = htons(ip_id);
    ip.ip_off = 0x0;
    ip.ip_ttl = 64;
    ip.ip_p = IPPROTO_TCP;
    ip.ip_sum = 0x0;
    ip.ip_src.s_addr = inet_addr(kRequest.sourceIp);
    ip.ip_dst.s_addr = inet_addr(kRequest.destIp);
    ip.ip_sum = in_cksum((unsigned short *)&ip, sizeof(ip));
    memcpy(packet, &ip, sizeof(ip));
    
    tcp.th_sport = htons(kRequest.srcPort);
    //Set dest port
    tcp.th_dport = htons(kRequest.destPort);
    tcp.th_seq = htonl(tcp_seq);
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
    
    
    //wait for 1 sec for response
    time_t start, end;
    double diff;
    time(&start);
    while (1) {
        time(&end);
        diff = difftime(end, start);
        if(diff>=2.00000)
            break;
    }
    
    
    
    
    struct pcap_pkthdr header;
    const u_char *recPakcet = pcap_next(handle, &header);
    if(recPakcet!=NULL)
    {
        struct ip *iph = (struct ip*)(recPakcet + 14);
        //logIpHeader(iph);
        
        //check is protocol is TCP
        if((unsigned int)iph->ip_p == IPPROTO_TCP)
        {
            struct tcphdr *tcpHdr = (struct tcphdr*)(recPakcet + 34);
            //check whether response is valid by comparing seq numbers and ack numbers
            unsigned long int ack = ntohl(tcpHdr->th_ack);
            if(ack==tcp_seq+1)
            {
                //logTCPHeader(tcpHdr);
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
            
            
        }
        else if((unsigned int)iph->ip_p == IPPROTO_ICMP)
        {
            //Handle ICMP packets
            
            //cout<<"\n.......GOT ICMP FOR TCP";
            struct icmp *icmph = (struct icmp*)(recPakcet + 14 + 20);
            unsigned int code = (unsigned int)icmph->icmp_code;
            unsigned int type = (unsigned int)icmph->icmp_type;
            //logICMPHeader(icmph);
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
    pthread_mutex_lock(&k_request_mutex);
    ScanRequest newRequest;
    newRequest.srcPort = srcPort;
    newRequest.destPort = destPort;
    newRequest.sourceIp = srcIp;
    newRequest.destIp = destIp;
    newRequest.scanType = kScanType;
    pthread_mutex_unlock(&k_request_mutex);
    return newRequest;
    
    
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


void printProtocolScanResult(ProtocolScanResult kResult)
{
    cout<<endl<<"-----------------------------------------"<<endl;
    cout<<"\nProtocol Number : "<<kResult.protocolNumber;
    if(kResult.icmp_type != INVALID_TYPE && kResult.icmp_code != INVALID_CODE)
        cout<<"\n ICMP type: "<<kResult.icmp_type<<" code :"<<kResult.icmp_code;
    if(kResult.protocolSupported)
        cout<<" : Protocol  Supported";
    else
        cout<<" : Protocol Not Supported";
    cout<<endl<<"\n-----------------------------------------"<<endl;
    
    
}


void ScanController::scanPorts()
{
    
    
    
    //for each port run TCP and UDP scan
    //this->allPortsScanResultIndex = 0;
    
    for(int index=0;index<totalJobs;index++)
    {
        Job nextJob = allJobs[index];
        
        //if job is port scan
        if(nextJob.type == kPortScan)
        {
            nextJob.result.portNo = nextJob.desPort;
            nextJob.result.synState = kNotUsed;
            nextJob.result.ackState = kNotUsed;
            nextJob.result.finState = kNotUsed;
            nextJob.result.xmasState = kNotUsed;
            nextJob.result.nullState = kNotUsed;
            
            
            //check which type of scans to be carried out
            
            if(nextJob.scanTypeToUse[SYN_SCAN]==1)
            {
                //cout<<"\nInside SYN";
                ScanRequest synRequest = createScanRequestFor(nextJob.srcPort, nextJob.desPort, nextJob.srcIp, nextJob.desIp,SYN_SCAN);
                ScanResult synResult = sharedInstance->runTCPscan(synRequest);
                nextJob.result.synState = synResult.tcp_portState;
                //                    cout<<"\n SYN Scanned By : "<<myId<<"  "<<synResult.srcIp<<"---"<<synResult.destIp<<" dd "<<synResult.destPort<<" rr "<<getStringForPortState(synResult.tcp_portState);
            }
            
            if(nextJob.scanTypeToUse[FIN_SCAN]==1)
            {
                // cout<<"\nInside FIN";
                ScanRequest finRequest = createScanRequestFor(nextJob.srcPort, nextJob.desPort, nextJob.srcIp, nextJob.desIp,FIN_SCAN);
                ScanResult finResult = sharedInstance->runTCPscan(finRequest);
                nextJob.result.finState = finResult.tcp_portState;
                //                    cout<<"\n-FIN Scanned By : "<<myId<<"  "<<finResult.srcIp<<"---"<<finResult.destIp<<" dd "<<finResult.destPort<<" rr "<<getStringForPortState(finResult.tcp_portState);
            }
            if(nextJob.scanTypeToUse[ACK_SCAN]==1)
            {
                // cout<<"\nInside FIN";
                ScanRequest ackRequest = createScanRequestFor(nextJob.srcPort, nextJob.desPort, nextJob.srcIp, nextJob.desIp,ACK_SCAN);
                ScanResult ackResult = sharedInstance->runTCPscan(ackRequest);
                nextJob.result.ackState = ackResult.tcp_portState;
                //                    cout<<"\n--ACK Scanned By : "<<myId<<"  "<<ackResult.srcIp<<"---"<<ackResult.destIp<<" dd "<<ackResult.destPort<<" rr "<<getStringForPortState(ackResult.tcp_portState);
            }
            if(nextJob.scanTypeToUse[NULL_SCAN]==1)
            {
                // cout<<"\nInside FIN";
                ScanRequest nullRequest = createScanRequestFor(nextJob.srcPort, nextJob.desPort, nextJob.srcIp, nextJob.desIp,NULL_SCAN);
                ScanResult nullResult = sharedInstance->runTCPscan(nullRequest);
                nextJob.result.nullState = nullResult.tcp_portState;
                //                    cout<<"\n---NULL Scanned By : "<<myId<<"  "<<nullResult.srcIp<<"---"<<nullResult.destIp<<" dd "<<nullResult.destPort<<" rr "<<getStringForPortState(nullResult.tcp_portState);
            }
            if(nextJob.scanTypeToUse[XMAS_SCAN]==1)
            {
                // cout<<"\nInside FIN";
                ScanRequest xmasRequest = createScanRequestFor(nextJob.srcPort, nextJob.desPort, nextJob.srcIp, nextJob.desIp,XMAS_SCAN);
                ScanResult xmasResult = sharedInstance->runTCPscan(xmasRequest);
                nextJob.result.xmasState = xmasResult.tcp_portState;
                //                    cout<<"\n----XMAS Scanned By : "<<myId<<"  "<<xmasResult.srcIp<<"---"<<xmasResult.destIp<<" dd "<<xmasResult.destPort<<" rr "<<getStringForPortState(xmasResult.tcp_portState);
            }
            
            
            submitJob(nextJob);
            //Job is complete submit the job
            
        }
        //else if job is protocol scan
        else if(nextJob.type == kProtocolScan)
        {
            
//            nextJob.protocolScanResult.protocolNumber = nextJob.protocolNumber;
//            ProtocolScanRequest protoScanReq;
//            protoScanReq.protocolNumber = nextJob.protocolNumber;
//            protoScanReq.srcPort = nextJob.srcPort;
//            protoScanReq.sourceIp = nextJob.srcIp;
//            protoScanReq.destIp = nextJob.desIp;
//            ProtocolScanResult protoScanResult = runScanForProtocol(protoScanReq);
//            nextJob.protocolScanResult = protoScanResult;
//            //            cout<<"\n%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"<<nextJob.protocolNumber;
//            //submitJob(nextJob);
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

void ScanController::setUpJobsAndJobDistribution()
{
    
    totalJobs = this->totalPortsToScan;
    int jobId = 0;
    for(jobId = 0;jobId<this->totalPortsToScan;jobId++)
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
        
        allJobs[jobId]=newJob;
        
    }
    cout<<"\n>>>>>>>>>"<<jobId;
    cout<<"\n-------->>>"<<this->totalProtocolsToScan;
    totalJobs = totalJobs + this->totalProtocolsToScan;
    for(int index = 0;index<this->totalProtocolsToScan;index++)
    {
        int protocolNumber = this->protocolNumbersToScan[index];
        Job newJob;
        newJob.jobId = jobId;
        newJob.type = kProtocolScan;
        newJob.srcPort = NOT_REQUIRED;
        newJob.desPort = NOT_REQUIRED;
        newJob.srcIp = this->sourceIP;
        newJob.desIp = this->targetIP;
        newJob.protocolNumber = protocolNumber;
        
        newJob.scanTypeToUse[SYN_SCAN] = NOT_REQUIRED;
        newJob.scanTypeToUse[ACK_SCAN] = NOT_REQUIRED;
        newJob.scanTypeToUse[FIN_SCAN] = NOT_REQUIRED;
        newJob.scanTypeToUse[NULL_SCAN] = NOT_REQUIRED;
        newJob.scanTypeToUse[XMAS_SCAN] = NOT_REQUIRED;
        newJob.scanTypeToUse[UDP_SCAN] = NOT_REQUIRED;
        newJob.scanTypeToUse[PROTO_SCAN] = this->typeOfScans[PROTO_SCAN];
        
        allJobs[jobId]=newJob;
        jobId++;
    }
    
    if(this->totalWorkers>NO_WORKERS)
    {
        //distribute work if number of workers is greater than zero
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


Job  ScanController::getNextJob(int kWorkerId)
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
        //nextJob = &nJob;
        
    }
    else if(curretJob == endJob)
    {
        //all jobs are complete look for additional job
        //nextJob =getBonusJobForWorker(kWorkerId);
        nJob.type = kInvalidJob;
    }
    pthread_mutex_unlock(&kMutex);
    
    return nJob;
    
}


void submitJob(Job kJob)
{
    
    pthread_mutex_lock(&kMutex);
    cout<<"\n Submitting Job"<<kJob.jobId;
    allJobs[kJob.jobId]=kJob;
    if(kJob.type == kPortScan)
        printScanResultForPort(kJob.result);
    else if(kJob.type == kProtocolScan)
        printProtocolScanResult(kJob.protocolScanResult);
    pthread_mutex_unlock(&kMutex);
    
    
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
    Job nextJob;
    while (1)
    {
        nextJob = sharedInstance->getNextJob(myId);
        
        if(nextJob.type == kInvalidJob)
            break;
        else
        {
            //cout<<"\n Job for : "<<myId<<"sip :"<<nextJob.srcIp<<" dip :"<<nextJob.desIp<<" sp ;"<<nextJob.srcPort<<" dp ;  "<<nextJob.desPort;
            if(nextJob.type == kPortScan)
            {
                //Job is of kind port scan
                //initialsize results array
                nextJob.result.portNo = nextJob.desPort;
                nextJob.result.synState = kNotUsed;
                nextJob.result.ackState = kNotUsed;
                nextJob.result.finState = kNotUsed;
                nextJob.result.xmasState = kNotUsed;
                nextJob.result.nullState = kNotUsed;
                
                //check which type of scans to be carried out
                
                if(nextJob.scanTypeToUse[SYN_SCAN]==1)
                {
                    //cout<<"\nInside SYN";
                    ScanRequest synRequest = createScanRequestFor(nextJob.srcPort, nextJob.desPort, nextJob.srcIp, nextJob.desIp,SYN_SCAN);
                    ScanResult synResult = sharedInstance->runTCPscan(synRequest);
                    nextJob.result.synState = synResult.tcp_portState;
                    //                    cout<<"\n SYN Scanned By : "<<myId<<"  "<<synResult.srcIp<<"---"<<synResult.destIp<<" dd "<<synResult.destPort<<" rr "<<getStringForPortState(synResult.tcp_portState);
                }
                
                if(nextJob.scanTypeToUse[FIN_SCAN]==1)
                {
                    // cout<<"\nInside FIN";
                    ScanRequest finRequest = createScanRequestFor(nextJob.srcPort, nextJob.desPort, nextJob.srcIp, nextJob.desIp,FIN_SCAN);
                    ScanResult finResult = sharedInstance->runTCPscan(finRequest);
                    nextJob.result.finState = finResult.tcp_portState;
                    //                    cout<<"\n-FIN Scanned By : "<<myId<<"  "<<finResult.srcIp<<"---"<<finResult.destIp<<" dd "<<finResult.destPort<<" rr "<<getStringForPortState(finResult.tcp_portState);
                }
                if(nextJob.scanTypeToUse[ACK_SCAN]==1)
                {
                    // cout<<"\nInside FIN";
                    ScanRequest ackRequest = createScanRequestFor(nextJob.srcPort, nextJob.desPort, nextJob.srcIp, nextJob.desIp,ACK_SCAN);
                    ScanResult ackResult = sharedInstance->runTCPscan(ackRequest);
                    nextJob.result.ackState = ackResult.tcp_portState;
                    //                    cout<<"\n--ACK Scanned By : "<<myId<<"  "<<ackResult.srcIp<<"---"<<ackResult.destIp<<" dd "<<ackResult.destPort<<" rr "<<getStringForPortState(ackResult.tcp_portState);
                }
                if(nextJob.scanTypeToUse[NULL_SCAN]==1)
                {
                    // cout<<"\nInside FIN";
                    ScanRequest nullRequest = createScanRequestFor(nextJob.srcPort, nextJob.desPort, nextJob.srcIp, nextJob.desIp,NULL_SCAN);
                    ScanResult nullResult = sharedInstance->runTCPscan(nullRequest);
                    nextJob.result.nullState = nullResult.tcp_portState;
                    //                    cout<<"\n---NULL Scanned By : "<<myId<<"  "<<nullResult.srcIp<<"---"<<nullResult.destIp<<" dd "<<nullResult.destPort<<" rr "<<getStringForPortState(nullResult.tcp_portState);
                }
                if(nextJob.scanTypeToUse[XMAS_SCAN]==1)
                {
                    // cout<<"\nInside FIN";
                    ScanRequest xmasRequest = createScanRequestFor(nextJob.srcPort, nextJob.desPort, nextJob.srcIp, nextJob.desIp,XMAS_SCAN);
                    ScanResult xmasResult = sharedInstance->runTCPscan(xmasRequest);
                    nextJob.result.xmasState = xmasResult.tcp_portState;
                    //                    cout<<"\n----XMAS Scanned By : "<<myId<<"  "<<xmasResult.srcIp<<"---"<<xmasResult.destIp<<" dd "<<xmasResult.destPort<<" rr "<<getStringForPortState(xmasResult.tcp_portState);
                }
                
                
                submitJob(nextJob);
                //Job is complete submit the job
            }
        }
        
        
        
    }
    pthread_exit(arg);
}

void ScanController::scanPortsWithThread()
{
    
    pthread_mutex_init(&kMutex, NULL);
    pthread_mutex_init(&k_request_mutex, NULL);
    pthread_mutex_init(&k_syn_mutex, NULL);
    pthread_mutex_init(&k_nextJob_mutex, NULL);
    int j[MAX_WORKERS];
    for (int i=0; i<MAX_WORKERS; i++) {
        j[i] = i;
        pthread_create(&allWorkerThreads[i], NULL, handleJob, (void*)&j[i]);
        
    }
    
    void *result;
    
    for(int i=0; i<MAX_WORKERS;i++)
    {
        pthread_join(allWorkerThreads[i], &result);
        //cout<<"\n Exit : "<<*(int *)result;
    }
    
    pthread_mutex_destroy(&kMutex);
    pthread_mutex_destroy(&k_request_mutex);
    pthread_mutex_destroy(&k_syn_mutex);
    pthread_mutex_destroy(&k_nextJob_mutex);
    cout<<"\nALl Done";
    
}