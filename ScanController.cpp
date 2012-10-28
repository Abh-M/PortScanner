/*
 * ScanController.cpp
 *
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



Job allJobs[MAX_JOBS];
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
    //setTargetIPAddress(hostDevAndIp.localHost_ip);
    
    populateIpAddressToScan();
    
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


//void ScanController::setSrcAndDesAndDevString(bool islocalhost, char *kDestIp)
//{
//    if(islocalhost)
//    {
//        this->devString = hostDevAndIp.localhost_dev;
//        this->sourceIP = hostDevAndIp.localHost_ip;
//        this->targetIP = hostDevAndIp.localHost_ip;
//    }
//    else if(!islocalhost && kDestIp!=NULL)
//    {
//        this->devString = hostDevAndIp.dev;
//        this->sourceIP = hostDevAndIp.ip;
//        this->targetIP = kDestIp;
//
//    }
//    else
//    {
//        cout<<"\n Invalid Ip addresses";
//    }
//
//}

//void ScanController::setTargetIPAddress(char *kTargetIp)
//{
//    if(strcmp(kTargetIp, hostDevAndIp.localHost_ip)==0)
//    {
//        //if localhost
//        setSrcAndDesAndDevString(true, NULL);
//
//    }
//    else
//    {
//        setSrcAndDesAndDevString(false, kTargetIp);
//
//    }
//}


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

void ScanController::populateIpAddressToScan()
{
    this->allIpAddressToScan.push_back(this->hostDevAndIp.localHost_ip);
    this->devString = this->hostDevAndIp.localhost_dev;
    this->totalIpAddressToScan = (int)this->allIpAddressToScan.size();
    this->sourceIP = this->hostDevAndIp.localHost_ip;
}



void ScanController::populateIpAddressToScan(vector<string> kIpAddressList)
{
    
    if(kIpAddressList.size()==1)
    {
        const char *singleIp = kIpAddressList[0].c_str();
        if((strcmp(singleIp,this->hostDevAndIp.localHost_ip))==0)
        {
            //localhost
            //do nothing
            
        }
        else
        {
            this->totalIpAddressToScan =(int) kIpAddressList.size();
            this->allIpAddressToScan=kIpAddressList;
            this->devString = this->hostDevAndIp.dev;
            this->sourceIP = this->hostDevAndIp.ip;
            
            
        }
    }
    else
    {
        this->totalIpAddressToScan =(int) kIpAddressList.size();
        this->allIpAddressToScan=kIpAddressList;
        this->devString = this->hostDevAndIp.dev;
        this->sourceIP = this->hostDevAndIp.ip;
        
        
    }
    
}



ProtocolScanResult ScanController::runScanForProtocol(ProtocolScanRequest req)
{
    ProtocolScanResult result;
    result.protocolNumber = req.protocolNumber;
    result.protocolSupported = false;
    result.icmp_code = INVALID_CODE;
    result.icmp_type = INVALID_TYPE;
    
    
    bool isv6 = isIpV6(req.destIp);
	    
    
    
    char *dev, errBuff[50];
    bool islhost = islocalhost(req.destIp);
    int eth_fr_size;
    
    if(islhost)
    {
        dev = this->hostDevAndIp.localhost_dev;
        eth_fr_size=4;
    }
    else
    {
        dev = this->hostDevAndIp.dev;
        eth_fr_size = 14;
    }
    cout<<dev;
    
    pcap_t *handle;
    
    
    struct bpf_program fp;
    
    char filter_exp[100];
    if(isv6)
    {
        sprintf(filter_exp,"icmp6 && src host %s",req.destIp);
        
    }
    else
    {
        sprintf(filter_exp,"icmp && src host %s",req.destIp);
    }
    
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
    
    if(!isv6)
    {
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
        
        
        if(ip.ip_p == IPPROTO_ICMP)
        {
            struct icmp icmphd;
            icmphd.icmp_type = ICMP_ECHO;
            icmphd.icmp_code = 0;
            icmphd.icmp_id = 1000;
            icmphd.icmp_seq = 0;
            //icmphd.icmp_cksum = 0;
            icmphd.icmp_cksum = in_cksum((unsigned short *)&icmphd, 8);
            memcpy(packet + 20, &icmphd, 8);
            //cout<<"SCANNIN XXXX ICMP"<<endl;
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
        
        
    }
    else if(isv6)
    {
        packet = (u_char *)malloc(sizeof(struct icmp6_hdr));
        const char* des =  req.destIp;// "::1";
        struct sockaddr_in6 desa; desa.sin6_family=AF_INET6; inet_pton(AF_INET6, des, &desa.sin6_addr);
        if(req.protocolNumber == IPPROTO_ICMP)
        {
            struct icmp6_hdr icmp6hdr;
            icmp6hdr.icmp6_type = ICMP6_ECHO_REQUEST;
            icmp6hdr.icmp6_code = 0;
            icmp6hdr.icmp6_cksum = 0;
            //icmphd.icmp_cksum = in_cksum((unsigned short *)&icmphd, 8);
            memcpy(packet, &icmp6hdr, 8);
        }
        
        
        sd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
        int offset=2;
        if (setsockopt(sd, IPPROTO_IPV6, IPV6_CHECKSUM, &offset, sizeof(offset)) < 0) {
            perror("setsockopt");
            exit(1);
        }
        struct iovec iov;
        struct  msghdr msg;
        memset(&msg, 0, sizeof(struct msghdr));
        
        iov.iov_base = packet;
        iov.iov_len =sizeof(struct icmp6_hdr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_name = &desa;
        msg.msg_namelen = sizeof(desa);
        msg.msg_control = NULL;
        msg.msg_controllen=0;
        size_t res=0;
        res  =  sendmsg(sd, &msg,0);
        cout<<"\n"<<res;
        
        
        
    }
    
    
    
    
    //RECV
    struct pcap_pkthdr header;
    const u_char *recPakcet =  pcap_next(handle, &header);
    //recPakcet =  pcap_next(handle, &header);
    
    if(recPakcet!=NULL)
    {
        printf("\nJacked a packet with length of [%d]\n", header.caplen);
        
        if(isv6)
        {
            //icmpv6
            //TODO : hardcoded value of 6 is for localhost need to fix this
            struct ip6_hdr *ip6 = (struct ip6_hdr*)(recPakcet+14);
            logIP6Header(ip6);
            srcDesIpv6 ipPair = getIpPairForIp6Header(ip6);
            if(  ((strcmp(ipPair.src, req.destIp))==0) && ((strcmp(ipPair.des, req.sourceIp))==0) )
            {
                //FIX: 14 is inconsistent
                struct icmp6_hdr *icmp6 = (struct icmp6_hdr*)(recPakcet+14+40);
                logICMP6Header(icmp6);
                //check if reply
                if((unsigned short)icmp6->icmp6_type==ICMP6_ECHO_REPLY){
                    //set status
                    result.icmp_type = (unsigned short)icmp6->icmp6_type;
                    result.icmp_type = (unsigned short)icmp6->icmp6_code;
                    
                }
                else//analyze payload
                {
                    struct ip6_hdr *inner_ip6 = (struct ip6_hdr*)(recPakcet+14+40+8);
                    logIP6Header(inner_ip6);
                    //                struct udphdr *inner_udp = (struct udphdr*)(recPakcet+4+40+8+40);
                    //                if(kRequest.srcPort == ntohs(inner_udp->uh_sport)&&(kRequest.destPort)==ntohs(inner_udp->uh_dport))
                    //                {
                    //                    logUDPHeader(inner_udp);
                    //                    unsigned int code = (unsigned short)icmp6->icmp6_code;
                    //                    unsigned int type = (unsigned short)icmp6->icmp6_type;
                    //                    if(type==3 && (code==1 || code==2 || code==3 || code==9 || code ==10 || code==13))
                    //                        status.udp_portState = kFiltered;
                    //                    else{
                    //                        status.udp_portState = kUnkown;
                    //                    }
                    //
                    //                }
                    
                    
                }
            }
            
        }
        else if(!isv6)//if v4
        {
            struct ip *iph = (struct ip*)(recPakcet+14);
            cout<<"\nOuter Ip Header :";
            logIpHeader(iph);
            
            unsigned int proto = (unsigned)iph->ip_p;
            if((strcmp(inet_ntoa(iph->ip_src), req.destIp))==0)
            {
                if(proto==IPPROTO_ICMP )
                {
                    

                    struct icmp *icmpHdr = (struct icmp*)(recPakcet  + 20 + 14);
                    cout<<"\n ICMP header";
                    logICMPHeader(icmpHdr);

                    //check if reply is echo reply
                    if( (unsigned int)icmpHdr->icmp_type == 0 && (unsigned int)icmpHdr->icmp_code == 0)
                    {
                        result.icmp_code = (unsigned int)icmpHdr->icmp_code;
                        result.icmp_type = (unsigned int)icmpHdr->icmp_type;
                        result.protocolSupported = true;
                    }
                    else
                    {
                        //analyze icmp payload
                        struct ip *p =(struct ip*)(recPakcet+14+20+8);
                        cout<<"\n Inner Ip Header";
                        logIpHeader(p);
                        cout<<"\n......"<<(unsigned short)p->ip_id;
                        if( ((unsigned short)p->ip_id) == ip_id)
                        {
                            cout<<"\n valid inner ip header";
                            logIpHeader(p);
                            result.icmp_code = (unsigned int)icmpHdr->icmp_code;
                            result.icmp_type = (unsigned int)icmpHdr->icmp_type;
                        }
                    }
                }
                else if (proto == req.protocolNumber)
                {
                    cout<<"\n Other Protocol Number "<<proto;
                }
                
                
            }
        }
    }
    else //no packet recieved
    {
        cout<<"\n Did not recieve packet";
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
        /*ProtocolScanResult res = */runScanForProtocol(newReq);
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
    for(int i=0;i<50;i++)
    {
        this->protocolNumbersToScan[i]=i+1;
        this->totalProtocolsToScan++;
    }
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
    status.srcPort = kRequest.srcPort;
    status.destPort = kRequest.destPort;
    status.srcIp = kRequest.sourceIp;
    status.destIp = kRequest.destIp;
    status.udp_portState = kUnkown;
    
    
    bool isv6= isIpV6(kRequest.destIp);
    
    
    char *dev, errBuff[50];
    bool islhost = islocalhost(kRequest.destIp);
    int eth_fr_size;
    
    if(islhost)
    {
        dev = this->hostDevAndIp.localhost_dev;
        eth_fr_size=4;
    }
    else
    {
        dev = this->hostDevAndIp.dev;
        eth_fr_size = 14;
    }
    cout<<dev;
    
    
    pcap_t *handle;
    
    
    struct bpf_program fp;
    
    //set filter exp depending upon source port
    //TODO: dynamically generate pcap filter expressions
    char filter_exp[256];
    sprintf(filter_exp,"(icmp && src host %s) || (icmp6 && src host %s)",kRequest.destIp,kRequest.destIp);
    cout<<"\n FILTER EXP "<<filter_exp;
    
    bpf_u_int32 mask;
    bpf_u_int32 net;
    
    if (pcap_lookupnet(dev, &net, &mask, errBuff) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }
    handle = pcap_open_live(dev, 65535, 1, 3000, errBuff);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errBuff);
    }
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    }
    
    int kOffset = (isv6)?0:sizeof(struct ip);
    
    struct ip ip;
    struct udphdr udp;
    int sd;
    const int on = 1;
    struct sockaddr_in sin;
    u_char *packet;
    
    //depending on ip ver allocate bytes
    if(isv6)
        packet = (u_char *)malloc(sizeof(struct udphdr)); // as we do dont fill up ipv6 header
    else
        packet = (u_char *)malloc(60);
    
    int sz = sizeof(struct udphdr);
    cout<<sz;
    
    
    
    if(!isv6)
    {
        ip.ip_hl = 0x5;
        ip.ip_v = 0x4;
        ip.ip_tos = 0x0;
        ip.ip_len = 60;
        ip.ip_id = htons(12830);
        ip.ip_off = 0x0;
        ip.ip_ttl = 64;
        ip.ip_p = IPPROTO_UDP;
        ip.ip_sum = 0x0;
        ip.ip_src.s_addr = inet_addr(kRequest.sourceIp);
        ip.ip_dst.s_addr =  inet_addr(kRequest.destIp);
        ip.ip_sum = in_cksum((unsigned short *)&ip, sizeof(ip));
        memcpy(packet, &ip, sizeof(ip));
        
        udp.uh_sport = htons(kRequest.srcPort);
        udp.uh_dport = htons(kRequest.destPort);
        udp.uh_ulen = htons(8);
        udp.uh_sum = 0;
        // udp.uh_sum = in_cksum_udp(ip.ip_src.s_addr, ip.ip_dst.s_addr, (unsigned short *)&udp, sizeof(udp));
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
        
        
        
    }
    else if(isv6)
    {
        const char* des =  kRequest.destIp;// "::1";
        struct sockaddr_in6 desa; desa.sin6_family=AF_INET6; inet_pton(AF_INET6, des, &desa.sin6_addr);
        
        udp.uh_sport = htons(kRequest.srcPort);
        udp.uh_dport = htons(kRequest.destPort);
        udp.uh_ulen = htons(8);
        udp.uh_sum = 0;
        
        
        memcpy(packet, &udp, sizeof(udp));
        
        
        sd = socket(AF_INET6, SOCK_RAW, IPPROTO_UDP);
        int offset=6;
        if (setsockopt(sd, IPPROTO_IPV6, IPV6_CHECKSUM, &offset, sizeof(offset)) < 0) {
            perror("setsockopt");
            exit(1);
        }
        
        
        struct iovec iov;
        struct  msghdr msg;
        memset(&msg, 0, sizeof(struct msghdr));
        
        iov.iov_base = packet;
        iov.iov_len =sizeof(struct udphdr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_name = &desa;
        msg.msg_namelen = sizeof(desa);
        msg.msg_control = NULL;
        msg.msg_controllen=0;
        size_t res=0;
        res  =  sendmsg(sd, &msg,0);
        cout<<errno;
        cout<<"\n"<<res;
        
    }
    
    //RECV
    struct pcap_pkthdr header;
    const u_char *recPakcet =  pcap_next(handle, &header);
    
    
    if(recPakcet!=NULL)
    {
        cout<<"\nGOt UDP Packet response\n";
        printf("\nJacked a packet with length of [%d]\n", header.caplen);
        //check for icmp or icmpv6 depending
        if(isv6){
            //icmpv6
            //TODO : hardcoded value of 6 is for localhost need to fix this
            struct ip6_hdr *ip6 = (struct ip6_hdr*)(recPakcet+eth_fr_size);
            logIP6Header(ip6);
            srcDesIpv6 ipPair = getIpPairForIp6Header(ip6);
            if(  ((strcmp(ipPair.src, kRequest.destIp))==0) && ((strcmp(ipPair.des, kRequest.sourceIp))==0) )
            {
                
                struct icmp6_hdr *icmp6 = (struct icmp6_hdr*)(recPakcet+eth_fr_size+40);
                logICMP6Header(icmp6);
                struct ip6_hdr *inner_ip6 = (struct ip6_hdr*)(recPakcet+eth_fr_size+40+8);
                logIP6Header(inner_ip6);
                struct udphdr *inner_udp = (struct udphdr*)(recPakcet+eth_fr_size+40+8+40);
                if(kRequest.srcPort == ntohs(inner_udp->uh_sport)&&(kRequest.destPort)==ntohs(inner_udp->uh_dport))
                {
                    logUDPHeader(inner_udp);
                    unsigned int code = (unsigned short)icmp6->icmp6_code;
                    unsigned int type = (unsigned short)icmp6->icmp6_type;
                    if(type==3 && (code==1 || code==2 || code==3 || code==9 || code ==10 || code==13))
                        status.udp_portState = kFiltered;
                    else{
                        status.udp_portState = kUnkown;
                    }
                    
                }
            }
            
        }
        else
        {
            //icmp
            //FIX:remove hardcoding
            struct ip iip;
            struct ip *iph = (struct ip*)(recPakcet+eth_fr_size);
            iip.ip_dst = iph->ip_dst;
            iip.ip_src = iph->ip_src;
            logIpHeader(iph);
            srcDesIpv4 srcAndDes = getIpPairForIpHeader(iph);
            //cross check source and destination address
            if( (strcmp(srcAndDes.src, kRequest.destIp))==0 && (strcmp(srcAndDes.des, kRequest.sourceIp))==0)
            {
                //                    logIpHeader(iph);
                if((unsigned int)iph->ip_p == IPPROTO_ICMP)
                {
                    //FIX:remove hard-coded value
                    struct icmp *icmpHeader = (struct icmp*)(recPakcet + eth_fr_size + 20);
                    //                        logICMPHeader(icmpHeader);
                    //check is valid icmp is present
                    //                        struct ip *inner_ip = (struct ip*)(recPakcet + 14 + 20 +8);
                    //                        logIpHeader(inner_ip);
                    struct udphdr *inner_udp = (struct udphdr*)(recPakcet + eth_fr_size+20+8+20);//ether+ip+icmp+orignal ip
                    //                        logUDPHeader(inner_udp);
                    unsigned short  kk= ntohs(inner_udp->uh_dport);
                    
                    //as inner udp will have same source and dest port as the orignal request
                    if(kRequest.srcPort == ntohs(inner_udp->uh_sport)&&(kRequest.destPort)==ntohs(inner_udp->uh_dport))
                    {
                        logICMPHeader(icmpHeader);
                        logUDPHeader(inner_udp);
                        unsigned int code = (unsigned int)icmpHeader->icmp_code;
                        unsigned int type = (unsigned int)icmpHeader->icmp_type;
                        if(type==3 && (code==1 || code==2 || code==3 || code==9 || code ==10 || code==13))
                            status.udp_portState = kFiltered;
                        
                        
                    }
                    
                }
                
                
            }
            
        }
        
    }
    else
    {
        status.udp_portState = kOpenORFiltered;
    }
    
    
    
    
    
    
    
    //close socket
    //close pcap session
    
    
    close(sd);
    pcap_close(handle);
    return status;
}




ScanResult ScanController::runTCPscan(ScanRequest kRequest)
{
    
    //TODO: run ipv6 scan for and implementation of icmp6
    
    ScanResult status;
    status.srcPort = kRequest.srcPort;
    status.destPort = kRequest.destPort;
    status.srcIp = kRequest.sourceIp;
    status.destIp = kRequest.destIp;
    status.tcp_portState = kUnkown;
    
    
    bool isv6=isIpV6(kRequest.destIp);
    bool islhost = islocalhost(kRequest.destIp);
    int eth_fr_size;
    //// Set pcap parameters
    
    char *dev, errBuff[50];
    if(islhost)
    {
        dev = this->hostDevAndIp.localhost_dev;
        eth_fr_size=4;
    }
    else
    {
        dev = this->hostDevAndIp.dev;
        eth_fr_size = 14;
    }
    
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[256];
    sprintf(filter_exp,"(icmp && src host %s) || (src host %s && dst port 5678)",kRequest.destIp,kRequest.destIp);
    
    bpf_u_int32 mask;
    bpf_u_int32 net;
    
    if (pcap_lookupnet(dev, &net, &mask, errBuff) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }
    handle = pcap_open_live(dev, 65535, 1, 3000, errBuff);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errBuff);
    }
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    }
    
    struct ip ip;
    struct tcphdr tcp;
    const int on = 1;
    int tcp_seq = rand()%100+1;
    int ip_id = rand()%100+1;
    int sd;
    u_char *packet;
    if(isv6)
        packet = (u_char *)malloc(20);
    else
        packet = (u_char *)malloc(60);
    
    
    
    //create socket and set options
    tcp.th_sport = htons(kRequest.srcPort);
    tcp.th_dport = htons(kRequest.destPort);
    
    tcp.th_seq = htonl(tcp_seq);
    tcp.th_off = sizeof(struct tcphdr) / 4;
    
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
    tcp.th_win = htons(32768);
    tcp.th_sum = 0;
    
    if(!isv6)
    {
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
        
        
    }
    else if(isv6)
    {
        
        const char* des =  kRequest.destIp;// "::1";
        struct sockaddr_in6 desa; desa.sin6_family=AF_INET6; inet_pton(AF_INET6, des, &desa.sin6_addr);
        
        sd = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP);
        int offset=16;
        if (setsockopt(sd, IPPROTO_IPV6, IPV6_CHECKSUM, &offset, sizeof(offset)) < 0) {
            perror("setsockopt");
            exit(1);
        }
        
        memcpy(packet, &tcp, sizeof(tcp));
        
        struct iovec iov;
        struct  msghdr msg;
        memset(&msg, 0, sizeof(struct msghdr));
        
        iov.iov_base = packet;
        iov.iov_len =20;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_name = &desa;
        msg.msg_namelen = sizeof(desa);
        msg.msg_control = NULL;
        msg.msg_controllen=0;
        size_t res=0;
        res  =  sendmsg(sd, &msg,0);
        cout<<res;
        
    }
    
    
    
    
    //TODO: command line arg for timeout and set default value according to trial and error
    //    time_t start, end;
    //    double diff=0;
    //    time(&start);
    //    while (1) {
    //        time(&end);
    //        diff = difftime(end, start);
    //        //cout<<"\n..."<<diff;
    //        if(diff>=5.0)
    //            break;
    //    }
    
    
    
    struct pcap_pkthdr header;
    const u_char *recPakcet = pcap_next(handle, &header);
    if(recPakcet!=NULL)
    {
        
        bool isTcp = false;
        bool isIcmp = false;
        bool isicmp6 = false;
        int ip_hdr_size = 0;
        
        
        if(isv6)
        {
            struct ip6_hdr *v6hdr;
            v6hdr = (struct ip6_hdr*)(recPakcet+eth_fr_size);
            if((v6hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_TCP))
            {
                isTcp = true;
                isIcmp = false;
                isicmp6 = false;
            }
            else if((v6hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_TCP))
            {
                isTcp = false;
                isIcmp = false;
                isicmp6 = true;
            }
            
            
            ip_hdr_size = sizeof(struct ip6_hdr);
            logIP6Header(v6hdr);
        }
        else{
            //logIpHeader(iph);
            
            
            struct ip *iph = (struct ip*)(recPakcet + eth_fr_size);
            isTcp = ((unsigned int)iph->ip_p == IPPROTO_TCP);
            isIcmp = ((unsigned int)iph->ip_p == IPPROTO_ICMP);
            ip_hdr_size = sizeof(struct ip);
            logIpHeader(iph);
            
        }
        if(isTcp)
        {
            //TODO : hardcode value of will change is this is ipv6
            struct tcphdr *tcpHdr = (struct tcphdr*)(recPakcet + ip_hdr_size +eth_fr_size);
            logTCPHeader(tcpHdr);
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
        //        else if((unsigned int)iph->ip_p == IPPROTO_ICMP)
        else if(isIcmp)
        {
            //Handle ICMP packets
            //check if captured icmp is valid
            //TODO:: remove hardcoded values for header lengths
            struct icmp *icmph = (struct icmp*)(recPakcet + eth_fr_size + ip_hdr_size);
            //            cout<<endl<<"-";
            logICMPHeader(icmph);
            struct ip *inner_ip = (struct ip*)(recPakcet+eth_fr_size+ip_hdr_size+8);
            //            cout<<endl<<"--";
            logIpHeader(inner_ip);
            struct tcphdr *inner_tcp  = (struct tcphdr*)(recPakcet + eth_fr_size + ip_hdr_size + 28);
            //            cout<<endl<<"---";
            logTCPHeader(inner_tcp);
            int inner_seq = ntohl(inner_tcp->th_seq);
            if(inner_seq == tcp_seq)
            {
                //valid icmp
                unsigned int code = (unsigned int)icmph->icmp_code;
                unsigned int type = (unsigned int)icmph->icmp_type;
                //                cout<<endl<<"----";
                logICMPHeader(icmph);
                switch (kRequest.scanType)
                {
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
        else if(isicmp6 == true)
        {
            //FIX:add icmp6 processing
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






void printScanResultForPort(AllScanResultForPort kResult, const char *ip)
{
    cout<<"\n Scan Result IP : "<<ip<<" PORT : "<<kResult.portNo;
    cout<<" |SYN  : "<<getStringForPortState(kResult.synState);
    cout<<" |ACK  : "<<getStringForPortState(kResult.ackState);
    cout<<" |NULL : "<<getStringForPortState(kResult.nullState);
    cout<<" |FIN  : "<<getStringForPortState(kResult.finState);
    cout<<" |XMAS : "<<getStringForPortState(kResult.xmasState);
}


void printProtocolScanResult(ProtocolScanResult kResult)
{
    //cout<<endl<<"-----------------------------------------"<<endl;
    cout<<"\nProtocol Number : "<<kResult.protocolNumber;
    if(kResult.icmp_type != INVALID_TYPE && kResult.icmp_code != INVALID_CODE)
        cout<<"\n ICMP type: "<<kResult.icmp_type<<" code :"<<kResult.icmp_code;
    if(kResult.protocolSupported)
        cout<<" : Protocol  Supported";
    else
        cout<<" : Protocol Not Supported";
    //cout<<endl<<"\n-----------------------------------------"<<endl;
    
    
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
            if(nextJob.protocolNumber == IPPROTO_TCP)
            {
                //For all ports gather scanresult for all types of scan
                //                ProtocolScanResult tcpScanResult;
                //                tcpScanResult.totalPortsScannedForProtocol = nextJob.totalPortsForProtocolScan;
                for(int index = 0;index<nextJob.totalPortsForProtocolScan;index++)
                {
                    //for all ports do all types of tcp scan;
                    AllScanResult allScanTypeResultForPort;
                    int portNo = nextJob.portsForProtocolScan[index];
                    allScanTypeResultForPort.portNo = portNo;
                    
                    //FIX: only SYN scan for port is done
                    //TODO: other types of scans needs to be done;
                    ScanRequest synRequest = createScanRequestFor(nextJob.srcPort, portNo, nextJob.srcIp, nextJob.desIp,SYN_SCAN);
                    ScanResult synResult = sharedInstance->runTCPscan(synRequest);
                    allScanTypeResultForPort.synState = synResult.tcp_portState;
                    nextJob.protocolScanResult.tcpOrUdpPortScans.tcpProtoPortsScanResult[index]=allScanTypeResultForPort;
                    
                }
                
            }
            else if(nextJob.protocolNumber == IPPROTO_UDP)
            {
                //For all ports gather result for UDP scan result
                //                ProtocolScanResult  udpScanResult;
                //                udpScanResult.totalPortsScannedForProtocol = nextJob.totalPortsForProtocolScan;
                for(int index=0;index<nextJob.totalPortsForProtocolScan;index++)
                {
                    
                    int portNo = nextJob.portsForProtocolScan[index];
                    AllScanResult scanResultForUDPport;
                    scanResultForUDPport.portNo = portNo;
                    
                    ScanRequest udpScanReq = createScanRequestFor(nextJob.srcPort, portNo, nextJob.srcIp, nextJob.desIp,UDP_SCAN);
                    ScanResult udpScanResultForPort = sharedInstance->runUDPScan(udpScanReq);
                    scanResultForUDPport.udpState = udpScanResultForPort.udp_portState;
                    nextJob.protocolScanResult.tcpOrUdpPortScans.udpPortsScanResult[index]=scanResultForUDPport;
                }
                
            }
            else if(nextJob.protocolNumber <= IPPROTO_MAX && nextJob.protocolNumber!=IPPROTO_TCP && nextJob.protocolNumber!=IPPROTO_UDP)//for other protocols including ICMP
            {
                //not port is involved
                nextJob.protocolScanResult.protocolNumber = nextJob.protocolNumber;
                ProtocolScanRequest protoScanReq;
                protoScanReq.protocolNumber = nextJob.protocolNumber;
                protoScanReq.srcPort = nextJob.srcPort;
                protoScanReq.sourceIp = nextJob.srcIp;
                protoScanReq.destIp = nextJob.desIp;
                ProtocolScanResult protoScanResult = runScanForProtocol(protoScanReq);
                nextJob.protocolScanResult = protoScanResult;
                
            }
            submitJob(nextJob);
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
    
    totalJobs = 0;
    int jobId = 0;
    for (int i=0; i<this->totalIpAddressToScan; i++) {
        const char *nextIp = this->allIpAddressToScan[i].c_str();
        
        totalJobs = totalJobs+this->totalPortsToScan;//+this->totalProtocolsToScan;
        for(int portIndex=0;portIndex<totalPortsToScan;portIndex++)
        {
            int destPort = this->portsToScan[portIndex];
            Job newJob;
            newJob.jobId = jobId;
            newJob.type = kPortScan;
            //TODO: remove hard coding for SRC_PORT
            newJob.srcPort = SRC_PORT;
            newJob.desPort = destPort;
            newJob.srcIp = this->sourceIP;
            newJob.desIp = (char*)nextIp;
            newJob.scanTypeToUse[SYN_SCAN] = this->typeOfScans[SYN_SCAN];
            newJob.scanTypeToUse[ACK_SCAN] = this->typeOfScans[ACK_SCAN];
            newJob.scanTypeToUse[FIN_SCAN] = this->typeOfScans[FIN_SCAN];
            newJob.scanTypeToUse[NULL_SCAN] = this->typeOfScans[NULL_SCAN];
            newJob.scanTypeToUse[XMAS_SCAN] = this->typeOfScans[XMAS_SCAN];
            newJob.scanTypeToUse[UDP_SCAN] = NOT_REQUIRED;
            newJob.scanTypeToUse[PROTO_SCAN] = NOT_REQUIRED;
            allJobs[jobId]=newJob;
            jobId++;
            
            
        }
        
        totalJobs = totalJobs + this->totalProtocolsToScan;
        
        for(int portNoIndex=0;portNoIndex<this->totalProtocolsToScan;portNoIndex++)
        {
            int proto = this->protocolNumbersToScan[portNoIndex];
            Job newJob;
            newJob.jobId =jobId;
            newJob.type = kProtocolScan;
            if(proto == IPPROTO_TCP || proto == IPPROTO_UDP)
            {
                memcpy(newJob.portsForProtocolScan, this->portsToScan, this->totalPortsToScan);
                newJob.totalPortsForProtocolScan = this->totalPortsToScan;
            }
            else
                newJob.totalPortsForProtocolScan = -1;
            
            newJob.srcIp = this->sourceIP;
            newJob.desIp = (char*)nextIp;
            
            newJob.srcPort = SRC_PORT;
            newJob.desPort = NOT_REQUIRED;
            
            newJob.protocolNumber = proto;
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
        
    }
    cout<<"\n Total Jobs"<<totalJobs;
    
    //    totalJobs = this->totalPortsToScan;
    //    int jobId = 0;
    //    for(jobId = 0;jobId<this->totalPortsToScan;jobId++)
    //    {
    //
    //        int destport = this->portsToScan[jobId];
    //
    //        Job newJob;
    //        newJob.jobId = jobId;
    //        newJob.type = kPortScan;
    //        newJob.srcPort = SRC_PORT;
    //        newJob.desPort = destport;
    //        newJob.srcIp = this->sourceIP;
    //        newJob.desIp = this->targetIP;
    //        newJob.scanTypeToUse[SYN_SCAN] = this->typeOfScans[SYN_SCAN];
    //        newJob.scanTypeToUse[ACK_SCAN] = this->typeOfScans[ACK_SCAN];
    //        newJob.scanTypeToUse[FIN_SCAN] = this->typeOfScans[FIN_SCAN];
    //        newJob.scanTypeToUse[NULL_SCAN] = this->typeOfScans[NULL_SCAN];
    //        newJob.scanTypeToUse[XMAS_SCAN] = this->typeOfScans[XMAS_SCAN];
    //        newJob.scanTypeToUse[UDP_SCAN] = this->typeOfScans[UDP_SCAN];
    //        newJob.scanTypeToUse[PROTO_SCAN] = this->typeOfScans[PROTO_SCAN];
    //
    //        allJobs[jobId]=newJob;
    //
    //    }
    //    cout<<"\n>>>>>>>>>"<<jobId;
    //    cout<<"\n-------->>>"<<this->totalProtocolsToScan;
    //    totalJobs = totalJobs + this->totalProtocolsToScan;
    //    for(int index = 0;index<this->totalProtocolsToScan;index++)
    //    {
    //        int protocolNumber = this->protocolNumbersToScan[index];
    //        Job newJob;
    //        newJob.jobId = jobId;
    //        newJob.type = kProtocolScan;
    //        newJob.srcPort = NOT_REQUIRED;
    //        newJob.desPort = NOT_REQUIRED;
    //        newJob.srcIp = this->sourceIP;
    //        newJob.desIp = this->targetIP;
    //        newJob.protocolNumber = protocolNumber;
    //
    //        newJob.scanTypeToUse[SYN_SCAN] = NOT_REQUIRED;
    //        newJob.scanTypeToUse[ACK_SCAN] = NOT_REQUIRED;
    //        newJob.scanTypeToUse[FIN_SCAN] = NOT_REQUIRED;
    //        newJob.scanTypeToUse[NULL_SCAN] = NOT_REQUIRED;
    //        newJob.scanTypeToUse[XMAS_SCAN] = NOT_REQUIRED;
    //        newJob.scanTypeToUse[UDP_SCAN] = NOT_REQUIRED;
    //        newJob.scanTypeToUse[PROTO_SCAN] = this->typeOfScans[PROTO_SCAN];
    //
    //        allJobs[jobId]=newJob;
    //        jobId++;
    //    }
    
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
    cout<<"\n------------------------------------------------------------\n";
    cout<<"Submitting Job"<<kJob.jobId;
    allJobs[kJob.jobId]=kJob;
    if(kJob.type == kPortScan)
        printScanResultForPort(kJob.result,kJob.desIp);
    else if(kJob.type == kProtocolScan)
        printProtocolScanResult(kJob.protocolScanResult);
    cout<<"\n------------------------------------------------------------\n";
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
