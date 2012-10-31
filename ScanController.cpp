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

vector<vector<int> > jobDistribution;
vector<Job> jobQueue;


//Job allJobs[MAX_JOBS];
sem_t mutex_allJobs;
int totalJobs=0;
sem_t mutex_totalJobs;
int currentJob;
sem_t mutex_currJob;
//Worker workers[MAX_WORKERS];
//int workDistribution[MAX_WORKERS][3];
sem_t mutex_wrkD;
sem_t mutex_raw_sockets;

vector<pthread_t> allWorkerThreadId;
//pthread_t allWorkerThreads[MAX_WORKERS];
//sem_t kMutex;
pthread_mutex_t kMutex;
pthread_mutex_t k_syn_mutex;
pthread_mutex_t k_request_mutex;
pthread_mutex_t k_nextJob_mutex;
pthread_mutex_t k_tcp_scan_result_mutex;
void submitJob(Job kJob);
void printProtocolScanResult(ProtocolScanResult kResult);
void printResult();



static ScanController *sharedInstance;
ScanController::ScanController() {
    
    //by default scan 0-1024;
    this->startPort = 0;
    this->endPort = 1024;
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
    this->typeOfScans[UDP_SCAN]=0;
    
    
    
    
    
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
    
    
    this->defaultTimeout=3;
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



void ScanController::populatePortsList(int kStart, int kEnd)
{
    
    // cout<<kStart<<" "<<kEnd;
    this->totalPortsToScan = 0;
    for(int port = kStart; port<=kEnd;port++)
    {
        this->portsToScan[this->totalPortsToScan++]=port;
    }
    cout<<this->totalPortsToScan;
//    for (int i=0; i<this->totalPortsToScan;i++) {
//        cout<<"\n PORT : "<<this->portsToScan[i];
//    }
    
}




void ScanController::populatePortsList(int kPortsList[MAX_PORTS])
{
    
    int index = 0;
    while (kPortsList[index]!=INVALID_PORT)
    {
        this->portsToScan[this->totalPortsToScan++]=kPortsList[index];
        index++;
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
    for(port = 0;port<=1024;port++)
    {
        this->portsToScan[index++]=port;
        this->totalPortsToScan++;
    }
}

void ScanController::populateIpAddressToScan()
{
    this->allIpAddressToScan.push_back(this->hostDevAndIp.localHost_ip);
    this->totalIpAddressToScan = (int)this->allIpAddressToScan.size();
    this->devString = this->hostDevAndIp.localhost_dev;
    this->sourceIP = this->hostDevAndIp.localHost_ip;
    this->targetIP = this->hostDevAndIp.localHost_ip;
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
            string str = kIpAddressList[0];
            this->allIpAddressToScan[0]=str;
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
    
    cout<<"\n Starting Protocol Scan scan for  IP :"<<req.destIp<<" Protocol Number: "<<req.protocolNumber;

    bool isv6 = isIpV6(req.destIp);
    
    
    
    char *dev, errBuff[50];
    bool islhost = islocalhost(req.destIp);
    int eth_fr_size =14;
    
    if(islhost && isv6)
    {
        dev = this->hostDevAndIp.localhost_dev;
        req.sourceIp = this->hostDevAndIp.ipv6;
        req.destIp = this->hostDevAndIp.ipv6;
    }
    else if(islhost && !isv6)
    {
        dev = this->hostDevAndIp.localhost_dev;
        req.sourceIp = this->hostDevAndIp.ip;
        req.destIp = this->hostDevAndIp.ip;
        
    }
    else if(!islhost)
    {
        dev = this->hostDevAndIp.dev;
    }

    //cout<<dev;
    
    pcap_t *handle;
    
    
    struct bpf_program fp;
    
    char filter_exp[256];
    if(isv6)
    {
        sprintf(filter_exp,"icmp6 && src host %s && ip6[40] != 128",req.destIp);
        
    }
    else
    {
        sprintf(filter_exp,"icmp && src host %s && icmp[icmptype] != icmp-echo ",req.destIp);
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
    if(filter_exp[strlen(filter_exp)-1]==':')
    {
        filter_exp[strlen(filter_exp)-1]='\0';
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
        
        //sem_wait(&mutex_raw_sockets);
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
        if(req.protocolNumber == IPPROTO_ICMPV6)
        {
            struct icmp6_hdr icmp6hdr;
            icmp6hdr.icmp6_type = ICMP6_ECHO_REQUEST;
            icmp6hdr.icmp6_code = 0;
            icmp6hdr.icmp6_cksum = 0;
            //icmphd.icmp_cksum = in_cksum((unsigned short *)&icmphd, 8);
            memcpy(packet, &icmp6hdr, 8);
        }
        
        //sem_wait(&mutex_raw_sockets);
        sd = socket(AF_INET6, SOCK_RAW, req.protocolNumber);
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
//        cout<<"\n"<<res;
        
        
        
    }
    time_t start, end;
    double diff=0;
    time(&start);
    while (1) {
        time(&end);
        diff = difftime(end, start);
        if(diff>=3.0)
            break;
    }

    
    
    
    sleep(this->defaultTimeout);

    //RECV
    struct pcap_pkthdr header;
    const u_char *recPakcet =  pcap_next(handle, &header);
    
    if(recPakcet!=NULL)
    {

        if(isv6)
        {
            //icmpv6
            //TODO : hardcoded value of 6 is for localhost need to fix this
            struct ip6_hdr *ip6 = (struct ip6_hdr*)(recPakcet+eth_fr_size);
            logIP6Header(ip6);
            int payload = ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen);
            srcDesIpv6 ipPair = getIpPairForIp6Header(ip6);
            if(  ((strcmp(ipPair.src, req.destIp))==0) && ((strcmp(ipPair.des, req.sourceIp))==0) )
            {
                //FIX: 14 is inconsistent
                struct icmp6_hdr *icmp6 = (struct icmp6_hdr*)(recPakcet+eth_fr_size+40);
                logICMP6Header(icmp6);
                //check if reply
                if((unsigned short)icmp6->icmp6_type==ICMP6_ECHO_REPLY){
                    //set status
                    result.icmp_type = (unsigned short)icmp6->icmp6_type;
                    result.icmp_type = (unsigned short)icmp6->icmp6_code;
                    result.protocolSupported = true;
                }
                else//analyze payload
                {
                    if( payload > (sizeof(struct ip6_hdr)+ sizeof(struct icmp6_hdr) ))
                    {
                        struct ip6_hdr *inner_ip6 = (struct ip6_hdr*)(recPakcet+eth_fr_size+40+8);
                        logIP6Header(inner_ip6);
                        
                    }
                    else
                    {
                        //something else
                    }
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
            struct ip *iph = (struct ip*)(recPakcet+eth_fr_size);
            cout<<"\nOuter Ip Header :";
            
            unsigned int proto = (unsigned)iph->ip_p;
            if((strcmp(inet_ntoa(iph->ip_src), req.destIp))==0)
            {
                logIpHeader(iph);
                if(proto==IPPROTO_ICMP )
                {
                    struct icmp *icmpHdr = (struct icmp*)(recPakcet  + 20 + eth_fr_size);
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
                        //FIX: remove harded coded values
                        struct ip *p =(struct ip*)(recPakcet+eth_fr_size+20+8);
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
    //sem_post(&mutex_raw_sockets);

    pcap_freecode(&fp);
    pcap_close(handle);
    free(packet);
    return result;
    
}






void ScanController::populateProtocolNumberToScan(int kProtocolNumbersList[MAX_PROTOCOL_NUMBERS])
{
    this->totalProtocolsToScan=0;
    flushArray(this->protocolNumbersToScan, 256);
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
        //distribute work

        setUpJobsAndJobDistribution();
        if(totalJobs>0)
            scanPortsWithThread();
        else
        {
            cout<<"\nno jobs";
            exit(1);
        }

        
    }
    else if(this->spawnThreads == false)
    {
        //dont distribute work

        this->totalWorkers = NO_WORKERS;
        setUpJobsAndJobDistribution();
        if(totalJobs>0)
            scanPorts();
        else
        {
            cout<<"\nno jobs";
            exit(1);
        }
        
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
    
    cout<<"\n Starting UDP scan for  IP :"<<kRequest.destIp<<" Port: "<<kRequest.destPort;
    bool isv6= isIpV6(kRequest.destIp);
    bool islhost = islocalhost(kRequest.destIp);

    
    char *dev, errBuff[50];
    int eth_fr_size=14;
    
    if(islhost && isv6)
    {
        dev = this->hostDevAndIp.localhost_dev;
        kRequest.sourceIp = this->hostDevAndIp.ipv6;
        kRequest.destIp = this->hostDevAndIp.ipv6;
    }
    else if(islhost && !isv6)
    {
        dev = this->hostDevAndIp.localhost_dev;
        kRequest.sourceIp = this->hostDevAndIp.ip;
        kRequest.destIp = this->hostDevAndIp.ip;
        
    }
    else if(!islhost)
    {
        dev = this->hostDevAndIp.dev;
    }

    
    
    pcap_t *handle;
    struct bpf_program fp;
    //set filter exp depending upon source port
    char filter_exp[256];
    sprintf(filter_exp,"(icmp && src host %s) || (icmp6 && src host %s)",kRequest.destIp,kRequest.destIp);
    
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
    if(filter_exp[strlen(filter_exp)-1]==':')
    {
        filter_exp[strlen(filter_exp)-1]='\0';
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    }
    
    
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
        
        
        //sem_wait(&mutex_raw_sockets);
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
        const char* des =  kRequest.destIp;
        struct sockaddr_in6 desa; desa.sin6_family=AF_INET6; inet_pton(AF_INET6, des, &desa.sin6_addr);
        
        udp.uh_sport = htons(kRequest.srcPort);
        udp.uh_dport = htons(kRequest.destPort);
        udp.uh_ulen = htons(8);
        udp.uh_sum = 0;
        
        
        memcpy(packet, &udp, sizeof(udp));
        
        //sem_wait(&mutex_raw_sockets);
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
    
    sleep(this->defaultTimeout);

    //RECV
    struct pcap_pkthdr header;
    const u_char *recPakcet =  pcap_next(handle, &header);
    
    
    if(recPakcet!=NULL)
    {
        //check for icmp or icmpv6 depending
        if(isv6){
            //icmpv6
            //TODO : hardcoded value of 6 is for localhost need to fix this
            struct ip6_hdr *ip6 = (struct ip6_hdr*)(recPakcet+eth_fr_size);
            logIP6Header(ip6);
            srcDesIpv6 ipPair = getIpPairForIp6Header(ip6);
            if(  ((strcmp(ipPair.src, kRequest.destIp))==0) && ((strcmp(ipPair.des, kRequest.sourceIp))==0) )
            {
                //check if icmp;
                
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
                    //FIX: no check for type 4 code 1 : port unreachable
                }
            }
            else{
                status.udp_portState = kOpenORFiltered;
            }
            
        }
        else
        {
            //icmp
            //FIX:remove hardcoding
            struct ip *iph = (struct ip*)(recPakcet+eth_fr_size);
            srcDesIpv4 srcAndDes = getIpPairForIpHeader(iph);
            //cross check source and destination address
            if( (strcmp(srcAndDes.src, kRequest.destIp))==0 && (strcmp(srcAndDes.des, kRequest.sourceIp))==0)
            {
                logIpHeader(iph);
                if((unsigned int)iph->ip_p == IPPROTO_ICMP)
                {
                    //FIX:remove hard-coded value
                    struct icmp *icmpHeader = (struct icmp*)(recPakcet + eth_fr_size + 20);
                    struct udphdr *inner_udp = (struct udphdr*)(recPakcet + eth_fr_size+20+8+20);//ether+ip+icmp+orignal ip
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
                else if((unsigned int)iph->ip_p == IPPROTO_UDP)
                {
                    //FIX:
                    cout<<"\n got udp response for udp request";
                }
                else
                {
                    cout<<"\n got response for udp requesr but unknown protocol";
                    //status.udp_portState = kOpenORFiltered;
                }
                
                
            }
            else
            {
                cout<<"\n Got udp response";
            }
            
        }
        
    }
    else
    {
        status.udp_portState = kOpenORFiltered;
    }
    
    close(sd);
    //sem_post(&mutex_raw_sockets);
    pcap_freecode(&fp);
    pcap_close(handle);
    free(packet);
    return status;
}




ScanResult ScanController::runTCPscan(ScanRequest kRequest)
{
    
    //pthread_mutex_lock(&k_tcp_scan_result_mutex);
    ScanResult status;
    status.srcPort = kRequest.srcPort;
    status.destPort = kRequest.destPort;
    status.srcIp = kRequest.sourceIp;
    status.destIp = kRequest.destIp;
    status.tcp_portState = kUnkown;
    
    cout<<"\n Starting "<<scanNumToString(kRequest.scanType)<<"scan for  IP :"<<kRequest.destIp<<" Port: "<<kRequest.destPort;
    
    
    bool isv6=isIpV6(kRequest.destIp);
    bool islhost = islocalhost(kRequest.destIp);
    int eth_fr_size=14;
    //// Set pcap parameters
    
    char *dev, errBuff[50];
    char filter_exp[256];

    if(islhost && isv6)
    {
        dev = this->hostDevAndIp.localhost_dev;
        kRequest.sourceIp = this->hostDevAndIp.ipv6;
        kRequest.destIp = this->hostDevAndIp.ipv6;
    }
    else if(islhost && !isv6)
    {
        dev = this->hostDevAndIp.localhost_dev;
        kRequest.sourceIp = this->hostDevAndIp.ip;
        kRequest.destIp = this->hostDevAndIp.ip;

    }
    else if(!islhost)
    {
        dev = this->hostDevAndIp.dev;
    }
        
    
    pcap_t *handle;
    struct bpf_program fp;
    memset(&filter_exp, '\0', 256);
    if(isv6)
    {
        if(!islhost)
            sprintf(filter_exp,"src host %s",kRequest.destIp);
        else
            sprintf(filter_exp,"src host %s && dst port %d",kRequest.destIp,kRequest.srcPort);
    }
    
    else
    {
        if(!islhost)
            sprintf(filter_exp,"src %s",kRequest.destIp);
        else
            sprintf(filter_exp,"src host %s && dst port %d",kRequest.destIp,kRequest.srcPort);

    }
    
    
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
    if(filter_exp[strlen(filter_exp)-1]==':')
    {
        filter_exp[strlen(filter_exp)-1]='\0';
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
        //sem_wait(&mutex_raw_sockets);
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
    
    
    
    sleep(this->defaultTimeout);
    
    
    struct pcap_pkthdr header;
    const u_char *recPakcet = pcap_next(handle, &header);
    
    
    if(recPakcet!=NULL)
    {
        bool isTcp = false;
        bool isIcmp = false;
        bool isicmp6 = false;
        int ip_hdr_size = 0;
        struct ip *iph;
        struct ip6_hdr *v6hdr;
        
        if(isv6)
        {
            //check if v6 is valid
            v6hdr = (struct ip6_hdr*)(recPakcet+eth_fr_size);
            srcDesIpv6 ipPair = getIpPairForIp6Header(v6hdr);
            int sourceValid = strcmp(ipPair.des,kRequest.sourceIp);
            int destValid = strcmp(ipPair.src, kRequest.destIp);
            if(sourceValid == 0 && destValid == 0)
            {
                
                if(v6hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_TCP)
                {
                    isTcp = true;
                    isIcmp = false;
                    isicmp6 = false;
                }
                else if(v6hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_ICMPV6)
                {
                    
                    
                    isTcp = false;
                    isIcmp = false;
                    isicmp6 = true;
                }
                ip_hdr_size = sizeof(struct ip6_hdr);
                logIP6Header(v6hdr);

                
            }
            else
            {
                isTcp = false;
                isIcmp = false;
                isicmp6 = false;
            }

        }
        else//it is ipv4
        {
            //logIpHeader(iph);
            //FIX: check if source and destinateion are valid
            iph = (struct ip*)(recPakcet + eth_fr_size);
            srcDesIpv4 ipPair = getIpPairForIpHeader(iph);
            int sourceValid = strcmp(ipPair.des,kRequest.sourceIp);
            int destValid = strcmp(ipPair.src, kRequest.destIp);
            if(sourceValid==0 && destValid==0)
            {
                isTcp = ((unsigned int)iph->ip_p == IPPROTO_TCP);
                isIcmp = ((unsigned int)iph->ip_p == IPPROTO_ICMP);
                ip_hdr_size = sizeof(struct ip);
                logIpHeader(iph);

                
            }
            else
            {
                isTcp = false;
                isIcmp = false;
            }
            
        }
        
        
        if(isTcp)
        {
            //TODO : hardcode value of will change is this is ipv6
            struct tcphdr *tcpHdr = (struct tcphdr*)(recPakcet + ip_hdr_size +eth_fr_size);
            //check whether response is valid by comparing seq numbers and ack numbers
            unsigned long int ack = ntohl(tcpHdr->th_ack);
            if(ack==tcp_seq+1)
            {
                
                logTCPHeader(tcpHdr);
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
            else
            {
                if(kRequest.scanType==XMAS_SCAN)
                    status.tcp_portState = kOpenORFiltered;
                if(kRequest.scanType == NULL_SCAN)
                    status.tcp_portState = kOpenORFiltered;
                if(kRequest.scanType == FIN_SCAN)
                    status.tcp_portState = kOpenORFiltered;
                if(kRequest.scanType == SYN_SCAN)
                    status.tcp_portState = kFiltered;
                if(kRequest.scanType == ACK_SCAN)
                    status.tcp_portState = kFiltered;
                
            }
            
            
            
        }
        else if(isIcmp)
        {
            //Handle ICMP packets
            //check if captured icmp is valid
            //TODO:: remove hardcoded values for header lengths
            struct icmp *icmph = (struct icmp*)(recPakcet + eth_fr_size + ip_hdr_size);
            //logICMPHeader(icmph);
            struct ip *inner_ip = (struct ip*)(recPakcet+eth_fr_size+ip_hdr_size+8);
            //logIpHeader(inner_ip);
            struct tcphdr *inner_tcp  = (struct tcphdr*)(recPakcet + eth_fr_size + ip_hdr_size + 28);
            //logTCPHeader(inner_tcp);
            int inner_seq = ntohl(inner_tcp->th_seq);
            if(inner_seq == tcp_seq)
            {
                //valid icmp
                unsigned int code = (unsigned int)icmph->icmp_code;
                unsigned int type = (unsigned int)icmph->icmp_type;
                //                cout<<endl<<"----";
                cout<<"\n Valid ICMP recieved";
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
                        
                    case FIN_SCAN:
                    {
                        if(type==3 && (code==1 || code==2 || code==3 || code==9 || code==10 || code==13))
                            status.tcp_portState = kFiltered;
                    }
                        break;
                        
                    case NULL_SCAN:
                    {
                        if(type==3 && (code==1 || code==2 || code==3 || code==9 || code==10 || code==13))
                            status.tcp_portState = kFiltered;
                    }
                        break;
                    case XMAS_SCAN:
                    {
                        if(type==3 && (code==1 || code==2 || code==3 || code==9 || code==10 || code==13))
                            status.tcp_portState = kFiltered;
                    }
                        break;
                        
                        
                        
                        
                    default:
                        break;
                }
                
            }
            else
            {
                if(kRequest.scanType==XMAS_SCAN)
                    status.tcp_portState = kOpenORFiltered;
                if(kRequest.scanType == NULL_SCAN)
                    status.tcp_portState = kOpenORFiltered;
                if(kRequest.scanType == FIN_SCAN)
                    status.tcp_portState = kOpenORFiltered;
                if(kRequest.scanType == SYN_SCAN)
                    status.tcp_portState = kFiltered;
                if(kRequest.scanType == ACK_SCAN)
                    status.tcp_portState = kFiltered;
                
            }
            
            
        }
        else if(isicmp6 == true)
        {
            //FIX:add icmp6 processing
            cout<<"\n GOT ICMP6 TCP SCAN";
        }
        else
        {
            if(kRequest.scanType==XMAS_SCAN)
                status.tcp_portState = kOpenORFiltered;
            if(kRequest.scanType == NULL_SCAN)
                status.tcp_portState = kOpenORFiltered;
            if(kRequest.scanType == FIN_SCAN)
                status.tcp_portState = kOpenORFiltered;
            if(kRequest.scanType == SYN_SCAN)
                status.tcp_portState = kFiltered;
            if(kRequest.scanType == ACK_SCAN)
                status.tcp_portState = kFiltered;
            
        }
        
    }
    else if(recPakcet==NULL)
    {
        if(kRequest.scanType==XMAS_SCAN)
            status.tcp_portState = kOpenORFiltered;
        if(kRequest.scanType == NULL_SCAN)
            status.tcp_portState = kOpenORFiltered;
        if(kRequest.scanType == FIN_SCAN)
            status.tcp_portState = kOpenORFiltered;
        if(kRequest.scanType == SYN_SCAN)
            status.tcp_portState = kFiltered;
        if(kRequest.scanType == ACK_SCAN)
            status.tcp_portState = kFiltered;
        
    }
    
    close(sd);
    //sem_post(&mutex_raw_sockets);
    pcap_close(handle);
    free(packet);
    pcap_freecode(&fp);
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
    cout<<"\nTCP Scan Result >> IP : "<<ip<<" PORT : "<<kResult.portNo;
    cout<<" |SYN  : "<<getStringForPortState(kResult.synState);
    cout<<" |ACK  : "<<getStringForPortState(kResult.ackState);
    cout<<" |NULL : "<<getStringForPortState(kResult.nullState);
    cout<<" |FIN  : "<<getStringForPortState(kResult.finState);
    cout<<" |XMAS : "<<getStringForPortState(kResult.xmasState);
}


void printProtocolScanResult(ProtocolScanResult kResult)
{
    if(kResult.protocolNumber== IPPROTO_UDP)
    {
        for(int i=0; i<kResult.totalPortsScannedForProtocol;i++)
        {
            
            AllScanResult res =  kResult.tcpOrUdpPortScans.udpPortsScanResult[i];
            cout<<"\nUDP Protocol Scan Result >>  PORT:"<<res.portNo<<" | "<<getStringForPortState(res.udpState);
        }
    }
    else if(kResult.protocolNumber ==IPPROTO_TCP)
    {
        for(int i=0; i<kResult.totalPortsScannedForProtocol;i++)
        {
            
            AllScanResult res =  kResult.tcpOrUdpPortScans.tcpProtoPortsScanResult[i];
            cout<<"\nTCP Protocol Scan Result >> PORT:"<<res.portNo<<" | "<<getStringForPortState(res.synState);
            
        }
        
    }
    else
    {
        cout<<"\nProtocol Scan result Number >> "<<kResult.protocolNumber;
        if(kResult.icmp_type != INVALID_TYPE && kResult.icmp_code != INVALID_CODE)
            cout<<"\n ICMP type: "<<kResult.icmp_type<<" code :"<<kResult.icmp_code;
        if(kResult.protocolSupported)
            cout<<" : Protocol  Supported";
        else
            cout<<" : Protocol Not Supported";
        
        
    }
    
    
}


void ScanController::scanPorts()
{
    
    
    
    //for each port run TCP and UDP scan
    //this->allPortsScanResultIndex = 0;
    
    for(int index=0;index<totalJobs;index++)
    {
        //        Job nextJob = allJobs[index];
        Job nextJob = jobQueue[index];
        
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
                nextJob.protocolScanResult.totalPortsScannedForProtocol =  nextJob.totalPortsForProtocolScan;
                nextJob.protocolScanResult.protocolNumber = nextJob.protocolNumber;
                
                for(int index = 0;index<nextJob.totalPortsForProtocolScan;index++)
                {
                    //for all ports do all types of tcp scan;
                    int portNo = nextJob.portsForProtocolScan[index];
                    AllScanResult allScanTypeResultForPort;
                    allScanTypeResultForPort.portNo = portNo;
                    
                    //FIX: only SYN scan for port is done
                    //TODO: other types of scans needs to be done;
                    ScanRequest synRequest = createScanRequestFor(nextJob.srcPort, portNo, nextJob.srcIp, nextJob.desIp,SYN_SCAN);
                    ScanResult synResult = sharedInstance->runTCPscan(synRequest);
                    allScanTypeResultForPort.synState = synResult.tcp_portState;
                    nextJob.protocolScanResult.tcpOrUdpPortScans.tcpProtoPortsScanResult[index]=allScanTypeResultForPort;
                    
                    
                }
                submitJob(nextJob);
                
                
            }
            else if(nextJob.protocolNumber == IPPROTO_UDP)
            {
                //For all ports gather result for UDP scan result
                //                ProtocolScanResult  udpScanResult;
                //                udpScanResult.totalPortsScannedForProtocol = nextJob.totalPortsForProtocolScan;
                nextJob.protocolScanResult.totalPortsScannedForProtocol =  nextJob.totalPortsForProtocolScan;
                nextJob.protocolScanResult.protocolNumber = nextJob.protocolNumber;
                //                nextJob.protocolScanResult.tcpOrUdpPortScans.
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
                submitJob(nextJob);
                
                
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
                submitJob(nextJob);
                
                
            }
        }
    }
    printResult();

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
    cout<<"\n Setting job queue.....";
    totalJobs = 0;
    int jobId = 0;
    for (int i=0; i<this->totalIpAddressToScan; i++) {
        const char *nextIp = this->allIpAddressToScan[i].c_str();
        
        char *srcIp;
        
        if(isIpV6(nextIp) )
        {
            if(islocalhost((char*)nextIp))
                srcIp = this->hostDevAndIp.localHost_ipv6;
            else
                srcIp = this->hostDevAndIp.ipv6;
            
        }
        else
        {
            
            if(islocalhost((char*)nextIp))
                srcIp = this->hostDevAndIp.localHost_ip;
            else
                srcIp = this->hostDevAndIp.ip;
        }
        
        totalJobs = totalJobs+this->totalPortsToScan;//+this->totalProtocolsToScan;
        //this->jobQueue.resize(totalJobs);
        for(int portIndex=0;portIndex<totalPortsToScan;portIndex++)
        {
            int destPort = this->portsToScan[portIndex];
            Job newJob;
            newJob.jobId = jobId;
            newJob.type = kPortScan;
            //TODO: remove hard coding for SRC_PORT
            newJob.srcPort = SRC_PORT;
            newJob.desPort = destPort;
            
            
            newJob.srcIp = srcIp;
            newJob.desIp = (char*)nextIp;
            newJob.scanTypeToUse[SYN_SCAN] = this->typeOfScans[SYN_SCAN];
            newJob.scanTypeToUse[ACK_SCAN] = this->typeOfScans[ACK_SCAN];
            newJob.scanTypeToUse[FIN_SCAN] = this->typeOfScans[FIN_SCAN];
            newJob.scanTypeToUse[NULL_SCAN] = this->typeOfScans[NULL_SCAN];
            newJob.scanTypeToUse[XMAS_SCAN] = this->typeOfScans[XMAS_SCAN];
            newJob.scanTypeToUse[UDP_SCAN] = NOT_REQUIRED;
            newJob.scanTypeToUse[PROTO_SCAN] = NOT_REQUIRED;
            jobQueue.push_back(newJob);
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
                memcpy(&newJob.portsForProtocolScan, &this->portsToScan,sizeof(int)*this->totalPortsToScan);
                newJob.totalPortsForProtocolScan = this->totalPortsToScan;
            }
            else
                newJob.totalPortsForProtocolScan = -1;
            
            newJob.srcIp = srcIp;
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
            jobQueue.push_back(newJob);
            jobId++;
            
        }
        
    }
    cout<<"\n Total Jobs : "<<totalJobs;
    
    
    if(totalJobs>0)
    {
        
        if(this->totalWorkers>NO_WORKERS)
        {

            
            
            //distribute work if number of workers is greater than zero
            int jobsPerWorker = totalJobs/this->totalWorkers;
            
            if(jobsPerWorker<1)
                this->totalWorkers = totalJobs;
            
            jobDistribution.resize(this->totalWorkers);
            for (int i=0; i<this->totalWorkers; i++) {
                jobDistribution[i].resize(3);
            }

            
            int temp_totalJobs = totalJobs;
            
            for (int workerId =0; workerId<this->totalWorkers; workerId++) {
                Worker newWorker;
                newWorker.workerId = workerId;
                
                int startindex = workerId*jobsPerWorker;
                int endindex=-1;
                
                if(workerId==(this->totalWorkers-1))//last worker check  remaining jobs
                {
                    endindex = totalJobs-1;
                    temp_totalJobs = temp_totalJobs - temp_totalJobs;
                }
                else
                {
                    endindex = startindex + jobsPerWorker-1;
                    temp_totalJobs = temp_totalJobs - jobsPerWorker;
                }
                
                jobDistribution[workerId][JOB_START_INDEX] = startindex;
                jobDistribution[workerId][JOB_END_INDEX] = endindex;
                jobDistribution[workerId][JOB_CURRENT_INDEX] = NOT_STARTED;
            }
            
            
        }

        
    }
    
    
    
    
    
}




Job*  ScanController::getNextJob(int kWorkerId)
{
    pthread_mutex_lock(&kMutex);

    Job *nJob = NULL;
    
    int curretJob = jobDistribution[kWorkerId][JOB_CURRENT_INDEX];
    int startJob = jobDistribution[kWorkerId][JOB_START_INDEX];
    int endJob = jobDistribution[kWorkerId][JOB_END_INDEX];
    
    
    //when this is the first job
    if(!(curretJob == endJob))
    {
        if(curretJob==-1)
            curretJob = startJob;
        else
            curretJob++;
        
        jobDistribution[kWorkerId][JOB_CURRENT_INDEX] = curretJob;
        nJob = &jobQueue[curretJob];
        
    }
    else if(curretJob == endJob)
    {
        //all jobs are complete look for additional job
        for(int wkr=0;wkr<totalWorkers;wkr++)
        {
            if(kWorkerId!=wkr)
                //look for pending jobs of other workers
            {
                int currJob = jobDistribution[wkr][JOB_CURRENT_INDEX];
                int startJob = jobDistribution[wkr][JOB_START_INDEX];
                int endJob = jobDistribution[wkr][JOB_END_INDEX];
                if(currJob<endJob)
                {
                    if(currJob==-1)
                        currJob = startJob;
                    else
                        currJob++;
                    nJob = &jobQueue[currJob];
                    jobDistribution[wkr][JOB_CURRENT_INDEX] = currJob;
                    break;
                }
            }
        }
    }
    pthread_mutex_unlock(&kMutex);
    
    return nJob;
    
}


void submitJob(Job kJob)
{
    
    pthread_mutex_lock(&kMutex);
    jobQueue[kJob.jobId]=kJob;
//    if(kJob.type == kPortScan)
//        printScanResultForPort(kJob.result,kJob.desIp);
//    else if(kJob.type == kProtocolScan)
//        printProtocolScanResult(kJob.protocolScanResult);
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
    Job nextJob;
    while (1)
    {
        Job *nnj = sharedInstance->getNextJob(myId);
        
        if(nnj==NULL)
            break;
        else
        {
            nextJob = *nnj;
            if(nextJob.type == kPortScan)
            {
                //pthread_mutex_lock(&k_tcp_scan_result_mutex);
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
                    ScanRequest synRequest = createScanRequestFor(nextJob.srcPort, nextJob.desPort, nextJob.srcIp, nextJob.desIp,SYN_SCAN);
                    ScanResult synResult = sharedInstance->runTCPscan(synRequest);
                    nextJob.result.synState = synResult.tcp_portState;
                }
                
                if(nextJob.scanTypeToUse[FIN_SCAN]==1)
                {
                    ScanRequest finRequest = createScanRequestFor(nextJob.srcPort, nextJob.desPort, nextJob.srcIp, nextJob.desIp,FIN_SCAN);
                    ScanResult finResult = sharedInstance->runTCPscan(finRequest);
                    nextJob.result.finState = finResult.tcp_portState;
                }
                if(nextJob.scanTypeToUse[ACK_SCAN]==1)
                {
                    ScanRequest ackRequest = createScanRequestFor(nextJob.srcPort, nextJob.desPort, nextJob.srcIp, nextJob.desIp,ACK_SCAN);
                    ScanResult ackResult = sharedInstance->runTCPscan(ackRequest);
                    nextJob.result.ackState = ackResult.tcp_portState;
                }
                if(nextJob.scanTypeToUse[NULL_SCAN]==1)
                {
                    ScanRequest nullRequest = createScanRequestFor(nextJob.srcPort, nextJob.desPort, nextJob.srcIp, nextJob.desIp,NULL_SCAN);
                    ScanResult nullResult = sharedInstance->runTCPscan(nullRequest);
                    nextJob.result.nullState = nullResult.tcp_portState;
                }
                if(nextJob.scanTypeToUse[XMAS_SCAN]==1)
                {
                    ScanRequest xmasRequest = createScanRequestFor(nextJob.srcPort, nextJob.desPort, nextJob.srcIp, nextJob.desIp,XMAS_SCAN);
                    ScanResult xmasResult = sharedInstance->runTCPscan(xmasRequest);
                    nextJob.result.xmasState = xmasResult.tcp_portState;
                }
                
                
                submitJob(nextJob);
            }
            else if(nextJob.type == kProtocolScan )
            {
                if(nextJob.protocolNumber == IPPROTO_TCP )
                {
                    //For all ports gather scanresult for all types of scan
                    //                ProtocolScanResult tcpScanResult;
                    //                tcpScanResult.totalPortsScannedForProtocol = nextJob.totalPortsForProtocolScan;
                    nextJob.protocolScanResult.totalPortsScannedForProtocol =  nextJob.totalPortsForProtocolScan;
                    nextJob.protocolScanResult.protocolNumber = nextJob.protocolNumber;
                    
                    for(int index = 0;index<nextJob.totalPortsForProtocolScan;index++)
                    {
                        //for all ports do all types of tcp scan;
                        int portNo = nextJob.portsForProtocolScan[index];
                        AllScanResult allScanTypeResultForPort;
                        allScanTypeResultForPort.portNo = portNo;
                        
                        //FIX: only SYN scan for port is done
                        //TODO: other types of scans needs to be done;
                        ScanRequest synRequest = createScanRequestFor(nextJob.srcPort, portNo, nextJob.srcIp, nextJob.desIp,SYN_SCAN);
                        ScanResult synResult = sharedInstance->runTCPscan(synRequest);
                        allScanTypeResultForPort.synState = synResult.tcp_portState;
                        nextJob.protocolScanResult.tcpOrUdpPortScans.tcpProtoPortsScanResult[index]=allScanTypeResultForPort;
                        
                        
                    }
                    submitJob(nextJob);
                    
                    
                }
                else if(nextJob.protocolNumber == IPPROTO_UDP )
                {
                    //For all ports gather result for UDP scan result
                    //                ProtocolScanResult  udpScanResult;
                    //                udpScanResult.totalPortsScannedForProtocol = nextJob.totalPortsForProtocolScan;
                    nextJob.protocolScanResult.totalPortsScannedForProtocol =  nextJob.totalPortsForProtocolScan;
                    nextJob.protocolScanResult.protocolNumber = nextJob.protocolNumber;
                    //                nextJob.protocolScanResult.tcpOrUdpPortScans.
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
                    
                    submitJob(nextJob);
                    
                    
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
                    ProtocolScanResult protoScanResult = sharedInstance->runScanForProtocol(protoScanReq);
                    nextJob.protocolScanResult = protoScanResult;
                    submitJob(nextJob);
                    
                    
                }
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
    pthread_mutex_init(&k_tcp_scan_result_mutex, NULL);
    sem_init(&mutex_raw_sockets, 0, 1000);
    int j[this->totalWorkers];
    for (int i=0; i<this->totalWorkers; i++) {
        j[i] = i;
        allWorkerThreadId.resize(i+1);
        usleep(i*100);
        pthread_create(&allWorkerThreadId[i], NULL, handleJob, (void*)&j[i]);
        
    }
    
    void *result;
    
    for(int i=0; i<this->totalWorkers;i++)
    {
        pthread_join(allWorkerThreadId[i], &result);
    }
    
    pthread_mutex_destroy(&kMutex);
    pthread_mutex_destroy(&k_request_mutex);
    pthread_mutex_destroy(&k_syn_mutex);
    pthread_mutex_destroy(&k_nextJob_mutex);
    pthread_mutex_destroy(&k_tcp_scan_result_mutex);
    sem_destroy(&mutex_raw_sockets);
    cout<<"\n All threads joined\n";
    
    
    printResult();
}


void scanServices(Job kJob)
{
    
    if(kJob.desPort == 80||kJob.desPort == 587||kJob.desPort == 43||kJob.desPort == 110||kJob.desPort == 143||kJob.desPort == 22||kJob.desPort == 25) //HTTP
    {
        if(kJob.result.ackState == kOpen||kJob.result.finState == kOpen || kJob.result.nullState == kOpen || kJob.result.synState == kOpen ||kJob.result.xmasState == kOpen)
        {
            scanWellKnownServices(kJob.desIp,kJob.desPort);
        } 
    } 
}

void printResult()
{
    for(int i=0; i<totalJobs ; i++)
    {
        Job kJob = jobQueue[i];
        
        cout<<"\n.................IP : "<<kJob.desIp<<".....................";
        if(kJob.type == kPortScan)
        {
            printScanResultForPort(kJob.result,kJob.desIp);
            scanServices(kJob);
            
        }
        else if(kJob.type == kProtocolScan)
            printProtocolScanResult(kJob.protocolScanResult);
        pthread_mutex_unlock(&kMutex);
        
        
        
    }
}
