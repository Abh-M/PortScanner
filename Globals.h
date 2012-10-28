

#ifndef GLOBALS_H_
#define GLOBALS_H_

#include <sys/types.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include "PCH.h"

#pragma mark - constants


/*..........Header length constans.................*/



#define SRC_PORT 5678
#define DEST_PORT 2008


#define NOT_REQUIRED -999


//#define SRC_IP "127.0.0.1"
//#define SRC_IP "10.0.0.3"
//#define SRC_IP "140.182.144.196"
//#define SRC_IP "140.182.147.44"

//#define DEST_IP "140.182.147.44"
//#define DEST_IP "129.79.246.79"
//#define DEST_IP "129.79.247.5"
//#define DEST_IP "129.110.10.36"
//#define DEST_IP "129.79.247.4"
//#define DEST_IP "72.26.99.2"
//#define DEST_IP "10.0.0.3"
//#define DEST_IP "127.0.0.1"
//#define DEST_IP "74.125.225.210"
//#define DEST_IP "69.171.242.70"
//#define DEST_IP "182.18.135.36"
//giganta
//#define DEST_IP "129.79.246.79"
//#define DEST_IP "129.79.247.195"
//#define DEST_IP "203.199.134.78"
//#define DEST_IP "2607:f8b0:400f:801::1014"

#define ARG_HELP "--help"
#define ARG_PORTS "--ports"
#define ARG_PREFIX "--prefix"
#define ARG_FILE "--file"
#define ARG_SPEED "--speedup"
#define ARG_SCAN "--scan"
#define ARG_PROTO "--pr"
#define ARG_IP "--ip"

#define HELP_FILE "help.txt"
#define SUBNET_IP_FILE "/Users/abhineet/Github/demo/demo/subnetips.txt"

#define INVALID_PORT -1
#define INVALID_CODE -99
#define INVALID_TYPE -99

//Type of scans
#define SYN_SCAN   0
#define ACK_SCAN   1
#define NULL_SCAN  2
#define FIN_SCAN   3
#define XMAS_SCAN  4
#define PROTO_SCAN 5
#define UDP_SCAN   6
#define UNKNOWN_SCAN -1


//-----------  variables for multi-threading---------------//
#define MAX_WORKERS 5
#define NO_WORKERS 0
#define JOB_START_INDEX 0
#define JOB_END_INDEX 1
#define JOB_CURRENT_INDEX 2
#define NO_JOB -99
#define NOT_STARTED -1
#define MAX_PROTOCOL_NUMBERS 256
#define MAX_PORTS 200
#define MIN_PORTS 1
#define MAX_JOBS MAX_PORTS+MAX_PROTOCOL_NUMBERS
//--------------------------------------------------------//



typedef enum{
    kSYN,
    kACK,
    kNULL,
    kXMAS,
    kFIN,
    kUDP,
    kInvalidScanType,
}TCPScanType;



typedef enum{
	kOpen = 0,
	kClosed,
	kFiltered,
	kUnFiltered,
	kClosedAndUnfiltered,
	kCloedAndFiltered,
	kOpenAndUnfiltered,
	kOpenAndFiltered,
    kOpenORFiltered,
    kNoResposne,
	kUnkown,
    kNotUsed,
    
    
    
}portStates;






struct psd_tcp {
	struct in_addr src;
	struct in_addr dst;
	unsigned char pad;
	unsigned char proto;
	unsigned short tcp_len;
	struct tcphdr tcp;
};

#pragma mark - structures


typedef struct
{
    char src[INET_ADDRSTRLEN];
    char des[INET_ADDRSTRLEN];
}srcDesIpv4;


typedef struct
{
    char src[INET6_ADDRSTRLEN];
    char des[INET6_ADDRSTRLEN];
}srcDesIpv6;


typedef struct devNamesAndIp
{
    char localHost_ip[INET_ADDRSTRLEN];
    char ip[INET_ADDRSTRLEN];
    char localHost_ipv6[INET6_ADDRSTRLEN];
    char localhost_dev[5];
    char ipv6[INET6_ADDRSTRLEN];
    char dev[5];
}devAndIp;

typedef struct AllScanResult
{
    /* structure to store scan result of various types for a particular port*/
    int portNo;

    portStates synState;
    portStates ackState;
    portStates finState;
    portStates nullState;
    portStates xmasState;
    portStates udpState;
    
}AllScanResultForPort;

struct TcpFlags
{
    bool isSYN;
    bool isACK;
    bool isRST;
    bool isFIN;
    bool isPSH;
    bool isURG;
};

struct ScanResult
{
    
	portStates tcp_portState;
    portStates udp_portState;
	int destPort;
    int srcPort;
    char *srcIp;
    char *destIp;
    
};

struct ScanRequest
{
    
    int srcPort;
    int destPort;
    int scanType;
    char *sourceIp;
    char *destIp;
    struct sockaddr_in src;
    struct sockaddr_in dest;
};


typedef struct ProtocolScanRequest
{
    int protocolNumber;
    char *sourceIp;
    char *destIp;
    int srcPort;
    int desPort;
    
}ProtocolScanRequest;

typedef struct ProtocolScanResult
{
    int protocolNumber;
    bool protocolSupported;
    int icmp_code;
    int icmp_type;
    int totalPortsScannedForProtocol;
    union{
        AllScanResult tcpProtoPortsScanResult[MAX_PORTS];
        AllScanResult udpPortsScanResult[MAX_PORTS];
    }tcpOrUdpPortScans;
}ProtocolScanResult;


typedef enum
{
    kProtocolScan,
    kPortScan,
    kInvalidJob,
    
}JobType;


typedef struct kJob
{
    int jobId; //this is index to the Jobs list
    
    JobType type;


    int srcPort;
    int desPort;
    
    char *srcIp;
    char *desIp;
    

    
    int scanTypeToUse[7];
    AllScanResultForPort result;
    
    int protocolNumber;
    ProtocolScanResult protocolScanResult;
    int portsForProtocolScan[MAX_PORTS];
    int totalPortsForProtocolScan;
    
}Job;

typedef struct kWorker
{
    int workerId;
    pthread_t thread_id;
    
} Worker;









#endif /* GLOBALS_H_ */
