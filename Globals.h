

#ifndef GLOBALS_H_
#define GLOBALS_H_

#include <sys/types.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

#define SETLOCAL 0
/* COMMAND LINE ARGS
 *     --help <display invocation options>
    --ports <ports to scan>
    --ip <IP address to scan>
    --prefix <IP prefix to scan>
    --file <file name containing IP addresses to scan>
    --speedup <parallel threads to use>
    --scan <one or more scans>
    --protocol-range <transport layer protocols to scan>
 *
 **/

#define TCP_SOURCE_PORT 5678
#define TCP_SRC_IP "127.0.0.1"

#define SRC_PORT 5678
#define DEST_PORT 2008


#define LOCALHST 0
#define APPLE 1

//#define SRC_IP "127.0.0.1"
#define SRC_IP "10.0.0.3"

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
#define DEST_IP "129.79.246.79"
//#define DEST_IP "129.79.247.195"
//#define DEST_IP "203.199.134.78"

#define ARG_HELP "--help"
#define ARG_PORTS "--ports"
#define ARG_PREFIX "--prefix"
#define ARG_FILE "--file"
#define ARG_SPEED "--speedup"
#define ARG_SCAN "--scan"
#define ARG_PROTO "protocol-range"



//Type of scans
#define SYN_SCAN   0
#define ACK_SCAN   1
#define NULL_SCAN  2
#define FIN_SCAN   3
#define XMAS_SCAN  4
#define PROTO_SCAN 5
#define UDP_SCAN   6

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



//typedef enum{
//	SYN_SCAN  = 0,
//	ACK_SCAN  = 1,
//	NULL_SCAN = 2,
//	FIN_SCAN  = 3,
//	XMAS_SCAN = 4,
//	PROTO_SCAN = 5,
//}SCAN_INDEX;





#define MAX_PORTS 65535
#define MIN_PORTS 1

struct psd_tcp {
	struct in_addr src;
	struct in_addr dst;
	unsigned char pad;
	unsigned char proto;
	unsigned short tcp_len;
	struct tcphdr tcp;
};




#endif /* GLOBALS_H_ */
