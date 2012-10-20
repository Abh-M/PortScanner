

#ifndef GLOBALS_H_
#define GLOBALS_H_

#include <sys/types.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
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
#define DEST_PORT 80

#define SRC_IP "10.0.0.3"
//#define DEST_IP "129.79.247.149"
//#define DEST_IP "72.26.99.2"
//#define DEST_IP "10.0.0.3"
//#define DEST_IP "74.125.225.210"
//#define DEST_IP "69.171.242.70"
//ss
//#define DEST_IP "182.18.135.36"
//giganta
//#define DEST_IP "129.79.246.79"
//#define DEST_IP "129.79.247.195"
#define DEST_IP "203.199.134.78"

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
    kNoResposne,
	kUnkown,



}portStates;



//typedef enum{
//	SYN_SCAN  = 0,
//	ACK_SCAN  = 1,
//	NULL_SCAN = 2,
//	FIN_SCAN  = 3,
//	XMAS_SCAN = 4,
//	PROTO_SCAN = 5,
//}SCAN_INDEX;


#pragma mark  - Copied
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
    u_char ip_vhl;		/* version << 4 | header length >> 2 */
    u_char ip_tos;		/* type of service */
    u_short ip_len;		/* total length */
    u_short ip_id;		/* identification */
    u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
    u_char ip_ttl;		/* time to live */
    u_char ip_p;		/* protocol */
    u_short ip_sum;		/* checksum */
    struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
struct sniff_tcp {
    u_short th_sport;	/* source port */
    u_short th_dport;	/* destination port */
    tcp_seq th_seq;		/* sequence number */
    tcp_seq th_ack;		/* acknowledgement number */
    
    u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;		/* window */
    u_short th_sum;		/* checksum */
    u_short th_urp;		/* urgent pointer */
};



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
