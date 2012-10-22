/*
 * ScanController.h
 *
 *  Created on: Oct 13, 2012
 *      Author: raj
 */

#ifndef SCANCONTROLLER_H_
#define SCANCONTROLLER_H_


#include "PCH.h"
//struct scanResult
//{
//	int syn,rst,psh,ack,fin,urg;
//	int scanType;
//	int port;
//};



typedef struct AllScanResult
{
    
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
    
}ProtocolScanRequest;

typedef struct ProtocolScanResult
{
    int protocolNumber;
    bool protocolSupported;
}ProtocolScanResult;

class ScanController {
public:
    
    
#pragma mark - memeber variables
	//port range
	//if only one port set endPort=-1
	int startPort;
	int endPort;
    
    
	// 0 0 0 0 0 0...each set bit denotes which type of scan to carry out
	int typeOfScans[7];
    
    //to read IP from filename
	char *fileName;
    
	bool speed;
	
    bool scanLocalhost;
    
	char *targetIP;
	char *sourceIP;
    
	int portsToScan[MAX_PORTS];
	int totalPortsToScan;
	
    bool isRange;
    
    AllScanResultForPort allPortsScanResult[65535];
    int allPortsScanResultIndex;
    
    
    int protocolNumbersToScan[256];
    int totalProtocolsToScan;
    
    
    int totalIpAddressToScan;
    char *ipaddresses[10];
    
    
#pragma mark - methods
    
	ScanController();
	virtual   				 ~ScanController();
    
	static ScanController*  shared();
	ScanResult       		runTCPscan(ScanRequest kRequest);
    ScanResult              runUDPScan(ScanRequest kRequest);
	void       				setTargetIPAddress(char *kTargetIp);
	void                    scanPort(ScanRequest kRequest);
    void                    scanPorts();
    void                    populateProtocolNumberToScan();
    void                    runProtocolScan();
    void                    populatePortsList();
    ProtocolScanResult      runScanForProtocol(ProtocolScanRequest req);
    void                    resetAllScanTypes();
    void                    printScanTypeConf();
    void                    flushPortsList();
    void                    populatePortsList(int array[]);
    void                    populatePortsList(int kStart, int kEnd);
    
};

#endif /* SCANCONTROLLER_H_ */
