/*
 * ScanController.h
 *
 *  Created on: Oct 13, 2012
 *      Author: raj
 */

#ifndef SCANCONTROLLER_H_
#define SCANCONTROLLER_H_

#include "Globals.h"
#include <cstring>

//struct scanResult
//{
//	int syn,rst,psh,ack,fin,urg;
//	int scanType;
//	int port;
//};


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

class ScanController {
public:

    
#pragma mark - memeber variables
	//port range
	//if only one port set endPort=-1
	int startPort;
	int endPort;
    

	// 0 0 0 0 0 0...each set bit denotes which type of scan to carry out
	int typeOfScans[6];

    //to read IP from filename
	char *fileName;

	bool speed;
	
    bool scanLocalhost;

	char *targetIP;
	char *sourceIP;

	int portsToScan[65536];
	int totalPortsToScan;
	
    bool isRange;
    
    
    
    
    
#pragma mark - methods

	ScanController();
	virtual   				 ~ScanController();

	static ScanController*  shared();
	ScanResult       				runTCPscan(ScanRequest kRequest);
	void       				setTargetIPAddress(char *kTargetIp);
	ScanResult 				scanPort(ScanRequest kRequest);
    void                    scanPorts();
    void populatePortsList();

};

#endif /* SCANCONTROLLER_H_ */
