/*
 * ScanController.h
 *
 *  Created on: Oct 13, 2012
 *      Author: raj
 */

#ifndef SCANCONTROLLER_H_
#define SCANCONTROLLER_H_


#include "PCH.h"
#include "Globals.h"
//struct scanResult
//{
//	int syn,rst,psh,ack,fin,urg;
//	int scanType;
//	int port;
//};


using namespace std;




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
	void       				setTargetIPAddress(char *kSourceIp,char *kTargetIp);
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
    void                    setUpJobsAndJobDistribution();
    Job*                    getNextJob(int kWorkerId);
};

#endif /* SCANCONTROLLER_H_ */
