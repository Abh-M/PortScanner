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
    
	bool spawnThreads;
	
    bool scanLocalhost;
    
	char *targetIP;
	char *sourceIP;
    
	int portsToScan[MAX_PORTS];
	int totalPortsToScan;
	
    bool isRange;
    
    AllScanResultForPort allPortsScanResult[65535];
    int allPortsScanResultIndex;
    
    
    int protocolNumbersToScan[MAX_PROTOCOL_NUMBERS];
    int totalProtocolsToScan;
    
    
    
    int totalWorkers;
    
    
    devAndIp hostDevAndIp;
    char *devString;
    
    
    vector<string> allIpAddressToScan;
    int totalIpAddressToScan;

    
    
#pragma mark - methods
    
	ScanController();
	virtual   				 ~ScanController();
    
	static ScanController*  shared();
    
    void                    setTargetIPAddress(char *kTargetIp);
    void                    setSrcAndDesAndDevString(bool islocalhost, char *kDestIp);
    void                    printScanTypeConf();
    void                    resetAllScanTypes();



    
	ScanResult       		runTCPscan(ScanRequest kRequest);
    ScanResult              runUDPScan(ScanRequest kRequest);
  
    void                    startScan();
	void                    scanPort();
    void                    scanPorts();
    void                    scanPortsWithThread();
    void                    runProtocolScan();
    ProtocolScanResult      runScanForProtocol(ProtocolScanRequest req);



    void                    flushPortsList();
    void                    populateProtocolNumberToScan();
    void                    populateProtocolNumberToScan(int kProtocolNumbersList[MAX_PROTOCOL_NUMBERS]);
    void                    populatePortsList();
    void                    populatePortsList(int array[]);
    void                    populatePortsList(int kStart, int kEnd);


    
    
    void                    setUpJobsAndJobDistribution();
    Job                     getNextJob(int kWorkerId);
    
    void                    populateIpAddressToScan(vector<string> kIpAddressList);
    void                    populateIpAddressToScan();

    
    
};

#endif /* SCANCONTROLLER_H_ */
