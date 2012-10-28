//
//  main.cpp
//  demo
//
//  Created by Abhineet on 10/10/12.
//  Copyright (c) 2012 Abhineet. All rights reserved.
//

#include "PCH.h"
#include "ScanController.h" 
#include "Helpers.h"
#include "Utils.h"

using namespace std;


int main(int argc, const char * argv[])
{
//    char *ipv6 = "2001:18e8:2:28a6:462a:60ff:fef3:c6ae";
//    char *mask = "126";
//    getAllIPV6AddressesInSubnet(ipv6, mask);
//    return 0;
    
    //create scan controller with default parameters
	ScanController *con =  ScanController::shared();
    
	const char *argSeperator = " ";
	const char *valueSeperator = "=";
    vector<string> allIPaddress;
	int portsList[MAX_PORTS];
	for(int i=1;i<argc;i++)
        //0 is command
	{
		const char *arg = argv[i];
		char *param = strtok((char *)arg, argSeperator);
		cout<<"Param="<<param<<endl;
		char* val = NULL;
		if(strcmp(param, ARG_HELP)==0)
		{
			readHelpFile(HELP_FILE);
			return 0;
		}
        if(strstr(param,ARG_IP)!=NULL)
        {
            char*ipParam = strtok((char *)param, valueSeperator);
            strlen(ipParam);
            char*ipAddress = strtok((char *)NULL, valueSeperator);
            if(ipAddress!=NULL)
            {
//                vector<string> allIPaddress;
                allIPaddress.push_back(ipAddress);
                //cout<<"IP Address Entered: "<<ipAddress;
                //Use ipaddress as required
            }
        }
		if((strstr(param, ARG_PORTS))!=NULL)
		{
            flushArray(portsList, MAX_PORTS);
            con->flushPortsList();
			char *ports= strtok((char *)param, valueSeperator);
            strlen(ports);
			while ((val = strtok(NULL, valueSeperator))!=NULL)
			{
				//seperate ports according to whether user has entered range or individual ports.
                //cout<<val<<endl;
				char *value;
                //Range of ports found.
				if(strstr(val,"-")!=NULL)
				{
                    
					value = strtok(val,"[-]");
					con->startPort = atoi(value);
					while(value!=NULL)
					{
						con->endPort = atoi(value);
						value = strtok(NULL,"[-]");
                        
					}
                    
                    
                    con->populatePortsList(con->startPort, con->endPort);
				}
				else if(strstr(val,",")!=NULL)
				{
                    //list of ports found
					int i=1;
					value = strtok(val,",");
					portsList[0]=atoi(value);
                    //cout<<portsList[0];
					while(value!=NULL)
					{
						value = strtok(NULL,",");
						if(value!=NULL)
						{
							portsList[i] = atoi(value);
							i++;
						}
					}
                    con->populatePortsList(portsList);
				}
                else
                {
                    portsList[0]=atoi(val);
                    con->populatePortsList(portsList);
                }
			}
            
            
		}
		if((strstr(param, ARG_PREFIX))!=NULL)
            //read ip prefix
		{
			char*prefix = strtok((char *)param, valueSeperator);
			char *networkIP;
			char *mask;
			cout<<prefix;
			while ((val = strtok(NULL, valueSeperator))!=NULL)
			{
				networkIP = strtok(val,"/");
				//cout<<"IP:"<<networkIP;
				if(networkIP!=NULL)
				{
					mask = strtok(NULL,"/");
				}
				//cout<<"mask"<<mask<<endl;
			}
			int totalIps = getAllIPAddressesInSubnet(networkIP, mask);
            allIPaddress =  readIPFile("/Users/abhineet/Github/demo/demo/subnetips.txt");
            cout<<"\nTotal Ip in subnet"<<allIPaddress.size();
            
            
            
		}
		if((strcmp(param, ARG_FILE))==0)
		{
			cout<<"Reading From File!"<<endl;
			 allIPaddress =  readIPFile("/Users/abhineet/Github/demo/demo/IPAddressList.txt");
            cout<<"Reading From Done!"<<endl;//<<allIPaddress[1];
            const char *ipp =allIPaddress[1].c_str();
            cout<<"\n"<<ipp;
            
            
		}
		if((strcmp(param, ARG_SPEED))==0)
		{
            //enable multithreading
			con->spawnThreads = true;
			cout<<"Speedup="<<con->spawnThreads;
		}
		if((strstr(param, ARG_SCAN))!=NULL)
		{
            con->resetAllScanTypes();
            
            //seperate and organise list types of scans
			char *scans= strtok((char *)param, valueSeperator);
            strlen(scans);
			while ((val = strtok(NULL, valueSeperator))!=NULL)
			{
				char *value;
				int scantype;
				if(strstr(val,",")!=NULL)
				{
                    //list of scanTypes found
					value = strtok(val,",");
					if(value!=NULL)
					{
						scantype = scanStringToNumber(value);
						if(scantype!=UNKNOWN_SCAN)
							con->typeOfScans[scantype]=1;
					}
					while(value!=NULL)
					{
						value = strtok(NULL,",");
						if(value!=NULL)
						{
							scantype = scanStringToNumber(value);
							if(scantype!=UNKNOWN_SCAN)
								con->typeOfScans[scantype]=1;
						}
					}
				}
                else
				{
					scantype = scanStringToNumber(val);
					if(scantype!=UNKNOWN_SCAN)
						con->typeOfScans[scantype]=1;
				}
			}
		}
        
        if((strstr(param,ARG_PROTO))!=NULL)
        {
            //seperate protocols to scan according to whether user has entered range or individual protocol numbers.
            char*protocols= strtok((char *)param, valueSeperator);
            //cout<<"Protocols"<<protocols;
            int endProtocol;
            int startProtocol;
            int protocolList[255];
            flushArray(protocolList, 255);
            while ((val = strtok(NULL, valueSeperator))!=NULL)
            {
                char *value;
                //Range of protocols found.
                if(strstr(val,"-")!=NULL)
                {
                    value = strtok(val,"[-]");
                    //con->startPort = atoi(value);
                    startProtocol = atoi(value);
                    
                    while(value!=NULL)
                    {
                        endProtocol = atoi(value);
                        value = strtok(NULL,"[-]");
                        
                    }
                    cout<<"start Protocol:"<<startProtocol<<endl;
                    cout<<"end Protocol:"<<endProtocol;
                }
                else if(strstr(val,",")!=NULL)
                {
                    //list of ports found
                    int i=1;
                    value = strtok(val,",");
                    protocolList[0]=atoi(value);
                    //cout<<portsList[0];
                    while(value!=NULL)
                    {
                        value = strtok(NULL,",");
                        if(value!=NULL)
                        {
                            protocolList[i] = atoi(value);
                            i++;
                        }
                    }
                }else protocolList[0]=atoi(val);
                
            }//con->populateProtocolNumberToScan(protocolList);
        }
        
        
	}
    
    
    
    
    ScanRequest newReq;
    newReq.srcPort = 5678;
    newReq.destPort = 80;
    newReq.scanType = SYN_SCAN;
    newReq.destIp="140.182.277.77";
    newReq.sourceIp = con->hostDevAndIp.ip;
////    newReq.destIp = "::1";
//    newReq.destIp = "2607:f8b0:400c:c01::69";
    con->runTCPscan(newReq);
    
//    2001:4860:4860::8888
    //2001:18e8:2:28a6:462a:60ff:fef3:c6ae
//    ScanRequest udpScanReq;// = createScanRequestFor(5678, 53, con->hostDevAndIp.ip, "8.8.8.8",UDP_SCAN);
//    udpScanReq.destIp = "8.8.8.8";
//        udpScanReq.destIp = "129.79.246.79";
//    udpScanReq.sourceIp = con->hostDevAndIp.ip;
//    udpScanReq.destIp = "2607:f8b0:400c:c01::69";
//    udpScanReq.destIp = "2607:f8b0:400c:c01::68";
//    udpScanReq.sourceIp = "fe80::462a:60ff:fef3:c6ae";
//    udpScanReq.destIp = "fe80::5054:ff:fefe:23e4";
//    udpScanReq.sourceIp = "::1";
    //    udpScanReq.destIp = "fe80::5054:ff:fefe:23e4";
//    udpScanReq.destIp = "::1";

    
        //udpScanReq.sourceIp = "140.182.146.113";

//
//    udpScanReq.srcPort = 5678;
//        udpScanReq.destPort = 45;
//    ScanResult udpScanResultForPort = con->runUDPScan(udpScanReq);
//    ProtocolScanRequest req;
//    req.srcPort = 5678;
//    req.desPort = 45;
//    req.sourceIp = con->hostDevAndIp.ip;
//        req.sourceIp = "2001:18e8:2:28a6:354a:d9cc:2b81:d47a";
//    req.destIp = "140.182.147.5";
//        req.destIp = "127.0.0.1";
//    req.destIp="fe80::222:fbff:fe19:fb8e";
//    req.destIp = "2607:f8b0:400c:c01::69";
//        req.destIp = "2001:4860:4860::8844";
//    for(int i=0;i<=255;i++)
//    {
//        cout<<"\n---------------------------\n";
//        req.protocolNumber = 213;
//        con->runScanForProtocol(req);
//        cout<<"\n---------------------------\n";
        
//    }


    
//con->populateIpAddressToScan(allIPaddress);
//cout<<"\n Total Ip address"<<allIPaddress.size();
////con->setTargetIPAddress(DEST_IP);
//con->spawnThreads=false;
//con->startScan();
    
    
    
    
    //con->setUpJobsAndJobDistribution();
    //con->scanPortsWithThread();
    //con->scanPorts();
    //    Job *j = con->getNextJob(0);
    //    j=con->getNextJob(1);
    //    j=con->getNextJob(2);
    //    j=con->getNextJob(3);
    //    j=con->getNextJob(4);
    //    j=con->getNextJob(1);
    //    j=con->getNextJob(1);
    //    j=con->getNextJob(0);
    //    j=con->getNextJob(3);
    //    j=con->getNextJob(3);
    //    j=con->getNextJob(2);
    //    j=con->getNextJob(1);
    //con->scanPorts();
    //    con->printScanTypeConf();
    //    con->scanPorts();
	return 0;
}



