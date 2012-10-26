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
					scantype = scanStringToNumber(value);
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
    
    
    //TODO: this thing works
    
//    const char* src = "fe80::462a:60ff:fef3:c6ae";
//    
//    struct in6_addr srcAddr;
//    struct sockaddr_in6 srca; srca.sin6_family=AF_INET6; inet_pton(AF_INET6, src, &srca);
//    cout<<"\n....."<<sizeof(srca.sin6_addr);
//    char iip[50];
//    
//    inet_ntop(AF_INET6, &srca.sin6_addr, iip, 50);
//    cout<<"...."<<iip;

//    cout<<"\n...in6_addr src and dest address : "<<sizeof(struct in6_addr);
//        cout<<"\n...in_addr : "<<sizeof(struct in_addr);
//    cout<<"\n...unsigned char : "<<sizeof(unsigned char);
//    cout<<"\n...unsigned short : "<<sizeof(unsigned short);
//    cout<<"\n...unsigned int --> tcp length   : "<<sizeof(u_int);
//        cout<<"\n...unsigned int --> tcp length   : "<<sizeof(u_int);
 //   cout<<"\n..."<<sizeof(struct pseudo_tcp6);
    
    ScanRequest newReq;
    newReq.srcPort = 5679;
    newReq.destPort = 80;
    newReq.scanType = SYN_SCAN;
    con->runTCPscan(newReq);
    //con->populateIpAddressToScan(allIPaddress);
    //cout<<"\n Total Ip address"<<allIPaddress.size();
    //set source and destination IP address and then start scan
    //con->setTargetIPAddress(DEST_IP);
    //con->spawnThreads=true;
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



