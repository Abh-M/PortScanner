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
    
//    char  *ip = "129.79.247.149";
//    scanHTTP(ip);
//    return 0;
//    
//    
//    getMyIpAddress();
//    return 0;
    
	ScanController *con =  ScanController::shared();
    
	const char *argSeperator = " ";
	const char *valueSeperator = "=";
    bool isIpProvided = false;
    vector<string> allIPaddress;
	int portsList[MAX_PORTS];
	for(int i=1;i<argc;i++)
        //0 is command
	{
		const char *arg = argv[i];
		char *param = strtok((char *)arg, argSeperator);
		cout<<"Param="<<param<<endl;
		char* val = NULL;
        //		if(strcmp(param, ARG_HELP)==0)
        //		{
        //			readHelpFile(HELP_FILE);
        //            //as help is a standalone argument return and don't process further commands
        //			return 0;
        //		}
		if((strstr(param, ARG_PORTS))!=NULL)
		{
            flushArray(portsList, MAX_PORTS);
            con->flushPortsList();
			char*ports= strtok((char *)param, valueSeperator);
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
        //		if((strcmp(param, ARG_PREFIX))==0){}
        //        //read ip prefix
        //		{
        //
        //		}
		if((strcmp(param, ARG_FILE))==0)
		{
			cout<<"Reading From File!"<<endl;
			vector<string> allIPaddress =  readIPFile("/Users/abhineet/Github/demo/demo/IPAddressList.txt");
            cout<<"Reading From Done!"<<allIPaddress[1];
            
            
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
        
        //		if((strstr(param,ARG_PROTO))!=NULL)
        //		{
        //            //seperate protocols to scan according to whether user has entered range or individual protocol numbers.
        //			char*protocols= strtok((char *)param, valueSeperator);
        //            //cout<<"Protocols"<<protocols;
        //			int endProtocol;
        //			int startProtocol;
        //			int protocolList[255];
        //			while ((val = strtok(NULL, valueSeperator))!=NULL)
        //			{
        //				char *value;
        //                //Range of protocols found.
        //				if(strstr(val,"-")!=NULL)
        //				{
        //					value = strtok(val,"[-]");
        //                    //con->startPort = atoi(value);
        //					startProtocol = atoi(value);
        //
        //					while(value!=NULL)
        //					{
        //						endProtocol = atoi(value);
        //						value = strtok(NULL,"[-]");
        //
        //					}
        //					cout<<"start Protocol:"<<startProtocol<<endl;
        //					cout<<"end Protocol:"<<endProtocol;
        //				}
        //				else if(strstr(val,",")!=NULL)
        //				{
        //                    //list of ports found
        //					int i=1;
        //					value = strtok(val,",");
        //					protocolList[0]=atoi(value);
        //                    //cout<<portsList[0];
        //					while(value!=NULL)
        //					{
        //						value = strtok(NULL,",");
        //						if(value!=NULL)
        //						{
        //							protocolList[i] = atoi(value);
        //							i++;
        //						}
        //					}
        //				}
        //			}
        //		}
        
	}
    
    
    
    
    
    
    //set source and destination IP address and then start scan
    //con->setTargetIPAddress(SRC_IP, DEST_IP);
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



