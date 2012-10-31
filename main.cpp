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
	{
		const char *arg = argv[i];
		char *param = strtok((char *)arg, argSeperator);
        //		cout<<"Param="<<param<<endl;
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
            	if(validateTarget(ipAddress))
            		allIPaddress.push_back(ipAddress);
            	else
            	{
            		cout<<"Invalid IP address."<<endl;
            		return 0;
            	}
                //cout<<"IP Address Entered: "<<ipAddress;
                //Use ipaddress as required
            }
        }
		if((strstr(param, ARG_PORTS))!=NULL)
		{
            //			cout<<"Inside !"<<endl;
            flushArray(portsList, MAX_PORTS);
            con->flushPortsList();
			char *ports= strtok((char *)param, valueSeperator);
            //			cout<<"Ports= "<<ports;
			if((strcmp(ARG_PORTS,ports))!=0)
			{
                
				cout<<"Invalid argument. Use "<<ARG_PORTS<<" instead of: "<<ports;
				return 0;
                
			}
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
			char prefixType[15];
			char*prefix = strtok((char *)param, valueSeperator);
			char *networkIP;
			char *mask;
            //			cout<<prefix;
			while ((val = strtok(NULL, valueSeperator))!=NULL)
			{
				networkIP = strtok(val,"/");
				if(networkIP!=NULL)
				{
					if(validateTarget(networkIP))
					{
                        
						mask = strtok(NULL,"/");
						if(!isIpV6(networkIP))
						{
							if(atoi(mask)>31 || atoi(mask)<1)
							{
								cout<<"Invalid subnet mask: "<<mask<<endl;
								return 0;
							}
						}else
						{
							if(atoi(mask)>127 || atoi(mask)<1)
							{
								cout<<"Invalid subnet mask: "<<mask<<endl;
								return 0;
							}
						}
					}
					else
					{
						cout<<"Invalid IP prefix: "<<networkIP;
						return 0;
					}
				}
				//cout<<"mask"<<mask<<endl;
			}
			int res = isIpV6(networkIP);
			if(!isIpV6(networkIP))
				getAllIPAddressesInSubnet(networkIP, mask);
			else
				getAllIPV6AddressesInSubnet(networkIP, mask);
            allIPaddress =  readIPFile("subnetips.txt");
            cout<<"\nTotal Ip in subnet"<<allIPaddress.size();
            
		}
		if((strcmp(param, ARG_FILE))==0)
		{
            //			cout<<"Reading From File!"<<endl;
            allIPaddress =  readIPFile(IP_LIST_FILE);
            //            cout<<"Reading From Done!"<<endl;//<<allIPaddress[1];
            const char *ipp =allIPaddress[1].c_str();
            //            cout<<"\n"<<ipp;
            
		}
		if((strstr(param, ARG_SPEED))!=NULL)
		{
            //enable multithreading
			con->spawnThreads = true;
            con->totalWorkers = MIN_WORKERS;
			cout<<"Speedup="<<con->spawnThreads;
            strtok((char *)param, valueSeperator);
            char* threadsCount = strtok((char *)NULL, valueSeperator);
            if(threadsCount!=NULL)
            {
                
                con->totalWorkers = atoi(threadsCount);
            }
            
            
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
        if((strstr(param, ARG_TIMEOUT))!=NULL)
        {
            strtok((char *)param, valueSeperator);
            char* timeoutInterval = strtok((char *)NULL, valueSeperator);
            if(timeoutInterval!=NULL);
                con->defaultTimeout=atoi(timeoutInterval);
        }
        
        if((strstr(param,ARG_PROTO))!=NULL)
        {
            //seperate protocols to scan according to whether user has entered range or individual protocol numbers.
            char*protocols= strtok((char *)param, valueSeperator);
            int endProtocol;
            int startProtocol;
            int protocolList[MAX_PROTOCOL_NUMBERS];
            int totalProtocols = 0;
            flushArray(protocolList, MAX_PROTOCOL_NUMBERS);
            while ((val = strtok(NULL, valueSeperator))!=NULL)
            {
                char *value;
                //Range of protocols found.
                if(strstr(val,"-")!=NULL)
                {
                    value = strtok(val,"[-]");
                    startProtocol = atoi(value);
                    while(value!=NULL)
                    {
                        endProtocol = atoi(value);
                        value = strtok(NULL,"[-]");
                    }
                    int index=0;
                    for(int i=startProtocol;i<=endProtocol;i++)
                    {
                        if(i<MAX_PROTOCOL_NUMBERS)
                        {
                            protocolList[index++]=i;
                            totalProtocols++;
                            
                        }
                        else
                        {
                            cout<<"\n Protocol number out of range, scanning "<<startProtocol<<" to "<<i;
                            break;
                        }
                        
                    }
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
                            totalProtocols++;
                        }
                    }
                }else
                {
                    protocolList[0]=atoi(val);
                    totalProtocols=1;
                }
                
            }
            if(totalProtocols>0)
                con->populateProtocolNumberToScan(protocolList);
        }
        
        
	}
    
    if(allIPaddress.size()>0)
        con->populateIpAddressToScan(allIPaddress);
    
    //FIX : remove this
    time_t start, end;
    double diff=0;
    time(&start);
    con->startScan();
    time(&end);
    diff = difftime(end, start);
    cout<<"\n Total time elapsed "<<diff<<" seconds";
	return 0;
}



