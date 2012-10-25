/*
 * Utils.cpp
 *
 *  Created on: Oct 13, 2012
 *      Author: raj
 */

#include "Utils.h"
#include <string.h>
#include <stdio.h>
#include <fstream>
#include <sstream>
#include<iostream>
#include <stdlib.h>
#include<vector>
using namespace std;



void flushArray(int *arr,int len)
{
    for (int i=0; i<len; i++) {
        arr[i]=INVALID_PORT;
    }
}

char *scanNumToString(int scanType)
{
	char *str = new char[10]();
	switch(scanType)
	{
        case SYN_SCAN:
            strcpy(str,"SYN");
            break;
        case FIN_SCAN:
            strcpy(str,"FIN");
            break;
        case ACK_SCAN:
            strcpy(str,"ACK");
            break;
        case NULL_SCAN:
            strcpy(str,"NULL");
            break;
        case XMAS_SCAN:
            strcpy(str,"XMAS");
            break;
        case PROTO_SCAN:
            strcpy(str,"PROTOCOL");
            break;
        default:
            strcpy(str,"Unknown scan type!!");
            break;
            
	}
	return str;
    
}

int scanStringToNumber(char* scanType)
{
	if(strcmp(scanType,"SYN")==0)
		return SYN_SCAN;
	else if(strcmp(scanType,"NULL")==0)
		return NULL_SCAN;
	else if(strcmp(scanType,"FIN")==0)
		return FIN_SCAN;
	else if(strcmp(scanType,"XMAS")==0)
		return XMAS_SCAN;
	else if(strcmp(scanType,"ACK")==0)
		return ACK_SCAN;
	else return UNKNOWN_SCAN;
}

int getPacketSizeForScanType(int scanType)
{
    int packetsize = 0;
    
    switch (scanType) {
        case SYN_SCAN:
        case FIN_SCAN:
        case ACK_SCAN:
        case XMAS_SCAN:
        case NULL_SCAN:
            packetsize = 20+20; //ip 20 and tcp 20
            break;
        case UDP_SCAN:
            packetsize = 20+8;
            break;
        default:
            break;
    }
    return packetsize;
}

TCPScanType  getTCPScanTypeFromScanType(int kType)
{
    TCPScanType type;
    switch (kType) {
        case SYN_SCAN:
            type = kSYN;
            break;
        case ACK_SCAN:
            type = kACK;
            break;
        case FIN_SCAN:
            type = kFIN;
            break;
        case NULL_SCAN:
            type = kNULL;
            break;
        case XMAS_SCAN:
            type =kXMAS;
            break;
        default:
            type =kInvalidScanType;
            break;
    }
    return type;
}


char *getStringForPortState(portStates kState)
{
    
    char *str = "Not Used";
    switch (kState) {
        case kOpen:str="open";break;
        case kClosed:str="closed";break;
        case kCloedAndFiltered: str="closed and filtered";break;
        case kFiltered: str="filtered"; break;
        case kUnkown: str="unknown"; break;
        case kUnFiltered: str="unfiltered"; break;
        case kNoResposne: str="no response"; break;
        case kOpenORFiltered: str="open or filtered"; break;
        case kClosedAndUnfiltered: str="closed or filtered"; break;
        case kOpenAndFiltered: str="open and filtered"; break;
        case kOpenAndUnfiltered: str="open and unfiltered"; break;
        default:break;
    }
    return str;
}


char* statusToStr(portStates state)
{
	char *str =new char[20]();
	memset(str,0,20);
	switch(state)
	{
        case kOpen: strcpy(str,"Open");break;
        case kClosed: strcpy(str,"Closed");break;
        case kFiltered: strcpy(str,"Filtered");break;
        case kUnFiltered: strcpy(str,"UnFiltered"); break;
        default: strcpy(str,"Invalid state"); break;
            
	}
    
	return str;
}

#pragma mark -obsolete
struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
};

/*
 Generic checksum calculation function
 */
unsigned short csum(unsigned short *ptr,int nbytes)
{
	register long sum;
	unsigned short oddbyte;
	register short answer;
    
	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}
    
	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;
    
	return(answer);
}

void readHelpFile(char *fileName)
{
    ifstream infile;
    infile.open(fileName);
    string line, contents;
    
    if (infile.is_open())
    {
        while (!infile.eof())
        {
            getline(infile, line);
            cout<<line<<endl;
            contents = contents + line + "\n";
        }
    }
    
}

vector<string> readIPFile(char *fileName)
{
	ifstream infile;
	vector<string> ipaddStringList;
	ipaddStringList.clear();
	infile.open(fileName);
	string line, contents;
    
	if (infile.is_open())
	{
		while (!infile.eof())
		{
			getline(infile, line);
			cout<<line<<endl;
			ipaddStringList.push_back(line);
		}
	}
    //danger
    ipaddStringList.pop_back();
    return ipaddStringList;
}

void writeToFile(char *fileName, char *ipAddress)
{
    ofstream file;
    file.open (fileName,ofstream::out | ofstream::app);
    file <<ipAddress<<"\n";
    file.close();
}

void truncateFile(char* fileName)
{
	ofstream file;
    file.open(fileName,fstream::out | fstream::trunc);
	file.close();
}


int getAllIPAddressesInSubnet(char* networkAddress, char* mask)
{
    
    int totalIpAddressInSubnet = 0;
	truncateFile(SUBNET_IP_FILE);
	cout<<"NetworkAddress:"<<networkAddress<<endl<<"Mask:"<<mask;
	char* octet1 = strtok((char *)networkAddress, ".");
	cout<<"Octet1: "<<octet1<<endl;
	char* octet2 = strtok((char *)NULL, ".");
	cout<<"Octet2: "<<octet2<<endl;
	char* octet3 = strtok((char *)NULL, ".");
	cout<<"Octet3: "<<octet3<<endl;
	char* octet4 = strtok((char *)NULL, ".");
	cout<<"Octet4: "<<octet4<<endl;
    
	stringstream myString;
    
	int intMask=atoi(mask);
	int bitsChangedinOct1,bitsChangedinOct2,bitsChangedinOct3,bitsChangedinOct4;
	float totalBitsChangedFloat = 32 - intMask;
	int totalBitsChanged = (int)totalBitsChangedFloat;
    
	cout<<"totalbitsChanged= "<<totalBitsChanged<<endl;
	cout<<"division/8= "<<totalBitsChanged/8<<endl;
	if((totalBitsChangedFloat/8)>3)
	{
		cout<<"totalBitsChanged > 24"<<endl;
		if((totalBitsChanged % 8)==0)
			bitsChangedinOct1 = 8;
		else bitsChangedinOct1 = (totalBitsChanged % 8);
		bitsChangedinOct2 = 8;
		bitsChangedinOct3 = 8;
		bitsChangedinOct4 = 8;
	}else if((totalBitsChangedFloat/8)>2 && (totalBitsChangedFloat/8)<=3)
	{
		cout<<"totalBitsChanged > 16"<<endl;
		bitsChangedinOct1 = 0;
		if((totalBitsChanged % 8)==0)
			bitsChangedinOct2 = 8;
		else bitsChangedinOct2 = (totalBitsChanged % 8);
		bitsChangedinOct3 = 8;
		bitsChangedinOct4 = 8;
	}else if((totalBitsChangedFloat/8)>1 && (totalBitsChanged/8)<=2)
	{
		cout<<"totalBitsChanged > 8"<<endl;
		bitsChangedinOct1 = 0;
		bitsChangedinOct2 = 0;
		if((totalBitsChanged % 8)==0)
			bitsChangedinOct3 = 8;
		else bitsChangedinOct3 = (totalBitsChanged % 8);
		bitsChangedinOct4 = 8;
	}else if((totalBitsChangedFloat/8)>=0 && (totalBitsChangedFloat/8)<=1)
	{
		cout<<"totalBitsChanged > 0"<<endl;
		bitsChangedinOct1 = 0;
		bitsChangedinOct2 = 0;
		bitsChangedinOct3 = 0;
		if((totalBitsChanged % 8)==0)
			bitsChangedinOct4 = 8;
		else bitsChangedinOct4 = (totalBitsChanged % 8);
	}
    
	int oct4,oct3,oct2,oct1;
    
	oct1 = atoi(octet1);
	oct2 = atoi(octet2);
	oct3 = atoi(octet3);
	oct4 = atoi(octet4);
    
	for(int i=0;i<pow(2,bitsChangedinOct1);i++)
	{
		cout<<"Oct1:"<<oct1<<endl;
		if(oct1>255)
		{
			oct1=atoi(octet1);
			break;
		}
		for(int j=0;j<pow(2,bitsChangedinOct2);j++)
		{
			cout<<"Oct2:"<<oct2<<endl;
			if(oct2>255)
			{
				oct2=atoi(octet2);
				oct1 = oct1+1;
				break;
			}
			for(int k=0;k<pow(2,bitsChangedinOct3);k++)
			{
				cout<<"Oct3:"<<oct3<<endl;
				if(oct3>255)
				{
					oct3=atoi(octet3);
					oct2 = oct2+1;
					break;
				}
                
				for(int l=0;l<pow(2,bitsChangedinOct4);l++)
				{
					char addr[50];
					sprintf(addr,"%d.%d.%d.%d",oct1,oct2,oct3,oct4);
                    //cout<<"\n--->"<<addr;
					writeToFile(SUBNET_IP_FILE,addr);
                    totalIpAddressInSubnet++;
					oct4 = oct4+1;
					if(oct4>255)
					{
						oct4=atoi(octet4);
						oct3 = oct3+1;
						break;
					}
                    
				}
			}
		}
        
	}
    
    return totalIpAddressInSubnet;
}
