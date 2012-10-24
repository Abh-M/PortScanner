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
    return ipaddStringList;
}

