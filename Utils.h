/*
 * Utils.h
 *
 *  Created on: Oct 13, 2012
 *      Author: raj
 */

#ifndef UTILS_H_
#define UTILS_H_

#include "Globals.h"
#include "PCH.h"
using namespace std;
char* statusToStr(portStates state);
int getPacketSizeForScanType(int scanType);
TCPScanType  getTCPScanTypeFromScanType(int kType);
void readHelpFile(char *fileName);
vector<string> readIPFile(char *fileName);
char *getStringForPortState(portStates kState);

int scanStringToNumber(char* scanType);
char *scanNumToString(int scanType);
void flushArray(int *arr,int len);
void getAllIPAddressesInSubnet(char* networkAddress, char* mask);

#endif /* UTILS_H_ */
