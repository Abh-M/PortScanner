
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
bool validateTarget(const char* ipAddress);

int scanStringToNumber(char* scanType);
char *scanNumToString(int scanType);
void flushArray(int *arr,int len);
int getAllIPAddressesInSubnet(char* networkAddress, char* mask);
void getAllIPV6AddressesInSubnet(char *address, char* maskv6);

#endif /* UTILS_H_ */
