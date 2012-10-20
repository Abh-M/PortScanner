/*
 * Utils.h
 *
 *  Created on: Oct 13, 2012
 *      Author: raj
 */

#ifndef UTILS_H_
#define UTILS_H_

#include "Globals.h"


char* statusToStr(portStates state);
int getPacketSizeForScanType(int scanType);
TCPScanType  getTCPScanTypeFromScanType(int kType);




#endif /* UTILS_H_ */
