/*
 * log.h
 *
 *  Created on: Feb 10, 2014
 *      Author: ivan
 */

#ifndef LOG_H_
#define LOG_H_
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
typedef int bool;
#define true 1
#define false 0
#define LOGFILE	"kerb.log"     // all Log(); messages will be appended to this file
extern bool LogCreated;      // keeps track whether the log file is created or not
void Log (char *message);    // logs a message to LOGFILE
void LogErr (char *message); // logs a message;
void date(char *);

#endif /* LOG_H_ */
