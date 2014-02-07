/*
 * date.c
 *
 *  Created on: Dec 16, 2013
 *      Author: ivan
 */
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <time.h>
char* asd(const struct tm *timeptr);
void date(char *date_mas){
	time_t rawtime;
	struct tm * timeinfo;
	time (&rawtime);
	timeinfo = localtime (&rawtime);
	strcpy(date_mas,asd(timeinfo));
}
char* asd(const struct tm *timeptr)
{
  static const char mon_name[][4] = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
  static char result[26];
  sprintf(result, "%2d %.3s %d %.2d:%.2d:%.2d",timeptr->tm_mday,mon_name[timeptr->tm_mon],1900 + timeptr->tm_year, timeptr->tm_hour,
    timeptr->tm_min, timeptr->tm_sec);
  return result;
}
