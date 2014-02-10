/*
 * date.c
 *
 *  Created on: Dec 16, 2013
 *      Author: ivan
 */
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
void date(char *date_mas){
	time_t rawtime;
	  struct tm * timeinfo;

	  time (&rawtime);
	  timeinfo = localtime (&rawtime);
	  strcpy(date_mas,asctime(timeinfo));
	  printf ("Current local time and date: %s", asctime(timeinfo));
}
