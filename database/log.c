/*
 * log.c
 *
 *  Created on: Feb 10, 2014
 *      Author: ivan
 */
#include "log.h"

void Log (char *message)
{   char time[250];
    FILE *file;


        file = fopen(LOGFILE, "aw");

    if (file == NULL)
        return;
    else
    {
    	date(time);
    	strcat(message," ");
    	strcat(message,time);
    	fputs(message,file);
        fclose(file);
    }

}

void LogErr (char *message)
{
    Log(message);
}

