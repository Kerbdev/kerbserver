/*
 * request.c
 *
 *  Created on: Jan 10, 2014
 *      Author: ivan
 */
#include "request.h"
void client_to_AS_REP(int new_fd,char *date_time,char *user_name,krb5_kdc_req *as_rep,char *FLAGS){
//date sync
	as_rep->magic=htonl(as_rep->magic);
	if (send(new_fd, &as_rep->magic,sizeof(as_rep->magic) , 0) == -1){
	               //       perror("send");}






















	     char enter_id_client[]="Enter ID client:";
	    char enter_id_service_tgs[]="Enter ID service TGS:";
            date(date_time);
            if (send(new_fd, date_time,MAXDATASIZE , 0) == -1){
                      perror("send");}

            //send Enter ID client
        if (send(new_fd, enter_id_client, MAXDATASIZE , 0) == -1)
            perror("send");

	   if(recv(new_fd, user_name, sizeof user_name, 0) == -1)
	    perror("recv");
	    //send Ender Id services TGS
	   if (send(new_fd, enter_id_service_tgs,MAXDATASIZE , 0) == -1)
	               perror("send");


	    //Compare with data. And send result to client Denied or Acses
		if(!(strcmp(user_name,"Ivan"))){
			*FLAGS=1;
			if (send(new_fd, "You in sytem\n",MAXDATASIZE, 0) == -1)
                              perror("send");
	        printf("\n%s is Enter",user_name);

		    }
		else{
			if (send(new_fd, "Denied acses\n",MAXDATASIZE, 0) == -1)
                             perror("send");
                         printf("\n%s trie connect in system,Denied",user_name);}

		if (send(new_fd, FLAGS, 1 , 0) == -1)
		           perror("send");
		fflush(stdout);

		//if in BD set FLAGS in 1
		//filewrite("/home/ivan/fghjk","Hello world");
           }}
