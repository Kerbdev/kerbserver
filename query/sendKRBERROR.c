/*
 * sendKRBERROR.c
 *
 *  Created on: Feb 16, 2014
 *      Author: ivan
 */
#include "request.h"

void send_krb5_error(int new_fd,krb5_error err){
	    err.magic=htonl(err.magic);
		if (send(new_fd, &err.magic,sizeof(err.magic) , 0) == -1){
						                   perror("send");}
		err.ctime=htonl(err.ctime);
				if (send(new_fd, &err.ctime,sizeof(err.ctime) , 0) == -1){
					perror("send");}
		err.cusec=htonl(err.cusec);
				if (send(new_fd, &err.cusec,sizeof(err.cusec) , 0) == -1){
											perror("send");}
		err.susec=htonl(err.susec);
				if (send(new_fd, &err.susec,sizeof(err.susec) , 0) == -1){
											perror("send");}
		err.stime=htonl(err.stime);
				if (send(new_fd, &err.stime,sizeof(err.stime) , 0) == -1){
											perror("send");}
		send_principal_data(new_fd,*err.server);
		send_principal_data(new_fd,*err.client);
		send_krb5_data(new_fd,err.text);
		send_krb5_data(new_fd,err.e_data);
				}
