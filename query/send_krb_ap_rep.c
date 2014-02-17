/*
 * send_krb_ap_rep.c
 *
 *  Created on: Feb 17, 2014
 *      Author: ivan
 */
#include "request.h"
void send_krb5_ap_rep(int sockfd,krb5_ap_rep *req){
	req->magic=htonl(req->magic);
	if (send(sockfd, &req->magic,sizeof(req->magic) , 0) == -1){
			                   perror("send");}

	send_krb5_enc_data(sockfd,&req->enc_part);

}


