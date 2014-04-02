/*
 * recv_krb5_ap_req.c
 *
 *  Created on: Feb 17, 2014
 *      Author: ivan
 */
#include "request.h"
void recv_krb5_ap_req(int sockfd,krb5_ap_req *req){

	if (recv(sockfd, &req->magic,sizeof(req->magic) , 0) == -1){
			                   perror("recv");}
	req->magic=ntohl(req->magic);
	if (recv(sockfd, &req->ap_options,sizeof(req->ap_options) , 0) == -1){
					                   perror("recv");}
	req->ap_options=ntohl(req->ap_options);
	recv_krb5_ticket(sockfd,req->ticket);
	recv_krb5_enc_data(sockfd,&req->authenticator);

}

