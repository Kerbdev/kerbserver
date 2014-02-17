/*
 * send&recv_krb5_priv.c
 *
 *  Created on: Feb 17, 2014
 *      Author: ivan
 */

#include "request.h"

void send_krb5_priv(int sockfd,krb5_priv *priv){
	priv->magic=htonl(priv->magic);
	if (send(sockfd, &priv->magic,sizeof(priv->magic) , 0) == -1){
			                   perror("send");}
	send_krb5_enc_data(sockfd,&priv->enc_part);

}
void recv_krb5_priv(int sockfd,krb5_priv *priv){
	if (send(sockfd, &priv->magic,sizeof(priv->magic) , 0) == -1){
			                   perror("send");}
	priv->magic=ntohl(priv->magic);
	recv_krb5_enc_data(sockfd,&priv->enc_part);

}
