/*
 * request.h
 *
 *  Created on: Jan 10, 2014
 *      Author: ivan
 */

#ifndef REQUEST_H_
#define REQUEST_H_

#include "request.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#define BACKLOG 10     // как много может быть ожидающих соединений
#define MAXDATASIZE 1024
struct TGT{
	char sesion_key_client_TGS[MAXDATASIZE];
	char user_name[MAXDATASIZE];
	int time_live;
	char mark_time[MAXDATASIZE];
	char ip_client[MAXDATASIZE];
};
struct AUTH_CLIENT{
	char id_client[MAXDATASIZE];
	int time_data;
};
struct TICKET{
	char id_client[MAXDATASIZE];
	char ip_client[MAXDATASIZE];
	char time_data[MAXDATASIZE];
	int time_live;
	char sesion_key_client_service[MAXDATASIZE];

};
struct SERVICE_TICKET{
	char sesion_key_client_service[MAXDATASIZE];
	char id_service[MAXDATASIZE];
	int time_live;

};
void date(char *);
void confirm(int new_fd,struct AUTH_CLIENT NEW_AUTH);
void Connect_from_service(int new_fd,struct AUTH_CLIENT NEW_AUTH,struct SERVICE_TICKET service_ticket);
void TGS_REP(int new_fd,struct TICKET ticket,struct SERVICE_TICKET service_ticket);
void TGS_RECV(int sockfd,char *id_service,struct TGT tgt,struct AUTH_CLIENT AUTH);
void AS_REP(int new_fd,char *session_key_client_tgs_secret,char *id_server_secret,int time_live_secret,struct TGT *tgt);
void client_to_AS_REP(int new_fd,char *date_time,char *user_name,char *ID_TGS,char *FLAGS);
#endif /* REQUEST_H_ */
