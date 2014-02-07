#include "request.h"
void AS_REP(int new_fd,char *session_key_client_tgs_secret,char *id_server_secret,int time_live_secret,struct TGT *tgt){

	date(tgt->mark_time);

	//AC send to client session key Client/TGS
	if (send(new_fd, session_key_client_tgs_secret,MAXDATASIZE , 0) == -1)
                        perror("send");

            //send ID client
        if (send(new_fd, id_server_secret, MAXDATASIZE , 0) == -1)
            perror("send");

	    //send time live
	    if (send(new_fd, (int *)&time_live_secret,sizeof time_live_secret , 0) == -1)
	                perror("send");
        //send tgt copy session key Client/TGS
	    if(send(new_fd, tgt->sesion_key_client_TGS, MAXDATASIZE, 0) == -1)
	    	    	perror("send");

	    //send tgt id client
	    	    if(send(new_fd, tgt->user_name, MAXDATASIZE, 0) == -1)
	    	    	    	perror("recv");
	    	    //send tgt mark time
	    	    	    if(send(new_fd, tgt->mark_time, MAXDATASIZE, 0) == -1)
	    	    	    	    	perror("recv");
	    	    	    //send tgt copy session key Client/TGS
	    	    	    	    if(send(new_fd, (int *) &(tgt->time_live), sizeof tgt->time_live , 0) == -1)
	    	    	    	    	    	perror("recv");
	    	    	    	    //send tgt ip
	    	    	    	    	    if(send(new_fd, tgt->ip_client, MAXDATASIZE, 0) == -1)
	    	    	    	    	    	    	perror("recv");}
