#include "request.h"
void TGS_REP(int new_fd,struct TICKET ticket,struct SERVICE_TICKET service_ticket){
	//AC send to client session key Client/TGS
		if (send(new_fd, ticket.id_client,MAXDATASIZE , 0) == -1)
	                        perror("send");

	            //send ID client
	        if (send(new_fd, ticket.ip_client, MAXDATASIZE , 0) == -1)
	            perror("send");

		    //send time live
		    if (send(new_fd, (int *) &ticket.time_live,sizeof ticket.time_live , 0) == -1)
		                perror("send");
	        //send tgt copy session key Client/TGS
		    if(send(new_fd, ticket.sesion_key_client_service, MAXDATASIZE, 0) == -1)
		    	    	perror("send");

		    //send tgt id client
		    	    if(send(new_fd, ticket.time_data, MAXDATASIZE, 0) == -1)
		    	    	    	perror("send");
		    	    //send tgt mark time
		    	    	    if(send(new_fd, service_ticket.id_service, MAXDATASIZE, 0) == -1)
		    	    	    	    	perror("send");
		    	    	    //send tgt copy session key Client/TGS
		    	    	    	    if(send(new_fd, (int *) &service_ticket.time_live, sizeof service_ticket.time_live , 0) == -1)
		    	    	    	    	    	perror("send");
		    	    	    	    //send tgt ip
		    	    	    	    	    if(send(new_fd, service_ticket.sesion_key_client_service, MAXDATASIZE, 0) == -1)
		    	    	    	    	    	    	perror("send");}
