#include "request.h"
void Connect_from_service(int new_fd,struct AUTH_CLIENT NEW_AUTH,struct SERVICE_TICKET service_ticket){
	//AC send to client session key Client/TGS
		if (recv(new_fd, NEW_AUTH.id_client,MAXDATASIZE , 0) == -1)
	                        perror("recv");

	            //send ID client
	        if (recv(new_fd, (int *) &NEW_AUTH.time_data, 4, 0) == -1)
	            perror("recv");

		    	    //send tgt mark time
		    	    	    if(recv(new_fd, service_ticket.id_service, MAXDATASIZE, 0) == -1)
		    	    	    	    	perror("recv");
		    	    	    //send tgt copy session key Client/TGS
		    	    	    	    if(recv(new_fd, (int *) &service_ticket.time_live, sizeof service_ticket.time_live , 0) == -1)
		    	    	    	    	    	perror("send");
		    	    	    	    //send tgt ip
		    	    	    	    	    if(recv(new_fd, service_ticket.sesion_key_client_service, MAXDATASIZE, 0) == -1)
		    	    	    	    	    	    	perror("recv");}
