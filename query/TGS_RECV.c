#include "request.h"
void TGS_RECV(int new_fd,char *id_service,struct TGT tgt,struct AUTH_CLIENT AUTH){

	//recv ID service
		if(recv(new_fd, id_service, MAXDATASIZE, 0) == -1)
				    	    	perror("recv");


		//recv tgt copy session key Client/TGS
			    if(recv(new_fd, tgt.sesion_key_client_TGS, MAXDATASIZE, 0) == -1)
			    	    	perror("recv");

			    //recv tgt id client
			    	    if(recv(new_fd, tgt.user_name, MAXDATASIZE, 0) == -1)
			    	    	    	perror("recv");
			    	    //recv tgt mark time
			    	    	    if(recv(new_fd, tgt.mark_time, MAXDATASIZE, 0) == -1)
			    	    	    	    	perror("recv");
			    	    	    //recv tgt copy session key Client/TGS
			    	    	    	    if(recv(new_fd, (int *) &tgt.time_live, sizeof tgt.time_live , 0) == -1)
			    	    	    	    	    	perror("recv");
			    	    	    	    //send tgt ip
			    	    	    	    	    if(recv(new_fd, tgt.ip_client, MAXDATASIZE, 0) == -1)
			    	    	    	    	    	    	perror("recv");

		 //recv auth information
		if(recv(new_fd, AUTH.id_client, MAXDATASIZE, 0) == -1)
		perror("recv");
		//recv auth information
			if(recv(new_fd, (int *) &AUTH.time_data, 4, 0) == -1)
			perror("recv");



	}
