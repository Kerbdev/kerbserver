/*
 * create.c
 *
 *  Created on: Feb 17, 2014
 *      Author: ivan
 */
#include "dynamic.h"
void malloc_krb5_kdc_req(krb5_kdc_req *as_rep){
        	as_rep=malloc(sizeof(krb5_kdc_req));
            	if(as_rep == NULL){
            	perror("Out of memory");
                exit(-1);
                }
        	as_rep->padata=malloc(sizeof(krb5_pa_data));
        	if(as_rep->padata == NULL){
        	            	perror("Out of memory");
        	                exit(-1);
        	                }
        	as_rep->client=malloc(sizeof(krb5_principal_data));
        	if(as_rep->client == NULL){
        	        	            	perror("Out of memory");
        	        	                exit(-1);
        	        	                }
        	as_rep->client->data=malloc(sizeof(krb5_data));
        	if(as_rep->client->data == NULL){
        	            	perror("Out of memory");
        	                exit(-1);
        	                }
        	as_rep->server=malloc(sizeof(krb5_principal_data));
        	 if(as_rep->server == NULL){
        	        	   perror("Out of memory");
        	        	   exit(-1);
        	        	   }
            as_rep->server->data=malloc(sizeof(krb5_data));
        	 if(as_rep->server->data == NULL){
        	        	     perror("Out of memory");
        	        	     exit(-1);
        	        	     }
        	as_rep->addresses=malloc(sizeof(krb5_address));
        	if(as_rep->addresses == NULL){
        	            	perror("Out of memory");
        	                exit(-1);
        	                }
        	as_rep->unenc_authdata=malloc(sizeof(krb5_authdata));
        	if(as_rep->unenc_authdata == NULL){
        	            	perror("Out of memory");
        	                exit(-1);
        	                }
        	as_rep->second_ticket=malloc(sizeof(krb5_ticket));
        	if(as_rep->second_ticket == NULL){
        	            	perror("Out of memory");
        	                exit(-1);
        	                }
        	as_rep->second_ticket->server=malloc(sizeof(krb5_principal_data));
        	 if(as_rep->second_ticket == NULL){
        	        	    perror("Out of memory");
        	        	    exit(-1);
        	        	     }
        	as_rep->second_ticket->enc_part2=malloc(sizeof(krb5_ticket));
        	 if(as_rep->second_ticket == NULL){
        	        	     perror("Out of memory");
        	        	     exit(-1);
        	        	     }
}
