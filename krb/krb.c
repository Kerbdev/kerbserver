/*
 * krb.c
 *
 *  Created on: Feb 14, 2014
 *      Author: ivan
 */
#include "krb.h"
#include <string.h>
#include <stdio.h>
void req_cline(krb5_principal bab,char *client_name){
	krb5_data *b=(krb5_data *) &bab->data;
	b->data=client_name;





}
void init_as_req(krb5_kdc_req *request,char *client_name){
	memset(request,1,sizeof(*request));
	request->magic=0;
	request->msg_type=KRB5_AS_REQ;
	krb5_pa_data *b=(krb5_pa_data *) &request->padata;
	b->magic=0;
	//(**request->padata).magic=0;

    b->magic=request->magic;
	b->pa_type=0;
	b->contents=0;
	b->length=sizeof(**(request->padata));
	request->kdc_options=0;
	req_cline(request->client,client_name);






}

