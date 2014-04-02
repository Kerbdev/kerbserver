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
	//krb5_data *b=(krb5_data *) bab->data;
	//(*c)->data=client_name;





}
void init_as_req(krb5_kdc_req *request,char *client_name){
	memset(request,0,sizeof(*request));
	request->magic=0;
	request->msg_type=KRB5_AS_REQ;
	krb5_pa_data *c=(krb5_pa_data *) &request->padata;
	//(**request->padata).magic=0;

	c->magic=request->magic;
	c->pa_type=0;
	c->contents=0;
	c->length=24;
	request->kdc_options=0;
	req_cline(request->client,client_name);

}

