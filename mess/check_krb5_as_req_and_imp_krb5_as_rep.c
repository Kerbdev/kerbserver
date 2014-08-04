/*
 * check_krb5_as_req_and_imp_krb5_as_rep.c
 *
 *  Created on: May 6, 2014
 *      Author: ivan
 */
#include "mess.h"
int check_krb5_as_req_and_imp_krb5_as_rep(krb5_kdc_req *as_req,krb5_kdc_rep *as_rep,configuration *config ){
	time_t kdc_time=time(NULL);
	char pass[512]="12345";
	char server_key[512]="Hello";
	time_t till;
	time_t rtime;
	/*if(ldap_coonect(as_req->client->data->data,pass)!=AUTH_OK){
				perror("Error");
				return(1);
		} */
	fprintf(stderr,"%s",pass);
	krb5_decrypt_pa_data(as_req->padata,pass);
				//perror("Error");
				//return(1);}
	if(!(difftime(kdc_time,as_req->padata->pa_type)>=0 && difftime(kdc_time,as_req->padata->pa_type)<=300))
	perror("Error");
	as_rep->ticket->server->data->data=as_req->server->data->data;
	as_rep->ticket->server->realm.data=as_req->server->realm.data;
	if (int_to_bit(as_req->kdc_options, FORWARDABLE))
		set_bit(&as_rep->ticket->enc_part2->flags,FORWARDABLE,SET_ONE);
	if (int_to_bit(as_req->kdc_options,PROXIABLE))
		set_bit(&as_rep->ticket->enc_part2->flags,PROXIABLE,SET_ONE);
	if (int_to_bit(as_req->kdc_options, ALLOW_POSTDATE))
		set_bit(&as_rep->ticket->enc_part2->flags,ALLOW_POSTDATE,SET_ONE);
	if((int_to_bit(as_rep->ticket->enc_part2->flags, RENEW) ||
		   int_to_bit(as_rep->ticket->enc_part2->flags, VALIDATE) ||
		   int_to_bit(as_rep->ticket->enc_part2->flags, PROXY) ||
		   int_to_bit(as_rep->ticket->enc_part2->flags, FORWARDED) ||
		   int_to_bit(as_rep->ticket->enc_part2->flags, ENC_TKT_IN_SKEY)))
		perror("Error");
	as_rep->ticket->enc_part2->session->contents=realloc(as_rep->ticket->enc_part2->session->contents,KEY_LENGHT+1);
	generate_session_key(as_rep->ticket->enc_part2->session->contents,KEY_LENGHT);
	memset(as_rep->ticket->enc_part2->session->contents+KEY_LENGHT,'\0',1);
	while(1){
	if(strlen(as_rep->ticket->enc_part2->session->contents)!=KEY_LENGHT){
		generate_session_key(as_rep->ticket->enc_part2->session->contents,KEY_LENGHT);
			memset(as_rep->ticket->enc_part2->session->contents+KEY_LENGHT,'\0',1);}
	else
		break;}

	fprintf(stderr,"%d",(int)strlen(as_rep->ticket->enc_part2->session->contents));
	memset(as_rep->ticket->enc_part2->session->contents+KEY_LENGHT,'\0',1);
	fprintf(stderr,"%s",as_rep->ticket->enc_part2->session->contents);
	as_rep->ticket->enc_part2->client->realm.data=realloc(as_rep->ticket->enc_part2->client->realm.data,strlen(as_req->client->realm.data)+1);
	strcpy(as_rep->ticket->enc_part2->client->realm.data,as_req->client->realm.data);
	as_rep->ticket->enc_part2->client->data->data=realloc(as_rep->ticket->enc_part2->client->data->data,strlen(as_req->client->data->data)+1);
	strcpy(as_rep->ticket->enc_part2->client->data->data,as_req->client->data->data);
	as_rep->ticket->enc_part2->times.authtime=kdc_time;
	as_rep->ticket->enc_part2->times.starttime=as_req->from;
	if(as_req->till)
		till=as_req->till;
	else
		till=LONG_MAX;
	as_rep->ticket->enc_part2->times.endtime=min(till,as_rep->ticket->enc_part2->times.starttime+config->max_life,-1);

	if(int_to_bit(as_req->kdc_options,RENEWABLE_OK) && as_rep->ticket->enc_part2->times.endtime < as_req->till){
		set_bit(&as_req->kdc_options,RENEWABLE,SET_ONE);
		as_req->rtime=as_req->till;}
	if(as_req->rtime)
		rtime=as_req->rtime;
	else
		rtime=LONG_MAX;

	if(int_to_bit(as_req->kdc_options,RENEWABLE)){
		set_bit(&as_rep->ticket->enc_part2->flags,RENEWABLE,SET_ONE);
		as_rep->ticket->enc_part2->times.renew_till=min(rtime,as_rep->ticket->enc_part2->times.starttime+config->max_life,-1);
	}
	else
		as_rep->ticket->enc_part2->times.renew_till=0;

	as_rep->ticket->enc_part2->flags=as_req->kdc_options;
	as_rep->msg_type=KRB5_AS_REP;
	as_rep->client->data->data=as_req->client->data->data;
	as_rep->client->realm.data=as_req->client->realm.data;
	as_rep->enc_part2->session->contents=realloc(as_rep->ticket->enc_part2->session->contents,KEY_LENGHT+1);
	memcpy ( as_rep->enc_part2->session->contents, as_rep->ticket->enc_part2->session->contents, KEY_LENGHT+1 );
	as_rep->enc_part2->flags=as_rep->ticket->enc_part2->flags;
	as_rep->enc_part2->times.authtime=as_rep->ticket->enc_part2->times.authtime;
	as_rep->enc_part2->times.starttime=as_rep->ticket->enc_part2->times.starttime;
	as_rep->enc_part2->times.endtime=as_rep->ticket->enc_part2->times.endtime;

	if(int_to_bit(as_rep->ticket->enc_part2->flags, RENEWABLE))
		as_rep->enc_part2->times.renew_till=as_rep->ticket->enc_part2->times.renew_till;
	as_rep->client->data->data=realloc(as_rep->client->data->data,strlen(as_rep->ticket->enc_part2->client->data->data)+1);
	strcpy(as_rep->client->data->data,as_rep->ticket->enc_part2->client->data->data);
	as_rep->client->realm.data=realloc(as_rep->client->realm.data,strlen(as_rep->ticket->enc_part2->client->realm.data)+1);
	strcpy(as_rep->client->realm.data,as_rep->ticket->enc_part2->client->realm.data);
	as_rep->enc_part2->server->data->data=realloc(as_rep->enc_part2->server->data->data,strlen(config->server_name)+1);
	strcpy(as_rep->enc_part2->server->data->data,config->server_name);

	as_rep->enc_part2->server->realm.data=realloc(as_rep->enc_part2->server->realm.data,strlen(config->server_realm)+1);
	strcpy(as_rep->enc_part2->server->realm.data,config->server_realm);
	krb5_crypt_kdc_rep_part(as_rep->enc_part2,pass);
	krb5_crypt_tkt_part(as_rep->ticket->enc_part2,server_key);
	return 0;
}

