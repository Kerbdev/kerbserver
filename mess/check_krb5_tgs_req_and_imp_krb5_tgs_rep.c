/*
 * check_krb5_tgs_req_and_imp_krb5_tgs_rep.c
 *
 *  Created on: May 13, 2014
 *      Author: ivan
 */
#include "mess.h"
//TGS function
int check_krb5_tgs_req_and_imp_krb5_tgs_rep(krb5_kdc_req *tgs_req,krb5_kdc_rep *tgs_rep,configuration *conf){
	time_t kdc_time=time(NULL);
	time_t till;
	time_t rtime;
	char *session;
	char key_ap[]="Hell";
	if(tgs_req->padata->pa_type!=KRB5_AP_REQ){
		perror("KDC_ERR_PADATA_TYPE_NOSUPP");
		return KDC_ERR_PADATA_TYPE_NOSUPP;
	}
	char server_key[512]="Hello";
	krb5_decrypt_tkt_part(tgs_req->second_ticket->enc_part2,server_key);
	session=malloc(KEY_LENGHT+1);
	memcpy(session,tgs_req->second_ticket->enc_part2->session->contents,KEY_LENGHT);
	memset(session+KEY_LENGHT,'\0',1);
	fprintf(stderr,"%d",(int)strlen(tgs_req->second_ticket->enc_part2->session->contents));
	tgs_rep->ticket->server->data->data=conf->server_name;
	tgs_rep->ticket->server->realm.data=conf->server_realm;
	if(int_to_bit(tgs_req->kdc_options,FORWARDABLE)){
		if(!int_to_bit(tgs_req->second_ticket->enc_part2->flags,FORWARDABLE)){
			perror("KDC_ERR_BADOPTION");
			return KDC_ERR_BADOPTION;
		}
		else
			set_bit(&tgs_rep->ticket->enc_part2->flags,FORWARDABLE,SET_ONE);}
	if(int_to_bit(tgs_req->kdc_options,FORWARDED)){
		if(!int_to_bit(tgs_req->second_ticket->enc_part2->flags,FORWARDED)){
			perror("KDC_ERR_BADOPTION");
			return KDC_ERR_BADOPTION;
		}
		else{
			set_bit(&tgs_rep->ticket->enc_part2->flags,FORWARDABLE,SET_ONE);

		}}
	if(int_to_bit(tgs_req->kdc_options,PROXIABLE)){
		if(!int_to_bit(tgs_req->second_ticket->enc_part2->flags,PROXIABLE)){
			perror("KDC_ERR_BADOPTION");
			return KDC_ERR_BADOPTION;
		}
		else{
			set_bit(&tgs_rep->ticket->enc_part2->flags,PROXIABLE,SET_ONE);
		}
	}
	if(int_to_bit(tgs_req->kdc_options,PROXY)){
		if(!int_to_bit(tgs_req->second_ticket->enc_part2->flags,PROXY)){
			perror("KDC_ERR_BADOPTION");
			return KDC_ERR_BADOPTION;
			}
		else{
			set_bit(&tgs_rep->ticket->enc_part2->flags,PROXY,SET_ONE);
		}
	}
	if(int_to_bit(tgs_req->kdc_options,ALLOW_POSTDATE)){
		if(!int_to_bit(tgs_req->second_ticket->enc_part2->flags,ALLOW_POSTDATE)){
			perror("KDC_ERR_BADOPTION");
			return KDC_ERR_BADOPTION;
			}
		else{
			set_bit(&tgs_rep->ticket->enc_part2->flags,ALLOW_POSTDATE,SET_ONE);
		}
	}
	if(int_to_bit(tgs_req->kdc_options,POSTDATED)){
		if(!int_to_bit(tgs_req->second_ticket->enc_part2->flags,POSTDATED)){
			perror("KDC_ERR_BADOPTION");
			return KDC_ERR_BADOPTION;
			}
		else{
			set_bit(&tgs_rep->ticket->enc_part2->flags,POSTDATED,SET_ONE);
			tgs_rep->ticket->enc_part2->times.starttime=tgs_req->from;

		}
	}
	if(int_to_bit(tgs_req->kdc_options,VALIDATE)){
		if(!int_to_bit(tgs_req->second_ticket->enc_part2->flags,INVALID)){
			perror("KDC_ERR_POLICY");
			return KDC_ERR_POLICY;
			}
		if( tgs_req->second_ticket->enc_part2->times.starttime > kdc_time) {
			perror("KRB_AP_ERR_TKT_NYV");
			return KRB_AP_ERR_TKT_NYV;
		}
	}
	tgs_rep->ticket->enc_part2->times.authtime=tgs_req->second_ticket->enc_part2->times.authtime;
	if(int_to_bit(tgs_req->kdc_options,RENEW)){
		if(!int_to_bit(tgs_req->second_ticket->enc_part2->flags,RENEW)){
			perror("KDC_ERR_BADOPTION");
			return KDC_ERR_BADOPTION;
			}
		if( tgs_req->second_ticket->enc_part2->times.renew_till >= kdc_time){
			perror("KRB_AP_ERR_TKT_EXPIRED");
			return KRB_AP_ERR_TKT_EXPIRED;
		}
		tgs_rep->ticket->enc_part2->times.starttime=kdc_time;
		time_t old_life=tgs_req->second_ticket->enc_part2->times.endtime-tgs_req->second_ticket->enc_part2->times.starttime;
		tgs_rep->ticket->enc_part2->times.endtime=min(tgs_req->second_ticket->enc_part2->times.renew_till,
														tgs_rep->ticket->enc_part2->times.starttime+old_life,-1);
	}
	else{
		tgs_rep->ticket->enc_part2->times.starttime=kdc_time;
		if(tgs_req->till==0)
			till=LONG_MAX;
		else
			till=tgs_req->till;
		tgs_rep->ticket->enc_part2->times.endtime=min(till,
													  tgs_rep->ticket->enc_part2->times.starttime+conf->max_life,
													  tgs_req->second_ticket->enc_part2->times.endtime,-1);
		if(int_to_bit(tgs_req->kdc_options,RENEWABLE_OK) &&
			(tgs_rep->ticket->enc_part2->times.endtime < tgs_req->till) &&
			int_to_bit(tgs_req->second_ticket->enc_part2->flags,RENEWABLE) ){
			set_bit(&tgs_req->kdc_options,RENEWABLE,SET_ONE);
			tgs_req->rtime=min(tgs_req->till,
								tgs_req->second_ticket->enc_part2->times.renew_till,-1);
		}
	}
	if(tgs_req->rtime==0)
		rtime=LONG_MAX;
	else
		rtime=tgs_req->rtime;
	if(int_to_bit(tgs_req->kdc_options,RENEWABLE) &&
		(int_to_bit(tgs_req->second_ticket->enc_part2->flags,RENEWABLE))){
		set_bit(&tgs_rep->ticket->enc_part2->times.renew_till,RENEWABLE,SET_ONE);
		tgs_rep->ticket->enc_part2->times.renew_till=min(rtime,tgs_rep->ticket->enc_part2->times.starttime+conf->max_life,
														tgs_req->second_ticket->enc_part2->times.renew_till,-1);

	}
	tgs_rep->msg_type=KRB5_TGS_REP;

	tgs_rep->ticket->enc_part2->session->contents=realloc(tgs_rep->ticket->enc_part2->session->contents,KEY_LENGHT+1);
	generate_session_key(tgs_rep->ticket->enc_part2->session->contents,KEY_LENGHT);
	memset(tgs_rep->ticket->enc_part2->session->contents+KEY_LENGHT,'\0',1);
	while(1){
		if(strlen(tgs_rep->ticket->enc_part2->session->contents)!=KEY_LENGHT){
			generate_session_key(tgs_rep->ticket->enc_part2->session->contents,KEY_LENGHT);
				memset(tgs_rep->ticket->enc_part2->session->contents+KEY_LENGHT,'\0',1);}
		else
			break;}
	fprintf(stderr,"%d",(int)strlen(tgs_rep->ticket->enc_part2->session->contents));
	tgs_rep->client->data->data=realloc(tgs_rep->client->data->data,strlen(tgs_req->second_ticket->enc_part2->client->data->data)+1);
	strcpy(tgs_rep->client->data->data,tgs_req->second_ticket->enc_part2->client->data->data);
	tgs_rep->client->realm.data=realloc(tgs_rep->client->realm.data,strlen(tgs_req->second_ticket->enc_part2->client->realm.data)+1);
	strcpy(tgs_rep->client->realm.data,tgs_req->second_ticket->enc_part2->client->realm.data);
	make_copy_enc_part(tgs_rep->enc_part2,tgs_rep->ticket->enc_part2);
	krb5_crypt_kdc_rep_part(tgs_rep->enc_part2,session);
	krb5_crypt_tkt_part(tgs_rep->ticket->enc_part2,key_ap);
	return 0;
	}
