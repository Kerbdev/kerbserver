#include "message.h"
#include "../error/error.h"
int decrypt_error()
	{
		return 0;
	}
void KRB_AS_REP(configuration config,krb5_kdc_rep *rep, krb5_kdc_req *req, krb5_pa_data *pa, krb5_error *err)
	{
		int is_pa_enc_timestamp_required = 0;
		int pa_enc_timestamp;
		char* db_client = "client";
		char* db_server = "server";
		time_t kdc_time = time(NULL);
		unsigned char key[32]; // keyfrom REQ for decryption
		unsigned char iv[16]; // initialization vector from REQ for decryption
		struct tm *ptr;
		char str[80];
		time_t clienttime = time(NULL);
		unsigned char* req_output;
		unsigned char* input;
		unsigned char decrypted_enc_timestamp[128];
		struct tm time;
		time_t t;
		krb5_timestamp till;
		krb5_timestamp rtime;
		int ko = 10; // kdc-options claimed from client
		int flags = 0;
		krb5_ticket tkt;
		unsigned char session_key[32];
		char *pers = "session_key_generation";
		int ret;
		/* erros filling */
		err->client->data->data = db_client;
		err->server->data->data = db_server;
		err->stime = kdc_time;
		err->error = KDC_ERR_NONE;
		/* end */
		rep->client->data->data = "client";
		//fprintf(stderr,"%s",rep->client->data->data);
		rep->client->data->data = req->client->data->data;
		if (rep->client->data->data != db_client)
			printf("%d", err->error = KDC_ERR_C_PRINCIPAL_UNKNOWN);
		if (req->server->data->data != db_server)
			printf("%d", err->error = KDC_ERR_S_PRINCIPAL_UNKNOWN);
		if ((is_pa_enc_timestamp_required) && (!pa_enc_timestamp))
			printf("%d", err->error = KDC_ERR_PREAUTH_REQUIRED);
		if (pa_enc_timestamp)
			{
				/* PA-DATA decryption */
				/* decrypting */
				input = req_output;

				/* end */
				if (decrypt_error())
					printf("%d", err->error = KRB_AP_ERR_BAD_INTEGRITY);
				//strptime(decrypted_enc_timestamp, "%d%m%Y%H%M", &time);
				t = mktime(&time);
				if(difftime(kdc_time + config.max_life, t) < 0)
					printf("%d", err->error = KDC_ERR_PREAUTH_FAILED);
				/* check for replay KDC_ERR_PREAUTH_FAILED
				...
				*/
		}
				if (int_to_bit(ko, FORWARDABLE))
				{
					set_bit(&flags, FORWARDABLE, 1);
				}
				if (int_to_bit(ko, PROXIABLE))
				{
					set_bit(&flags, PROXIABLE, 1);
				}
				if (int_to_bit(ko, ALLOW_POSTDATE))
				{
					set_bit(&flags, ALLOW_POSTDATE, 1);
				}
				if (int_to_bit(ko, RENEW) || int_to_bit(ko, VALIDATE) || int_to_bit(ko, PROXY) || int_to_bit(ko, FORWARDED) || int_to_bit(ko, ENC_TKT_IN_SKEY))
					printf("%d", err->error = KDC_ERR_BADOPTION);
				/* end */
				
				/* session key generator */
				tkt.enc_part2->session->contents = (krb5_octet *)&session_key;
				tkt.enc_part2->client->data = req->client->data;
				tkt.server->realm = req->client->realm;
				tkt.enc_part2->transited.tr_contents.data = "";
				tkt.enc_part2->times.authtime = kdc_time;
				/* end */
				if (int_to_bit(ko, POSTDATED))
					{
						if(!(int_to_bit(ko, ALLOW_POSTDATE)))
							printf("%d", err->error = KDC_ERR_POLICY);
						set_bit(&flags, INVALID, 1);
						tkt.enc_part2->times.starttime = req->from;
					}
				else
					tkt.enc_part2->times.starttime = 0;
		if (req->till == 0)
			till = 0;
		else
			till = req->till;
		tkt.enc_part2->times.endtime = min(till, tkt.enc_part2->times.starttime + config.max_life);
		if((int_to_bit(ko, RENEWABLE_OK) && (tkt.enc_part2->times.endtime < req->till)))
		{
			set_bit(&ko, RENEWABLE, 1);
			req->rtime = req->till;
		}
		if (req->rtime == 0)
			rtime = 0;
		else
			rtime = req->rtime;
		if (int_to_bit(ko, RENEWABLE))
		{
			set_bit(&flags, RENEWABLE, 1);
			tkt.enc_part2->times.renew_till = min(rtime, tkt.enc_part2->times.starttime + config.max_renewable_life);
		}
		else
			tkt.enc_part2->times.renew_till = 0;
		if(req->addresses)
			tkt.enc_part2->caddrs = req->addresses;
		else
			tkt.enc_part2->caddrs = NULL;
		tkt.enc_part2->authorization_data = NULL;
		/* encode to-be-encrypted part of ticket into OCTET STRING;
        new_tkt.enc-part := encrypt OCTET STRING
            using etype_for_key(server.key), server.key, server.p_kvno;
		*/

		 /* Start processing the response */

		rep->enc_part.kvno = 5;
		rep->enc_part2->msg_type = 11;
		rep->client->data = req->client->data;
		rep->client->realm.data = req->client->realm.data;
		rep->ticket = &tkt;
		rep->enc_part2->session->contents = tkt.enc_part2->session->contents;
	  //rep->enc_part2->last_req = fetch_last_request_info(client);
		rep->enc_part2->nonce = req->nonce;
		rep->enc_part2->key_exp = config.ticket_lifetime;
		rep->ticket->enc_part2->flags = tkt.enc_part2->flags;
		rep->enc_part2->times.authtime = tkt.enc_part2->times.authtime;
		rep->enc_part2->times.starttime = tkt.enc_part2->times.starttime;
		rep->enc_part2->times.endtime = tkt.enc_part2->times.endtime;

		if (int_to_bit(flags, RENEWABLE))
			rep->enc_part2->times.renew_till = tkt.enc_part2->times.renew_till;

		rep->enc_part2->server->realm.data = tkt.server->realm.data;
		rep->enc_part2->server->data->data = tkt.server->data->data;
		rep->enc_part2->aaddrs = tkt.enc_part2->caddrs;
		/*
		encode body of reply into OCTET STRING;

        resp.enc-part := encrypt OCTET STRING
                         using use_etype, client.key, client.p_kvno;
        send(resp);
		*/
	}
