/*
 * krb5_as_req.c
 *
 *  Created on: Feb 24, 2014
 *      Author: ivan
 */
#include "message.h"
void KRB_AS_REQ(krb5_kdc_req *kkk, krb5_pa_data *ppp)
	{
		const char* clientpass = "12345"; // pass
		unsigned char key[32];
		unsigned char iv[16];
		int ret;
		configuration conf;
		conf.max_life=1;
		conf.retries=1;
		conf.max_renewable_life=1;
		conf.ticket_lifetime=1;
		conf.timeout=1;
		krb5_preauthtype padatatype;
		int is_pa_enc_timestamp_required = 0;
		int chk;
		int pver = pvno; // Kerb ver
		unsigned char* input;
		unsigned char output[128];
		size_t input_len = 40;
		size_t output_len = 0;
		struct tm *ptr;
		char str[80];
		int ko = 10; // kdc-options
		time_t starttime = time(NULL);
		time_t clienttime = time(NULL);
		time_t endtime = starttime + conf.max_life * 3600;
		//kkk->padata->contents="Hello";
		kkk->msg_type=10;
		kkk->msg_type = 10; // Msg type
		if (is_pa_enc_timestamp_required)
			ppp->pa_type = 0; // Pre-auth type check
/*				 generating client key
		entropy_init( &entropy );
		if((ret = ctr_drbg_init(&ctr_drbg, entropy_func, &entropy,
			(unsigned char *)clientpass, strlen(clientpass))) != 0 )
			printf(" failed\n ! ctr_drbg_init returned -0x%04x\n", -ret);
		if((ret = ctr_drbg_random(&ctr_drbg, key, 32)) != 0)
			printf(" failed\n ! ctr_drbg_random returned -0x%04x\n", -ret);
		end

		 generating iv
		entropy_init( &entropy );
		if((ret = ctr_drbg_init(&ctr_drbg, entropy_func, &entropy,
			(unsigned char*)clientpass, strlen(clientpass))) != 0)
			printf(" failed\n ! ctr_drbg_init returned -0x%04x\n", -ret);
		if((ret = ctr_drbg_random(&ctr_drbg, iv, 16)) != 0)
			printf(" failed\n ! ctr_drbg_random returned -0x%04x\n", -ret);
		 end */

		/* encrypting */
		ptr = localtime(&clienttime);
		strftime(str, 80, "%d%m%Y%H%M", ptr);
		input = (unsigned char*)str;
		/* end */

		kkk->client->data->data = "HELLLLLLLLOOOOOOOOOOOOOOO";
		kkk->server->data->data = "server";
		//kkk->client->realm = "realm";
		if (int_to_bit(ko, POSTDATED))
			kkk->from = starttime;
			kkk->till = endtime;
		if (int_to_bit(ko, RENEWABLE))
			kkk->rtime = conf.max_renewable_life;
		kkk->nonce = 13243;
		kkk->ktype = 0;
	}

