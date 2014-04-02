#include "message.h"
#include "../error/error.h"
void AS_TGS_REP_CHECK(krb5_kdc_req *req, krb5_error *err, krb5_kdc_rep *resp, configuration config)
	{
		int ko = 10;
		int flags = 0;
		time_t kdc_time = time(NULL);
		if (decrypt_error() 
			|| (req->client->data->data != resp->client->data->data)
			|| (req->client->realm.data != resp->client->realm.data)
			|| (req->server->data->data != resp->enc_part2->server->data->data)
			|| (req->server->realm.data != resp->enc_part2->server->realm.data)
			|| (req->nonce != resp->enc_part2->nonce)
			|| (req->addresses != resp->enc_part2->aaddrs))
		{
			resp->enc_part2->session->contents = NULL;
			printf("%d", err->error = int_to_bit(ko, KRB_AP_ERR_MODIFIED));
		}
		/* make sure no flags are set that shouldn't be, and that  */
        /* all that should be are set                              */
        /*if (!check_flags_for_compatability(req.kdc-options,resp.flags))
                then destroy resp.key;*/
		if((req->from == 0) && (difftime(kdc_time + config.max_life, resp->enc_part2->times.starttime) < 0))
		{
			resp->enc_part2->session->contents = NULL;
			printf("%d", err->error = int_to_bit(ko, KRB_AP_ERR_SKEW));
		}
		if((req->from != 0) && (req->from != resp->enc_part2->times.starttime))
		{
			resp->enc_part2->session->contents = NULL;
			printf("%d", err->error = int_to_bit(ko, KRB_AP_ERR_MODIFIED));
		}
		if ((req->till != 0) && (resp->enc_part2->times.endtime > req->till))
		{
			resp->enc_part2->session->contents = NULL;
			printf("%d", err->error = int_to_bit(ko, KRB_AP_ERR_MODIFIED));
		}
		if ((int_to_bit(ko, RENEWABLE) && (req->rtime != 0) && (resp->enc_part2->times.renew_till > req->rtime)))
		{
			resp->enc_part2->session->contents = NULL;
			printf("%d", err->error = int_to_bit(ko, KRB_AP_ERR_MODIFIED));
		}
		if ((int_to_bit(ko, RENEWABLE_OK) && (int_to_bit(flags, RENEWABLE)) && (req->till != 0) && (resp->enc_part2->times.renew_till > req->till)))
		{
			resp->enc_part2->session->contents = NULL;
			printf("%d", err->error = int_to_bit(ko, KRB_AP_ERR_MODIFIED));
		}
	}
