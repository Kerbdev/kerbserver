
#include "message.h"
#include "../error/error.h"
void KRB_TGS_REQ_FORM (krb5_kdc_req *req, configuration *config)
{
	req->msg_type = KRB5_TGS_REQ;
	req->kdc_options = 10;
	req->server->data->data = "server";
	req->server->realm.data = "realm";
	if (int_to_bit(req->kdc_options, POSTDATED))
	{
		req->from = time(NULL);
	}
	else
	{
		req->from = NULL;
	}
	req->till = req->from + config->max_life;
	if (int_to_bit(req->kdc_options, RENEWABLE))
	{
		req->rtime = config->max_renewable_life;
	}
	req->nonce = 0;
	req->ktype = 1;
	/*
	if (user supplied addresses) then
                body.addresses := user's addresses;
        else
                omit body.addresses;
        endif
	*/
	req->authorization_data;
	if (int_to_bit(req->kdc_options, ENC_TKT_IN_SKEY))
	{
		/* body.additional-tickets_ticket := second TGT;*/
	}
	/* request.req-body := body; */
	/* check := generate_checksum (req.body,checksumtype);*/
	req->padata->pa_type = 1;
	req->padata->contents = 0;
	/*
	kerberos := lookup(name of local kerberose server (or servers));
        send(packet,kerberos);

        wait(for response);
        if (timed_out) then
                retry or use alternate server;
        endif

		*/

}