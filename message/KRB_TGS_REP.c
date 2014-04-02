#include "message.h"
#include "../error/error.h"
void KRB_TGS_REP_FORM(krb5_kdc_req *req, krb5_error *err, krb5_ticket *tkt)
{
	if (req->padata->contents == NULL)
		printf("%d", err->error = KDC_ERR_PADATA_TYPE_NOSUPP);
	/*
	auth_hdr := KRB_AP_REQ;
        tgt := auth_hdr.ticket;

	*/
	//tkt->enc_part.
}
