#include "message.h"
#include "../error/error.h"
int krb_ap_rep_check(krb5_ap_rep *packet, krb5_error *err, krb5_authenticator *cleartext, krb5_authenticator *authenticator)
{
	err->error = KDC_ERR_NONE;
	/*receive packet;*/
	if (packet->msg_type != KRB5_AP_REP)
	/*cleartext := decrypt(packet.enc-part)
                     using ticket's session key;
	*/
	if (decrypt_error())
		printf("%d", err->error = KRB_AP_ERR_BAD_INTEGRITY);
	if (cleartext->ctime != authenticator->ctime)
		printf("%d", err->error = KRB_AP_ERR_MUT_FAIL);
	if (cleartext->cusec != authenticator->cusec)
		printf("%d", err->error = KRB_AP_ERR_MUT_FAIL);
	if (cleartext->subkey->contents != 0)
		//1;/* save cleartext.subkey for future use;*/
	if (cleartext->seq_number != 0)
		//1;/*save cleartext.seq-number for future verifications;*/
		;
		return 1; //AUTHENTICATION_SUCCEEDED
}
