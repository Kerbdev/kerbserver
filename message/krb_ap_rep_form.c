#include "message.h"
#include "../error/error.h"
void krb_ap_rep_form(krb5_ap_rep *packet)
{
	//body->ctime = time(NULL);
	//body->cusec;
	if (/*selecting sub-session key*/1)
	{
		/*select sub-session key;*/
		//body->seq_number = 1/*initial sequence*/;
	}
	/*
	encode body into OCTET STRING;

        select encryption type;
        encrypt OCTET STRING into packet.enc-part;

	*/
}
