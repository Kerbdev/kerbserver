#include "message.h"
#include "../error/error.h"
void krb_ap_req (krb5_ap_req *packet)
{
	/*obtain ticket and session_key from cache;*/
	//packet->ap_options = 10; // for example
	/* */
	packet->authenticator.kvno = pvno;
	/*packet.msg-type := message type; */
	if (MUTUAL_AUTH)
		packet->ap_options= 1;
	else
		packet->ap_options= 0;
	if (/*using session key for ticket*/1)
		packet->ap_options= 1;
	else packet->ap_options=0;
	/*packet.ticket := ticket;  ticket
    generate authenticator;
    encode authenticator into OCTET STRING;
    encrypt OCTET STRING into packet.authenticator
                             using session_key;
	*/

}
