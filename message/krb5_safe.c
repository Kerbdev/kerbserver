#include "message.h"
#include "../error/error.h"
void krb_safe(krb5_safe *safe, krb5_kdc_rep *packet)
{
	krb5_checksum *packet_cksum;
	krb5_safe *packet_safe_body;
	/*collect user data in buffer;*/
	/* assemble packet: */
	packet -> enc_part.kvno = 5;
	packet -> msg_type = KRB5_SAFE;
	safe -> user_data.data = "data"; //buffer data
	if (1/*using timestamp*/)
	{
		safe -> timestamp = time(NULL);
		safe -> usec = time(NULL);
	}
	if (1/*using sequence numbers*/)
		safe -> s_address -> contents = "recipient host address";
	if (1/*only one recipient*/)
		safe -> r_address -> contents = "sequence number";
	safe -> checksum -> checksum_type = 1;
	//compute checksum over body;
	safe -> checksum ->contents = "checksum";
	/*result*/
	packet_cksum = safe -> checksum;
	packet_safe_body = safe;
	/* end */
}
void krb_safe_check(krb5_safe *safe, krb5_kdc_rep *packet, krb5_error *err)
{
	/*recieved*/
	krb5_checksum *packet_cksum;
	/*end*/
	krb5_checksum *computed_cksum;
	/*receive packet;*/
	if (packet -> enc_part.kvno != 5)
		printf("%d", err -> error = KRB_AP_ERR_BADVERSION);
	if (packet -> msg_type != KRB5_SAFE)
		printf("%d", err -> error = KRB_AP_ERR_MSG_TYPE);
	if (1/*packet.checksum.cksumtype is not both collision-proof
                                             and keyed*/)
	    printf("%d", err -> error = KRB_AP_ERR_INAPP_CKSUM);
	if (1/*safe_priv_common_checks_ok(packet)*/)
		computed_cksum = packet_cksum;
	if (computed_cksum != packet_cksum)
		printf("%d", err -> error = KRB_AP_ERR_MODIFIED);
/*
	return (packet, PACKET_IS_GENUINE);
        else
                return common_checks_error;
        endif
*/

}
