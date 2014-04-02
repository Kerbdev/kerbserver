#include "message.h"
#include "../error/error.h"
void krb_priv (krb5_priv *body, krb5_kdc_rep *packet)
{
	/*collect user data in buffer;*/
	packet -> enc_part.enctype = 5;
	packet -> msg_type = KRB5_PRIV;
	packet -> enc_part.enctype = 1;//encryption type
	body ->enc_part.user_data.data = "111"; //buffer
	if (1/*using timestamp*/)
	{
		body -> enc_part.timestamp = time(NULL);
		body -> enc_part.usec = time(NULL); 
	}
	if (1/*using sequence numbers*/)
		body -> enc_part.seq_number = 1; //sequence number
	body -> enc_part.s_address -> contents = "ssss"; //sender host address
	if (1/*only one recipient*/)
		body -> enc_part.r_address -> contents = "rrrr"; //recipient host address
	/*
	encode body into OCTET STRING;

        select encryption type;
        encrypt OCTET STRING into packet.enc-part.cipher;
	*/
}
void krb_priv_check (krb5_priv *body, krb5_kdc_rep *packet, krb5_error *err)
{
	/* receive packet;*/
	if (packet -> enc_part.kvno != 5)
		printf("%d", err -> error = KRB_AP_ERR_BADVERSION);
	if (packet -> msg_type != KRB5_PRIV)
		printf("%d", err -> error = KRB_AP_ERR_MSG_TYPE);
	/*cleartext := decrypt(packet.enc-part) using negotiated key;*/
	if (decrypt_error())
		printf("%d", err -> error = KRB_AP_ERR_BAD_INTEGRITY);
	/*
	if (safe_priv_common_checks_ok(cleartext)) then
            return(cleartext.DATA, PACKET_IS_GENUINE_AND_UNMODIFIED);
        else
                return common_checks_error;
        endif
	*/
}