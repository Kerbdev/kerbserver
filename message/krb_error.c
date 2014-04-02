#include "message.h"
#include "../error/error.h"
void krb_error (krb5_error *packet, krb5_kdc_rep *packet2)
{
	packet2 -> enc_part.kvno = 5;
	packet2 -> msg_type = KRB5_ERROR;
	packet -> stime = time(NULL);
	packet -> server -> realm.data = "realm";
	packet -> server -> data -> data = "sname";
	if (1/*client time availavle*/)
	{
		packet -> ctime ;//client time
	}
	packet -> error = 0; // error code
	if (1/*client name available*/)
	{
		packet -> client -> data -> data = "client";
		packet -> client -> realm.data = "realm";
	}
	if (1/*error text available*/)
		packet -> text.data = "text";
	if (1/*error data available*/)
		packet -> e_data.data = "11";//error data
}