#include "message.h"
#include "../error/error.h"
void auth_form(configuration *config, krb5_authenticator *auth)
{
	//body.authenticator-vno := authenticator vno
	char *checksum;
	char *subkey;
	int seq_number = 1;
	auth->client->data->data = "client";
	auth->client->realm.data = "realm";

	if (/*supplying checksum*/1)
	{
		auth->checksum->contents = checksum; 
	}
	time_t systime = time(NULL);
	auth->ctime = systime;
	if (/*selecting sub-session key*/1)
	{
		auth->subkey->contents = subkey;
	}
	if (/*using sequence numbers*/1)
	{
		auth->seq_number = seq_number;
	}
}