/*
 * dynamic.h
 *
 *  Created on: Feb 17, 2014
 *      Author: ivan
 */

#ifndef DYNAMIC_H_
#define DYNAMIC_H_
#include "../krb/krb.h"
#include <stdlib.h>
#include <stdio.h>
void free_krb5_kdc_req(krb5_kdc_req *);
void malloc_krb5_kdc_req(krb5_kdc_req *);
void krb5_free_address (krb5_context context, krb5_address *val);
void  	krb5_free_ap_rep (krb5_context context, register krb5_ap_rep *val);
void  	krb5_free_ap_req (krb5_context context, register krb5_ap_req *val);
void  	krb5_free_ap_rep_enc_part (krb5_context context, krb5_ap_rep_enc_part *val);
void  	krb5_free_authenticator_contents (krb5_context context, krb5_authenticator *val);
void  	krb5_free_authenticator (krb5_context context, krb5_authenticator *val);
void  	krb5_free_checksum (krb5_context context, register krb5_checksum *val);
void  	krb5_free_checksum_contents (krb5_context context, register krb5_checksum *val);
void  	krb5_free_cred (krb5_context context, register krb5_cred *val);
void  	krb5_free_cred_contents (krb5_context context, krb5_creds *val);
void krb5_free_pa_data(krb5_context context, krb5_pa_data *val);
void  	krb5_free_cred_enc_part (krb5_context context, register krb5_cred_enc_part *val);
void  	krb5_free_data (krb5_context context, krb5_data *val);
void  	krb5_free_octet_data (krb5_context context, krb5_octet_data *val);
void  	krb5_free_data_contents (krb5_context context, krb5_data *val);
void  	krb5_free_enc_data (krb5_context context, krb5_enc_data *val);
void  	krb5_free_enc_kdc_rep_part (krb5_context context, register krb5_enc_kdc_rep_part *val);
void  	krb5_free_enc_tkt_part (krb5_context context, krb5_enc_tkt_part *val);
void  	krb5_free_error (krb5_context context, register krb5_error *val);
void  	krb5_free_kdc_rep (krb5_context context, krb5_kdc_rep *val);
void  	krb5_free_kdc_req (krb5_context context, krb5_kdc_req *val);
void  	krb5_free_keyblock_contents (krb5_context context, register krb5_keyblock *key);
void  	krb5_free_keyblock (krb5_context context, register krb5_keyblock *val);
void  	krb5_free_last_req (krb5_context context, krb5_last_req_entry *val);
void  	krb5_free_pa_data (krb5_context context, krb5_pa_data *val);
void  	krb5_free_principal (krb5_context context, krb5_principal val);
void  	krb5_free_priv (krb5_context context, register krb5_priv *val);
void  	krb5_free_priv_enc_part (krb5_context context, register krb5_priv_enc_part *val);
void  	krb5_free_pwd_data (krb5_context context, krb5_pwd_data *val);
void  	krb5_free_passwd_phrase_element (krb5_context context, passwd_phrase_element *val);
void  	krb5_free_safe (krb5_context context, register krb5_safe *val);
void  	krb5_free_ticket (krb5_context context, krb5_ticket *val);
void  	krb5_free_tkt_authent (krb5_context context, krb5_tkt_authent *val);
void  	krb5_free_unparsed_name (krb5_context context, char *val);
void  	krb5_free_string (krb5_context context, char *val);
void krb5_free_authdata	(	krb5_context 	context,krb5_authdata *);
#endif /* DYNAMIC_H_ */
