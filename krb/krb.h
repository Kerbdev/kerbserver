/*
 * krb.c
 *
 *  Created on: Feb 10, 2014
 *      Author: ivan
 */
#define MAXDATASIZE 1024
//for KRB_KDC_REQ
typedef struct {
	int pvno;
	int msg_type;
}KDC_REQ;
//for KRB_KDC_REQ
typedef struct {
			int padata_type;
			char padata_vae[MAXDATASIZE];
}PA_DATA;
//KRB_KDC_REQ
typedef struct KDC_REQ_BODY{
	int kdc_options;
	char cname[MAXDATASIZE];
	char realm[MAXDATASIZE];
	int sname;
	int from;
	int till;
	int rtime;
	int nonce;
	int etype;
	char addresses[MAXDATASIZE];
	int enc_auth_data;
	int add_tickets;
}KDC_REQ_BODY;
//def KRB_KDC_REQ
struct KRB_KDC_REQ{
	int req_type;
	KDC_REQ kdc_req;
	PA_DATA pa_data;
	KDC_REQ_BODY kdc_req_body;}
//for KRB_KDC_REP
typedef struct {
	int pvno;
	int msg_type;
	int padata;
	char realm[MAXDATASIZE];
	char cname[MAXDATASIZE];
	int ticket;
	char enc_part[MAXDATASIZE];
}KDC_REP;
//for KRB_KDC_REP
typedef struct{
	char key[MAXDATASIZE];
	int last_req;
	int nonce;
	int key_expiration;
	int flags;
	int auth_time;
	int start_time;
	int end_time;
	int renew_till;
	char srealm[MAXDATASIZE];
	char sname[MAXDATASIZE];
	char caddr[MAXDATASIZE];
}ENC_KDC_REP_PART;
//struct for KRB_KDC_REP
struct KRB_KDC_REP{
	int rep_type;
	KDC_REP kdc_rep;
	int enc_as_rep_part;
	int enc_tgs_rep_part;
	ENC_KDC_REP_PART enc_kdc_rep_part;
};
//Encrypted part of ticket
typedef struct {
	int flags;
	char key[MAXDATASIZE];
	char crealm[MAXDATASIZE];
	char cname[MAXDATASIZE];
	char transited[MAXDATASIZE];
	int auth_time;
	int start_time;
	int end_time;
	int renew_till;
	char caddrint[MAXDATASIZE];
	char auth_data[MAXDATASIZE];
}ENC_TICKET_PART;
//encoded Transited field
typedef struct{
	int tr_type;
	char contents[MAXDATASIZE];
}TRANSITED_ENCODING;

struct TICKET{
	int tkt_vno;
	char realm[MAXDATASIZE];
	char sname[MAXDATASIZE];
	char enc_part[MAXDATASIZE];
	ENC_TICKET_PART enc_ticket_part;
	TRANSITED_ENCODING transited_encoding;
	};
//Unencrypted authenticator
struct AUTH{
	int auth_vno;
	char crealm[MAXDATASIZE];
	char cname[MAXDATASIZE];
	char cksum[MAXDATASIZE];
	int cusec;
	int ctime;
	char subkey[MAXDATASIZE];
	int seq_number;
	char auth_data[MAXDATASIZE];
};


//KRB_ERROR






