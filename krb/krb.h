/*
 * krb.c
 *
 *  Created on: Feb 10, 2014
 *      Author: ivan
 */
#define MAXDATASIZE 1024
typedef struct {
	int pvno;
	int msg_type;
}KDC_REQ;


typedef struct {
			int padata_type;
			char padata_vae[MAXDATASIZE];
}PA_DATA;
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

struct KRB_KDC_REQ{
	int req_type;
	KDC_REQ kdc_req;
	PA_DATA pa_data;
	KDC_REQ_BODY kdc_req_body;}
typedef struct {
	int pvno;
	int msg_type;



}



struct KRB_KDC_REP{
	int rep_type;


}

//KRB_ERROR






