/*
 * mess.h
 *
 *  Created on: May 6, 2014
 *      Author: ivan
 */

#ifndef MESS_H_
#define MESS_H_
#include "../krb/krb.h"
#include "../parser/get_config_param.h"
#include <stdio.h>
#include <limits.h>
#include <time.h>
#include "../error/error.h"
#include "../usefull_func/usefull.h"
#include "../ldap/ldap.h"
int check_krb5_as_req_and_imp_krb5_as_rep(krb5_kdc_req *as_req,krb5_kdc_rep *as_rep,configuration *config );
int check_krb5_tgs_req_and_imp_krb5_tgs_rep(krb5_kdc_req *tgs_req,krb5_kdc_rep *tgs_rep,configuration *conf);
#endif /* MESS_H_ */
