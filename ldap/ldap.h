

#ifndef LDAP_H_
#define LDAP_H_
#include <stdio.h>
#define LDAP_DEPRECATED 1
#include <ldap.h>
#define ROOT_PASSWORD "Su56Df12"
#include <stdlib.h>
/* LDAP Server settings */
#define LDAP_SERVER "ldap://ltmksrv.kbpm.ru:389"

#define PASS_OK 3
#define PASS_FAIL 4
#define AUTH_OK 5
#define NAME_FAIL 6
int verif_pass(char *,char *);
int connect_from_root(char *,char *);
#endif
