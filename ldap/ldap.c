/*
 ============================================================================
 Name        : dgedv.c
 Author      : 
 Version     :
 Copyright   : Your copyright notice
 Description : Hello World in C, Ansi-style
 ============================================================================
 */


#include "ldap.h"


int verif_pass(char *dn,char *pass);
int connect_from_root(char *name,char *pass)
{
	LDAP        *ld;
char **vals;
int        rc;
char        bind_dn[100];
int l=LDAP_VERSION3;/* Get username and password */
char *a, *dn=NULL;
BerElement *ber;
char *Rg[]={"uid","mail",NULL};
LDAPMessage *res,*e;

/* Open LDAP Connection */

if( ldap_initialize( &ld, LDAP_SERVER ) )
{
perror( "ldap_initialize" );
return( 1 );
}
ldap_set_option(ld,LDAP_OPT_PROTOCOL_VERSION,&l);
//ldap_set_option(ld,LDAP_OPT_PROTOCOL_VERSION, &l);
/* User authentication (bind) */

rc = ldap_simple_bind_s( ld, bind_dn, ROOT_PASSWORD);
if( rc != LDAP_SUCCESS )
{
fprintf(stderr, "ldap_simple_bind_s: %s\n", ldap_err2string(rc) );
return( 1 );
}
rc=ldap_search_s(ld,"dc=tmk,dc=kbpm,dc=ru",LDAP_SCOPE_SUBTREE,name,Rg,0,&res);
if(rc==-1){
	fprintf(stderr, "search_error %s\n", ldap_err2string(rc) );
	return( 1 );
}
for ( e = ldap_first_entry( ld, res ); e != NULL;
     e = ldap_next_entry( ld, e ) ) {
	dn = ldap_get_dn( ld, e );
       for ( a = ldap_first_attribute( ld, e, &ber );
        a != NULL; a = ldap_next_attribute( ld, e, ber ) ) {
          if ((vals = ldap_get_values( ld, e, a)) != NULL ) {
             ldap_value_free( vals );
          }
          ldap_memfree( a );
       }}
ldap_msgfree(res);
ldap_unbind_s(ld);
if(dn==NULL)
	return NAME_FAIL;
else{
			if (verif_pass(dn,pass)==PASS_OK){
				ldap_memfree( dn );
				return AUTH_OK;}
			else {
				ldap_memfree( dn );
					return PASS_FAIL;}}

}
int verif_pass(char *dn,char *pass){

	LDAP        *ll;
	int rc;
	int l=LDAP_VERSION3;
	if( ldap_initialize( &ll, LDAP_SERVER ) )
	{
	perror( "ldap_initialize" );
	return( 1 );
	}
	ldap_set_option(ll,LDAP_OPT_PROTOCOL_VERSION, &l);
	rc = ldap_simple_bind_s( ll, dn, pass);
	ldap_unbind_s(ll);
	if( rc == LDAP_SUCCESS )
	{
	return PASS_OK;
	}
	return PASS_FAIL;

}
int ldap_coonect(char *name,char *pass){
	char *n="*";
			if (strstr(n,name)!=NULL)
				return NAME_FAIL;
	int l=strlen(name);
	char *str=(char *)malloc(l+10);
	strcpy(str,"uid=");
	strcat(str,name);
	int c=connect_from_root(str,pass);
	return c;
}
