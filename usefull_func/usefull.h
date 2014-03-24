/*
 * usefull.h
 *
 *  Created on: Feb 21, 2014
 *      Author: ivan
 */

#ifndef USEFULL_H_
#define USEFULL_H_
#define RESERVED 0
#define FORWARDABLE 1
#define FORWARDED 2
#define PROXIABLE 3
#define PROXY 4
#define MAY_POSDATE 5
#define ALLOW_POSTDATE 5
#define POSTDATED 6
#define INVALID 7
#define RENEWABLE 8
#define INITIAL 9
#define PRE_AUTHENT 10
#define HW_AUTHENT 11
#define RENEWABLE_OK 27
#define ENC_TKT_IN_SKEY 28
#define RENEW 20
#define VALIDATE 31
#define SET_ZERO 0
#define SET_ONE 1


int int_to_bit(unsigned int,int);
void set_bit(int *,int ,int);
int min(int a, ...);
#endif /* USEFULL_H_ */
