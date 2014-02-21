/*
 * usefull.c
 *
 *  Created on: Feb 21, 2014
 *      Author: ivan
 */
int int_to_bit(unsigned int b,int c){
	b=(b>>c)&1;
	return b;
}

