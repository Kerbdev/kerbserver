/*
 * usefull.c
 *
 *  Created on: Feb 21, 2014
 *      Author: ivan
 */
#include <stdarg.h>
int int_to_bit(unsigned int b,int c){
	b=(b>>c)&1;
	return b;
}
void set_bit(int *b,int c,int set){
	if(set==1)
		*b|=(1U<<c);
	if(set==0)
		*b&=(~(1U<<c));
}
int min(int a, ...)
{
	int i;
	int minimum = 0;
	va_list list;
	va_start(list, a);
	if (a != -1)
		minimum = a;
	while ((i = va_arg(list, int)) != -1)
	{
		if (i < minimum)
			minimum = i;
	}
	va_end(list);
	return minimum;
}