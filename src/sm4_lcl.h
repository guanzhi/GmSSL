/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#ifndef GMSSL_SM4_LCL_H
#define GMSSL_SM4_LCL_H

#include <gmssl/sm4.h>

extern const uint8_t SM4_S[256];
extern const uint32_t SM4_T[256];
extern const uint32_t SM4_D[65536];

#define S32(A)					\
	((SM4_S[((A) >> 24)       ] << 24) ^	\
	 (SM4_S[((A) >> 16) & 0xff] << 16) ^	\
	 (SM4_S[((A) >>  8) & 0xff] <<  8) ^	\
	 (SM4_S[((A))       & 0xff]))

#define ROUNDS(x0, x1, x2, x3, x4)		\
	ROUND(x0, x1, x2, x3, x4, 0);		\
	ROUND(x1, x2, x3, x4, x0, 1);		\
	ROUND(x2, x3, x4, x0, x1, 2);		\
	ROUND(x3, x4, x0, x1, x2, 3);		\
	ROUND(x4, x0, x1, x2, x3, 4);		\
	ROUND(x0, x1, x2, x3, x4, 5);		\
	ROUND(x1, x2, x3, x4, x0, 6);		\
	ROUND(x2, x3, x4, x0, x1, 7);		\
	ROUND(x3, x4, x0, x1, x2, 8);		\
	ROUND(x4, x0, x1, x2, x3, 9);		\
	ROUND(x0, x1, x2, x3, x4, 10);		\
	ROUND(x1, x2, x3, x4, x0, 11);		\
	ROUND(x2, x3, x4, x0, x1, 12);		\
	ROUND(x3, x4, x0, x1, x2, 13);		\
	ROUND(x4, x0, x1, x2, x3, 14);		\
	ROUND(x0, x1, x2, x3, x4, 15);		\
	ROUND(x1, x2, x3, x4, x0, 16);		\
	ROUND(x2, x3, x4, x0, x1, 17);		\
	ROUND(x3, x4, x0, x1, x2, 18);		\
	ROUND(x4, x0, x1, x2, x3, 19);		\
	ROUND(x0, x1, x2, x3, x4, 20);		\
	ROUND(x1, x2, x3, x4, x0, 21);		\
	ROUND(x2, x3, x4, x0, x1, 22);		\
	ROUND(x3, x4, x0, x1, x2, 23);		\
	ROUND(x4, x0, x1, x2, x3, 24);		\
	ROUND(x0, x1, x2, x3, x4, 25);		\
	ROUND(x1, x2, x3, x4, x0, 26);		\
	ROUND(x2, x3, x4, x0, x1, 27);		\
	ROUND(x3, x4, x0, x1, x2, 28);		\
	ROUND(x4, x0, x1, x2, x3, 29);		\
	ROUND(x0, x1, x2, x3, x4, 30);		\
	ROUND(x1, x2, x3, x4, x0, 31)

#endif
