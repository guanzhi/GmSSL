/* crypto/sms4/sms4.c */
/* ====================================================================
 * Copyright (c) 2014 - 2015 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 */

#include "sms4.h"

#define FK0	0xa3b1bac6
#define FK1	0x56aa3350
#define FK2	0x677d9197
#define FK3	0xb27022dc

#define CK0	0x00070e15
#define CK1	0x1c232a31
#define CK2	0x383f464d
#define CK3	0x545b6269
#define CK4	0x70777e85
#define CK5	0x8c939aa1
#define CK6	0xa8afb6bd
#define CK7	0xc4cbd2d9 
#define CK8	0xe0e7eef5
#define CK9	0xfc030a11
#define CK10	0x181f262d
#define CK11	0x343b4249
#define CK12	0x50575e65
#define CK13	0x6c737a81
#define CK14	0x888f969d
#define CK15	0xa4abb2b9 
#define CK16	0xc0c7ced5
#define CK17	0xdce3eaf1
#define CK18	0xf8ff060d
#define CK19	0x141b2229
#define CK20	0x30373e45
#define CK21	0x4c535a61
#define CK22	0x686f767d
#define CK23	0x848b9299
#define CK24	0xa0a7aeb5
#define CK25	0xbcc3cad1
#define CK26	0xd8dfe6ed
#define CK27	0xf4fb0209
#define CK28	0x10171e25
#define CK29	0x2c333a41
#define CK30	0x484f565d
#define CK31	0x646b7279 

static const uint8_t SBOX[256] = {
	0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7,
	0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
	0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3,
	0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
	0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a,
	0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
	0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95,
	0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
	0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
	0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
	0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b,
	0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
	0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2,
	0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
	0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
	0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
	0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5,
	0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
	0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55,
	0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
	0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
	0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
	0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f,
	0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
	0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f,
	0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
	0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
	0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
	0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e,
	0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
	0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20,
	0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48 
};


#define GETU32(pc)  ( \
		((uint32_t)(pc)[0] << 24) ^ \
		((uint32_t)(pc)[1] << 16) ^ \
		((uint32_t)(pc)[2] <<  8) ^ \
		((uint32_t)(pc)[3]))

#define PUTU32(st, ct)  { \
		(ct)[0] = (uint8_t)((st) >> 24); \
		(ct)[1] = (uint8_t)((st) >> 16); \
		(ct)[2] = (uint8_t)((st) >>  8); \
		(ct)[3] = (uint8_t)(st); }


#define ROT(A,i) (((A) << i) | ((A) >> (32 - i)))

#define S(A)	((SBOX[((A) >> 24)       ] << 24) ^ \
		 (SBOX[((A) >> 16) & 0xff] << 16) ^ \
		 (SBOX[((A) >>  8) & 0xff] <<  8) ^ \
		 (SBOX[((A))       & 0xff]))

#define L(B)	((B) ^ ROT((B), 2) ^ ROT((B),10) ^ ROT((B),18) ^ ROT((B), 24))
#define L_(B)	((B) ^ ROT((B),13) ^ ROT((B),23))

#define ROUND(X0,X1,X2,X3,X4,RK)	X4=(X1)^(X2)^(X3)^(RK); X4=S(X4); X4=(X0)^L(X4)
#define ROUND_(X0,X1,X2,X3,X4,CK,RK)	X4=(X1)^(X2)^(X3)^(CK); X4=S(X4); X4=(X0)^L_(X4); RK=X4

void sms4_set_encrypt_key(sms4_key_t *key, const unsigned char *user_key)
{
	uint32_t *rk = key->rk;
	uint32_t X0, X1, X2, X3, X4;

	X0 = GETU32(user_key     ) ^ FK0;
	X1 = GETU32(user_key  + 4) ^ FK1;
	X2 = GETU32(user_key  + 8) ^ FK2;
	X3 = GETU32(user_key + 12) ^ FK3;

	ROUND_(X0, X1, X2, X3, X4, CK0,  rk[0]);
	ROUND_(X1, X2, X3, X4, X0, CK1,  rk[1]);
	ROUND_(X2, X3, X4, X0, X1, CK2,  rk[2]);
	ROUND_(X3, X4, X0, X1, X2, CK3,  rk[3]);
	ROUND_(X4, X0, X1, X2, X3, CK4,  rk[4]);
	ROUND_(X0, X1, X2, X3, X4, CK5,  rk[5]);
	ROUND_(X1, X2, X3, X4, X0, CK6,  rk[6]);
	ROUND_(X2, X3, X4, X0, X1, CK7,  rk[7]);
	ROUND_(X3, X4, X0, X1, X2, CK8,  rk[8]);
	ROUND_(X4, X0, X1, X2, X3, CK9,  rk[9]);
	ROUND_(X0, X1, X2, X3, X4, CK10, rk[10]);
	ROUND_(X1, X2, X3, X4, X0, CK11, rk[11]);
	ROUND_(X2, X3, X4, X0, X1, CK12, rk[12]);
	ROUND_(X3, X4, X0, X1, X2, CK13, rk[13]);
	ROUND_(X4, X0, X1, X2, X3, CK14, rk[14]);
	ROUND_(X0, X1, X2, X3, X4, CK15, rk[15]);
	ROUND_(X1, X2, X3, X4, X0, CK16, rk[16]);
	ROUND_(X2, X3, X4, X0, X1, CK17, rk[17]);
	ROUND_(X3, X4, X0, X1, X2, CK18, rk[18]);
	ROUND_(X4, X0, X1, X2, X3, CK19, rk[19]);
	ROUND_(X0, X1, X2, X3, X4, CK20, rk[20]);
	ROUND_(X1, X2, X3, X4, X0, CK21, rk[21]);
	ROUND_(X2, X3, X4, X0, X1, CK22, rk[22]);
	ROUND_(X3, X4, X0, X1, X2, CK23, rk[23]);
	ROUND_(X4, X0, X1, X2, X3, CK24, rk[24]);
	ROUND_(X0, X1, X2, X3, X4, CK25, rk[25]);
	ROUND_(X1, X2, X3, X4, X0, CK26, rk[26]);
	ROUND_(X2, X3, X4, X0, X1, CK27, rk[27]);
	ROUND_(X3, X4, X0, X1, X2, CK28, rk[28]);
	ROUND_(X4, X0, X1, X2, X3, CK29, rk[29]);
	ROUND_(X0, X1, X2, X3, X4, CK30, rk[30]);
	ROUND_(X1, X2, X3, X4, X0, CK31, rk[31]);
}

void sms4_set_decrypt_key(sms4_key_t *key, const unsigned char *user_key)
{
	uint32_t *rk = key->rk;
	uint32_t X0, X1, X2, X3, X4;

	X0 = GETU32(user_key     ) ^ FK0;
	X1 = GETU32(user_key  + 4) ^ FK1;
	X2 = GETU32(user_key  + 8) ^ FK2;
	X3 = GETU32(user_key + 12) ^ FK3;

	ROUND_(X0, X1, X2, X3, X4, CK0,  rk[31]);
	ROUND_(X1, X2, X3, X4, X0, CK1,  rk[30]);
	ROUND_(X2, X3, X4, X0, X1, CK2,  rk[29]);
	ROUND_(X3, X4, X0, X1, X2, CK3,  rk[28]);
	ROUND_(X4, X0, X1, X2, X3, CK4,  rk[27]);
	ROUND_(X0, X1, X2, X3, X4, CK5,  rk[26]);
	ROUND_(X1, X2, X3, X4, X0, CK6,  rk[25]);
	ROUND_(X2, X3, X4, X0, X1, CK7,  rk[24]);
	ROUND_(X3, X4, X0, X1, X2, CK8,  rk[23]);
	ROUND_(X4, X0, X1, X2, X3, CK9,  rk[22]);
	ROUND_(X0, X1, X2, X3, X4, CK10, rk[21]);
	ROUND_(X1, X2, X3, X4, X0, CK11, rk[20]);
	ROUND_(X2, X3, X4, X0, X1, CK12, rk[19]);
	ROUND_(X3, X4, X0, X1, X2, CK13, rk[18]);
	ROUND_(X4, X0, X1, X2, X3, CK14, rk[17]);
	ROUND_(X0, X1, X2, X3, X4, CK15, rk[16]);
	ROUND_(X1, X2, X3, X4, X0, CK16, rk[15]);
	ROUND_(X2, X3, X4, X0, X1, CK17, rk[14]);
	ROUND_(X3, X4, X0, X1, X2, CK18, rk[13]);
	ROUND_(X4, X0, X1, X2, X3, CK19, rk[12]);
	ROUND_(X0, X1, X2, X3, X4, CK20, rk[11]);
	ROUND_(X1, X2, X3, X4, X0, CK21, rk[10]);
	ROUND_(X2, X3, X4, X0, X1, CK22, rk[9]);
	ROUND_(X3, X4, X0, X1, X2, CK23, rk[8]);
	ROUND_(X4, X0, X1, X2, X3, CK24, rk[7]);
	ROUND_(X0, X1, X2, X3, X4, CK25, rk[6]);
	ROUND_(X1, X2, X3, X4, X0, CK26, rk[5]);
	ROUND_(X2, X3, X4, X0, X1, CK27, rk[4]);
	ROUND_(X3, X4, X0, X1, X2, CK28, rk[3]);
	ROUND_(X4, X0, X1, X2, X3, CK29, rk[2]);
	ROUND_(X0, X1, X2, X3, X4, CK30, rk[1]);
	ROUND_(X1, X2, X3, X4, X0, CK31, rk[0]);
}

void sms4_encrypt(const unsigned char *in, unsigned char *out, const sms4_key_t *key)
{
	const uint32_t *rk = key->rk;
	uint32_t X0, X1, X2, X3, X4;

	X0 = GETU32(in     );
	X1 = GETU32(in +  4);
	X2 = GETU32(in +  8);
	X3 = GETU32(in + 12);

	ROUND(X0, X1, X2, X3, X4, rk[0]);
	ROUND(X1, X2, X3, X4, X0, rk[1]);
	ROUND(X2, X3, X4, X0, X1, rk[2]);
	ROUND(X3, X4, X0, X1, X2, rk[3]);
	ROUND(X4, X0, X1, X2, X3, rk[4]);
	ROUND(X0, X1, X2, X3, X4, rk[5]);
	ROUND(X1, X2, X3, X4, X0, rk[6]);
	ROUND(X2, X3, X4, X0, X1, rk[7]);
	ROUND(X3, X4, X0, X1, X2, rk[8]);
	ROUND(X4, X0, X1, X2, X3, rk[9]);
	ROUND(X0, X1, X2, X3, X4, rk[10]);
	ROUND(X1, X2, X3, X4, X0, rk[11]);
	ROUND(X2, X3, X4, X0, X1, rk[12]);
	ROUND(X3, X4, X0, X1, X2, rk[13]);
	ROUND(X4, X0, X1, X2, X3, rk[14]);
	ROUND(X0, X1, X2, X3, X4, rk[15]);
	ROUND(X1, X2, X3, X4, X0, rk[16]);
	ROUND(X2, X3, X4, X0, X1, rk[17]);
	ROUND(X3, X4, X0, X1, X2, rk[18]);
	ROUND(X4, X0, X1, X2, X3, rk[19]);
	ROUND(X0, X1, X2, X3, X4, rk[20]);
	ROUND(X1, X2, X3, X4, X0, rk[21]);
	ROUND(X2, X3, X4, X0, X1, rk[22]);
	ROUND(X3, X4, X0, X1, X2, rk[23]);
	ROUND(X4, X0, X1, X2, X3, rk[24]);
	ROUND(X0, X1, X2, X3, X4, rk[25]);
	ROUND(X1, X2, X3, X4, X0, rk[26]);
	ROUND(X2, X3, X4, X0, X1, rk[27]);
	ROUND(X3, X4, X0, X1, X2, rk[28]);
	ROUND(X4, X0, X1, X2, X3, rk[29]);
	ROUND(X0, X1, X2, X3, X4, rk[30]);
	ROUND(X1, X2, X3, X4, X0, rk[31]);

	PUTU32(X0, out);
	PUTU32(X4, out + 4);
	PUTU32(X3, out + 8);
	PUTU32(X2, out + 12);
}

