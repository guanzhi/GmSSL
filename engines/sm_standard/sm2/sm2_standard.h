/* ====================================================================
 * Copyright (c) 2015 - 2016 The GmSSL Project.  All rights reserved.
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
 */

#ifndef HEADER_SM2_STANDARD_H
#define HEADER_SM2_STANDARD_H


#include <string.h>
#include <stdlib.h>
#include <stdio.h>



#ifdef __cplusplus
extern "C" {
#endif

#include "miracl.h"
#include "mirdef.h"
#include "kdf_standard.h"

#define ERR_INFINITY_POINT 0x00000001
#define ERR_NOT_VALID_ELEMENT 0x00000002
#define ERR_NOT_VALID_POINT 0x00000003
#define ERR_ORDER 0x00000004
#define ERR_ECURVE_INIT 0x00000005
#define ERR_KEYEX_RA 0x00000006
#define ERR_KEYEX_RB 0x00000007
#define ERR_EQUAL_S1SB 0x00000008
#define ERR_EQUAL_S2SA 0x00000009
#define ERR_SELFTEST_Z 0x0000000A
#define ERR_SELFTEST_INI_I 0x0000000B
#define ERR_SELFTEST_RES_I 0x0000000C
#define ERR_SELFTEST_INI_II 0x0000000D
#define ERR_GENERATE_R 0x0000000E
#define ERR_GENERATE_S 0x0000000F
#define ERR_OUTRANGE_R 0x00000010
#define ERR_OUTRANGE_S 0x00000011
#define ERR_GENERATE_T 0x00000012
#define ERR_PUBKEY_INIT 0x00000013
#define ERR_DATA_MEMCMP 0x00000014
#define ERR_ARRAY_NULL 0x00000015
#define ERR_C3_MATCH 0x00000016
#define ERR_SELFTEST_KG 0x00000017
#define ERR_SELFTEST_ENC 0x00000018
#define ERR_SELFTEST_DEC 0x00000019


static unsigned char SM2_p[32] = {0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
						   0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static unsigned char SM2_a[32] = {0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
						   0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC};
static unsigned char SM2_b[32] = {0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34, 0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7,
						   0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92, 0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93};
static unsigned char SM2_n[32] = {0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
						   0x72, 0x03, 0xDF, 0x6B, 0x21, 0xC6, 0x05, 0x2B, 0x53, 0xBB, 0xF4, 0x09, 0x39, 0xD5, 0x41, 0x23};
static unsigned char SM2_Gx[32] = {0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19, 0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
							0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1, 0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7};
static unsigned char SM2_Gy[32] = {0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C, 0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
							0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40, 0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0};
static unsigned char SM2_h[32] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
						   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

big para_p, para_a, para_b, para_n, para_Gx, para_Gy, para_h;
epoint *G;
miracl *mip;


int SM2_w(big n);
void SM3_z(unsigned char ID[], unsigned short int ELAN, epoint* pubKey, unsigned char hash[]);
static int Test_Point(epoint* point);
static int Test_PubKey(epoint *pubKey);
int Test_Null(unsigned char array[], int len);
int Test_Zero(big x);
int Test_n(big x);
static int Test_Range(big x);
static int SM2_standard_init();
static int SM2_standard_keygeneration(big priKey, epoint *pubKey);
int SM2_standard_sign_keygeneration(unsigned char PriKey[], unsigned char Px[], unsigned char Py[]);
int SM2_standard_keyex_init_i(big ra, epoint* RA);
int SM2_standard_keyex_re_i(big rb, big dB, epoint* RA, epoint* PA, unsigned char ZA[], unsigned char ZB[], unsigned char K[], int klen, epoint* RB, epoint* V, unsigned char hash[]);
int SM2_standard_keyex_init_ii(big ra, big dA, epoint* RA, epoint* RB, epoint* PB, unsigned char ZA[], unsigned char ZB[], unsigned char SB[], unsigned char K[], int klen, unsigned char SA[]);
int SM2_standard_keyex_re_ii(epoint *V, epoint *RA, epoint *RB, unsigned char ZA[], unsigned char ZB[], unsigned char SA[]);
int SM2_standard_keyex_selftest();
int SM2_standard_encrypt(unsigned char* randK, epoint *pubKey, unsigned char M[], int klen, unsigned char C[]);
int SM2_standard_decrypt(big dB, unsigned char C[], int Clen, unsigned char M[]);
int SM2_standard_enc_selftest();
int SM2_standard_sign(unsigned char *message, int len, unsigned char ZA[], unsigned char rand[], unsigned char d[], unsigned char R[], unsigned char S[]);
int SM2_standard_verify(unsigned char *message, int len, unsigned char ZA[], unsigned char Px[], unsigned char Py[], unsigned char R[], unsigned char S[]);
int SM2_standard_selfcheck();


/* Initiate SM2 curve */
static int SM2_standard_init()
{
	epoint *nG;
	para_p = mirvar(0);
	para_a = mirvar(0);
	para_b = mirvar(0);
	para_n = mirvar(0);
	para_Gx = mirvar(0);
	para_Gy = mirvar(0);
	para_h = mirvar(0);
	
    	G = epoint_init();
	nG = epoint_init();
	
    	bytes_to_big(SM2_NUMWORD, SM2_p, para_p);
	bytes_to_big(SM2_NUMWORD, SM2_a, para_a);
	bytes_to_big(SM2_NUMWORD, SM2_b, para_b);
	bytes_to_big(SM2_NUMWORD, SM2_n, para_n);
	bytes_to_big(SM2_NUMWORD, SM2_Gx, para_Gx);
	bytes_to_big(SM2_NUMWORD, SM2_Gy, para_Gy);
	bytes_to_big(SM2_NUMWORD, SM2_h, para_h);

	ecurve_init(para_a, para_b, para_p, MR_PROJECTIVE);		//Initialises GF(p) elliptic curve.
															//MR_PROJECTIVE specifying projective coordinates
	if (!epoint_set(para_Gx, para_Gy, 0, G))	//initialise point G
	{
		return ERR_ECURVE_INIT;
	}
	ecurve_mult(para_n, G, nG);
	if (!point_at_infinity(nG))		//test if the order of the point is n
	{
		return ERR_ORDER;
	}
	return 0;
}


/* test if the given point is on SM2 curve */
static int Test_Point(epoint* point)
{
	big x, y, x_3, tmp;
	x = mirvar(0);
	y = mirvar(0);
	x_3 = mirvar(0);
	tmp = mirvar(0);

	//test if y^2 = x^3 + ax + b
	epoint_get(point, x, y);
	power(x, 3, para_p, x_3);	//x_3 = x^3 mod p
	multiply(x, para_a, x); 	//x = a * x
	divide(x, para_p, tmp); 	//x = a * x mod p, tmp = a * x / p
	add(x_3, x, x);				//x = x^3 + ax
	add(x, para_b, x);			//x = x^3 + ax + b
	divide(x, para_p, tmp);		//x = x^3 + ax + b mod p
	power(y, 2, para_p, y);		//y = y^2 mod p
	if (mr_compare(x, y) != 0)
		return ERR_NOT_VALID_POINT;
	else
		return 0;
}


/* test if the given public key is valid */
static int Test_PubKey(epoint *pubKey)
{
	big x, y, x_3, tmp;
	epoint *nP;
	x = mirvar(0);
	y = mirvar(0);
	x_3 = mirvar(0);
	tmp = mirvar(0);
	
	nP = epoint_init();

	//test if the pubKey is the point at infinity
	if (point_at_infinity(pubKey))		//if pubKey is point at infinity, return error;
		return ERR_INFINITY_POINT;
	
	//test if x < p and y<p both hold
	epoint_get(pubKey, x, y);
	if ((mr_compare(x, para_p) != -1) || (mr_compare(y, para_p) != -1))
		return ERR_NOT_VALID_ELEMENT;

	if (Test_Point(pubKey) != 0)
		return ERR_NOT_VALID_POINT;


	//test if the order of pubKey is equal to n
	ecurve_mult(para_n, pubKey, nP);	//nP=[n]P
	if (!point_at_infinity(nP))			//if np is point NOT at infinity, return error;
		return ERR_ORDER;
	return 0;
}


/* test if the big x belong to the range[1, n-1] */
static int Test_Range(big x)
{
	big one, decr_n;

	one = mirvar(0);
	decr_n = mirvar(0);

	convert(1, one);
	decr(para_n, 1, decr_n);

	if ((mr_compare(x, one) < 0) | (mr_compare(x, decr_n) > 0))
		return 1;
	return 0;
}


/* calculate a pubKey out of a given priKey */
static int SM2_standard_keygeneration(big priKey, epoint *pubKey)
{
	int i = 0;
	big x, y;
	x = mirvar(0);
	y = mirvar(0);

	//mip = mirsys(1000, 16);
	//mip->IOBASE = 16;
	
	ecurve_mult(priKey, G, pubKey);
	epoint_get(pubKey, x, y);

	i = Test_PubKey(pubKey);
	if (i)
		return i;
	else
		return 0;
}

#ifdef __cplusplus
}
# endif
#endif


