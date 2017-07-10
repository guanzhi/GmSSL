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


#include "mirdef.h"
#include "miracl.h"
#include "sm2_standard.h"



/* test if the big x is zero */
int Test_Zero(big x)
{
	big zero;
	zero = mirvar(0);
	if (mr_compare(x, zero) == 0)
		return 1;
	else 
		return 0;
}


/* test if the big x is order n */
int Test_n(big x)
{
	//bytes_to_big(32, SM2_n, n);
	if (mr_compare(x, para_n) == 0)
		return 1;
	else 
		return 0;
}



/* calculate a pubKey out of a given priKey */
int SM2_standard_sign_keygeneration(unsigned char PriKey[], unsigned char Px[], unsigned char Py[])
{
	int i = 0;
	big d, PAx, PAy;
	epoint *PA;

	SM2_standard_init();
	PA = epoint_init();

	d = mirvar(0);
	PAx = mirvar(0);
	PAy = mirvar(0);

	bytes_to_big(SM2_NUMWORD, PriKey, d);

	ecurve_mult(d, G, PA);
	epoint_get(PA, PAx, PAy);

	big_to_bytes(SM2_NUMWORD, PAx, Px, TRUE);
	big_to_bytes(SM2_NUMWORD, PAy, Py, TRUE);
	i = Test_PubKey(PA);
	if (i)
		return i;
	else
		return 0;
}


/* SM2 signature algorithm */
int SM2_standard_sign(unsigned char *message, int len, unsigned char ZA[], unsigned char rand[], unsigned char d[], unsigned char R[], unsigned char S[])
{
	unsigned char hash[SM3_len / 8];
	int M_len = len + SM3_len / 8;
	unsigned char *M = NULL;
	int i;

	big dA, r, s, e, k, KGx, KGy;
	big rem, rk, z1, z2;
	epoint *KG;

	i = SM2_standard_init();
	if (i) 
		return i;
	//initiate
	dA = mirvar(0);
	e = mirvar(0);
	k = mirvar(0);
	KGx = mirvar(0);
	KGy = mirvar(0);
	r = mirvar(0);
	s = mirvar(0);
	rem = mirvar(0);
	rk = mirvar(0);
	z1 = mirvar(0);
	z2 = mirvar(0);

	bytes_to_big(SM2_NUMWORD, d, dA);	//cinstr(dA, d);

	KG = epoint_init();

	//step1, set M = ZA || M
	M = (char *)malloc(sizeof(char)*(M_len + 1));
	memcpy(M, ZA, SM3_len / 8);
	memcpy(M + SM3_len / 8, message, len);

	//step2, generate e = H(M)
	SM3_256(M, M_len, hash);
	bytes_to_big(SM3_len / 8, hash, e);

	//step3:generate k
	bytes_to_big(SM3_len / 8, rand, k);

	//step4:calculate kG
	ecurve_mult(k, G, KG);

	//step5:calculate r
	epoint_get(KG, KGx, KGy);
	add(e, KGx, r);
	divide(r, para_n, rem);

	//judge r = 0 or n + k = n?
	add(r, k, rk);
	if (Test_Zero(r) | Test_n(rk))
		return ERR_GENERATE_R;

	//step6:generate s
	incr(dA, 1, z1);
	xgcd(z1, para_n, z1, z1, z1);
	multiply(r, dA, z2);
	divide(z2, para_n, rem);
	subtract(k, z2, z2);
	add(z2, para_n, z2);
	multiply(z1, z2, s);
	divide(s, para_n, rem);

	//judge s = 0?
	if (Test_Zero(s))
		return ERR_GENERATE_S ;

	big_to_bytes(SM2_NUMWORD, r, R, TRUE);
	big_to_bytes(SM2_NUMWORD, s, S, TRUE);

	free(M);
	return 0;
}


/* SM2 verification algorithm */
int SM2_standard_verify(unsigned char *message, int len, unsigned char ZA[], unsigned char Px[], unsigned char Py[], unsigned char R[], unsigned char S[])
{
	unsigned char hash[SM3_len / 8];
	int M_len = len + SM3_len / 8;
	unsigned char *M = NULL;
	int i;

	big PAx, PAy, r, s, e, t, rem, x1, y1;
	big RR;
	epoint *PA, *sG, *tPA;

	i = SM2_standard_init();
	if (i) 
		return i;

	PAx = mirvar(0);
	PAy = mirvar(0);
	r = mirvar(0);
	s = mirvar(0);
	e = mirvar(0);
	t = mirvar(0);
	x1 = mirvar(0);
	y1 = mirvar(0);
	rem = mirvar(0);
	RR = mirvar(0);

	PA = epoint_init();
	sG = epoint_init();
	tPA = epoint_init();

	bytes_to_big(SM2_NUMWORD, Px, PAx);
	bytes_to_big(SM2_NUMWORD, Py, PAy);

	bytes_to_big(SM2_NUMWORD, R, r);
	bytes_to_big(SM2_NUMWORD, S, s);
	
	if (!epoint_set(PAx, PAy, 0, PA))	//initialise public key
	{
		return ERR_PUBKEY_INIT;
	}

	//step1: test if r belong to [1, n-1]
	if (Test_Range(r))
		return ERR_OUTRANGE_R;

	//step2: test if s belong to [1, n-1]
	if (Test_Range(s))
		return ERR_OUTRANGE_S;

	//step3, generate M
	M = (char *)malloc(sizeof(char)*(M_len + 1));
	memcpy(M, ZA, SM3_len / 8);
	memcpy(M + SM3_len / 8, message, len);

	//step4, generate e = H(M)
	SM3_256(M, M_len, hash);
	bytes_to_big(SM3_len / 8, hash, e);

	//step5:generate t
	add(r, s, t);
	divide(t, para_n, rem);

	if (Test_Zero(t))
		return ERR_GENERATE_T;

	//step 6: generate(x1, y1)
	ecurve_mult(s, G, sG);
	ecurve_mult(t, PA, tPA);
	ecurve_add(sG, tPA);
	epoint_get(tPA, x1, y1);

	//step7:generate RR
	add(e, x1, RR);
	divide(RR, para_n, rem);

	free(M);
	if (mr_compare(RR, r) == 0)
		return 0;
	else
		return ERR_DATA_MEMCMP;
}


/* SM2 self check */
int SM2_standard_selfcheck()
{
	//the private key
	unsigned char dA[32] = {0x39, 0x45, 0x20, 0x8f, 0x7b, 0x21, 0x44, 0xb1, 0x3f, 0x36, 0xe3, 0x8a, 0xc6, 0xd3, 0x9f,
							0x95, 0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xb5, 0x1a, 0x42, 0xfb, 0x81, 0xef, 0x4d, 0xf7, 
							0xc5, 0xb8};
	unsigned char rand[32] = {0x59, 0x27, 0x6E, 0x27, 0xD5, 0x06, 0x86, 0x1A, 0x16, 0x68, 0x0F, 0x3A, 0xD9, 0xC0, 0x2D,
							  0xCC, 0xEF, 0x3C, 0xC1, 0xFA, 0x3C, 0xDB, 0xE4, 0xCE, 0x6D, 0x54, 0xB8, 0x0D, 0xEA, 0xC1, 
							  0xBC, 0x21};
	//the public key
	/* unsigned char xA[32] = {0x09, 0xf9, 0xdf, 0x31, 0x1e, 0x54, 0x21, 0xa1, 0x50, 0xdd, 0x7d, 0x16, 0x1e, 0x4b, 0xc5, 
							   0xc6, 0x72, 0x17, 0x9f, 0xad, 0x18, 0x33, 0xfc, 0x07, 0x6b, 0xb0, 0x8f, 0xf3, 0x56, 0xf3,
							   0x50, 0x20};
	unsigned char yA[32] = {0xcc, 0xea, 0x49, 0x0c, 0xe2, 0x67, 0x75, 0xa5, 0x2d, 0xc6, 0xea, 0x71, 0x8c, 0xc1, 0xaa,
							0x60, 0x0a, 0xed, 0x05, 0xfb, 0xf3, 0x5e, 0x08, 0x4a, 0x66, 0x32, 0xf6, 0x07, 0x2d, 0xa9, 
							0xad, 0x13};*/

	unsigned char xA[32], yA[32];
	unsigned char r[32], s[32];		// Signature

	unsigned char IDA[16] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33,
						 	 0x34, 0x35, 0x36, 0x37, 0x38};		//ASCII code of userA's identification
	int IDA_len = 16;
	unsigned char ENTLA[2] = {0x00, 0x80};		//the length of userA's identification, presentation in ASCII code

	unsigned char *message = "message digest";	//the message to be signed
	int len = strlen(message);		//the length of message
	unsigned char ZA[SM3_len / 8];		//ZA = Hash(ENTLA || IDA || a || b || Gx || Gy || xA|| yA)
	unsigned char Msg[210];		//210 = IDA_len + 2 + SM2_NUMWORD * 6
	
	int temp;

	mip = mirsys(10000, 16);
	mip->IOBASE = 16;

	temp = SM2_standard_sign_keygeneration(dA, xA, yA);
	if (temp)
		return temp;
	
	//ENTLA || IDA || a || b || Gx || Gy || xA || yA
	memcpy(Msg, ENTLA, 2);
	memcpy(Msg + 2, IDA, IDA_len);
	memcpy(Msg + 2 + IDA_len, SM2_a, SM2_NUMWORD);
	memcpy(Msg + 2 + IDA_len + SM2_NUMWORD, SM2_b, SM2_NUMWORD);
	memcpy(Msg + 2 + IDA_len + SM2_NUMWORD * 2, SM2_Gx, SM2_NUMWORD);
	memcpy(Msg + 2 + IDA_len + SM2_NUMWORD * 3, SM2_Gy, SM2_NUMWORD);
	memcpy(Msg + 2 + IDA_len + SM2_NUMWORD * 4, xA, SM2_NUMWORD);
	memcpy(Msg + 2 + IDA_len + SM2_NUMWORD * 5, yA, SM2_NUMWORD);
	SM3_256(Msg, 210, ZA);
	
	temp = SM2_standard_sign(message, len, ZA, rand, dA, r, s);
	if (temp)
		return temp;
	
	temp = SM2_standard_verify(message, len, ZA, xA, yA, r, s);
	if (temp)
		return temp;

	return 0;
}
