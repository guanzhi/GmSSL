/* ====================================================================
 * Copyright (c) 2014 - 2016 The GmSSL Project.  All rights reserved.
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


#include <zmmintrin.h>
#include <openssl/sms4.h>
#include "sms4_lcl.h"


static __m512i mask_ff00;
static __m512i mask_ffff;
static __m512i mask_ff0000;
static __m512i vindex_0s;
static __m512i vindex_4i;


void sms4_knc_encrypt_init(sms4_key_t *key)
{
	uint64_t value[sizeof(__m512i)/sizeof(uint64_t)];
	int *p = (int *)value;

	for (i = 0; i < 16; i++)
		p[i] = 0xff00;
	mask_ff00 = _mm512_load_epi32(value);

	for (i = 0; i < 16; i++)
		p[i] = 0xffff;
	mask_ffff = _mm512_load_epi32(value);

	for (i = 0; i < 16; i++)
		p[i] = 0xff0000;
	mask_ff0000 = _mm512_load_epi32(value);

	for (i = 0; i < 16; i++)
		p[i] = 0;
	vindex_0s = _mm512_load_epi32(value);

	for (i = 0; i < 16; i++)
		p[i] = 4 * i;
	vindex_4i = _mm512_load_epi32(value);

	sms4_init_sbox32();
}

#define SWAP32(x)						\
	t0 = _mm512_slli_epi32(x, 24);				\
	t1 = _mm512_srli_epi32(x, 24);				\
	t2 = _mm512_or_epi32(t0, t1);				\
	t0 = _mm512_slli_epi32(x, 8);				\
	t1 = _mm512_and_epi32(t0, mask_ff0000);			\
	t0 = _mm512_or_epi32(t2, t1);				\
	t1 = _mm512_srli_epi32(x, 8);				\
	t2 = _mm512_and_epi32(t1, mask_ff00);			\
	x  = _mm512_or_epi32(t0, t2)

#define GET_BLKS(x0, x1, x2, x3, in)				\
	x0 = _mm512_i32gather_epi32(vindex_4i, in+4*0, 4);	\
	x1 = _mm512_i32gather_epi32(vindex_4i, in+4*1, 4);	\
	x2 = _mm512_i32gather_epi32(vindex_4i, in+4*2, 4);	\
	x3 = _mm512_i32gather_epi32(vindex_4i, in+4*3, 4);	\
	SWAP32(x0); SWAP32(x1); SWAP32(x2); SWAP32(x3)

#define PUT_BLKS(out, x0, x1, x2, x3)				\
	SWAP32(x0); SWAP32(x1); SWAP32(x2); SWAP32(x3);		\
	_mm512_i32scatter_epi32(out+4*0, vindex_4i, x0, 4);	\
	_mm512_i32scatter_epi32(out+4*1, vindex_4i, x1, 4);	\
	_mm512_i32scatter_epi32(out+4*2, vindex_4i, x2, 4);	\
	_mm512_i32scatter_epi32(out+4*3, vindex_4i, x3, 4)

#define S(x0, t0, t1, t2)					\
	t0 = _mm512_and_epi32(x0, mask_ffff);			\
	t1 = _mm512_i32gather_epi32(t0, SBOX32L, 4);		\
	t0 = _mm512_srli_epi32(x0, 16);				\
	t2 = _mm512_i32gather_epi32(t0, SBOX32H, 4);		\
	x0 = _mm512_xor_epi32(t1, t2)

#define ROT(r0, x0, i, t0, t1)					\
	t0 = _mm512_slli_epi32(x0, i);				\
	t1 = _mm512_srli_epi32(x0, 32-i);			\
	r0 = _mm512_xor_epi32(t0, t1)

#define L(x0, t0, t1, t2, t3, t4)				\
	ROT(t0, x0,  2, t2, t3);				\
	ROT(t1, x0, 10, t2, t3);				\
	t4 = _mm512_xor_epi32(t0, t1);				\
	ROT(t0, x0, 18, t2, t3);				\
	ROT(t1, x0, 24, t2, t3);				\
	t3 = _mm512_xor_epi32(t0, t1);				\
	t2 = _mm512_xor_epi32(x0, t3);				\
	x0 = _mm512_xor_epi32(t2, t4)

#define ROUND(x0, x1, x2, x3, x4, i)				\
	t0 = _mm512_i32gather_epi32(vindex_0s, rk+i*4, 4);	\
	t1 = _mm512_xor_epi32(x1, x2);				\
	t2 = _mm512_xor_epi32(x3, t0);				\
	t0 = _mm512_xor_epi32(t1, t2);				\
	S(t0, x4, t1, t2);					\
	L(t0, x4, t1, t2, t3, t4);				\
	x4 = _mm512_xor_epi32(x0, t0)


void sms4_knc_encrypt_16blocks(sms4_key_t *key, const unsigned char *in, unsigned char *out)
{
	int *rk = (int *)key->rk;
	__m512i x0, x1, x2, x3, x4;
	__m512i t0, t1, t2, t3, t4;

	GET_BLKS(x0, x1, x2, x3, in);
	ROUNDS(x0, x1, x2, x3, x4, ROUND);
	PUT_BLKS(out, x2, x3, x4, x0);
}

