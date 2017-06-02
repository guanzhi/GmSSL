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


#include <immintrin.h>
#include <openssl/sms4.h>
#include "sms4_lcl.h"

static __m256i mask_ffff;
static __m256i vindex_0s;
static __m256i vindex_4i;
static __m256i vindex_swap;
static __m256i vindex_read;


void sms4_avx2_encrypt_init(sms4_key_t *key)
{
	mask_ffff = _mm256_set1_epi32(0xffff);
	vindex_0s = _mm256_set1_epi32(0);
	vindex_4i = _mm256_setr_epi32(0,4,8,12,16,20,24,28);
	vindex_read = _mm256_setr_epi32(0,8,16,24,1,9,17,25);
	vindex_swap = _mm256_setr_epi8(
		3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12,
		3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12
	);
	sms4_init_sbox32();
}

#define GET_BLKS(x0, x1, x2, x3, in)					\
	t0 = _mm256_i32gather_epi32((int *)(in+4*0), vindex_4i, 4);	\
	t1 = _mm256_i32gather_epi32((int *)(in+4*1), vindex_4i, 4);	\
	t2 = _mm256_i32gather_epi32((int *)(in+4*2), vindex_4i, 4);	\
	t3 = _mm256_i32gather_epi32((int *)(in+4*3), vindex_4i, 4);	\
	x0 = _mm256_shuffle_epi8(t0, vindex_swap);			\
	x1 = _mm256_shuffle_epi8(t1, vindex_swap);			\
	x2 = _mm256_shuffle_epi8(t2, vindex_swap);			\
	x3 = _mm256_shuffle_epi8(t3, vindex_swap)

#define PUT_BLKS(out, x0, x1, x2, x3)					\
	t0 = _mm256_shuffle_epi8(x0, vindex_swap);			\
	t1 = _mm256_shuffle_epi8(x1, vindex_swap);			\
	t2 = _mm256_shuffle_epi8(x2, vindex_swap);			\
	t3 = _mm256_shuffle_epi8(x3, vindex_swap);			\
	_mm256_storeu_si256((__m256i *)(out+32*0), t0);			\
	_mm256_storeu_si256((__m256i *)(out+32*1), t1);			\
	_mm256_storeu_si256((__m256i *)(out+32*2), t2);			\
	_mm256_storeu_si256((__m256i *)(out+32*3), t3);			\
	x0 = _mm256_i32gather_epi32((int *)(in+32*0), vindex_read, 4);	\
	x1 = _mm256_i32gather_epi32((int *)(in+32*1), vindex_read, 4);	\
	x2 = _mm256_i32gather_epi32((int *)(in+32*2), vindex_read, 4);	\
	x3 = _mm256_i32gather_epi32((int *)(in+32*3), vindex_read, 4);	\
	_mm256_storeu_si256((__m256i *)(out+2*0), x0);			\
	_mm256_storeu_si256((__m256i *)(out+2*1), x1);			\
	_mm256_storeu_si256((__m256i *)(out+2*2), x2);			\
	_mm256_storeu_si256((__m256i *)(out+2*3), x3)

#define S(x0, t0, t1, t2)					\
	t0 = _mm256_and_si256(x0, mask_ffff);			\
	t1 = _mm256_i32gather_epi32(SBOX32L, t0, 4);		\
	t0 = _mm256_srli_epi32(x0, 16);				\
	t2 = _mm256_i32gather_epi32(SBOX32H, t0, 4);		\
	x0 = _mm256_xor_si256(t1, t2)

#define ROT(r0, x0, i, t0, t1)					\
	t0 = _mm256_slli_epi32(x0, i);				\
	t1 = _mm256_srli_epi32(x0,32-i);			\
	r0 = _mm256_xor_si256(t0, t1)

#define L(x0, t0, t1, t2, t3, t4)				\
	ROT(t0, x0,  2, t2, t3);				\
	ROT(t1, x0, 10, t2, t3);				\
	t4 = _mm256_xor_si256(t0, t1);				\
	ROT(t0, x0, 18, t2, t3);				\
	ROT(t1, x0, 24, t2, t3);				\
	t3 = _mm256_xor_si256(t0, t1);				\
	t2 = _mm256_xor_si256(x0, t3);				\
	x0 = _mm256_xor_si256(t2, t4)

#define ROUND(x0, x1, x2, x3, x4, i)				\
	t0 = _mm256_i32gather_epi32(rk+i, vindex_0s, 4);	\
	t1 = _mm256_xor_si256(x1, x2);				\
	t2 = _mm256_xor_si256(x3, t0);				\
	t0 = _mm256_xor_si256(t1, t2);				\
	S(t0, x4, t1, t2);					\
	L(t0, x4, t1, t2, t3, t4);				\
	x4 = _mm256_xor_si256(x0, t0);


void sms4_avx2_encrypt_8blocks(const unsigned char *in, unsigned char *out, const sms4_key_t *key)
{
	const int *rk = (int *)key->rk;
	__m256i x0, x1, x2, x3, x4;
	__m256i t0, t1, t2, t3, t4;
	GET_BLKS(x0, x1, x2, x3, in);
	ROUNDS(x0, x1, x2, x3, x4);
	PUT_BLKS(out, x0, x4, x3, x2);
}

void sms4_avx2_encrypt_16blocks(const unsigned char *in, unsigned char *out, const sms4_key_t *key)
{
	sms4_encrypt_8blocks(key, in, out);
	sms4_encrypt_8blocks(key, in + 16*8, out + 16*8);
}
