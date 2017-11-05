/* ====================================================================
 * Copyright (c) 2014 - 2017 The GmSSL Project.  All rights reserved.
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

#include <openssl/speck.h>
#include "speck_lcl.h"

void speck_set_encrypt_key16(SPECK_TYPE16 const K[SPECK_KEY_LEN16], SPECK_TYPE16 S[SPECK_ROUNDS16])
{
	SPECK_TYPE16 i, b = K[0];
	SPECK_TYPE16 a[SPECK_KEY_LEN16 - 1];
	for (i = 0; i < (SPECK_KEY_LEN16 - 1); i++)
	{
		a[i] = K[i + 1];
	}
	S[0] = b;
	for (i = 0; i < SPECK_ROUNDS16 - 1; i++) {
		R16(a[i % (SPECK_KEY_LEN16 - 1)], b, i);
		S[i + 1] = b;
	}
}

void speck_set_decrypt_key16(SPECK_TYPE16 const K[SPECK_KEY_LEN16], SPECK_TYPE16 S[SPECK_ROUNDS16])
{
	SPECK_TYPE16 i, b = K[0];
	SPECK_TYPE16 a[SPECK_KEY_LEN16 - 1];
	for (i = 0; i < (SPECK_KEY_LEN16 - 1); i++)
	{
		a[i] = K[i + 1];
	}
	S[0] = b;
	for (i = 0; i < SPECK_ROUNDS16 - 1; i++) {
		R16(a[i % (SPECK_KEY_LEN16 - 1)], b, i);
		S[i + 1] = b;
	}
}

void speck_encrypt16(SPECK_TYPE16 const pt[2], SPECK_TYPE16 ct[2], SPECK_TYPE16 const K[SPECK_ROUNDS16])
{
	SPECK_TYPE16 i;
	ct[0] = pt[0]; ct[1] = pt[1];
	for (i = 0; i < SPECK_ROUNDS16; i++){
		R16(ct[1], ct[0], K[i]);
	}
}

void speck_decrypt16(SPECK_TYPE16 const ct[2], SPECK_TYPE16 pt[2], SPECK_TYPE16 const K[SPECK_ROUNDS16])
{
	SPECK_TYPE16 i;
	pt[0] = ct[0]; pt[1] = ct[1];

	for (i = 0; i < SPECK_ROUNDS16; i++){
		RR16(pt[1], pt[0], K[(SPECK_ROUNDS16 - 1) - i]);
	}
}

void speck_set_encrypt_key32(SPECK_TYPE32 const K[SPECK_KEY_LEN32], SPECK_TYPE32 S[SPECK_ROUNDS32])
{
	SPECK_TYPE32 i, b = K[0];
	SPECK_TYPE32 a[SPECK_KEY_LEN32 - 1];
	for (i = 0; i < (SPECK_KEY_LEN32 - 1); i++)
	{
		a[i] = K[i + 1];
	}
	S[0] = b;
	for (i = 0; i < SPECK_ROUNDS32 - 1; i++) {
		R32(a[i % (SPECK_KEY_LEN32 - 1)], b, i);
		S[i + 1] = b;
	}
}

void speck_set_decrypt_key32(SPECK_TYPE32 const K[SPECK_KEY_LEN32], SPECK_TYPE32 S[SPECK_ROUNDS32])
{
	SPECK_TYPE32 i, b = K[0];
	SPECK_TYPE32 a[SPECK_KEY_LEN32 - 1];
	for (i = 0; i < (SPECK_KEY_LEN32 - 1); i++)
	{
		a[i] = K[i + 1];
	}
	S[0] = b;
	for (i = 0; i < SPECK_ROUNDS32 - 1; i++) {
		R32(a[i % (SPECK_KEY_LEN32 - 1)], b, i);
		S[i + 1] = b;
	}
}

void speck_encrypt32(SPECK_TYPE32 const pt[2], SPECK_TYPE32 ct[2], SPECK_TYPE32 const K[SPECK_ROUNDS32])
{
	SPECK_TYPE32 i;
	ct[0] = pt[0]; ct[1] = pt[1];
	for (i = 0; i < SPECK_ROUNDS32; i++){
		R32(ct[1], ct[0], K[i]);
	}
}

void speck_decrypt32(SPECK_TYPE32 const ct[2], SPECK_TYPE32 pt[2], SPECK_TYPE32 const K[SPECK_ROUNDS32])
{
	SPECK_TYPE32 i;
	pt[0] = ct[0]; pt[1] = ct[1];

	for (i = 0; i < SPECK_ROUNDS32; i++){
		RR32(pt[1], pt[0], K[(SPECK_ROUNDS32 - 1) - i]);
	}
}

void speck_set_encrypt_key64(SPECK_TYPE64 const K[SPECK_KEY_LEN64], SPECK_TYPE64 S[SPECK_ROUNDS64])
{
	SPECK_TYPE64 i, b = K[0];
	SPECK_TYPE64 a[SPECK_KEY_LEN64 - 1];
	for (i = 0; i < (SPECK_KEY_LEN64 - 1); i++)
	{
		a[i] = K[i + 1];
	}
	S[0] = b;
	for (i = 0; i < SPECK_ROUNDS64 - 1; i++) {
		R64(a[i % (SPECK_KEY_LEN64 - 1)], b, i);
		S[i + 1] = b;
	}
}

void speck_set_decrypt_key64(SPECK_TYPE64 const K[SPECK_KEY_LEN64], SPECK_TYPE64 S[SPECK_ROUNDS64])
{
	SPECK_TYPE64 i, b = K[0];
	SPECK_TYPE64 a[SPECK_KEY_LEN64 - 1];
	for (i = 0; i < (SPECK_KEY_LEN64 - 1); i++)
	{
		a[i] = K[i + 1];
	}
	S[0] = b;
	for (i = 0; i < SPECK_ROUNDS64 - 1; i++) {
		R64(a[i % (SPECK_KEY_LEN64 - 1)], b, i);
		S[i + 1] = b;
	}
}

void speck_encrypt64(SPECK_TYPE64 const pt[2], SPECK_TYPE64 ct[2], SPECK_TYPE64 const K[SPECK_ROUNDS64])
{
	SPECK_TYPE64 i;
	ct[0] = pt[0]; ct[1] = pt[1];
	for (i = 0; i < SPECK_ROUNDS64; i++){
		R64(ct[1], ct[0], K[i]);
	}
}

void speck_decrypt64(SPECK_TYPE64 const ct[2], SPECK_TYPE64 pt[2], SPECK_TYPE64 const K[SPECK_ROUNDS64])
{
	SPECK_TYPE64 i;
	pt[0] = ct[0]; pt[1] = ct[1];

	for (i = 0; i < SPECK_ROUNDS64; i++){
		RR64(pt[1], pt[0], K[(SPECK_ROUNDS64 - 1) - i]);
	}
}
