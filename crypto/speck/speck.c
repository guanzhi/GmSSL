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

#define ROR(x, r) ((x >> r) | (x << ((sizeof(SPECK_TYPE) * 8) - r)))//循环右移
#define ROL(x, r) ((x << r) | (x >> ((sizeof(SPECK_TYPE) * 8) - r)))//循环左移

#ifdef SPECK_32_64
#define R(x, y, k) (x = ROR(x, 7), x += y, x ^= k, y = ROL(y, 2), y ^= x)
#define RR(x, y, k) (y ^= x, y = ROR(y, 2), x ^= k, x -= y, x = ROL(x, 7))
#else
#define R(x, y, k) (x = ROR(x, 8), x += y, x ^= k, y = ROL(y, 3), y ^= x)
#define RR(x, y, k) (y ^= x, y = ROR(y, 3), x ^= k, x -= y, x = ROL(x, 8))
#endif

void speck_set_encrypt_key(speck_key_t *key, const unsigned char *user_key)
{
	int i;
	for (i = 0; i < num_word; i++)
	{
		if (user_key[i] == '\0')
			break;
		key->rk[i] = user_key[i];
	}
	int j = 0;
	for (; i < num_word; i++)
	{
		key->rk[i] = user_key[j++];
	}
}
void speck_expand(SPECK_TYPE const K[ SPECK_KEY_LEN], SPECK_TYPE S[ SPECK_ROUNDS])
{
	SPECK_TYPE i, b = K[0];
	SPECK_TYPE a[SPECK_KEY_LEN - 1];
	for (i = 0; i < (SPECK_KEY_LEN - 1); i++)
	{
		a[i] = K[i + 1];
	}
	S[0] = b;
	for (i = 0; i < SPECK_ROUNDS - 1; i++) {
		R(a[i % (SPECK_KEY_LEN - 1)], b, i);
		S[i + 1] = b;
	}
}
void speck_encrypt(SPECK_TYPE const pt[ 2], SPECK_TYPE ct[ 2], SPECK_TYPE const K[ SPECK_ROUNDS])
{
	SPECK_TYPE i;
	ct[0] = pt[0]; ct[1] = pt[1];
	for (i = 0; i < SPECK_ROUNDS; i++){
		R(ct[1], ct[0], K[i]);
	}
}

void speck_decrypt(SPECK_TYPE const ct[ 2], SPECK_TYPE pt[ 2], SPECK_TYPE const K[ SPECK_ROUNDS])
{
	SPECK_TYPE i;
	pt[0] = ct[0]; pt[1] = ct[1];

	for (i = 0; i < SPECK_ROUNDS; i++){
		RR(pt[1], pt[0], K[(SPECK_ROUNDS - 1) - i]);
	}
}
