/*
 * Copyright (c) 2014 - 2020 The GmSSL Project.  All rights reserved.
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
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/gf128.h>
#include <gmssl/gcm.h>
#include <gmssl/oid.h>
#include <gmssl/error.h>
#include <gmssl/aes.h>
#include <gmssl/endian.h>


/*
 * GHASH(H, A, C) = X_{m + n + 1}
 *   A additional authenticated data, A = A_1, ..., A_{m-1}, A_{m^*}, nbits(A_{m^*}) = v
 *   C ciphertext, C = C_1, ..., C_{n-1}, C_{n^*}, nbits(C_{n^*}) = u
 *   H = E_K(0^128)
 *
 * X_i = 0                                         for i = 0
 *     = (X_{i-1}   xor  A_i                ) * H  for i = 1, ..., m-1
 *     = (X_{m-1}   xor (A_m^* || 0^{128-v})) * H  for i = m
 *     = (X_{i-1}   xor  C_i                ) * H  for i = m+1, ..., m + n − 1
 *     = (X_{m+n-1} xor (C_m^* || 0^{128-u})) * H  for i = m + n
 *     = (X_{m+n}   xor (nbits(A)||nbits(C))) * H  for i = m + n + 1
 */
void ghash(const uint8_t h[16], const uint8_t *aad, size_t aadlen, const uint8_t *c, size_t clen, uint8_t out[16])
{
	gf128_t H = gf128_from_bytes(h);
	gf128_t X = gf128_zero();
	gf128_t L;

	PUTU64(out, (uint64_t)aadlen << 3);
	PUTU64(out + 8, (uint64_t)clen << 3);
	L = gf128_from_bytes(out);

	while (aadlen) {
		gf128_t A;
		if (aadlen >= 16) {
			A = gf128_from_bytes(aad);
			aad += 16;
			aadlen -= 16;
		} else {
			memset(out, 0, 16);
			memcpy(out, aad, aadlen);
			A = gf128_from_bytes(out);
			aadlen = 0;
		}
		X = gf128_add(X, A);
		X = gf128_mul(X, H);
	}

	while (clen) {
		gf128_t C;
		if (clen >= 16) {
			C = gf128_from_bytes(c);
			c += 16;
			clen -= 16;
		} else {
			memset(out, 0, 16);
			memcpy(out, c, clen);
			C = gf128_from_bytes(out);
			clen = 0;
		}
		X = gf128_add(X, C);
		X = gf128_mul(X, H);
	}

	X = gf128_add(X, L);
	H = gf128_mul(X, H);
	gf128_to_bytes(H, out);
}

int gcm_encrypt(const BLOCK_CIPHER_KEY *key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	uint8_t *out, size_t taglen, uint8_t *tag)
{
	if (key->cipher == BLOCK_CIPHER_sm4()) {
		sm4_gcm_encrypt(&(key->u.sm4_key), iv, ivlen, aad, aadlen,  in, inlen, out, taglen, tag);
		return 1;
	} else if (key->cipher == BLOCK_CIPHER_aes128()) {
		aes_gcm_encrypt(&(key->u.aes_key), iv, ivlen, aad, aadlen,  in, inlen, out, taglen, tag);
		return 1;
	}
	error_print();
	return -1;
}

int gcm_decrypt(const BLOCK_CIPHER_KEY *key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	const uint8_t *tag, size_t taglen, uint8_t *out)
{
	if (key->cipher == BLOCK_CIPHER_sm4()) {
		sm4_gcm_decrypt(&(key->u.sm4_key), iv, ivlen, aad, aadlen,  in, inlen, tag, taglen, out);
	} else if (key->cipher == BLOCK_CIPHER_aes128()) {
		aes_gcm_decrypt(&(key->u.aes_key), iv, ivlen, aad, aadlen,  in, inlen, tag, taglen, out);
	}
	error_print();
	return -1;
}
