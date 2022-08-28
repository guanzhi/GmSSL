/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
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
		if (sm4_gcm_encrypt(&(key->u.sm4_key), iv, ivlen, aad, aadlen,  in, inlen, out, taglen, tag) != 1) {
			error_print();
			return -1;
		}
	} else if (key->cipher == BLOCK_CIPHER_aes128()) {
		if (aes_gcm_encrypt(&(key->u.aes_key), iv, ivlen, aad, aadlen,  in, inlen, out, taglen, tag) != 1) {
			error_print();
			return -1;
		}
	}
	return 1;
}

int gcm_decrypt(const BLOCK_CIPHER_KEY *key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	const uint8_t *tag, size_t taglen, uint8_t *out)
{
	if (key->cipher == BLOCK_CIPHER_sm4()) {
		if (sm4_gcm_decrypt(&(key->u.sm4_key), iv, ivlen, aad, aadlen,  in, inlen, tag, taglen, out) != 1) {
			error_print();
			return -1;
		}
	} else if (key->cipher == BLOCK_CIPHER_aes128()) {
		if (aes_gcm_decrypt(&(key->u.aes_key), iv, ivlen, aad, aadlen,  in, inlen, tag, taglen, out) != 1) {
			error_print();
			return -1;
		}
	}
	return 1;
}
