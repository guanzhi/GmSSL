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
#include <assert.h>
#include <gmssl/mem.h>
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


void ghash_init(GHASH_CTX *ctx, const uint8_t h[16], const uint8_t *aad, size_t aadlen)
{
	gf128_t A;

	memset(ctx, 0, sizeof(*ctx));
	ctx->H = gf128_from_bytes(h);
	ctx->X = gf128_zero();
	ctx->aadlen = aadlen;
	ctx->clen = 0;

	while (aadlen) {
		if (aadlen >= 16) {
			A = gf128_from_bytes(aad);
			aad += 16;
			aadlen -= 16;
		} else {
			memset(ctx->block, 0, 16);
			memcpy(ctx->block, aad, aadlen);
			A = gf128_from_bytes(ctx->block);
			aadlen = 0;
		}
		ctx->X = gf128_add(ctx->X, A);
		ctx->X = gf128_mul(ctx->X, ctx->H);
	}
}

void ghash_update(GHASH_CTX *ctx, const uint8_t *c, size_t clen)
{
	gf128_t C;

	assert(ctx->num < 16);

	ctx->clen += clen;

	if (ctx->num) {
		size_t left = 16 - ctx->num;
		if (clen < left) {
			memcpy(ctx->block + ctx->num, c, clen);
			ctx->num += clen;
			return;
		} else {
			memcpy(ctx->block + ctx->num, c, left);
			C = gf128_from_bytes(ctx->block);
			ctx->X = gf128_add(ctx->X, C);
			ctx->X = gf128_mul(ctx->X, ctx->H);
			c += left;
			clen -= left;
		}
	}

	while (clen >= 16) {
		C = gf128_from_bytes(c);
		ctx->X = gf128_add(ctx->X, C);
		ctx->X = gf128_mul(ctx->X, ctx->H);
		c += 16;
		clen -= 16;
	}

	ctx->num = clen;
	if (clen) {
		memcpy(ctx->block, c, clen);
	}
}

void ghash_finish(GHASH_CTX *ctx, uint8_t out[16])
{
	gf128_t C;
	gf128_t L;

	if (ctx->num) {
		memset(ctx->block + ctx->num, 0, 16 - ctx->num);
		C = gf128_from_bytes(ctx->block);
		ctx->X = gf128_add(ctx->X, C);
		ctx->X = gf128_mul(ctx->X, ctx->H);
	}

	PUTU64(ctx->block, (uint64_t)ctx->aadlen << 3);
	PUTU64(ctx->block + 8, (uint64_t)ctx->clen << 3);
	L = gf128_from_bytes(ctx->block);

	ctx->X = gf128_add(ctx->X, L);
	ctx->H = gf128_mul(ctx->X, ctx->H);
	gf128_to_bytes(ctx->H, out);

	gmssl_secure_clear(ctx, sizeof(*ctx));
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
