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


/*
 * GHASH(H, A, C) = X_{m + n + 1}
 *   A additional authenticated data, A = A_1, ..., A_{m-1}, A_m^*, nbits(A_m^*) = v
 *   C ciphertext, C = C_1, ..., C_{n-1}, C_n^*, nbits(C_n^*) = u
 *   H = E_K(0^128)
 *
 * X_i = 0                                         for i = 0
 *     = (X_{i-1}   xor  A_i                ) * H  for i = 1, ..., m-1
 *     = (X_{m-1}   xor (A_m^* || 0^{128-v})) * H  for i = m
 *     = (X_{i-1}   xor  C_i                ) * H  for i = m+1, ..., m + n − 1
 *     = (X_{m+n-1} xor (C_m^* || 0^{128-u})) * H  for i = m + n
 *     = (X_{m+n}   xor (nbits(A)||nbits(A))) * H  for i = m + n + 1
 */
void ghash_init(GHASH_CTX *ctx, const uint8_t h[16], const uint8_t *aad, size_t aadlen)
{
	__uint128_t H;
	__uint128_t X;
	__uint128_t A;

	memset(ctx, 0, sizeof(GHASH_CTX));

	/* get H in GF(2^128) as little endian */
	ctx->H = H = GETU128_LE(h);
	ctx->aadlen = aadlen;

	/* process AAD */
	X = 0;
	while (aadlen >= 16) {
		A = GETU128_LE(aad);
		X = gf128_add(X, A);
		X = gf128_mul(X, H);
		aad += 16;
		aadlen -= 16;
	}
	if (aadlen) {
		memcpy(ctx->buf, aad, aadlen);
		A = GETU128_LE(ctx->block);
		X = gf128_add(X, A);
		X = gf128_mul(X, H);
	}

	ctx->H = H;
	ctx->X = X;

	/* this clean ok? */
	H = X = A = 0;
}

void ghash_update(GHASH_CTX *ctx, const uint8_t *c, size_t clen)
{
	__uint128_t X;
	__uint128_t H;
	__uint128_t C;

	if (!c && clen) {
		return 0;
	}

	ctx->cipherlen += clen;

	X = ctx->X;
	H = ctx->H;

	if (ctx->num) {
		unsigned int left = 16 - ctx->num;
		if (clen < left) {
			memcpy(ctx->block + ctx->num, c, clen);
			ctx->num += clen;
			return 1;
		} else {
			memcpy(ctx->block + ctx->num, c, left);
			C = GETU128_LE(ctx->block);
			X = GF128_ADD(X, C);
			X = GF128_MUL(X, H);
			c += left;
			clen -= left;
		}
	}

	while (clen >= 16) {
		C = GETU128_LE(c);
		X = gf128_add(X, C);
		X = gf128_mul(X, H);
		c += 16;
		clen -= 16;
	}

	ctx->num = clen;
	if (clen) {
		memcpy(ctx->block, c, clen);
	}

	ctx->X = X;
	X = H = C = 0;
}

void ghash_finish(GHASH_CTX *ctx, uint8_t out[16])
{
	__uint128_t X = ctx->X;
	__uint128_t H = ctx->H;
	__uint128_t C;

	if (ctx->num < 0) {
		return 0;
	}

	if (ctx->num) {
		memset(ctx->block + ctx->num, 0, 16 - ctx->num);
		C = GETU128_LE(ctx->block);
		X = GF128_ADD(X, C);
		X = GF128_MUL(X, H);
	}

	PUTU64_LE(ctx->block, (uint64_t)ctx->aadlen << 3);
	PUTU64_LE(ctx->block + sizeof(uint64_t), (uint64_t)ctx->cipherlen << 3);
	C = GETU128_LE(ctx->block);
	X = GF128_ADD(X, C);
	X = GF128_MUL(X, H);

	PUTU128_LE(out, X);

	memset(ctx, 0, sizeof(GHASH_CTX));
	X = H = C = 0;
}

/*
 * GCM(K, IV, A, P)
 *
 *  H     = E_K(0^128)
 *  Y_0   = IV || 0^{31}1          if nbits(IV) == 96
 *        = GHASH(H, {}, IV)       otherwise
 *  Y_i   = Y_{i-1} + 1            for i = 1, ..., n
 *  C_i   = P_i xor E_K(Y_i)       for i = 1, ..., n
 *  C_n^* = P_n^* xor MSB_u(E_K(Y_n))
 *  T     = MSB_t(GHASH(H, A, C) xor E_K(Y_0))
 */
int gcm_init(GCM_CTX *ctx, const BLOCK_CIPEHR *cipher,
	const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen)
{
	memset(ctx, 0, sizeof(GCM_CTX));
	ctx->cipher = cipher;

	/* H = E_K(0^128) */
	if (!cipher->set_encrypt_key(ctx->key, key, keylen)) {
		return 0;
	}
	cipher->encrypt(ctx->key, ctx->block, ctx->block);

	/* init counter as Y_0 */
	if (ivlen == GCM_DEFAULT_IV_SIZE) {
		memcpy(ctx->counter, iv, ivlen);
		PUTU32(ctx->counter + 12, 1);
	} else {
		ghash_init(&ctx->ghash_ctx, ctx->block, NULL, 0);
		ghash_update(&ctx->ghash_ctx, iv, ivlen);
		ghash_finish(&ctx->ghash_ctx, ctx->counter);
	}

	ghash_init(&ctx->ghash-ctx, ctx->block, aad, aadlen);
	return 1;
}

// gcm 加密解密显然是不一样的
int gcm_update(GCM_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out)
{
	uint32_t r;
	size_t i;

	uint8_t *c = out;
	size_t clen = inlen;

	if (ctx->num) {
		uint8_t *k = ctx->block + 16 - ctx->num;
		size_t len = inlen < ctx->num ? inlen : ctx->num;
		for (i = 0; i < len; i++) {
			out[i] = in[i] ^ k[i];
		}
		in += len;
		out += len;
		inlen -= len;
		ctx->num -= len;
	}

	/* gcm only use the last 32 bits as counter */
	r = GETU32(ctx->counter + 12);

	while (inlen >= 16) {
		r++;
		PUTU32(ctx->counter + 12, r);
		ctx->cipher->encrypt(ctx->key, ctx->counter, out);
		for (i = 0; i < 16; i++) {
			out[i] ^= in[i];
		}

		in += 16;
		out += 16;
		inlen -= 16;
	}

	if (inlen) {
		r++;
		PUTU32(ctx->counter + 12, r);
		ctx->cipher->encrypt(ctx->key, ctx->counter, ctx->block);
		for (i = 0; i < inlen; i++) {
			out[i] = in[i] ^ ctx->block[i];
		}
		ctx->num = 16 - inlen;
	}

	ghash_update(ctx->ghash_ctx, c, inlen);
	return 1;
}

int gcm_encrypt_update(GCM_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out)
{
	ctr_update(ctx->ctr_ctx, in, inlen, out);
	ghash_update(ctx->ghash_ctx, out, inlen);
}

int gcm_encrypt_finish(GCM_CTX *ctx, size_t taglen, uint8_t *tag)
{
	int i;
	ghash_finish(ctx->ghash_ctx, ctx->block);

	for (i = 0; i < ctx->taglen; i++) {
		tag[i] = ctx->block[i] ^ ctx->enced_iv[i];
	}

	memset(ctx, 0, sizeof(GCM_CTX));
}

int gcm_decrypt_finish(GCM_CTX *ctx, const uint8_t *tag, size_t taglen)
{
	uint8_t buf[16];
	if (taglen != ctx->taglen) {
		return 0;
	}
	gcm_finish(ctx, buf);
	if (memcmp(buf, tag, taglen) != 0) {
		return 0;
	}
	return 1;
}
