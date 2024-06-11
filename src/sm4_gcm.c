/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <limits.h>
#include <gmssl/sm4.h>
#include <gmssl/mem.h>
#include <gmssl/ghash.h>
#include <gmssl/error.h>
#include <gmssl/endian.h>


// inc32() in nist-sp800-38d
static void ctr32_incr(uint8_t a[16])
{
	int i;
	for (i = 15; i >= 12; i--) {
		a[i]++;
		if (a[i]) break;
	}
}

int sm4_gcm_encrypt(const SM4_KEY *key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	uint8_t *out, size_t taglen, uint8_t *tag)
{
	uint8_t H[16] = {0};
	uint8_t Y[16];
	uint8_t T[16];

	if (ivlen < SM4_GCM_MIN_IV_SIZE || ivlen > SM4_GCM_MAX_IV_SIZE) {
		error_print();
		return -1;
	}
	if (taglen < SM4_GCM_MIN_TAG_SIZE || taglen > SM4_GCM_MAX_TAG_SIZE) {
		error_print();
		return -1;
	}
	if (inlen > SM4_GCM_MAX_PLAINTEXT_SIZE) {
		error_print();
		return -1;
	}

	sm4_encrypt(key, H, H);

	if (ivlen == 12) {
		memcpy(Y, iv, 12);
		Y[12] = Y[13] = Y[14] = 0;
		Y[15] = 1;
	} else {
		ghash(H, NULL, 0, iv, ivlen, Y);
	}

	sm4_encrypt(key, Y, T);

	ctr32_incr(Y);
	sm4_ctr32_encrypt(key, Y, in, inlen, out);

	ghash(H, aad, aadlen, out, inlen, H);
	gmssl_memxor(tag, T, H, taglen);

	return 1;
}

int sm4_gcm_decrypt(const SM4_KEY *key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	const uint8_t *tag, size_t taglen, uint8_t *out)
{
	uint8_t H[16] = {0};
	uint8_t Y[16];
	uint8_t T[16];

	if (ivlen < SM4_GCM_MIN_IV_SIZE || ivlen > SM4_GCM_MAX_IV_SIZE) {
		error_print();
		return -1;
	}
	if (taglen < SM4_GCM_MIN_TAG_SIZE || taglen > SM4_GCM_MAX_TAG_SIZE) {
		error_print();
		return -1;
	}
	if (inlen > SM4_GCM_MAX_PLAINTEXT_SIZE) {
		error_print();
		return -1;
	}

	sm4_encrypt(key, H, H);

	if (ivlen == 12) {
		memcpy(Y, iv, 12);
		Y[12] = Y[13] = Y[14] = 0;
		Y[15] = 1;
	} else {
		ghash(H, NULL, 0, iv, ivlen, Y);
	}

	ghash(H, aad, aadlen, in, inlen, H);

	sm4_encrypt(key, Y, T);
	gmssl_memxor(T, T, H, taglen);
	if (memcmp(T, tag, taglen) != 0) {
		error_print();
		return -1;
	}

	ctr32_incr(Y);
	sm4_ctr32_encrypt(key, Y, in, inlen, out);

	return 1;
}

int sm4_gcm_encrypt_init(SM4_GCM_CTX *ctx,
	const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, size_t taglen)
{
	uint8_t H[16] = {0};
	uint8_t Y[16];

	if (!ctx || !key || !iv || (!aad && aadlen)) {
		error_print();
		return -1;
	}
	if (keylen != 16) {
		error_print();
		return -1;
	}
	if (ivlen < SM4_GCM_MIN_IV_SIZE || ivlen > SM4_GCM_MAX_IV_SIZE) {
		error_print();
		return -1;
	}
	if (taglen < SM4_GCM_MIN_TAG_SIZE || taglen > SM4_GCM_MAX_TAG_SIZE) {
		error_print();
		return -1;
	}

	memset(ctx, 0, sizeof(*ctx));
	ctx->taglen = taglen;

	if (sm4_ctr32_encrypt_init(&ctx->enc_ctx, key, H) != 1) {
		error_print();
		return -1;
	}

	sm4_encrypt(&ctx->enc_ctx.sm4_key, H, H);

	ghash_init(&ctx->mac_ctx, H, aad, aadlen);

	if (ivlen == 12) {
		memcpy(Y, iv, 12);
		Y[12] = Y[13] = Y[14] = 0;
		Y[15] = 1;
	} else {
		ghash(H, NULL, 0, iv, ivlen, Y);
	}

	sm4_encrypt(&ctx->enc_ctx.sm4_key, Y, ctx->Y);

	ctr32_incr(Y);
	memcpy(ctx->enc_ctx.ctr, Y, 16);

	gmssl_secure_clear(H, sizeof(H));
	gmssl_secure_clear(Y, sizeof(Y));
	return 1;
}

int sm4_gcm_encrypt_update(SM4_GCM_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	if (!ctx || !in || !outlen) {
		error_print();
		return -1;
	}
	if (inlen > INT_MAX) {
		error_print();
		return -1;
	}
	if (inlen > SM4_GCM_MAX_PLAINTEXT_SIZE - ctx->encedlen) {
		error_print();
		return -1;
	}
	if (!out) {
		*outlen = 16 * ((inlen + 15)/16);
		return 1;
	}

	if (sm4_ctr32_encrypt_update(&ctx->enc_ctx, in, inlen, out, outlen) != 1) {
		error_print();
		return -1;
	}

	ghash_update(&ctx->mac_ctx, out, *outlen);

	ctx->encedlen += inlen;
	return 1;
}

int sm4_gcm_encrypt_finish(SM4_GCM_CTX *ctx, uint8_t *out, size_t *outlen)
{
	uint8_t mac[16];

	if (!ctx || !outlen) {
		error_print();
		return -1;
	}
	if (!out) {
		*outlen = SM4_BLOCK_SIZE * 2; // GCM output extra mac tag
		return 1;
	}
	if (sm4_ctr32_encrypt_finish(&ctx->enc_ctx, out, outlen) != 1) {
		error_print();
		return -1;
	}
	ghash_update(&ctx->mac_ctx, out, *outlen);
	ghash_finish(&ctx->mac_ctx, mac);

	gmssl_memxor(mac, mac, ctx->Y, ctx->taglen);
	memcpy(out + *outlen, mac, ctx->taglen);
	*outlen += ctx->taglen;

	return 1;
}

int sm4_gcm_decrypt_init(SM4_GCM_CTX *ctx,
	const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, size_t taglen)
{
	return sm4_gcm_encrypt_init(ctx, key, keylen, iv, ivlen, aad, aadlen, taglen);
}

int sm4_gcm_decrypt_update(SM4_GCM_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	size_t len;

	if (!ctx || !in || !outlen) {
		error_print();
		return -1;
	}
	if (inlen > INT_MAX) {
		error_print();
		return -1;
	}
	if (inlen > SM4_GCM_MAX_PLAINTEXT_SIZE - ctx->encedlen) {
		error_print();
		return -1;
	}

	if (!out) {
		*outlen = 16 * ((inlen + 15)/16);
		return 1;
	}
	if (ctx->maclen > ctx->taglen) {
		error_print();
		return -1;
	}

	if (ctx->maclen < ctx->taglen) {
		len = ctx->taglen - ctx->maclen;
		if (inlen <= len) {
			memcpy(ctx->mac + ctx->maclen, in, inlen);
			ctx->maclen += inlen;
			return 1;
		} else {
			memcpy(ctx->mac + ctx->maclen, in, len);
			ctx->maclen += len;
			in += len;
			inlen -= len;
		}
	}

	if (inlen <= ctx->taglen) {
		uint8_t tmp[GHASH_SIZE];
		ghash_update(&ctx->mac_ctx, ctx->mac, inlen);
		if (sm4_ctr32_encrypt_update(&ctx->enc_ctx, ctx->mac, inlen, out, outlen) != 1) {
			error_print();
			return -1;
		}
		len = ctx->taglen - inlen;
		memcpy(tmp, ctx->mac + inlen, len);
		memcpy(tmp + len, in, inlen);
		memcpy(ctx->mac, tmp, GHASH_SIZE);
	} else {
		ghash_update(&ctx->mac_ctx, ctx->mac, ctx->taglen);
		if (sm4_ctr32_encrypt_update(&ctx->enc_ctx, ctx->mac, ctx->taglen, out, outlen) != 1) {
			error_print();
			return -1;
		}
		out += *outlen;

		inlen -= ctx->taglen;
		ghash_update(&ctx->mac_ctx, in, inlen);
		if (sm4_ctr32_encrypt_update(&ctx->enc_ctx, in, inlen, out, &len) != 1) {
			error_print();
			return -1;
		}
		*outlen += len;
		memcpy(ctx->mac, in + inlen, GHASH_SIZE);
	}

	ctx->encedlen += inlen;
	return 1;
}

int sm4_gcm_decrypt_finish(SM4_GCM_CTX *ctx, uint8_t *out, size_t *outlen)
{
	uint8_t mac[GHASH_SIZE];

	if (!ctx || !outlen) {
		error_print();
		return -1;
	}
	if (!out) {
		*outlen = SM4_BLOCK_SIZE;
		return 1;
	}
	if (ctx->maclen != ctx->taglen) {
		error_print();
		return -1;
	}
	ghash_finish(&ctx->mac_ctx, mac);
	if (sm4_ctr32_encrypt_finish(&ctx->enc_ctx, out, outlen) != 1) {
		error_print();
		return -1;
	}

	gmssl_memxor(mac, mac, ctx->Y, ctx->taglen);
	if (memcmp(mac, ctx->mac, ctx->taglen) != 0) {
		error_print();
		return -1;
	}
	memset(ctx->mac, 0, GHASH_SIZE);
	ctx->maclen = 0;
	return 1;
}
