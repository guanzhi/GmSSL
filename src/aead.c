/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/sm4.h>
#include <gmssl/mem.h>
#include <gmssl/aead.h>
#include <gmssl/error.h>


int sm4_cbc_sm3_hmac_encrypt_init(SM4_CBC_SM3_HMAC_CTX *ctx,
	const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen)
{
	if (!ctx || !key || !iv || (!aad && aadlen)) {
		error_print();
		return -1;
	}
	if (keylen != 48 || ivlen != 16) {
		error_print();
		return -1;
	}
	memset(ctx, 0, sizeof(*ctx));
	if (sm4_cbc_encrypt_init(&ctx->enc_ctx, key, iv) != 1) {
		error_print();
		return -1;
	}
	sm3_hmac_init(&ctx->mac_ctx, key + SM4_KEY_SIZE, SM3_HMAC_SIZE);
	if (aad && aadlen) {
		sm3_hmac_update(&ctx->mac_ctx, aad, aadlen);
	}
	return 1;
}

int sm4_cbc_sm3_hmac_encrypt_update(SM4_CBC_SM3_HMAC_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	if (!ctx || !in || !out || !outlen) {
		error_print();
		return -1;
	}
	if (sm4_cbc_encrypt_update(&ctx->enc_ctx, in, inlen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	sm3_hmac_update(&ctx->mac_ctx, out, *outlen);
	return 1;
}

int sm4_cbc_sm3_hmac_encrypt_finish(SM4_CBC_SM3_HMAC_CTX *ctx, uint8_t *out, size_t *outlen)
{
	if (!ctx || !out || !outlen) {
		error_print();
		return -1;
	}
	if (sm4_cbc_encrypt_finish(&ctx->enc_ctx, out, outlen) != 1) {
		error_print();
		return -1;
	}
	sm3_hmac_update(&ctx->mac_ctx, out, *outlen);
	sm3_hmac_finish(&ctx->mac_ctx, out + *outlen);
	*outlen += SM3_HMAC_SIZE;
	return 1;
}

int sm4_cbc_sm3_hmac_decrypt_init(SM4_CBC_SM3_HMAC_CTX *ctx,
	const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen)
{
	if (!ctx || !key || !iv || (!aad && aadlen)) {
		error_print();
		return -1;
	}
	if (keylen != 48 || ivlen != 16) {
		error_print();
		return -1;
	}
	memset(ctx, 0, sizeof(*ctx));
	if (sm4_cbc_decrypt_init(&ctx->enc_ctx, key, iv) != 1) {
		error_print();
		return -1;
	}
	sm3_hmac_init(&ctx->mac_ctx, key + SM4_KEY_SIZE, SM3_HMAC_SIZE);
	if (aad && aadlen) {
		sm3_hmac_update(&ctx->mac_ctx, aad, aadlen);
	}
	return 1;
}

int sm4_cbc_sm3_hmac_decrypt_update(SM4_CBC_SM3_HMAC_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	size_t len;

	if (!ctx || !in || !out || !outlen) {
		error_print();
		return -1;
	}
	if (ctx->maclen > SM3_HMAC_SIZE) {
		error_print();
		return -1;
	}

	if (ctx->maclen < SM3_HMAC_SIZE) {
		len = SM3_HMAC_SIZE - ctx->maclen;
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

	if (inlen <= SM3_HMAC_SIZE) {
		uint8_t tmp[SM3_HMAC_SIZE];
		sm3_hmac_update(&ctx->mac_ctx, ctx->mac, inlen);
		if (sm4_cbc_decrypt_update(&ctx->enc_ctx, ctx->mac, inlen, out, outlen) != 1) {
			error_print();
			return -1;
		}
		len = SM3_HMAC_SIZE - inlen;
		memcpy(tmp, ctx->mac + inlen, len);
		memcpy(tmp + len, in, inlen);
		memcpy(ctx->mac, tmp, SM3_HMAC_SIZE);
	} else {
		sm3_hmac_update(&ctx->mac_ctx, ctx->mac, SM3_HMAC_SIZE);
		if (sm4_cbc_decrypt_update(&ctx->enc_ctx, ctx->mac, SM3_HMAC_SIZE, out, outlen) != 1) {
			error_print();
			return -1;
		}
		out += *outlen;

		inlen -= SM3_HMAC_SIZE;
		sm3_hmac_update(&ctx->mac_ctx, in, inlen);
		if (sm4_cbc_decrypt_update(&ctx->enc_ctx, in, inlen, out, &len) != 1) {
			error_print();
			return -1;
		}
		*outlen += len;
		memcpy(ctx->mac, in + inlen, SM3_HMAC_SIZE);
	}
	return 1;
}

int sm4_cbc_sm3_hmac_decrypt_finish(SM4_CBC_SM3_HMAC_CTX *ctx, uint8_t *out, size_t *outlen)
{
	uint8_t mac[SM3_HMAC_SIZE];

	if (!ctx || !out || !outlen) {
		error_print();
		return -1;
	}
	if (ctx->maclen != SM3_HMAC_SIZE) {
		error_print();
		return -1;
	}
	sm3_hmac_finish(&ctx->mac_ctx, mac);
	if (sm4_cbc_decrypt_finish(&ctx->enc_ctx, out, outlen) != 1) {
		error_print();
		return -1;
	}
	if (memcmp(mac, ctx->mac, SM3_HMAC_SIZE) != 0) {
		error_print();
		return -1;
	}
	memset(ctx->mac, 0, SM3_HMAC_SIZE);
	ctx->maclen = 0;
	return 1;
}

int sm4_ctr_sm3_hmac_encrypt_init(SM4_CTR_SM3_HMAC_CTX *ctx,
	const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen)
{
	if (!ctx || !key || !iv || (!aad && aadlen)) {
		error_print();
		return -1;
	}
	if (keylen != 48 || ivlen != 16) {
		error_print();
		return -1;
	}
	memset(ctx, 0, sizeof(*ctx));
	if (sm4_ctr_encrypt_init(&ctx->enc_ctx, key, iv) != 1) {
		error_print();
		return -1;
	}
	sm3_hmac_init(&ctx->mac_ctx, key + SM4_KEY_SIZE, SM3_HMAC_SIZE);
	if (aad && aadlen) {
		sm3_hmac_update(&ctx->mac_ctx, aad, aadlen);
	}
	return 1;
}

int sm4_ctr_sm3_hmac_encrypt_update(SM4_CTR_SM3_HMAC_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	if (!ctx || !in || !out || !outlen) {
		error_print();
		return -1;
	}
	if (sm4_ctr_encrypt_update(&ctx->enc_ctx, in, inlen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	sm3_hmac_update(&ctx->mac_ctx, out, *outlen);
	return 1;
}

int sm4_ctr_sm3_hmac_encrypt_finish(SM4_CTR_SM3_HMAC_CTX *ctx, uint8_t *out, size_t *outlen)
{
	if (!ctx || !out  || !outlen) {
		error_print();
		return -1;
	}
	if (sm4_ctr_encrypt_finish(&ctx->enc_ctx, out, outlen) != 1) {
		error_print();
		return -1;
	}
	sm3_hmac_update(&ctx->mac_ctx, out, *outlen);
	sm3_hmac_finish(&ctx->mac_ctx, out + *outlen);
	*outlen += SM3_HMAC_SIZE;
	return 1;
}

int sm4_ctr_sm3_hmac_decrypt_init(SM4_CTR_SM3_HMAC_CTX *ctx,
	const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen)
{
	if (!ctx || !key || !iv || (!aad && aadlen)) {
		error_print();
		return -1;
	}
	if (keylen != 48 || ivlen != 16) {
		error_print();
		return -1;
	}
	memset(ctx, 0, sizeof(*ctx));
	if (sm4_ctr_decrypt_init(&ctx->enc_ctx, key, iv) != 1) {
		error_print();
		return -1;
	}
	sm3_hmac_init(&ctx->mac_ctx, key + SM4_KEY_SIZE, SM3_HMAC_SIZE);
	if (aad && aadlen) {
		sm3_hmac_update(&ctx->mac_ctx, aad, aadlen);
	}
	return 1;
}

int sm4_ctr_sm3_hmac_decrypt_update(SM4_CTR_SM3_HMAC_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	size_t len;

	if (!ctx || !in || !out || !outlen) {
		error_print();
		return -1;
	}
	if (ctx->maclen > SM3_HMAC_SIZE) {
		error_print();
		return -1;
	}

	if (ctx->maclen < SM3_HMAC_SIZE) {
		len = SM3_HMAC_SIZE - ctx->maclen;
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

	if (inlen <= SM3_HMAC_SIZE) {
		uint8_t tmp[SM3_HMAC_SIZE];
		sm3_hmac_update(&ctx->mac_ctx, ctx->mac, inlen);
		if (sm4_ctr_decrypt_update(&ctx->enc_ctx, ctx->mac, inlen, out, outlen) != 1) {
			error_print();
			return -1;
		}
		len = SM3_HMAC_SIZE - inlen;
		memcpy(tmp, ctx->mac + inlen, len);
		memcpy(tmp + len, in, inlen);
		memcpy(ctx->mac, tmp, SM3_HMAC_SIZE);
	} else {
		sm3_hmac_update(&ctx->mac_ctx, ctx->mac, SM3_HMAC_SIZE);
		if (sm4_ctr_decrypt_update(&ctx->enc_ctx, ctx->mac, SM3_HMAC_SIZE, out, outlen) != 1) {
			error_print();
			return -1;
		}
		out += *outlen;

		inlen -= SM3_HMAC_SIZE;
		sm3_hmac_update(&ctx->mac_ctx, in, inlen);
		if (sm4_ctr_decrypt_update(&ctx->enc_ctx, in, inlen, out, &len) != 1) {
			error_print();
			return -1;
		}
		*outlen += len;
		memcpy(ctx->mac, in + inlen, SM3_HMAC_SIZE);
	}
	return 1;
}

int sm4_ctr_sm3_hmac_decrypt_finish(SM4_CTR_SM3_HMAC_CTX *ctx, uint8_t *out, size_t *outlen)
{
	uint8_t mac[SM3_HMAC_SIZE];

	if (!ctx || !out || !outlen) {
		error_print();
		return -1;
	}
	if (ctx->maclen != SM3_HMAC_SIZE) {
		error_print();
		return -1;
	}
	sm3_hmac_finish(&ctx->mac_ctx, mac);
	if (sm4_ctr_decrypt_finish(&ctx->enc_ctx, out, outlen) != 1) {
		error_print();
		return -1;
	}
	if (memcmp(mac, ctx->mac, SM3_HMAC_SIZE) != 0) {
		error_print();
		return -1;
	}
	memset(ctx->mac, 0, SM3_HMAC_SIZE);
	ctx->maclen = 0;
	return 1;
}

static void ctr_incr(uint8_t a[16])
{
	int i;
	for (i = 15; i >= 0; i--) {
		a[i]++;
		if (a[i]) break;
	}
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
	if (taglen < 8 || taglen > 16) {
		error_print();
		return -1;
	}

	memset(ctx, 0, sizeof(*ctx));
	ctx->taglen = taglen;

	if (sm4_ctr_encrypt_init(&ctx->enc_ctx, key, H) != 1) {
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

	ctr_incr(Y);
	memcpy(ctx->enc_ctx.ctr, Y, 16);

	gmssl_secure_clear(H, sizeof(H));
	gmssl_secure_clear(Y, sizeof(Y));
	return 1;
}

int sm4_gcm_encrypt_update(SM4_GCM_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	if (!ctx || !in || !out || !outlen) {
		error_print();
		return -1;
	}
	if (sm4_ctr_encrypt_update(&ctx->enc_ctx, in, inlen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	ghash_update(&ctx->mac_ctx, out, *outlen);
	return 1;
}

int sm4_gcm_encrypt_finish(SM4_GCM_CTX *ctx, uint8_t *out, size_t *outlen)
{
	uint8_t mac[16];

	if (!ctx || !out || !outlen) {
		error_print();
		return -1;
	}
	if (sm4_ctr_encrypt_finish(&ctx->enc_ctx, out, outlen) != 1) {
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

	if (!ctx || !in || !out || !outlen) {
		error_print();
		return -1;
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
		if (sm4_ctr_decrypt_update(&ctx->enc_ctx, ctx->mac, inlen, out, outlen) != 1) {
			error_print();
			return -1;
		}
		len = ctx->taglen - inlen;
		memcpy(tmp, ctx->mac + inlen, len);
		memcpy(tmp + len, in, inlen);
		memcpy(ctx->mac, tmp, GHASH_SIZE);
	} else {
		ghash_update(&ctx->mac_ctx, ctx->mac, ctx->taglen);
		if (sm4_ctr_decrypt_update(&ctx->enc_ctx, ctx->mac, ctx->taglen, out, outlen) != 1) {
			error_print();
			return -1;
		}
		out += *outlen;

		inlen -= ctx->taglen;
		ghash_update(&ctx->mac_ctx, in, inlen);
		if (sm4_ctr_decrypt_update(&ctx->enc_ctx, in, inlen, out, &len) != 1) {
			error_print();
			return -1;
		}
		*outlen += len;
		memcpy(ctx->mac, in + inlen, GHASH_SIZE);
	}
	return 1;
}

int sm4_gcm_decrypt_finish(SM4_GCM_CTX *ctx, uint8_t *out, size_t *outlen)
{
	uint8_t mac[GHASH_SIZE];

	if (!ctx || !out || !outlen) {
		error_print();
		return -1;
	}
	if (ctx->maclen != ctx->taglen) {
		error_print();
		return -1;
	}
	ghash_finish(&ctx->mac_ctx, mac);
	if (sm4_ctr_decrypt_finish(&ctx->enc_ctx, out, outlen) != 1) {
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
