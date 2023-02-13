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
#include <gmssl/aead.h>
#include <gmssl/error.h>


int sm4_cbc_sm3_hmac_encrypt_init(SM4_CBC_SM3_HMAC_CTX *ctx,
	const uint8_t key[SM4_KEY_SIZE + SM3_HMAC_SIZE], const uint8_t iv[SM4_BLOCK_SIZE],
	const uint8_t *aad, size_t aadlen)
{
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
	if (sm4_cbc_encrypt_update(&ctx->enc_ctx, in, inlen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	sm3_hmac_update(&ctx->mac_ctx, out, *outlen);
	return 1;
}

int sm4_cbc_sm3_hmac_encrypt_finish(SM4_CBC_SM3_HMAC_CTX *ctx, uint8_t *out, size_t *outlen)
{
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
	const uint8_t key[SM4_KEY_SIZE + SM3_HMAC_SIZE], const uint8_t iv[SM4_BLOCK_SIZE],
	const uint8_t *aad, size_t aadlen)
{
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
			in += len;
			inlen -= len;
		}
	}

	if (inlen <= SM3_HMAC_SIZE) {
		sm3_hmac_update(&ctx->mac_ctx, ctx->mac, inlen);
		if (sm4_cbc_decrypt_update(&ctx->enc_ctx, ctx->mac, inlen, out, outlen) != 1) {
			error_print();
			return -1;
		}
		len = SM3_HMAC_SIZE - inlen;
		memcpy(ctx->mac, ctx->mac + inlen, len);
		memcpy(ctx->mac + len, in, inlen);
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
	return 1;
}

int sm4_ctr_sm3_hmac_encrypt_init(SM4_CTR_SM3_HMAC_CTX *ctx,
	const uint8_t key[SM4_KEY_SIZE + SM3_HMAC_SIZE], const uint8_t iv[SM4_BLOCK_SIZE],
	const uint8_t *aad, size_t aadlen)
{
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
	if (sm4_ctr_encrypt_update(&ctx->enc_ctx, in, inlen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	sm3_hmac_update(&ctx->mac_ctx, out, *outlen);
	return 1;
}

int sm4_ctr_sm3_hmac_encrypt_finish(SM4_CTR_SM3_HMAC_CTX *ctx, uint8_t *out, size_t *outlen)
{
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
	const uint8_t key[SM4_KEY_SIZE + SM3_HMAC_SIZE], const uint8_t iv[SM4_BLOCK_SIZE],
	const uint8_t *aad, size_t aadlen)
{
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
			in += len;
			inlen -= len;
		}
	}

	if (inlen <= SM3_HMAC_SIZE) {
		sm3_hmac_update(&ctx->mac_ctx, ctx->mac, inlen);
		if (sm4_ctr_decrypt_update(&ctx->enc_ctx, ctx->mac, inlen, out, outlen) != 1) {
			error_print();
			return -1;
		}
		len = SM3_HMAC_SIZE - inlen;
		memcpy(ctx->mac, ctx->mac + inlen, len);
		memcpy(ctx->mac + len, in, inlen);
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
	return 1;
}

int sm4_gcm_encrypt_init(SM4_GCM_CTX *ctx,
	const uint8_t key[SM4_KEY_SIZE], const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen)
{
	return -1;
}

int sm4_gcm_encrypt_update(SM4_GCM_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	return -1;
}

int sm4_gcm_encrypt_finish(SM4_GCM_CTX *ctx, uint8_t *out, size_t *outlen)
{
	return -1;
}

int sm4_gcm_decrypt_init(SM4_GCM_CTX *ctx,
	const uint8_t key[SM4_KEY_SIZE], const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen)
{
	return -1;
}

int sm4_gcm_decrypt_update(SM4_GCM_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	return -1;
}

int sm4_gcm_decrypt_finish(SM4_GCM_CTX *ctx, uint8_t *out, size_t *outlen)
{
	return -1;
}

int zuc_with_mac_encrypt_init(ZUC_WITH_MAC_CTX *ctx,
	const uint8_t key[ZUC_KEY_SIZE], const uint8_t iv[ZUC_IV_SIZE],
	const uint8_t *aad, size_t aadlen)
{
	return -1;
}

int zuc_with_mac_encrypt_update(ZUC_WITH_MAC_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	return -1;
}

int zuc_with_mac_encrypt_finish(ZUC_WITH_MAC_CTX *ctx, uint8_t *out, size_t *outlen)
{
	return -1;
}

int zuc_with_mac_decrypt_init(ZUC_WITH_MAC_CTX *ctx,
	const uint8_t key[ZUC_KEY_SIZE], const uint8_t iv[ZUC_IV_SIZE],
	const uint8_t *aad, size_t aadlen)
{
	return -1;
}

int zuc_with_mac_decrypt_update(ZUC_WITH_MAC_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	return -1;
}

int zuc_with_mac_decrypt_finish(ZUC_WITH_MAC_CTX *ctx, uint8_t *out, size_t *outlen)
{
	return -1;
}
