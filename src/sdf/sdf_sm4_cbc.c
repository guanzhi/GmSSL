/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <gmssl/sdf.h>
#include <gmssl/sm4.h>
#include <gmssl/mem.h>
#include <gmssl/error.h>
#include "sdf.h"
#include "../sgd.h"


extern void *globalDeviceHandle;


typedef struct {
	void *hSession;
	void *hKey;
} SDF_SM4_KEY;


static int sdf_sm4_cbc_encrypt_blocks(SDF_SM4_KEY *key,
	const uint8_t iv[16], const uint8_t *in, size_t inlen, uint8_t *out)
{
	unsigned int outlen;
	int ret;

	if ((ret = SDF_Encrypt(key->hSession, key->hKey, SGD_SM4_CBC,
		(unsigned char *)iv, (unsigned char *)in, (unsigned int)inlen, out, &outlen)) != SDR_OK) {
		error_print();
		return -1;
	}
	return 1;
}

static int sdf_sm4_cbc_decrypt_blocks(SDF_SM4_KEY *key,
	const uint8_t iv[16], const uint8_t *in, size_t inlen, uint8_t *out)
{
	unsigned int outlen;
	int ret;

	if ((ret = SDF_Decrypt(key->hSession, key->hKey, SGD_SM4_CBC,
		(unsigned char *)iv, (unsigned char *)in, (unsigned int)inlen, out, &outlen)) != SDR_OK) {
		error_print();
		return -1;
	}
	return 1;
}

static int sdf_sm4_cbc_padding_encrypt(SDF_SM4_KEY *key,
	const uint8_t iv[16], const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen)
{
	uint8_t block[16];
	size_t rem = inlen % 16;
	int padding = 16 - inlen % 16;

	if (in) {
		memcpy(block, in + inlen - rem, rem);
	}
	memset(block + rem, padding, padding);
	if (inlen/16) {
		if (sdf_sm4_cbc_encrypt_blocks(key, iv, in, inlen/16, out) != 1) {
			error_print();
			return -1;
		}
		out += inlen - rem;
		iv = out - 16;
	}
	if (sdf_sm4_cbc_encrypt_blocks(key, iv, block, 1, out) != 1) {
		error_print();
		return -1;
	}
	*outlen = inlen - rem + 16;
	return 1;
}

static int sdf_sm4_cbc_padding_decrypt(SDF_SM4_KEY *key,
	const uint8_t iv[16], const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen)
{
	uint8_t block[16];
	size_t len = sizeof(block);
	int padding;

	if (inlen == 0) {
		error_puts("warning: input lenght = 0");
		return 0;
	}
	if (inlen%16 != 0 || inlen < 16) {
		error_puts("invalid cbc ciphertext length");
		return -1;
	}
	if (inlen > 16) {
		if (sdf_sm4_cbc_decrypt_blocks(key, iv, in, inlen/16 - 1, out) != 1) {
			error_print();
			return -1;
		}
		iv = in + inlen - 32;
	}
	if (sdf_sm4_cbc_decrypt_blocks(key, iv, in + inlen - 16, 1, block) != 1) {
		error_print();
		return -1;
	}

	padding = block[15];
	if (padding < 1 || padding > 16) {
		error_print();
		return -1;
	}
	len -= padding;
	memcpy(out + inlen - 16, block, len);
	*outlen = inlen - padding;
	return 1;
}

int sm4_cbc_encrypt_init(SM4_CBC_CTX *ctx,
	const uint8_t key[SM4_BLOCK_SIZE], const uint8_t iv[SM4_BLOCK_SIZE])
{
	SDF_SM4_KEY *sdf_sm4_key = (SDF_SM4_KEY *)&ctx->sm4_key;
	void *hSession = NULL;
	void *hKey = NULL;
	unsigned int uiIPKIndex = 1;
	ECCCipher eccCipher;
	int ret;

	if (!ctx || !key || !iv) {
		error_print();
		return -1;
	}

	// OpenDevice
	if (globalDeviceHandle == NULL) {
		if ((ret = SDF_OpenDevice(&globalDeviceHandle)) != SDR_OK) {
			error_print_msg("SDFerror: 0x%08X\n", ret);
			return -1;
		}
		if (globalDeviceHandle == NULL) {
			error_print();
			return -1;
		}
	}

	if ((ret = SDF_OpenSession(globalDeviceHandle, &hSession)) != SDR_OK) {
		error_print_msg("SDFerror: 0x%08X\n", ret);
		return -1;
	}

	// ImportKey
	ret = SDF_InternalEncrypt_ECC(hSession, uiIPKIndex, SGD_SM2_3, (unsigned char *)key, 16, &eccCipher);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	ret = SDF_ImportKeyWithISK_ECC(hSession, uiIPKIndex, &eccCipher, &hKey);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	// save hSession and hKey into CTX
	sdf_sm4_key->hSession = hSession;
	sdf_sm4_key->hKey = hKey;
	memcpy(ctx->iv, iv, SM4_BLOCK_SIZE);
	memset(ctx->block, 0, SM4_BLOCK_SIZE);
	ctx->block_nbytes = 0;
	return 1;
}

int sm4_cbc_encrypt_update(SM4_CBC_CTX *ctx,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	SDF_SM4_KEY *sdf_sm4_key = (SDF_SM4_KEY *)&ctx->sm4_key;
	size_t left;
	size_t nblocks;
	size_t len;

	if (!ctx || !in || !out || !outlen) {
		error_print();
		return -1;
	}
	if (ctx->block_nbytes >= SM4_BLOCK_SIZE) {
		error_print();
		return -1;
	}
	*outlen = 0;
	if (ctx->block_nbytes) {
		left = SM4_BLOCK_SIZE - ctx->block_nbytes;
		if (inlen < left) {
			memcpy(ctx->block + ctx->block_nbytes, in, inlen);
			ctx->block_nbytes += inlen;
			return 1;
		}
		memcpy(ctx->block + ctx->block_nbytes, in, left);
		if (sdf_sm4_cbc_encrypt_blocks(sdf_sm4_key, ctx->iv, ctx->block, 1, out) != 1) {
			error_print();
			return -1;
		}
		memcpy(ctx->iv, out, SM4_BLOCK_SIZE);
		in += left;
		inlen -= left;
		out += SM4_BLOCK_SIZE;
		*outlen += SM4_BLOCK_SIZE;
	}
	if (inlen >= SM4_BLOCK_SIZE) {
		nblocks = inlen / SM4_BLOCK_SIZE;
		len = nblocks * SM4_BLOCK_SIZE;
		if (sdf_sm4_cbc_encrypt_blocks(sdf_sm4_key, ctx->iv, in, nblocks, out) != 1) {
			error_print();
			return -1;
		}
		memcpy(ctx->iv, out + len - SM4_BLOCK_SIZE, SM4_BLOCK_SIZE);
		in += len;
		inlen -= len;
		out += len;
		*outlen += len;
	}
	if (inlen) {
		memcpy(ctx->block, in, inlen);
	}
	ctx->block_nbytes = inlen;
	return 1;
}

int sm4_cbc_encrypt_finish(SM4_CBC_CTX *ctx, uint8_t *out, size_t *outlen)
{
	SDF_SM4_KEY *sdf_sm4_key = (SDF_SM4_KEY *)&ctx->sm4_key;

	if (!ctx || !out || !outlen) {
		error_print();
		return -1;
	}
	if (ctx->block_nbytes >= SM4_BLOCK_SIZE) {
		error_print();
		return -1;
	}
	if (sdf_sm4_cbc_padding_encrypt(sdf_sm4_key, ctx->iv, ctx->block, ctx->block_nbytes, out, outlen) != 1) {
		error_print();
		return -1;
	}

	SDF_CloseSession(sdf_sm4_key->hSession);
	return 1;
}

// for SDF, encrypt/decrypt_init no difference
int sm4_cbc_decrypt_init(SM4_CBC_CTX *ctx,
	const uint8_t key[SM4_BLOCK_SIZE], const uint8_t iv[SM4_BLOCK_SIZE])
{
	if (sm4_cbc_encrypt_init(ctx, key, iv) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm4_cbc_decrypt_update(SM4_CBC_CTX *ctx,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	SDF_SM4_KEY *sdf_sm4_key = (SDF_SM4_KEY *)&ctx->sm4_key;
	size_t left, len, nblocks;

	if (!ctx || !in || !out || !outlen) {
		error_print();
		return -1;
	}
	if (ctx->block_nbytes > SM4_BLOCK_SIZE) {
		error_print();
		return -1;
	}

	*outlen = 0;
	if (ctx->block_nbytes) {
		left = SM4_BLOCK_SIZE - ctx->block_nbytes;
		if (inlen <= left) {
			memcpy(ctx->block + ctx->block_nbytes, in, inlen);
			ctx->block_nbytes += inlen;
			return 1;
		}
		memcpy(ctx->block + ctx->block_nbytes, in, left);
		if (sdf_sm4_cbc_decrypt_blocks(sdf_sm4_key, ctx->iv, ctx->block, 1, out) != 1) {
			error_print();
			return -1;
		}
		memcpy(ctx->iv, ctx->block, SM4_BLOCK_SIZE);
		in += left;
		inlen -= left;
		out += SM4_BLOCK_SIZE;
		*outlen += SM4_BLOCK_SIZE;
	}
	if (inlen > SM4_BLOCK_SIZE) {
		nblocks = (inlen-1) / SM4_BLOCK_SIZE;
		len = nblocks * SM4_BLOCK_SIZE;
		if (sdf_sm4_cbc_decrypt_blocks(sdf_sm4_key, ctx->iv, in, nblocks, out) != 1) {
			error_print();
			return -1;
		}
		memcpy(ctx->iv, in + len - SM4_BLOCK_SIZE, SM4_BLOCK_SIZE);
		in += len;
		inlen -= len;
		out += len;
		*outlen += len;
	}
	memcpy(ctx->block, in, inlen);
	ctx->block_nbytes = inlen;
	return 1;
}

int sm4_cbc_decrypt_finish(SM4_CBC_CTX *ctx, uint8_t *out, size_t *outlen)
{
	SDF_SM4_KEY *sdf_sm4_key = (SDF_SM4_KEY *)&ctx->sm4_key;

	if (!ctx || !out || !outlen) {
		error_print();
		return -1;
	}
	if (ctx->block_nbytes != SM4_BLOCK_SIZE) {
		error_print();
		return -1;
	}
	if (sdf_sm4_cbc_padding_decrypt(sdf_sm4_key, ctx->iv, ctx->block, SM4_BLOCK_SIZE, out, outlen) != 1) {
		error_print();
		return -1;
	}

	SDF_CloseSession(sdf_sm4_key->hSession);
	return 1;
}






























// copy from src/sm4_cbc.c

int sm4_cbc_padding_encrypt(const SM4_KEY *key, const uint8_t iv[16],
	const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen)
{
	uint8_t block[16];
	size_t rem = inlen % 16;
	int padding = 16 - inlen % 16;

	if (in) {
		memcpy(block, in + inlen - rem, rem);
	}
	memset(block + rem, padding, padding);
	if (inlen/16) {
		sm4_cbc_encrypt_blocks(key, iv, in, inlen/16, out);
		out += inlen - rem;
		iv = out - 16;
	}
	sm4_cbc_encrypt_blocks(key, iv, block, 1, out);
	*outlen = inlen - rem + 16;
	return 1;
}

int sm4_cbc_padding_decrypt(const SM4_KEY *key, const uint8_t iv[16],
	const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen)
{
	uint8_t block[16];
	size_t len = sizeof(block);
	int padding;

	if (inlen == 0) {
		error_puts("warning: input lenght = 0");
		return 0;
	}
	if (inlen%16 != 0 || inlen < 16) {
		error_puts("invalid cbc ciphertext length");
		return -1;
	}
	if (inlen > 16) {
		sm4_cbc_decrypt_blocks(key, iv, in, inlen/16 - 1, out);
		iv = in + inlen - 32;
	}
	sm4_cbc_decrypt_blocks(key, iv, in + inlen - 16, 1, block);

	padding = block[15];
	if (padding < 1 || padding > 16) {
		error_print();
		return -1;
	}
	len -= padding;
	memcpy(out + inlen - 16, block, len);
	*outlen = inlen - padding;
	return 1;
}




