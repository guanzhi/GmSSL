/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/sdf.h>
#include <gmssl/sm2.h>
#include <gmssl/sm4.h>
#include <gmssl/error.h>
#include "sdf.h"
#include "sdf_ext.h"


static const uint8_t zeros[ECCref_MAX_LEN - 32] = {0};

static void ECCrefPublicKey_from_SM2_Z256_POINT(ECCrefPublicKey *ref, const SM2_Z256_POINT *z256_point)
{
	SM2_POINT point;
	sm2_z256_point_to_bytes(z256_point, (uint8_t *)&point);
	ref->bits = 256;
	memcpy(ref->x, zeros, sizeof(zeros));
	memcpy(ref->x + sizeof(zeros), point.x, 32);
	memcpy(ref->y, zeros, sizeof(zeros));
	memcpy(ref->y + sizeof(zeros), point.y, 32);
}

static int ECCrefPublicKey_to_SM2_Z256_POINT(const ECCrefPublicKey *ref, SM2_Z256_POINT *z256_point)
{
	SM2_POINT point;
	if (ref->bits != 256
		|| memcmp(ref->x, zeros, sizeof(zeros)) != 0
		|| memcmp(ref->y, zeros, sizeof(zeros)) != 0) {
		error_print();
		return -1;
	}
	memcpy(point.x, ref->x + sizeof(zeros), 32);
	memcpy(point.y, ref->y + sizeof(zeros), 32);
	if (sm2_z256_point_from_bytes(z256_point, (uint8_t *)&point) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

static void ECCSignature_from_SM2_SIGNATURE(ECCSignature *ref, const SM2_SIGNATURE *sig)
{
	memcpy(ref->r, zeros, sizeof(zeros));
	memcpy(ref->r + sizeof(zeros), sig->r, 32);
	memcpy(ref->s, zeros, sizeof(zeros));
	memcpy(ref->s + sizeof(zeros), sig->s, 32);
}

static int ECCSignature_to_SM2_SIGNATURE(const ECCSignature *ref, SM2_SIGNATURE *sig)
{
	if (memcmp(ref->r, zeros, sizeof(zeros)) != 0
		|| memcmp(ref->s, zeros, sizeof(zeros)) != 0) {
		error_print();
		return -1;
	}
	memcpy(sig->r, ref->r + sizeof(zeros), 32);
	memcpy(sig->s, ref->s + sizeof(zeros), 32);
	return 1;
}

static void ECCCipher_from_SM2_CIPHERTEXT(ECCCipher *eccCipher, const SM2_CIPHERTEXT *ciphertext)
{
	memcpy(eccCipher->x, zeros, sizeof(zeros));
	memcpy(eccCipher->x + sizeof(zeros), ciphertext->point.x, 32);
	memcpy(eccCipher->y, zeros, sizeof(zeros));
	memcpy(eccCipher->y + sizeof(zeros), ciphertext->point.y, 32);
	memcpy(eccCipher->M, ciphertext->hash, 32);
	memcpy(eccCipher->C, ciphertext->ciphertext, ciphertext->ciphertext_size);
	eccCipher->L = ciphertext->ciphertext_size;
}

static int ECCCipher_to_SM2_CIPHERTEXT(const ECCCipher *eccCipher, SM2_CIPHERTEXT *ciphertext)
{
	static const uint8_t zeros[ECCref_MAX_LEN - 32] = {0};
	if (eccCipher->L > SM2_MAX_PLAINTEXT_SIZE
		|| memcmp(eccCipher->x, zeros, sizeof(zeros)) != 0
		|| memcmp(eccCipher->y, zeros, sizeof(zeros)) != 0) {
		error_print();
		return -1;
	}
	memcpy(ciphertext->point.x, eccCipher->x + sizeof(zeros), 32);
	memcpy(ciphertext->point.y, eccCipher->y + sizeof(zeros), 32);
	memcpy(ciphertext->hash, eccCipher->M, 32);
	memcpy(ciphertext->ciphertext, eccCipher->C, eccCipher->L);
	ciphertext->ciphertext_size = eccCipher->L;
	return 1;
}




int sdf_load_library(const char *so_path, const char *vendor)
{
	if (SDF_LoadLibrary((char *)so_path, (char *)vendor) != SDR_OK) {
		error_print();
		return -1;
	}
	return 1;
}

void sdf_unload_library(void)
{
	SDF_UnloadLibrary();
}

int sdf_open_device(SDF_DEVICE *dev)
{
	int ret = -1;
	void *hDevice = NULL;
	void *hSession = NULL;
	DEVICEINFO devInfo;

	if (SDF_OpenDevice(&hDevice) != SDR_OK) {
		error_print();
		return -1;
	}
	if (SDF_OpenSession(hDevice, &hSession) != SDR_OK) {
		(void)SDF_CloseDevice(hDevice);
		error_print();
		return -1;
	}
	if (SDF_GetDeviceInfo(hSession, &devInfo) != SDR_OK) {
		(void)SDF_CloseSession(hSession);
		(void)SDF_CloseDevice(hDevice);
		error_print();
		return -1;
	}
	(void)SDF_CloseSession(hSession);

	memset(dev, 0, sizeof(SDF_DEVICE));
	dev->handle = hDevice;
	memcpy(dev->issuer, devInfo.IssuerName, 40);
	memcpy(dev->name, devInfo.DeviceName, 16);
	memcpy(dev->serial, devInfo.DeviceSerial, 16);
	return 1;
}

int sdf_print_device_info(FILE *fp, int fmt, int ind, const char *lable, SDF_DEVICE *dev)
{
	void *hSession = NULL;
	DEVICEINFO devInfo;

	if (SDF_OpenSession(dev->handle, &hSession) != SDR_OK) {
		error_print();
		return -1;
	}
	if (SDF_GetDeviceInfo(hSession, &devInfo) != SDR_OK) {
		(void)SDF_CloseSession(hSession);
		error_print();
		return -1;
	}
	(void)SDF_CloseSession(hSession);

	(void)SDF_PrintDeviceInfo(fp, &devInfo);
	return 1;
}

int sdf_digest_init(SDF_DIGEST_CTX *ctx, SDF_DEVICE *dev)
{
	void *hSession;
	int ret;

	if (!dev || !ctx) {
		error_print();
		return -1;
	}
	if (!dev->handle) {
		error_print();
		return -1;
	}
	if ((ret = SDF_OpenSession(dev->handle, &hSession)) != SDR_OK) {
		error_print();
		return -1;
	}
	if ((ret = SDF_HashInit(hSession, SGD_SM3, NULL, NULL, 0)) != SDR_OK) {
		(void)SDF_CloseSession(hSession);
		error_print();
		return -1;
	}
	ctx->session = hSession;
	return 1;
}

int sdf_digest_update(SDF_DIGEST_CTX *ctx, const uint8_t *data, size_t datalen)
{
	int ret;

	if (!ctx) {
		error_print();
		return -1;
	}
	if (!ctx->session) {
		error_print();
		return -1;
	}
	if ((ret = SDF_HashUpdate(ctx->session, (uint8_t *)data, (unsigned int)datalen)) != SDR_OK) {
		error_print();
		return -1;
	}
	return 1;
}

int sdf_digest_finish(SDF_DIGEST_CTX *ctx, uint8_t dgst[SM3_DIGEST_SIZE])
{
	unsigned int dgstlen;
	int ret;

	if (!ctx || !dgst) {
		error_print();
		return -1;
	}
	if (!ctx->session) {
		error_print();
		return -1;
	}
	if ((ret = SDF_HashFinal(ctx->session, dgst, &dgstlen)) != SDR_OK) {
		error_print();
		return -1;
	}
	if (dgstlen != 32) {
		error_print();
		return -1;
	}
	return 1;
}

int sdf_digest_reset(SDF_DIGEST_CTX *ctx)
{
	int ret;

	if (!ctx) {
		error_print();
		return -1;
	}
	if (!ctx->session) {
		error_print();
		return -1;
	}
	if ((ret = SDF_HashInit(ctx->session, SGD_SM3, NULL, NULL, 0)) != SDR_OK) {
		error_print();
		return -1;
	}
	return 1;
}

int sdf_digest_cleanup(SDF_DIGEST_CTX *ctx)
{
	if (ctx && ctx->session) {
		if (SDF_CloseSession(ctx->session) != SDR_OK) {
			error_print();
			return -1;
		}
		ctx->session = NULL;
	}
	return 1;
}

static int sdf_cbc_encrypt_blocks(SDF_KEY *key, uint8_t iv[16], const uint8_t *in, size_t nblocks, uint8_t *out)
{
	unsigned int inlen = (unsigned int)(nblocks * 16);
	unsigned int outlen = 0;

	if (SDF_Encrypt(key->session, key->handle, SGD_SM4_CBC, iv,
		(unsigned char *)in, inlen, out, &outlen) != SDR_OK) {
		error_print();
		return -1;
	}
	if (outlen != inlen) {
		error_print();
		return -1;
	}
	if (outlen) {
		if (memcmp(iv, out + outlen - 16, 16) != 0) {
			memcpy(iv, out + outlen - 16, 16);
		}
	}
	return 1;
}

static int sdf_cbc_decrypt_blocks(SDF_KEY *key, uint8_t iv[16], const uint8_t *in, size_t nblocks, uint8_t *out)
{
	unsigned int inlen = (unsigned int)(nblocks * 16);
	unsigned int outlen = 0;

	if (SDF_Decrypt(key->session, key->handle, SGD_SM4_CBC,
		iv, (unsigned char *)in, inlen, out, &outlen) != SDR_OK) {
		error_print();
		return -1;
	}
	if (outlen != inlen) {
		error_print();
		return -1;
	}
	if (inlen) {
		if (memcmp(iv, in + inlen - 16, 16) != 0) {
			memcmp(iv, in + inlen - 16, 16);
		}
	}
	return 1;
}

static int sdf_cbc_padding_encrypt(SDF_KEY *key,
	const uint8_t piv[16], const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen)
{
	uint8_t iv[16];
	uint8_t block[16];
	size_t rem = inlen % 16;
	int padding = 16 - inlen % 16;

	memcpy(iv, piv, 16);
	if (in) {
		memcpy(block, in + inlen - rem, rem);
	}
	memset(block + rem, padding, padding);

	if (inlen/16) {
		if (sdf_cbc_encrypt_blocks(key, iv, in, inlen/16, out) != 1) {
			error_print();
			return -1;
		}
		out += inlen - rem;
	}

	if (sdf_cbc_encrypt_blocks(key, iv, block, 1, out) != 1) {
		error_print();
		return -1;
	}
	*outlen = inlen - rem + 16;
	return 1;
}

static int sdf_cbc_padding_decrypt(SDF_KEY *key,
	const uint8_t piv[16], const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen)
{
	uint8_t iv[16];
	uint8_t block[16];
	size_t len = sizeof(block);
	int padding;

	if (inlen%16 != 0 || inlen < 16) {
		error_print();
		return -1;
	}

	memcpy(iv, piv, 16);

	if (inlen > 16) {
		if (sdf_cbc_decrypt_blocks(key, iv, in, inlen/16 - 1, out) != 1) {
			error_print();
			return -1;
		}
	}

	if (sdf_cbc_decrypt_blocks(key, iv, in + inlen - 16, 1, block) != 1) {
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

int sdf_generate_key(SDF_DEVICE *dev, SDF_KEY *key,
	const SM2_KEY *sm2_key, uint8_t *wrappedkey, size_t *wrappedkey_len)
{
	void *hSession;
	void *hKey;
	ECCrefPublicKey eccPublicKey;
	ECCCipher eccCipher;
	SM2_CIPHERTEXT ciphertext;
	int ret;

	if (!dev || !key || !sm2_key || !wrappedkey_len) {
		error_print();
		return -1;
	}
	if (!dev->handle) {
		error_print();
		return -1;
	}
	if (!wrappedkey) {
		*wrappedkey_len = SM2_MAX_CIPHERTEXT_SIZE;
		return 1;
	}

	// ECCrefPublicKey <= SM2_KEY
	ECCrefPublicKey_from_SM2_Z256_POINT(&eccPublicKey, &sm2_key->public_key);

	// SDF_GenerateKeyWithEPK_ECC
	if (SDF_OpenSession(dev->handle, &hSession) != SDR_OK) {
		error_print();
		return -1;
	}
	if (SDF_GenerateKeyWithEPK_ECC(hSession, 128, SGD_SM2_3, &eccPublicKey, &eccCipher, &hKey) != SDR_OK) {
		(void)SDF_CloseSession(hSession);
		error_print();
		return -1;
	}

	// ECCCipher => SM2_CIPHERTEXT => DER
	if (ECCCipher_to_SM2_CIPHERTEXT(&eccCipher, &ciphertext) != 1) {
		(void)SDF_DestroyKey(hSession, hKey);
		(void)SDF_CloseSession(hSession);
		error_print();
		return -1;
	}
	*wrappedkey_len = 0;
	if (sm2_ciphertext_to_der(&ciphertext, &wrappedkey, wrappedkey_len) != 1) {
		(void)SDF_DestroyKey(hSession, hKey);
		(void)SDF_CloseSession(hSession);
		error_print();
		return -1;
	}

	key->session = hSession;
	key->handle = hKey;
	return 1;
}

int sdf_destroy_key(SDF_KEY *key)
{
	if (key) {
		if (key->session && key->handle) {
			if (SDF_DestroyKey(key->session, key->handle) != SDR_OK) {
				error_print();
				return -1;
			}
			key->session = NULL;
			key->handle = NULL;
		}
		if (key->session || key->handle) {
			error_print();
			return -1;
		}
	}
	return 1;
}

// FIXME:
// If SDF_ImportKeyWithISK_ECC does not need the GetPrivateKeyAccessRight
// then we can use `key_index` or `SDF_PRIVATE_KEY` as arg
// It's not secure to keep `pass` in memory
int sdf_import_key(SDF_DEVICE *dev, unsigned int key_index, const char *pass,
	const uint8_t *wrappedkey, size_t wrappedkey_len, SDF_KEY *key)
{
	void *hSession;
	void *hKey;
	ECCCipher eccCipher;
	SM2_CIPHERTEXT ciphertext;

	if (!dev || !pass || !wrappedkey || !wrappedkey_len) {
		error_print();
		return -1;
	}
	if (!dev->handle) {
		error_print();
		return -1;
	}

	// SM2_CIPHERTEXT <= DER
	if (sm2_ciphertext_from_der(&ciphertext, &wrappedkey, &wrappedkey_len) != 1) {
		error_print();
		return -1;
	}
	if (wrappedkey_len != 0) {
		error_print();
		return -1;
	}

	// ECCCipher <= SM2_CIPHERTEXT
	ECCCipher_from_SM2_CIPHERTEXT(&eccCipher, &ciphertext);

	// SDF_ImportKeyWithISK_ECC
	if (SDF_OpenSession(dev->handle, &hSession) != SDR_OK) {
		error_print();
		return -1;
	}
	// XXX: does import_key need the right?
	if (SDF_GetPrivateKeyAccessRight(hSession, key_index, (unsigned char *)pass, (unsigned int)strlen(pass)) != SDR_OK) {
		(void)SDF_CloseSession(hSession);
		error_print();
		return -1;
	}
	if (SDF_ImportKeyWithISK_ECC(hSession, key_index, &eccCipher, &hKey) != SDR_OK) {
		(void)SDF_CloseSession(hSession);
		error_print();
		return -1;
	}
	if (SDF_ReleasePrivateKeyAccessRight(hSession, (unsigned int)key_index) != SDR_OK) {
		(void)SDF_CloseSession(hSession);
		error_print();
		return -1;
	}

	key->session = hSession;
	key->handle = hKey;
	return 1;
}

int sdf_cbc_encrypt_init(SDF_CBC_CTX *ctx, const SDF_KEY *key, const uint8_t iv[16])
{
	if (!ctx || !key || !iv) {
		error_print();
		return -1;
	}
	if (!key->session || !key->handle) {
		error_print();
		return -1;
	}
	ctx->key = *key;
	memcpy(ctx->iv, iv, SM4_BLOCK_SIZE);
	memset(ctx->block, 0, SM4_BLOCK_SIZE);
	ctx->block_nbytes = 0;
	return 1;
}

int sdf_cbc_encrypt_update(SDF_CBC_CTX *ctx,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
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
		if (sdf_cbc_encrypt_blocks(&ctx->key, ctx->iv, ctx->block, 1, out) != 1) {
			error_print();
			return -1;
		}
		in += left;
		inlen -= left;
		out += SM4_BLOCK_SIZE;
		*outlen += SM4_BLOCK_SIZE;
	}
	if (inlen >= SM4_BLOCK_SIZE) {
		nblocks = inlen / SM4_BLOCK_SIZE;
		len = nblocks * SM4_BLOCK_SIZE;
		if (sdf_cbc_encrypt_blocks(&ctx->key, ctx->iv, in, nblocks, out) != 1) {
			error_print();
			return -1;
		}
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

int sdf_cbc_encrypt_finish(SDF_CBC_CTX *ctx, uint8_t *out, size_t *outlen)
{
	if (!ctx || !out || !outlen) {
		error_print();
		return -1;
	}
	if (ctx->block_nbytes >= SM4_BLOCK_SIZE) {
		error_print();
		return -1;
	}
	if (sdf_cbc_padding_encrypt(&ctx->key, ctx->iv, ctx->block, ctx->block_nbytes, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sdf_cbc_decrypt_init(SDF_CBC_CTX *ctx, const SDF_KEY *key, const uint8_t iv[16])
{
	if (!ctx || !key || !iv) {
		error_print();
		return -1;
	}
	if (!key->session || !key->handle) {
		error_print();
		return -1;
	}
	ctx->key = *key;
	memcpy(ctx->iv, iv, SM4_BLOCK_SIZE);
	memset(ctx->block, 0, SM4_BLOCK_SIZE);
	ctx->block_nbytes = 0;
	return 1;
}

int sdf_cbc_decrypt_update(SDF_CBC_CTX *ctx,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
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
		if (sdf_cbc_decrypt_blocks(&ctx->key, ctx->iv, ctx->block, 1, out) != 1) {
			error_print();
			return -1;
		}
		in += left;
		inlen -= left;
		out += SM4_BLOCK_SIZE;
		*outlen += SM4_BLOCK_SIZE;
	}
	if (inlen > SM4_BLOCK_SIZE) {
		nblocks = (inlen-1) / SM4_BLOCK_SIZE;
		len = nblocks * SM4_BLOCK_SIZE;
		if (sdf_cbc_decrypt_blocks(&ctx->key, ctx->iv, in, nblocks, out) != 1) {
			error_print();
			return -1;
		}
		in += len;
		inlen -= len;
		out += len;
		*outlen += len;
	}
	memcpy(ctx->block, in, inlen);
	ctx->block_nbytes = inlen;
	return 1;
}

int sdf_cbc_decrypt_finish(SDF_CBC_CTX *ctx, uint8_t *out, size_t *outlen)
{
	if (!ctx || !out || !outlen) {
		error_print();
		return -1;
	}
	if (ctx->block_nbytes != SM4_BLOCK_SIZE) {
		error_print();
		return -1;
	}
	if (sdf_cbc_padding_decrypt(&ctx->key, ctx->iv, ctx->block, SM4_BLOCK_SIZE, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sdf_export_sign_public_key(SDF_DEVICE *dev, int key_index, SM2_KEY *sm2_key)
{
	void *hSession;
	ECCrefPublicKey eccPublicKey;

	if (!dev || !sm2_key) {
		error_print();
		return -1;
	}

	if (SDF_OpenSession(dev->handle, &hSession) != SDR_OK) {
		error_print();
		return -1;
	}
	if (SDF_ExportSignPublicKey_ECC(hSession, key_index, &eccPublicKey) != SDR_OK) {
		(void)SDF_CloseSession(hSession);
		error_print();
		return -1;
	}
	(void)SDF_CloseSession(hSession);

	memset(sm2_key, 0, sizeof(SM2_KEY));
	if (ECCrefPublicKey_to_SM2_Z256_POINT(&eccPublicKey, &sm2_key->public_key) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sdf_export_encrypt_public_key(SDF_DEVICE *dev, int key_index, SM2_KEY *sm2_key)
{
	void *hSession;
	ECCrefPublicKey eccPublicKey;

	if (!dev || !sm2_key) {
		error_print();
		return -1;
	}

	if (SDF_OpenSession(dev->handle, &hSession) != SDR_OK) {
		error_print();
		return -1;
	}
	if (SDF_ExportEncPublicKey_ECC(hSession, key_index, &eccPublicKey) != SDR_OK) {
		(void)SDF_CloseSession(hSession);
		error_print();
		return -1;
	}
	(void)SDF_CloseSession(hSession);

	memset(sm2_key, 0, sizeof(SM2_KEY));
	if (ECCrefPublicKey_to_SM2_Z256_POINT(&eccPublicKey, &sm2_key->public_key) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sdf_load_private_key(SDF_DEVICE *dev, SDF_PRIVATE_KEY *key, int key_index, const char *pass)
{
	void *hSession = NULL;
	ECCrefPublicKey eccPublicKey;

	if (!dev || !key || !pass) {
		error_print();
		return -1;
	}
	if (key_index < 0) {
		error_print();
		return -1;
	}

	if (SDF_OpenSession(dev->handle, &hSession) != SDR_OK) {
		error_print();
		return -1;
	}
	if (SDF_GetPrivateKeyAccessRight(hSession, key_index, (unsigned char *)pass, (unsigned int)strlen(pass)) != SDR_OK) {
		(void)SDF_CloseSession(hSession);
		error_print();
		return -1;
	}

	key->session = hSession;
	key->index = key_index;
	return 1;
}

int sdf_sign(const SDF_PRIVATE_KEY *key, const uint8_t dgst[32], uint8_t *sig, size_t *siglen)
{
	ECCSignature ecc_sig;
	SM2_SIGNATURE sm2_sig;

	if (!key || !dgst || !sig || !siglen) {
		error_print();
		return -1;
	}
	if (SDF_InternalSign_ECC(key->session, key->index, (unsigned char *)dgst, 32, &ecc_sig) != SDR_OK) {
		error_print();
		return -1;
	}
	if (ECCSignature_to_SM2_SIGNATURE(&ecc_sig, &sm2_sig) != 1) {
		error_print();
		return -1;
	}
	*siglen = 0;
	if (sm2_signature_to_der(&sm2_sig, &sig, siglen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sdf_decrypt(const SDF_PRIVATE_KEY *key, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	ECCCipher eccCipher;
	SM2_CIPHERTEXT ciphertext;
	unsigned int uiLength = 0;

	if (!key || !in || !outlen) {
		error_print();
		return -1;
	}
	if (!key->session || key->index < 0) {
		error_print();
		return -1;
	}
	if (!out) {
		*outlen = SM2_MAX_PLAINTEXT_SIZE;
		return 1;
	}

	if (sm2_ciphertext_from_der(&ciphertext, &in, &inlen) != 1) {
		error_print();
		return -1;
	}
	if (inlen != 0) {
		error_print();
		return -1;
	}

	ECCCipher_from_SM2_CIPHERTEXT(&eccCipher, &ciphertext);

	if (SDF_InternalDecrypt_ECC(key->session, key->index, SGD_SM2_3, &eccCipher, out, &uiLength) != SDR_OK) {
		error_print();
		return -1;
	}

	*outlen = uiLength;
	return 1;
}

int sdf_sign_init(SDF_SIGN_CTX *ctx, const SDF_PRIVATE_KEY *key, const char *id, size_t idlen)
{
	ECCrefPublicKey eccPublicKey;
	SM2_Z256_POINT z256_point;

	if (!ctx || !key) {
		error_print();
		return -1;
	}
	if (!key->session) {
		error_print();
		return -1;
	}

	if (SDF_ExportSignPublicKey_ECC(key->session, key->index, &eccPublicKey) != SDR_OK) {
		error_print();
		return -1;
	}
	if (ECCrefPublicKey_to_SM2_Z256_POINT(&eccPublicKey, &z256_point) != 1) {
		error_print();
		return -1;
	}

	sm3_init(&ctx->sm3_ctx);
	if (id) {
		uint8_t z[SM3_DIGEST_SIZE];

		if (idlen <= 0 || idlen > SM2_MAX_ID_LENGTH) {
			error_print();
			return -1;
		}
		sm2_compute_z(z, &z256_point, id, idlen);
		sm3_update(&ctx->sm3_ctx, z, sizeof(z));
	}
	ctx->saved_sm3_ctx = ctx->sm3_ctx;

	ctx->key = *key;
	return 1;
}

int sdf_sign_update(SDF_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	if (data && datalen > 0) {
		sm3_update(&ctx->sm3_ctx, data, datalen);
	}
	return 1;
}

int sdf_sign_finish(SDF_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen)
{
	uint8_t dgst[SM3_DIGEST_SIZE];

	if (!ctx || !sig || !siglen) {
		error_print();
		return -1;
	}

	sm3_finish(&ctx->sm3_ctx, dgst);

	if (sdf_sign(&ctx->key, dgst, sig, siglen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sdf_sign_reset(SDF_SIGN_CTX *ctx)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	ctx->sm3_ctx = ctx->saved_sm3_ctx;
	return 1;
}

int sdf_release_key(SDF_PRIVATE_KEY *key)
{
	if (SDF_ReleasePrivateKeyAccessRight(key->session, key->index) != SDR_OK) {
		error_print();
	}
	if (SDF_CloseSession(key->session) != SDR_OK) {
		error_print();
		return -1;
	}
	return 1;
}

int sdf_close_device(SDF_DEVICE *dev)
{
	if (dev) {
		if (dev->handle) {
			if (SDF_CloseDevice(dev->handle) != SDR_OK) {
				error_print();
				return -1;
			}
			memset(dev, 0, sizeof(*dev));
		}
	}
	return 1;
}
