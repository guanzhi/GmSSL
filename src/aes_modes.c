/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/aes.h>
#include <gmssl/mem.h>
#include <gmssl/ghash.h>
#include <gmssl/error.h>


void aes_cbc_encrypt_blocks(const AES_KEY *key, const uint8_t iv[16],
	const uint8_t *in, size_t nblocks, uint8_t *out)
{
	while (nblocks--) {
		gmssl_memxor(out, in, iv, 16);
		aes_encrypt(key, out, out);
		iv = out;
		in += 16;
		out += 16;
	}
}

void aes_cbc_decrypt_blocks(const AES_KEY *key, const uint8_t iv[16],
	const uint8_t *in, size_t nblocks, uint8_t *out)
{
	while (nblocks--) {
		aes_decrypt(key, in, out);
		memxor(out, iv, 16);
		iv = in;
		in += 16;
		out += 16;
	}
}

int aes_cbc_padding_encrypt(const AES_KEY *key, const uint8_t iv[16],
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
		aes_cbc_encrypt_blocks(key, iv, in, inlen/16, out);
		out += inlen - rem;
		iv = out - 16;
	}
	aes_cbc_encrypt_blocks(key, iv, block, 1, out);
	*outlen = inlen - rem + 16;
	return 1;
}

int aes_cbc_padding_decrypt(const AES_KEY *key, const uint8_t iv[16],
	const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen)
{
	uint8_t block[16];
	size_t len = sizeof(block);
	int padding;
	int i;

	if (inlen == 0) {
		error_print();
		return 0;
	}
	if (inlen%16 != 0 || inlen < 16) {
		error_print();
		return -1;
	}
	if (inlen > 16) {
		aes_cbc_decrypt_blocks(key, iv, in, inlen/16 - 1, out);
		iv = in + inlen - 32;
	}
	aes_cbc_decrypt_blocks(key, iv, in + inlen - 16, 1, block);
	padding = block[15];
	if (padding < 1 || padding > 16) {
		error_print();
		return -1;
	}
	for (i = 16 - padding; i < 16; i++) {
		if (block[i] != padding) {
			error_print();
			return -1;
		}
	}

	len -= padding;
	memcpy(out + inlen - 16, block, len);
	*outlen = inlen - padding;
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

void aes_ctr_encrypt(const AES_KEY *key, uint8_t ctr[16], const uint8_t *in, size_t inlen, uint8_t *out)
{
	uint8_t block[16];
	size_t len;

	while (inlen) {
		len = inlen < 16 ? inlen : 16;
		aes_encrypt(key, ctr, block);
		gmssl_memxor(out, in, block, len);
		ctr_incr(ctr);
		in += len;
		out += len;
		inlen -= len;
	}
}

#ifdef ENABLE_AES_CCM
static void length_to_bytes(size_t len, size_t nbytes, uint8_t *out)
{
	uint8_t *p = out + nbytes - 1;
	while (nbytes--) {
		*p-- = len & 0xff;
		len >>= 8;
	}
}

static void ctr_n_incr(uint8_t a[16], size_t n)
{
	size_t i;
	for (i = 15; i >= 16 - n; i--) {
		a[i]++;
		if (a[i]) break;
	}
}

static void aes_ctr_n_encrypt(const AES_KEY *key, uint8_t ctr[16], size_t n, const uint8_t *in, size_t inlen, uint8_t *out)
{
	uint8_t block[16];
	size_t len;

	while (inlen) {
		len = inlen < 16 ? inlen : 16;
		aes_encrypt(key, ctr, block);
		gmssl_memxor(out, in, block, len);
		ctr_n_incr(ctr, n);
		in += len;
		out += len;
		inlen -= len;
	}
}

typedef struct {
	AES_KEY key;
	uint8_t iv[16];
	size_t ivlen;
} AES_CBC_MAC_CTX;

static int aes_cbc_mac_update(AES_CBC_MAC_CTX *ctx, const uint8_t *data, size_t datalen)
{
	if (!ctx || (!data && datalen)) {
		error_print();
		return -1;
	}
	if (ctx->ivlen >= 16) {
		error_print();
		return -1;
	}
	if (!data || !datalen) {
		return 1;
	}
	while (datalen) {
		size_t ivleft = 16 - ctx->ivlen;
		size_t len = datalen < ivleft ? datalen : ivleft;
		gmssl_memxor(ctx->iv + ctx->ivlen, ctx->iv + ctx->ivlen, data, len);
		ctx->ivlen += len;
		if (ctx->ivlen >= 16) {
			aes_encrypt(&ctx->key, ctx->iv, ctx->iv);
			ctx->ivlen = 0;
		}
		data += len;
		datalen -= len;
	}
	return 1;
}

static int aes_cbc_mac_finish(AES_CBC_MAC_CTX *ctx, uint8_t mac[16])
{
	if (!ctx || !mac) {
		error_print();
		return -1;
	}
	if (ctx->ivlen >= 16) {
		error_print();
		return -1;
	}
	if (ctx->ivlen) {
		aes_encrypt(&ctx->key, ctx->iv, ctx->iv);
		ctx->ivlen = 0;
	}
	memcpy(mac, ctx->iv, 16);
	return 1;
}

int aes_ccm_encrypt(const AES_KEY *key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	uint8_t *out, size_t taglen, uint8_t *tag)
{
	AES_CBC_MAC_CTX mac_ctx;
	const uint8_t zeros[16] = {0};
	uint8_t block[16] = {0};
	uint8_t ctr[16] = {0};
	uint8_t mac[16];
	size_t inlen_size;

	if (!key || !iv || (!aad && aadlen) || (!in && inlen) || !out || !tag) {
		error_print();
		return -1;
	}
	if (ivlen < 7 || ivlen > 13) {
		error_print();
		return -1;
	}
	if (taglen < 4 || taglen > 16 || taglen & 1) {
		error_print();
		return -1;
	}

	inlen_size = 15 - ivlen;
	if (inlen_size < 8 && inlen >= ((size_t)1 << (inlen_size * 8))) {
		error_print();
		return -1;
	}

	memset(&mac_ctx, 0, sizeof(mac_ctx));
	mac_ctx.key = *key;

	block[0] |= ((aadlen > 0) & 0x1) << 6;
	block[0] |= (((taglen - 2)/2) & 0x7) << 3;
	block[0] |= (inlen_size - 1) & 0x7;
	memcpy(block + 1, iv, ivlen);
	length_to_bytes(inlen, inlen_size, block + 1 + ivlen);
	aes_cbc_mac_update(&mac_ctx, block, 16);

	if (aad && aadlen) {
		size_t alen;

		if (aadlen < ((1<<16) - (1<<8))) {
			length_to_bytes(aadlen, 2, block);
			alen = 2;
		} else if ((uint64_t)aadlen < ((uint64_t)1<<32)) {
			block[0] = 0xff;
			block[1] = 0xfe;
			length_to_bytes(aadlen, 4, block + 2);
			alen = 6;
		} else {
			block[0] = 0xff;
			block[1] = 0xff;
			length_to_bytes(aadlen, 8, block + 2);
			alen = 10;
		}
		aes_cbc_mac_update(&mac_ctx, block, alen);
		aes_cbc_mac_update(&mac_ctx, aad, aadlen);
		if ((alen + aadlen) % 16) {
			aes_cbc_mac_update(&mac_ctx, zeros, 16 - (alen + aadlen)%16);
		}
	}

	ctr[0] = 0;
	ctr[0] |= (inlen_size - 1) & 0x7;
	memcpy(ctr + 1, iv, ivlen);
	memset(ctr + 1 + ivlen, 0, 15 - ivlen);
	aes_encrypt(key, ctr, block);

	ctr[15] = 1;
	aes_ctr_n_encrypt(key, ctr, 15 - ivlen, in, inlen, out);

	aes_cbc_mac_update(&mac_ctx, in, inlen);
	if (inlen % 16) {
		aes_cbc_mac_update(&mac_ctx, zeros, 16 - inlen % 16);
	}
	aes_cbc_mac_finish(&mac_ctx, mac);
	gmssl_memxor(tag, mac, block, taglen);

	gmssl_secure_clear(&mac_ctx, sizeof(mac_ctx));
	return 1;
}

int aes_ccm_decrypt(const AES_KEY *key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	const uint8_t *tag, size_t taglen, uint8_t *out)
{
	AES_CBC_MAC_CTX mac_ctx;
	const uint8_t zeros[16] = {0};
	uint8_t block[16] = {0};
	uint8_t ctr[16] = {0};
	uint8_t mac[16];
	size_t inlen_size;

	if (!key || !iv || (!aad && aadlen) || (!in && inlen) || !tag || !out) {
		error_print();
		return -1;
	}
	if (ivlen < 7 || ivlen > 13) {
		error_print();
		return -1;
	}
	if (taglen < 4 || taglen > 16 || taglen & 1) {
		error_print();
		return -1;
	}

	inlen_size = 15 - ivlen;
	if (inlen_size < 8 && inlen >= ((size_t)1 << (inlen_size * 8))) {
		error_print();
		return -1;
	}

	memset(&mac_ctx, 0, sizeof(mac_ctx));
	mac_ctx.key = *key;

	block[0] |= ((aadlen > 0) & 0x1) << 6;
	block[0] |= (((taglen - 2)/2) & 0x7) << 3;
	block[0] |= (inlen_size - 1) & 0x7;
	memcpy(block + 1, iv, ivlen);
	length_to_bytes(inlen, inlen_size, block + 1 + ivlen);
	aes_cbc_mac_update(&mac_ctx, block, 16);

	if (aad && aadlen) {
		size_t alen;

		if (aadlen < ((1<<16) - (1<<8))) {
			length_to_bytes(aadlen, 2, block);
			alen = 2;
		} else if ((uint64_t)aadlen < ((uint64_t)1<<32)) {
			block[0] = 0xff;
			block[1] = 0xfe;
			length_to_bytes(aadlen, 4, block + 2);
			alen = 6;
		} else {
			block[0] = 0xff;
			block[1] = 0xff;
			length_to_bytes(aadlen, 8, block + 2);
			alen = 10;
		}
		aes_cbc_mac_update(&mac_ctx, block, alen);
		aes_cbc_mac_update(&mac_ctx, aad, aadlen);
		if ((alen + aadlen) % 16) {
			aes_cbc_mac_update(&mac_ctx, zeros, 16 - (alen + aadlen)%16);
		}
	}

	ctr[0] = 0;
	ctr[0] |= (inlen_size - 1) & 0x7;
	memcpy(ctr + 1, iv, ivlen);
	memset(ctr + 1 + ivlen, 0, 15 - ivlen);
	aes_encrypt(key, ctr, block);

	ctr[15] = 1;
	aes_ctr_n_encrypt(key, ctr, 15 - ivlen, in, inlen, out);

	aes_cbc_mac_update(&mac_ctx, out, inlen);
	if (inlen % 16) {
		aes_cbc_mac_update(&mac_ctx, zeros, 16 - inlen % 16);
	}
	aes_cbc_mac_finish(&mac_ctx, mac);

	gmssl_memxor(mac, mac, block, taglen);
	if (gmssl_secure_memcmp(mac, tag, taglen) != 0) {
		error_print();
		gmssl_secure_clear(&mac_ctx, sizeof(mac_ctx));
		return -1;
	}

	gmssl_secure_clear(&mac_ctx, sizeof(mac_ctx));
	return 1;
}
#endif


static void ctr32_incr(uint8_t a[16])
{
	int i;
	for (i = 15; i >= 12; i--) {
		a[i]++;
		if (a[i]) break;
	}
}

static void aes_ctr32_encrypt(const AES_KEY *key, uint8_t ctr[16], const uint8_t *in, size_t inlen, uint8_t *out)
{
	uint8_t block[16];
	size_t len;

	while (inlen) {
		len = inlen < 16 ? inlen : 16;
		aes_encrypt(key, ctr, block);
		gmssl_memxor(out, in, block, len);
		ctr32_incr(ctr);
		in += len;
		out += len;
		inlen -= len;
	}
	gmssl_secure_clear(block, sizeof(block));
}

int aes_gcm_encrypt(const AES_KEY *key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	uint8_t *out, size_t taglen, uint8_t *tag)
{
	const uint8_t *pin = in;
	uint8_t *pout = out;
	size_t left = inlen;
	uint8_t H[16] = {0};
	uint8_t Y[16];
	uint8_t T[16];

	if (taglen > AES_GCM_MAX_TAG_SIZE) {
		error_print();
		return -1;
	}

	aes_encrypt(key, H, H);

	if (ivlen == 12) {
		memcpy(Y, iv, 12);
		Y[12] = Y[13] = Y[14] = 0;
		Y[15] = 1;
	} else {
		ghash(H, NULL, 0, iv, ivlen, Y);
	}

	aes_encrypt(key, Y, T);

	ctr32_incr(Y);
	aes_ctr32_encrypt(key, Y, in, inlen, out);

	ghash(H, aad, aadlen, out, inlen, H);
	gmssl_memxor(tag, T, H, taglen);

	gmssl_secure_clear(H, sizeof(H));
	gmssl_secure_clear(Y, sizeof(Y));
	gmssl_secure_clear(T, sizeof(T));
	return 1;
}

int aes_gcm_decrypt(const AES_KEY *key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	const uint8_t *tag, size_t taglen, uint8_t *out)
{
	const uint8_t *pin = in;
	uint8_t *pout = out;
	size_t left = inlen;
	uint8_t H[16] = {0};
	uint8_t Y[16];
	uint8_t T[16];

	if (taglen > AES_GCM_MAX_TAG_SIZE) {
		error_print();
		return -1;
	}

	aes_encrypt(key, H, H);

	if (ivlen == 12) {
		memcpy(Y, iv, 12);
		Y[12] = Y[13] = Y[14] = 0;
		Y[15] = 1;
	} else {
		ghash(H, NULL, 0, iv, ivlen, Y);
	}

	ghash(H, aad, aadlen, in, inlen, H);
	aes_encrypt(key, Y, T);
	gmssl_memxor(T, T, H, taglen);
	if (gmssl_secure_memcmp(T, tag, taglen) != 0) {
		gmssl_secure_clear(H, sizeof(H));
		gmssl_secure_clear(Y, sizeof(Y));
		gmssl_secure_clear(T, sizeof(T));
		error_print();
		return -1;
	}

	ctr32_incr(Y);
	aes_ctr32_encrypt(key, Y, in, inlen, out);

	gmssl_secure_clear(H, sizeof(H));
	gmssl_secure_clear(Y, sizeof(Y));
	gmssl_secure_clear(T, sizeof(T));
	return 1;
}
