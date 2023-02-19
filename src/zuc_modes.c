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
#include <gmssl/zuc.h>
#include <gmssl/error.h>
#include <gmssl/endian.h>


static void zuc_set_eea_key(ZUC_STATE *key, const uint8_t user_key[16],
	ZUC_UINT32 count, ZUC_UINT5 bearer, ZUC_BIT direction)
{
	uint8_t iv[16] = {0};
	iv[0] = iv[8] = count >> 24;
	iv[1] = iv[9] = count >> 16;
	iv[2] = iv[10] = count >> 8;
	iv[3] = iv[11] = count;
	iv[4] = iv[12] = ((bearer << 1) | (direction & 1)) << 2;
	zuc_init(key, user_key, iv);
}

void zuc_eea_encrypt(const ZUC_UINT32 *in, ZUC_UINT32 *out, size_t nbits,
	const uint8_t key[16], ZUC_UINT32 count, ZUC_UINT5 bearer,
	ZUC_BIT direction)
{
	ZUC_STATE zuc_key;
	size_t nwords = (nbits + 31)/32;
	size_t i;

	zuc_set_eea_key(&zuc_key, key, count, bearer, direction);
	zuc_generate_keystream(&zuc_key, nwords, out);
	for (i = 0; i < nwords; i++) {
		out[i] ^= in[i];
	}

	if (nbits % 32 != 0) {
		out[nwords - 1] &= (0xffffffff << (32 - (nbits%32)));
	}
}

static void zuc_set_eia_iv(uint8_t iv[16], ZUC_UINT32 count, ZUC_UINT5 bearer,
	ZUC_BIT direction)
{
	memset(iv, 0, 16);
	iv[0] = count >> 24;
	iv[1] = iv[9] = count >> 16;
	iv[2] = iv[10] = count >> 8;
	iv[3] = iv[11] = count;
	iv[4] = iv[12] = bearer << 3;
	iv[8] = iv[0] ^ (direction << 7);
	iv[14] = (direction << 7);
}

ZUC_UINT32 zuc_eia_generate_mac(const ZUC_UINT32 *data, size_t nbits,
	const uint8_t key[16], ZUC_UINT32 count, ZUC_UINT5 bearer,
	ZUC_BIT direction)
{
	ZUC_MAC_CTX ctx;
	uint8_t iv[16];
	uint8_t mac[4];
	zuc_set_eia_iv(iv, count, bearer, direction);
	zuc_mac_init(&ctx, key, iv);
	zuc_mac_finish(&ctx, (uint8_t *)data, nbits, mac);
	return GETU32(mac);
}

#define ZUC_BLOCK_SIZE 4

int zuc_encrypt_init(ZUC_CTX *ctx, const uint8_t key[ZUC_KEY_SIZE], const uint8_t iv[ZUC_IV_SIZE])
{
	if (!ctx || !key || !iv) {
		error_print();
		return -1;
	}
	zuc_init(&ctx->zuc_state, key, iv);
	memset(ctx->block, 0, ZUC_BLOCK_SIZE);
	ctx->block_nbytes = 0;
	return 1;
}

int zuc_encrypt_update(ZUC_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	size_t left;
	size_t nblocks;
	size_t len;

	if (ctx->block_nbytes >= ZUC_BLOCK_SIZE) {
		error_print();
		return -1;
	}
	*outlen = 0;
	if (ctx->block_nbytes) {
		left = ZUC_BLOCK_SIZE - ctx->block_nbytes;
		if (inlen < left) {
			memcpy(ctx->block + ctx->block_nbytes, in, inlen);
			ctx->block_nbytes += inlen;
			return 1;
		}
		memcpy(ctx->block + ctx->block_nbytes, in, left);
		zuc_encrypt(&ctx->zuc_state, ctx->block, ZUC_BLOCK_SIZE, out);
		in += left;
		inlen -= left;
		out += ZUC_BLOCK_SIZE;
		*outlen += ZUC_BLOCK_SIZE;
	}
	if (inlen >= ZUC_BLOCK_SIZE) {
		nblocks = inlen / ZUC_BLOCK_SIZE;
		len = nblocks * ZUC_BLOCK_SIZE;
		zuc_encrypt(&ctx->zuc_state, in, len, out);
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

int zuc_encrypt_finish(ZUC_CTX *ctx, uint8_t *out, size_t *outlen)
{
	if (ctx->block_nbytes >= ZUC_BLOCK_SIZE) {
		error_print();
		return -1;
	}
	zuc_encrypt(&ctx->zuc_state, ctx->block, ctx->block_nbytes, out);
	*outlen = ctx->block_nbytes;
	return 1;
}
