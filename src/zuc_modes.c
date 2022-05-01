/*
 * Copyright (c) 2015 - 2022 The GmSSL Project.  All rights reserved.
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
		out[nwords - 1] |= (0xffffffff << (32 - (nbits%32)));
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
	size_t left;
	if (ctx->block_nbytes >= ZUC_BLOCK_SIZE) {
		error_print();
		return -1;
	}
	zuc_encrypt(&ctx->zuc_state, ctx->block, ctx->block_nbytes, out);
	*outlen = ctx->block_nbytes;
	return 1;
}
