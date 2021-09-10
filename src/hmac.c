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

#include <string.h>
#include <gmssl/hmac.h>
#include <gmssl/error.h>


#define IPAD	0x36
#define OPAD	0x5C


int hmac_init(HMAC_CTX *ctx, const DIGEST *digest, const unsigned char *key, size_t keylen)
{
	uint8_t i_key[DIGEST_MAX_BLOCK_SIZE] = {0};
	uint8_t o_key[DIGEST_MAX_BLOCK_SIZE] = {0};
	size_t blocksize;
	int i;

	if (!ctx || !digest || !key || !keylen) {
		error_print();
		return -1;
	}

	ctx->digest = digest;

	blocksize = digest_block_size(digest);
	if (keylen <= blocksize) {
		memcpy(i_key, key, keylen);
		memcpy(o_key, key, keylen);
	} else {
		digest_init(&ctx->digest_ctx, digest);
		digest_update(&ctx->digest_ctx, key, keylen);
		digest_finish(&ctx->digest_ctx, i_key, &keylen);
		memcpy(o_key, i_key, keylen);
	}
	for (i = 0; i < blocksize; i++) {
		i_key[i] ^= IPAD;
		o_key[i] ^= OPAD;
	}

	digest_init(&ctx->i_ctx, digest);
	digest_update(&ctx->i_ctx, i_key, blocksize);
	digest_init(&ctx->o_ctx, digest);
	digest_update(&ctx->o_ctx, o_key, blocksize);
	memcpy(&ctx->digest_ctx, &ctx->i_ctx, sizeof(DIGEST_CTX));

	memset(i_key, 0, sizeof(i_key));
	memset(o_key, 0, sizeof(o_key));
	return 1;
}

int hmac_update(HMAC_CTX *ctx, const unsigned char *data, size_t datalen)
{
	if (!ctx || (!data &&  datalen != 0)) {
		error_print();
		return -1;
	}
	if (digest_update(&ctx->digest_ctx, data, datalen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int hmac_finish(HMAC_CTX *ctx, unsigned char *mac, size_t *maclen)
{
	if (digest_finish(&ctx->digest_ctx, mac, maclen) != 1) {
		error_print();
		return -1;
	}
	memcpy(&ctx->digest_ctx, &ctx->o_ctx, sizeof(DIGEST_CTX));
	if (digest_update(&ctx->digest_ctx, mac, *maclen) != 1
		|| digest_finish(&ctx->digest_ctx, mac, maclen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int hmac_finish_and_verify(HMAC_CTX *ctx, const uint8_t *mac, size_t maclen)
{
	uint8_t hmac[64];
	size_t hmaclen;

	if (hmac_finish(ctx, hmac, &hmaclen) != 1) {
		error_print();
		return -1;
	}
	if (maclen != hmaclen
		|| memcmp(hmac, mac, maclen) != 0) {
		error_print();
		return -1;
	}
	return 1;
}

int hmac(const DIGEST *digest, const unsigned char *key, size_t keylen,
	const unsigned char *data, size_t datalen,
	unsigned char *mac, size_t *maclen)
{
	int ret = 0;
	HMAC_CTX ctx;

	if (hmac_init(&ctx, digest, key, keylen) != 1
		|| hmac_update(&ctx, data, datalen) != 1
		|| hmac_finish(&ctx, mac, maclen) != 1) {
		goto end;
	}
	ret = 1;

end:
	memset(&ctx, 0, sizeof(ctx));
	return ret;
}
