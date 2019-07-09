/* ====================================================================
 * Copyright (c) 2014 - 2017 The GmSSL Project.  All rights reserved.
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
 * ====================================================================
 *
 */
#include <string.h>
#include <openssl/sm3.h>

/**
 * HMAC_k(m) = H((k ^ opad), H((k ^ ipad), m))
 * pseudo-code:
 * function hmac(key, message)
 *	opad = [0x5c * blocksize]
 *	ipad = [0x36 * blocksize]
 *	if (length(key) > blocksize) then
 *		key = hash(key)
 *	end if
 *	for i from 0 to length(key) - 1 step 1
 *		ipad[i] = ipad[i] XOR key[i]
 *		opad[i] = opad[i] XOR key[i]
 *	end for
 *	return hash(opad || hash(ipad || message))
 * end function
 */


#define IPAD	0x36
#define OPAD	0x5C

void sm3_hmac_init(sm3_hmac_ctx_t *ctx, const unsigned char *key, size_t key_len)
{
	int i;

	if (key_len <= SM3_BLOCK_SIZE) {
		memcpy(ctx->key, key, key_len);
		memset(ctx->key + key_len, 0, SM3_BLOCK_SIZE - key_len);
	} else {
		sm3_init(&ctx->sm3_ctx);
		sm3_update(&ctx->sm3_ctx, key, key_len);
		sm3_final(&ctx->sm3_ctx, ctx->key);
		memset(ctx->key + SM3_DIGEST_LENGTH, 0,
			SM3_BLOCK_SIZE - SM3_DIGEST_LENGTH);
	}
	for (i = 0; i < SM3_BLOCK_SIZE; i++) {
		ctx->key[i] ^= IPAD;
	}

	sm3_init(&ctx->sm3_ctx);
	sm3_update(&ctx->sm3_ctx, ctx->key, SM3_BLOCK_SIZE);
}

void sm3_hmac_update(sm3_hmac_ctx_t *ctx,
	const unsigned char *data, size_t data_len)
{
	sm3_update(&ctx->sm3_ctx, data, data_len);
}

void sm3_hmac_final(sm3_hmac_ctx_t *ctx, unsigned char mac[SM3_HMAC_SIZE])
{
	int i;
	for (i = 0; i < SM3_BLOCK_SIZE; i++) {
		ctx->key[i] ^= (IPAD ^ OPAD);
	}
	sm3_final(&ctx->sm3_ctx, mac);
	sm3_init(&ctx->sm3_ctx);
	sm3_update(&ctx->sm3_ctx, ctx->key, SM3_BLOCK_SIZE);
	sm3_update(&ctx->sm3_ctx, mac, SM3_DIGEST_LENGTH);
	sm3_final(&ctx->sm3_ctx, mac);
}

void sm3_hmac(const unsigned char *data, size_t data_len,
	const unsigned char *key, size_t key_len,
	unsigned char mac[SM3_HMAC_SIZE])
{
	sm3_hmac_ctx_t ctx;
	sm3_hmac_init(&ctx, key, key_len);
	sm3_hmac_update(&ctx, data, data_len);
	sm3_hmac_final(&ctx, mac);
	memset(&ctx, 0, sizeof(ctx));
}
