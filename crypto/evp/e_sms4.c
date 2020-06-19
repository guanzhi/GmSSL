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
 */
 /*
 * Copyright 2001-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include "evp_locl.h"
#include "internal/evp_int.h"
#include "modes_lcl.h"

#ifndef OPENSSL_NO_SMS4

# include <openssl/sms4.h>
# include "sms4_lcl.h"

# ifdef SMS4_AVX2
void sms4_avx2_ecb_encrypt_blocks(const unsigned char *in,
	unsigned char *out, size_t blocks, const sms4_key_t *key);
void sms4_avx2_ctr32_encrypt_blocks(const unsigned char *in,
	unsigned char *out, size_t blocks, const sms4_key_t *key,
	const unsigned char iv[16]);
# endif

typedef struct {
	block128_f block;
	union {
		cbc128_f cbc;
		ctr128_f ctr;
	} stream;
	union {
		double align;
		sms4_key_t ks;
	} ks;
} EVP_SMS4_KEY;


static int sms4_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
	const unsigned char *iv, int enc)
{
	int mode;
	EVP_SMS4_KEY *dat = EVP_C_DATA(EVP_SMS4_KEY, ctx);
	mode = EVP_CIPHER_CTX_mode(ctx);

	if ((mode == EVP_CIPH_ECB_MODE || mode == EVP_CIPH_CBC_MODE) && !enc) {
		sms4_set_decrypt_key(&dat->ks.ks, key);
	} else {
		sms4_set_encrypt_key(&dat->ks.ks, key);
	}
	dat->block = (block128_f)sms4_encrypt;

	if (mode == EVP_CIPH_CTR_MODE) {
# ifdef SMS4_AVX2
		dat->stream.ctr = (ctr128_f) sms4_avx2_ctr32_encrypt_blocks;
# else
		dat->stream.ctr = (ctr128_f) sms4_ctr32_encrypt_blocks;
# endif
	}

	return 1;
}

static int sms4_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr)
{
	switch (type) {
	case EVP_CTRL_PBE_PRF_NID:
		*(int *)ptr = NID_hmac_sm3;
		return 1;
	default:
		return -1;
	}
}

IMPLEMENT_BLOCK_CIPHER(sms4, ks.ks, sms4, EVP_SMS4_KEY, NID_sms4,
	SMS4_BLOCK_SIZE, SMS4_KEY_LENGTH, SMS4_IV_LENGTH, 128,
	EVP_CIPH_FLAG_DEFAULT_ASN1, sms4_init_key, NULL, NULL, NULL, sms4_ctrl)

# define MAXBITCHUNK     ((size_t)1<<(sizeof(size_t)*8-4))

static int sms4_cfb1_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
	const unsigned char *in, size_t len)
{
	EVP_SMS4_KEY *sms4_key = (EVP_SMS4_KEY *)ctx->cipher_data;

	if (ctx->flags & EVP_CIPH_FLAG_LENGTH_BITS) {
		CRYPTO_cfb128_1_encrypt(in, out, len, &sms4_key->ks.ks,
			ctx->iv, &ctx->num, ctx->encrypt, (block128_f)sms4_encrypt);
		return 1;
	}

	while (len >= MAXBITCHUNK) {
		CRYPTO_cfb128_1_encrypt(in, out, MAXBITCHUNK * 8, &sms4_key->ks.ks,
			ctx->iv, &ctx->num, ctx->encrypt, (block128_f)sms4_encrypt);
		len -= MAXBITCHUNK;
	}

	if (len) {
		CRYPTO_cfb128_1_encrypt(in, out, len * 8, &sms4_key->ks.ks,
			ctx->iv, &ctx->num, ctx->encrypt, (block128_f)sms4_encrypt);
	}

	return 1;
}

const EVP_CIPHER sms4_cfb1 = {
	NID_sms4_cfb1,
	1,
	SMS4_KEY_LENGTH,
	SMS4_IV_LENGTH,
	EVP_CIPH_CTR_MODE,
	sms4_init_key,
	sms4_cfb1_cipher,
	NULL,
	sizeof(EVP_SMS4_KEY),
	NULL,NULL,sms4_ctrl,NULL,
};

const EVP_CIPHER *EVP_sms4_cfb1(void)
{
	return &sms4_cfb1;
}

static int sms4_cfb8_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
	const unsigned char *in, size_t len)
{
	EVP_SMS4_KEY *sms4_key = (EVP_SMS4_KEY *)ctx->cipher_data;

	CRYPTO_cfb128_8_encrypt(in, out, len, &sms4_key->ks.ks,
		ctx->iv, &ctx->num, ctx->encrypt, (block128_f)sms4_encrypt);

	return 1;
}

const EVP_CIPHER sms4_cfb8 = {
	NID_sms4_cfb8,
	1,
	SMS4_KEY_LENGTH,
	SMS4_IV_LENGTH,
	EVP_CIPH_CTR_MODE,
	sms4_init_key,
	sms4_cfb8_cipher,
	NULL,
	sizeof(EVP_SMS4_KEY),
	NULL,NULL,sms4_ctrl,NULL,
};

const EVP_CIPHER *EVP_sms4_cfb8(void)
{
	return &sms4_cfb8;
}

static int sms4_ctr_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
	const unsigned char *in, size_t len)
{
	unsigned int num = EVP_CIPHER_CTX_num(ctx);
	EVP_SMS4_KEY *sms4 = (EVP_SMS4_KEY *)ctx->cipher_data;

	if (sms4->stream.ctr)
		CRYPTO_ctr128_encrypt_ctr32(in, out, len, &sms4->ks.ks,
			EVP_CIPHER_CTX_iv_noconst(ctx),
			EVP_CIPHER_CTX_buf_noconst(ctx),
			&num, sms4->stream.ctr);
	else
		CRYPTO_ctr128_encrypt(in, out, len, &sms4->ks.ks,
			EVP_CIPHER_CTX_iv_noconst(ctx),
			EVP_CIPHER_CTX_buf_noconst(ctx), &num,
			sms4->block);

	EVP_CIPHER_CTX_set_num(ctx, num);
	return 1;
}

const EVP_CIPHER sms4_ctr = {
	NID_sms4_ctr,
	1,
	SMS4_KEY_LENGTH,
	SMS4_IV_LENGTH,
	EVP_CIPH_CTR_MODE,
	sms4_init_key,
	sms4_ctr_cipher,
	NULL, /* cleanup() */
	sizeof(EVP_SMS4_KEY),
	NULL,NULL,sms4_ctrl,NULL,
};

const EVP_CIPHER *EVP_sms4_ctr(void)
{
	return &sms4_ctr;
}
#endif /* OPENSSL_NO_SMS4 */
