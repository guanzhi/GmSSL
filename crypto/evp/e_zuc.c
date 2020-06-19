/* ====================================================================
 * Copyright (c) 2014 - 2018 The GmSSL Project.  All rights reserved.
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

#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include "evp_locl.h"
# include "internal/evp_int.h"

#ifndef OPENSSL_NO_ZUC

# include <openssl/zuc.h>

typedef struct {
	ZUC_KEY ks;
} EVP_ZUC_KEY;


static int zuc_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
	const unsigned char *iv, int enc)
{
	EVP_ZUC_KEY *dctx = EVP_C_DATA(EVP_ZUC_KEY, ctx);
	ZUC_set_key(&dctx->ks, key, iv);
	return 1;
}

static int zuc_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
	const unsigned char *in, size_t len)
{
	EVP_ZUC_KEY *dctx = EVP_C_DATA(EVP_ZUC_KEY, ctx);
	unsigned char *buf = EVP_CIPHER_CTX_buf_noconst(ctx);
	unsigned int n = EVP_CIPHER_CTX_num(ctx);
	size_t l = 0;

	while (l < len) {
		if (n == 0) {
			ZUC_generate_keystream(&dctx->ks, 4, (uint32_t *)buf);
		}
		out[l] = in[l] ^ buf[n];
		++l;
		n = (n + 1) % 16;
	}

	EVP_CIPHER_CTX_set_num(ctx, n);
	return 1;
}

const EVP_CIPHER zuc_cipher = {
	NID_zuc,
	1,
	ZUC_KEY_LENGTH,
	ZUC_IV_LENGTH,
	0,
	zuc_init_key,
	zuc_do_cipher,
	NULL,
	sizeof(EVP_ZUC_KEY),
	NULL,NULL,NULL,NULL,
};

const EVP_CIPHER *EVP_zuc(void)
{
	return &zuc_cipher;
}

static int zuc256_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
	const unsigned char *iv, int enc)
{
	EVP_ZUC_KEY *dctx = EVP_C_DATA(EVP_ZUC_KEY, ctx);
	ZUC256_set_key(&dctx->ks, key, iv);
	return 1;
}

const EVP_CIPHER zuc256_cipher = {
	NID_zuc256,
	1,
	ZUC256_KEY_LENGTH,
	ZUC256_IV_LENGTH,
	0,
	zuc256_init_key,
	zuc_do_cipher,
	NULL,
	sizeof(EVP_ZUC_KEY),
	NULL,NULL,NULL,NULL,
};

const EVP_CIPHER *EVP_zuc256(void)
{
	return &zuc256_cipher;
}

#endif /* OPENSSL_NO_ZUC */
