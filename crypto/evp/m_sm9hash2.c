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
#include "internal/cryptlib.h"

#ifndef OPENSSL_NO_SM9
# include <openssl/sm9.h>
# include <openssl/evp.h>
# include <openssl/x509.h>
# include <openssl/objects.h>
# include "internal/evp_int.h"

# ifndef OPENSSL_NO_SM3
#  include <openssl/sm3.h>

static int sm9hash2_sm3_init(EVP_MD_CTX *ctx)
{
	if (!ctx || !EVP_MD_CTX_md_data(ctx)) {
		return 0;
	}
	sm3_init(EVP_MD_CTX_md_data(ctx));
	return 1;
}

static int sm9hash2_sm3_update(EVP_MD_CTX *ctx, const void *in, size_t inlen)
{
	if (!ctx || !EVP_MD_CTX_md_data(ctx) || (!in && inlen != 0)) {
		return 0;
	}
	sm3_update(EVP_MD_CTX_md_data(ctx), in, inlen);
	return 1;
}

static int sm9hash2_sm3_final(EVP_MD_CTX *ctx, unsigned char *md)
{
	if (!ctx || !EVP_MD_CTX_md_data(ctx) || !md) {
		return 0;
	}
	sm3_final(EVP_MD_CTX_md_data(ctx), md);
	return 1;
}

int sm9hash2_sm3_ctrl(EVP_MD_CTX *ctx, int cmd, int p1, void *p2)
{
	return 0;
}

# define SM9HASH2_SM3_CTX_SIZE (sizeof(EVP_MD *) + sizeof(sm3_ctx_t))

static const EVP_MD sm9hash2_sm3 = {
	NID_sm9hash2_with_sm3,	/* type */
	NID_sm9sign_with_sm3,	/* pkey_type */
	SM3_DIGEST_LENGTH,	/* md_size */
	0,			/* flags */
	sm9hash2_sm3_init,	/* init */
	sm9hash2_sm3_update,	/* update */
	sm9hash2_sm3_final,	/* final */
	NULL,			/* copy */
	NULL,			/* cleanup */
	SM3_BLOCK_SIZE,		/* block_size */
	SM9HASH2_SM3_CTX_SIZE,	/* ctx_size */
	sm9hash2_sm3_ctrl,	/* md_ctrl */
};

const EVP_MD *EVP_sm9hash2_sm3(void)
{
        return &sm9hash2_sm3;
}

# endif /* OPENSSL_NO_SM3 */

# ifndef OPENSSL_NO_SHA256
#  include <openssl/sha.h>

static int sm9hash2_sha256_init(EVP_MD_CTX *ctx)
{
	return 0;
}

static int sm9hash2_sha256_update(EVP_MD_CTX *ctx, const void *in, size_t inlen)
{
	return 0;
}

static int sm9hash2_sha256_final(EVP_MD_CTX *ctx, unsigned char *md)
{
	return 0;
}

int sm9hash2_sha256_ctrl(EVP_MD_CTX *ctx, int cmd, int p1, void *p2)
{
	return 0;
}

#define SM9HASH2_SHA256_CTX_SIZE (sizeof(EVP_MD *) + sizeof(SHA256_CTX))

static const EVP_MD sm9hash2_sha256 = {
	NID_sm9hash2_with_sha256,	/* type */
	NID_sm9sign_with_sha256,	/* pkey_type */
	SHA256_DIGEST_LENGTH,		/* md_size */
	0,				/* flags */
	sm9hash2_sha256_init,		/* init */
	sm9hash2_sha256_update,		/* update */
	sm9hash2_sha256_final,		/* final */
	NULL,				/* copy */
	NULL,				/* cleanup */
	SHA256_CBLOCK,			/* block_size */
	SM9HASH2_SHA256_CTX_SIZE,	/* ctx_size */
	sm9hash2_sha256_ctrl,		/* md_ctrl */
};

const EVP_MD *EVP_sm9hash2_sha256(void)
{
        return &sm9hash2_sha256;
}
# endif /* OPENSSL_NO_SHA256 */

#endif /* OPENSSL_NO_SM9 */
