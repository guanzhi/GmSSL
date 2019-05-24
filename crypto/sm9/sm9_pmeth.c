/* ====================================================================
 * Copyright (c) 2015 - 2018 The GmSSL Project.  All rights reserved.
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
#include <openssl/sm9.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/asn1t.h>
#include <openssl/objects.h>
#include "internal/cryptlib.h"
#include "internal/asn1_int.h"
#include "internal/evp_int.h"
#include "sm9_lcl.h"

typedef struct {
	int pairing; /* NID_sm9bn256v1 */
	int scheme; /* NID_sm9[sign|encrypt|keyagreement] */
	int hash1; /* NID_sm9hash1_with_[sm3|sha256] */
	int sign_scheme; /* NID_sm9sign_with_[sm3|sha256] */
	int encrypt_scheme; /*NID_sm9encrypt */
	char *id;
} SM9_MASTER_PKEY_CTX;

static int pkey_sm9_master_init(EVP_PKEY_CTX *ctx)
{
	SM9_MASTER_PKEY_CTX *dctx;
	if (!(dctx = OPENSSL_zalloc(sizeof(*dctx)))) {
		SM9err(SM9_F_PKEY_SM9_MASTER_INIT, ERR_R_MALLOC_FAILURE);
		return 0;
	}

	dctx->pairing = NID_sm9bn256v1;
	dctx->scheme = NID_sm9encrypt;
	dctx->hash1 = NID_sm9hash1_with_sm3;
	dctx->sign_scheme = NID_sm3;
	dctx->encrypt_scheme = NID_sm9encrypt_with_sm3_xor;
	dctx->id = NULL;

	ctx->data = dctx;
	return 1;
}

static int pkey_sm9_master_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
	SM9_MASTER_PKEY_CTX *dctx, *sctx;
	if (!pkey_sm9_master_init(dst))
		return 0;
	sctx = src->data;
	dctx = dst->data;
	*dctx = *sctx;
	if (!(dctx->id = OPENSSL_strdup(sctx->id))) {
		SM9err(SM9_F_PKEY_SM9_MASTER_COPY, ERR_R_MALLOC_FAILURE);
		return 0;
	}
	return 1;
}

static void pkey_sm9_master_cleanup(EVP_PKEY_CTX *ctx)
{
	SM9_MASTER_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
	if (dctx) {
		OPENSSL_free(dctx->id);
		OPENSSL_free(dctx);
	}
}

static int pkey_sm9_master_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
	SM9_MASTER_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
	SM9_MASTER_KEY *sm9_master;

	if (!(sm9_master = SM9_generate_master_secret(dctx->pairing,
		dctx->scheme, dctx->hash1))) {
		SM9err(SM9_F_PKEY_SM9_MASTER_KEYGEN, ERR_R_SM9_LIB);
		return 0;
	}
	if (!EVP_PKEY_assign_SM9_MASTER(pkey, sm9_master)) {
		SM9err(SM9_F_PKEY_SM9_MASTER_KEYGEN, ERR_R_EVP_LIB);
		SM9_MASTER_KEY_free(sm9_master);
		return 0;
	}
	return 1;
}

static int pkey_sm9_master_verify(EVP_PKEY_CTX *ctx,
	const unsigned char *sig, size_t siglen,
	const unsigned char *tbs, size_t tbslen)
{
	int ret;
	SM9_MASTER_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
	SM9_MASTER_KEY *sm9_master = EVP_PKEY_get0_SM9_MASTER(
		EVP_PKEY_CTX_get0_pkey(ctx));

	if (OBJ_obj2nid(sm9_master->scheme) != NID_sm9sign) {
		SM9err(SM9_F_PKEY_SM9_MASTER_VERIFY, SM9_R_INVALID_KEY_USAGE);
		return 0;
	}
	if (!dctx->id) {
		SM9err(SM9_F_PKEY_SM9_MASTER_VERIFY, SM9_R_SIGNER_ID_REQUIRED);
		return 0;
	}

	if ((ret = SM9_verify(dctx->sign_scheme, tbs, tbslen, sig, siglen,
		sm9_master, dctx->id, strlen(dctx->id))) < 0) {
		SM9err(SM9_F_PKEY_SM9_MASTER_VERIFY, ERR_R_SM9_LIB);
	}
	return ret;
}

static int pkey_sm9_master_encrypt(EVP_PKEY_CTX *ctx,
	unsigned char *out, size_t *outlen,
	const unsigned char *in, size_t inlen)
{
	SM9_MASTER_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
	SM9_MASTER_KEY *sm9_master = EVP_PKEY_get0_SM9_MASTER(
		EVP_PKEY_CTX_get0_pkey(ctx));

	if (OBJ_obj2nid(sm9_master->scheme) != NID_sm9encrypt) {
		SM9err(SM9_F_PKEY_SM9_MASTER_ENCRYPT, SM9_R_INVALID_KEY_USAGE);
		return 0;
	}

	if (!dctx->id) {
		SM9err(SM9_F_PKEY_SM9_MASTER_ENCRYPT, SM9_R_IDENTITY_REQUIRED);
		return 0;
	}

	if (!SM9_encrypt(dctx->encrypt_scheme, in, inlen, out, outlen,
		sm9_master, dctx->id, strlen(dctx->id))) {
		SM9err(SM9_F_PKEY_SM9_MASTER_ENCRYPT, ERR_R_SM9_LIB);
		return 0;
	}

	return 1;
}

static int pkey_sm9_master_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen)
{
	SM9_MASTER_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
	SM9_MASTER_KEY *sm9_master = EVP_PKEY_get0_SM9_MASTER(
		EVP_PKEY_CTX_get0_pkey(ctx));

	return -2;
}

static int pkey_sm9_master_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
	SM9_MASTER_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);

	switch (type) {
	case EVP_PKEY_CTRL_SM9_PAIRING:
		if (p1 == -2)
			return dctx->pairing;
		if (!sm9_check_pairing(p1)) {
		}
		dctx->pairing = p1;
		return 1;

	case EVP_PKEY_CTRL_SM9_SCHEME:
		if (p1 == -2)
			return dctx->scheme;
		if (!sm9_check_scheme(p1)) {
			SM9err(SM9_F_PKEY_SM9_MASTER_CTRL, SM9_R_INVALID_SCHEME);
			return 0;
		}
		dctx->scheme = p1;
		return 1;

	case EVP_PKEY_CTRL_SM9_HASH1:
		if (p1 == -2)
			return dctx->hash1;
		if (!sm9_check_hash1(p1)) {
			SM9err(SM9_F_PKEY_SM9_MASTER_CTRL, SM9_R_INVALID_HASH1);
			return 0;
		}
		dctx->hash1 = p1;
		return 1;

	case EVP_PKEY_CTRL_SM9_ID:
		if (!p2 || !strlen((char *)p2) || strlen((char *)p2) > SM9_MAX_ID_LENGTH) {
			SM9err(SM9_F_PKEY_SM9_MASTER_CTRL, SM9_R_INVALID_ID);
			return 0;
		} else {
			char *id = NULL;
			if (!(id = OPENSSL_strdup((char *)p2))) {
				SM9err(SM9_F_PKEY_SM9_MASTER_CTRL, ERR_R_MALLOC_FAILURE);
			}
			if (dctx->id) {
				OPENSSL_free(dctx->id);
			}
			dctx->id = id;
		}
		return 1;

	case EVP_PKEY_CTRL_GET_SM9_ID:
		*(const char **)p2 = dctx->id;
		return 1;
	}

	return -2;
}

static int pkey_sm9_master_ctrl_str(EVP_PKEY_CTX *ctx, const char *type, const char *value)
{
	if (!strcmp(type, "pairing")) {
		int nid = OBJ_txt2nid(value);
		if (!sm9_check_pairing(nid)) {
			SM9err(SM9_F_PKEY_SM9_MASTER_CTRL_STR, SM9_R_INVALID_PAIRING);
			return 0;
		}
		return EVP_PKEY_CTX_set_sm9_pairing(ctx, nid);

	} else if (!strcmp(type, "scheme")) {
		int nid = OBJ_txt2nid(value);
		if (!sm9_check_scheme(nid)) {
			SM9err(SM9_F_PKEY_SM9_MASTER_CTRL_STR, SM9_R_INVALID_SM9_SCHEME);
			return 0;
		}
		return EVP_PKEY_CTX_set_sm9_scheme(ctx, nid);

	} else if (!strcmp(type, "hash1")) {
		int nid = OBJ_txt2nid(value);
		if (!sm9_check_hash1(nid)) {
			SM9err(SM9_F_PKEY_SM9_MASTER_CTRL_STR, SM9_R_INVALID_SM9_SCHEME);
			return 0;
		}
		return EVP_PKEY_CTX_set_sm9_hash1(ctx, nid);

	} else if (!strcmp(type, "id")) {
		return EVP_PKEY_CTX_set_sm9_id(ctx, value);
	}

	return -2;
}

const EVP_PKEY_METHOD sm9_master_pkey_meth = {
	EVP_PKEY_SM9_MASTER,		/* pkey_id */
	0,				/* flags */
	pkey_sm9_master_init,		/* init */
	pkey_sm9_master_copy,		/* copy */
	pkey_sm9_master_cleanup,	/* cleanup */
	NULL,				/* paramgen_init */
	NULL,				/* paramgen */
	NULL,				/* keygen_init */
	pkey_sm9_master_keygen,		/* keygen */
	NULL,				/* sign_init */
	NULL,				/* sign */
	NULL,				/* verify_init */
	pkey_sm9_master_verify,		/* verify */
	NULL,				/* verify_recover_init */
	NULL,				/* verify_recover */
	NULL,				/* signctx_init */
	NULL,				/* signctx */
	NULL,				/* verifyctx_init */
	NULL,				/* verifyctx */
	NULL,				/* encrypt_init */
	pkey_sm9_master_encrypt,	/* encrypt */
	NULL,				/* decrypt_init */
	NULL,				/* decrypt */
	NULL,				/* derive_init */
	pkey_sm9_master_derive,		/* derive */
	pkey_sm9_master_ctrl,		/* ctrl */
	pkey_sm9_master_ctrl_str,	/* ctrl_str */
};

typedef struct {
	int sign_scheme;
	int encrypt_scheme;
	char *id;
} SM9_PKEY_CTX;

static int pkey_sm9_init(EVP_PKEY_CTX *ctx)
{
	SM9_PKEY_CTX *dctx;
	if (!(dctx = OPENSSL_zalloc(sizeof(*dctx)))) {
		SM9err(SM9_F_PKEY_SM9_INIT, ERR_R_MALLOC_FAILURE);
		return 0;
	}
	dctx->sign_scheme = NID_sm3; // FIXME: some like NID_sm9sign_sm3 			
	dctx->encrypt_scheme = NID_sm9encrypt_with_sm3_xor;
	dctx->id = NULL;
	OPENSSL_assert(EVP_PKEY_CTX_get_data(ctx) == NULL);
	(void)EVP_PKEY_CTX_set_data(ctx, dctx);
	return 1;
}

static int pkey_sm9_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
	SM9_PKEY_CTX *dctx, *sctx;
	if (!pkey_sm9_init(dst)) {
		SM9err(SM9_F_PKEY_SM9_COPY, ERR_R_SM9_LIB);
		return 0;
	}
	sctx = EVP_PKEY_CTX_get_data(src);
	dctx = EVP_PKEY_CTX_get_data(dst);
	*dctx = *sctx;
	if (!(dctx->id = OPENSSL_strdup(sctx->id))) {
		return 0;
	}
	return 1;
}

static void pkey_sm9_cleanup(EVP_PKEY_CTX *ctx)
{
	SM9_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
	if (dctx) {
		OPENSSL_free(dctx->id);
		OPENSSL_free(dctx);
	}
}

static int pkey_sm9_sign(EVP_PKEY_CTX *ctx,
	unsigned char *sig, size_t *siglen,
	const unsigned char *tbs, size_t tbslen)
{
	SM9_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
	SM9_KEY *sm9 = EVP_PKEY_get0_SM9(EVP_PKEY_CTX_get0_pkey(ctx));
	if (!SM9_sign(dctx->sign_scheme, tbs, tbslen, sig, siglen, sm9)) {
		SM9err(SM9_F_PKEY_SM9_SIGN, ERR_R_SM9_LIB);
		return 0;
	}
	return 1;
}

static int pkey_sm9_decrypt(EVP_PKEY_CTX *ctx,
	unsigned char *out, size_t *outlen,
	const unsigned char *in, size_t inlen)
{
	SM9_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
	SM9_KEY *sm9 = EVP_PKEY_get0_SM9(EVP_PKEY_CTX_get0_pkey(ctx));
	if (!SM9_decrypt(dctx->encrypt_scheme, in, inlen,
		out, outlen, sm9)) {
		SM9err(SM9_F_PKEY_SM9_DECRYPT, ERR_R_SM9_LIB);
		return 0;
	}
	return 1;
}

static int pkey_sm9_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen)
{
	return -2;
}

static int pkey_sm9_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
	SM9_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);

	switch (type) {
	case EVP_PKEY_CTRL_SM9_SIGN_SCHEME:
		if (p1 == -2)
			return dctx->sign_scheme;
		if (!sm9_check_sign_scheme(p1)) {
			SM9err(SM9_F_PKEY_SM9_CTRL, SM9_R_INVALID_SIGN_SCHEME);
			return 0;
		}
		dctx->sign_scheme = p1;
		return 1;

	case EVP_PKEY_CTRL_SM9_ENCRYPT_SCHEME:
		if (p1 == -2)
			return dctx->encrypt_scheme;
		if (!sm9_check_encrypt_scheme(p1)) {
			SM9err(SM9_F_PKEY_SM9_CTRL, SM9_R_INVALID_ENCRYPT_SCHEME);
			return 0;
		}
		dctx->encrypt_scheme = p1;
		return 1;

	case EVP_PKEY_CTRL_SM9_ID:
		if (!p2 || !strlen((char *)p2) || strlen((char *)p2) > SM9_MAX_ID_LENGTH) {
			return 0;
		} else {
		}
		return 1;

	case EVP_PKEY_CTRL_GET_SM9_ID:
		*(const char **)p2 = dctx->id;
		return 1;

	default:
		return -2;
	}

	return -2;
}

static int pkey_sm9_ctrl_str(EVP_PKEY_CTX *ctx, const char *type, const char *value)
{
	if (!strcmp(type, "sign_scheme")) {
		int nid = OBJ_txt2nid(value);
		if (!sm9_check_sign_scheme(nid)) {
			SM9err(SM9_F_PKEY_SM9_CTRL_STR, SM9_R_INVALID_SIGN_MD);
			return 0;
		}
		return EVP_PKEY_CTX_set_sm9_sign_scheme(ctx, nid);

	} else if (!strcmp(type, "encrypt_scheme")) {
		int nid = OBJ_txt2nid(value);
		if (!sm9_check_encrypt_scheme(nid)) {
			SM9err(SM9_F_PKEY_SM9_CTRL_STR, SM9_R_INVALID_ENCRYPT_SCHEME);
			return 0;
		}
		return EVP_PKEY_CTX_set_sm9_encrypt_scheme(ctx, nid);

	} else if (!strcmp(type, "id")) {
		return EVP_PKEY_CTX_set_sm9_id(ctx, value);
	}

	return -2;
}

/* TODO: currently data instead of dgst is signed.
 * we need to support to ctrl which to sign.
 */
const EVP_PKEY_METHOD sm9_pkey_meth = {
	EVP_PKEY_SM9,		/* pkey_id */
	0,			/* flags */
	pkey_sm9_init,		/* init */
	pkey_sm9_copy,		/* copy */
	pkey_sm9_cleanup,	/* cleanup */
	NULL,			/* paramgen_init */
	NULL,			/* paramgen */
	NULL,			/* keygen_init */
	NULL,			/* keygen */
	NULL,			/* sign_init */
	pkey_sm9_sign,		/* sign */
	NULL, 			/* verify_init */
	NULL,			/* verify */
	NULL,			/* verify_recover_init */
	NULL,			/* verify_recover */
	NULL,			/* signctx_init */
	NULL,			/* signctx */
	NULL,			/* verifyctx_init */
	NULL,			/* verifyctx */
	NULL,			/* encrypt_init */
	NULL,			/* encrypt */
	NULL,			/* decrypt_init */
	pkey_sm9_decrypt,	/* decrypt */
	NULL,			/* derive_init */
	pkey_sm9_derive,	/* derive */
	pkey_sm9_ctrl,		/* ctrl */
	pkey_sm9_ctrl_str,	/* ctrl_str */
};
