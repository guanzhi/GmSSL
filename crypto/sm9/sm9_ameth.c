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


static int sm9_params_encode(X509_PUBKEY *pubkey, const EVP_PKEY *pkey)
{
	unsigned char *penc = NULL;
	int penclen;

	if ((penclen = i2d_SM9PublicParameters(pkey->pkey.sm9_master, &penc)) <= 0) {
		return 0;
	}
	OPENSSL_assert(pubkey);

	if (X509_PUBKEY_set0_param(pubkey, OBJ_nid2obj(EVP_PKEY_SM9_MASTER),
		V_ASN1_NULL, NULL, penc, penclen)) {
		return 1;
	}

	OPENSSL_free(penc);
	return 0;
}

static int sm9_params_decode(EVP_PKEY *pkey, X509_PUBKEY *pubkey)
{
	const unsigned char *cp;
	int len;
	SM9PublicParameters *sm9_params = NULL;

	if (!X509_PUBKEY_get0_param(NULL, &cp, &len, NULL, pubkey)) {
		return 0;
	}
	if (!(sm9_params = d2i_SM9PublicParameters(NULL, &cp, len))) {
		SM9err(SM9_F_SM9_PARAMS_DECODE, ERR_R_SM9_LIB);
		return 0;
	}

	EVP_PKEY_assign_SM9PublicParameters(pkey, sm9_params);
	return 1;
}

static int sm9_params_cmp(const EVP_PKEY *a, const EVP_PKEY *b)
{
	/*
	if (OBJ_cmp(a->pkey.sm9_master->pairing, b->pkey.sm9_master->pairing) != 0
		|| OBJ_cmp(a->pkey.sm9_master->scheme, b->pkey.sm9_master->scheme) != 0
		|| OBJ_cmp(a->pkey.sm9_master->hash1, b->pkey.sm9_master->hash1) != 0
		|| ASN1_OCTET_STRING_cmp(a->pkey.sm9_master->pointPpub,
			b->pkey.sm9_master->pointPpub) != 0) {
		return 0;
	}
	*/
	return 1;
}

static int do_sm9_master_print(BIO *bp, const SM9MasterSecret *x, int off, int priv)
{
	return -2;
}

static int sm9_params_print(BIO *bp, const EVP_PKEY *pkey, int indent,
	ASN1_PCTX *ctx)
{
	return do_sm9_master_print(bp, pkey->pkey.sm9_master, indent, 0);
}

static int sm9_master_print(BIO *bp, const EVP_PKEY *pkey, int indent,
	ASN1_PCTX *ctx)
{
	return do_sm9_master_print(bp, pkey->pkey.sm9_master, indent, 1);
}

static int sm9_master_decode(EVP_PKEY *pkey, const PKCS8_PRIV_KEY_INFO *p8)
{
	const unsigned char *p;
	int pklen;
	SM9MasterSecret *sm9_master;

	if (!PKCS8_pkey_get0(NULL, &p, &pklen, NULL, p8))
		return 0;
	if (!(sm9_master = d2i_SM9MasterSecret(NULL, &p, pklen))) {
		SM9err(SM9_F_SM9_MASTER_DECODE, ERR_R_SM9_LIB);
		return 0;
	}
	EVP_PKEY_assign_SM9MasterSecret(pkey, sm9_master);
	return 1;
}

static int sm9_master_encode(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pkey)
{
	unsigned char *rk = NULL;
	int rklen;

	if ((rklen = i2d_SM9MasterSecret(pkey->pkey.sm9_master, &rk)) <= 0) {
		SM9err(SM9_F_SM9_MASTER_ENCODE, ERR_R_MALLOC_FAILURE);
		return 0;
	}

	if (!PKCS8_pkey_set0(p8, OBJ_nid2obj(EVP_PKEY_SM9_MASTER), 0,
		V_ASN1_NULL, NULL, rk, rklen)) {
		SM9err(SM9_F_SM9_MASTER_ENCODE, ERR_R_MALLOC_FAILURE);
		return 0;
	}

	return 1;
}

static int int_sm9_size(const EVP_PKEY *pkey)
{
	return 32 * 12;
}

static int sm9_bits(const EVP_PKEY *pkey)
{
	return 256 * 12;
}

static int sm9_security_bits(const EVP_PKEY *pkey)
{
	return 256/2;
}

static void int_sm9_master_free(EVP_PKEY *pkey)
{
	SM9MasterSecret_free(pkey->pkey.sm9_master);
}

static int sm9_master_pkey_ctrl(EVP_PKEY *pkey, int op, long arg1, void *arg2)
{
	return -2;
}

static int old_sm9_master_decode(EVP_PKEY *pkey,
	const unsigned char **pder, int derlen)
{
	SM9MasterSecret *sm9_master;
	if ((sm9_master = d2i_SM9MasterSecret(NULL, pder, derlen)) == NULL) {
		SM9err(SM9_F_OLD_SM9_MASTER_DECODE, SM9_R_DECODE_ERROR);
		return 0;
	}
	EVP_PKEY_assign_SM9MasterSecret(pkey, sm9_master);
	return 1;
}

static int old_sm9_master_encode(const EVP_PKEY *pkey, unsigned char **pder)
{
	return i2d_SM9MasterSecret(pkey->pkey.sm9_master, pder);
}

const EVP_PKEY_ASN1_METHOD sm9_master_asn1_meth = {
	EVP_PKEY_SM9_MASTER,	/* pkey_id */
	EVP_PKEY_SM9_MASTER,	/* pkey_base_id */
	0,			/* pkey_flags */
	"SM9 MASTER",		/* pem_str */
	"GmSSL SM9 system algorithm", /* info */
	sm9_params_decode,	/* pub_decode */
	sm9_params_encode,	/* pub_encode */
	sm9_params_cmp,		/* pub_cmp */
	sm9_params_print,	/* pub_print */
	sm9_master_decode,	/* priv_decode */
	sm9_master_encode,	/* priv_encode */
	sm9_master_print,	/* priv_print */
	int_sm9_size,		/* pkey_size */
	sm9_bits,		/* pkey_bits */
	sm9_security_bits,	/* pkey_security_bits */
	NULL,			/* param_decode */
	NULL,			/* param_encode */
	NULL,			/* param_missing */
	NULL,			/* param_copy */
	NULL,			/* param_cmp */
	NULL,			/* param_print */
	NULL,			/* sig_print */
	int_sm9_master_free,	/* pkey_free */
	sm9_master_pkey_ctrl,	/* pkey_ctrl */
	old_sm9_master_decode,	/* old_priv_decode */
	old_sm9_master_encode,	/* old_priv_encode */
	NULL,			/* item_verify */
	NULL,			/* item_sign */
};

static int sm9_pub_encode(X509_PUBKEY *pubkey, const EVP_PKEY *pkey)
{
	unsigned char *penc = NULL;
	int penclen;

	if ((penclen = i2d_SM9PublicKey(pkey->pkey.sm9, &penc)) <= 0) {
		return 0;
	}
	if (X509_PUBKEY_set0_param(pubkey, OBJ_nid2obj(EVP_PKEY_SM9),
				   V_ASN1_NULL, NULL, penc, penclen)) {
		return 1;
	}

	OPENSSL_free(penc);
	return 0;
}

static int sm9_pub_decode(EVP_PKEY *pkey, X509_PUBKEY *pubkey)
{
	const unsigned char *cp;
	int len;
	SM9PublicKey *sm9 = NULL;

	if (!X509_PUBKEY_get0_param(NULL, &cp, &len, NULL, pubkey)) {
		return 0;
	}
	if (!(sm9 = d2i_SM9PublicKey(NULL, &cp, len))) {
		SM9err(SM9_F_SM9_PUB_DECODE, ERR_R_SM9_LIB);
		return 0;
	}

	EVP_PKEY_assign_SM9PublicKey(pkey, sm9);
	return 1;
}

static int sm9_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b)
{
	const SM9PublicKey *ax = a->pkey.sm9;
	const SM9PublicKey *bx = b->pkey.sm9;
	if (OBJ_cmp(ax->pairing, bx->pairing)
		|| OBJ_cmp(ax->scheme, bx->scheme)
		|| OBJ_cmp(ax->hash1, bx->hash1)
		/* FIXME: decode point then compare to support point compression */
		|| ASN1_OCTET_STRING_cmp(ax->pointPpub, bx->pointPpub)
		|| ASN1_OCTET_STRING_cmp(ax->identity, bx->identity)
		|| ASN1_OCTET_STRING_cmp(ax->publicPoint, bx->publicPoint)) {
		return 0;
	}
	return 1;
}

static int do_sm9_print(BIO *bp, const SM9PrivateKey *x, int off, int priv)
{
	return -2;
}

static int sm9_pub_print(BIO *bp, const EVP_PKEY *pkey, int indent,
	ASN1_PCTX *ctx)
{
	return do_sm9_print(bp, pkey->pkey.sm9, indent, 0);
}

static int sm9_priv_print(BIO *bp, const EVP_PKEY *pkey, int indent,
	ASN1_PCTX *ctx)
{
	return do_sm9_print(bp, pkey->pkey.sm9, indent, 1);
}

static int sm9_priv_decode(EVP_PKEY *pkey, const PKCS8_PRIV_KEY_INFO *p8)
{
	const unsigned char *p;
	int pklen;
	SM9PrivateKey *sm9;

	if (!PKCS8_pkey_get0(NULL, &p, &pklen, NULL, p8))
		return 0;
	if (!(sm9 = d2i_SM9PrivateKey(NULL, &p, pklen))) {
		SM9err(SM9_F_SM9_PRIV_DECODE, ERR_R_SM9_LIB);
		return 0;
	}
	EVP_PKEY_assign_SM9PrivateKey(pkey, sm9);
	return 1;
}

static int sm9_priv_encode(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pkey)
{
	unsigned char *rk = NULL;
	int rklen;

	if ((rklen = i2d_SM9PrivateKey(pkey->pkey.sm9, &rk)) <= 0) {
		SM9err(SM9_F_SM9_PRIV_ENCODE, ERR_R_MALLOC_FAILURE);
		return 0;
	}

	if (!PKCS8_pkey_set0(p8, OBJ_nid2obj(EVP_PKEY_SM9), 0,
			     V_ASN1_NULL, NULL, rk, rklen)) {
		SM9err(SM9_F_SM9_PRIV_ENCODE, ERR_R_MALLOC_FAILURE);
		return 0;
	}

	return 1;
}

static void int_sm9_free(EVP_PKEY *pkey)
{
	SM9PrivateKey_free(pkey->pkey.sm9);
}

static int sm9_pkey_ctrl(EVP_PKEY *pkey, int op, long arg1, void *arg2)
{
	return -2;
}

static int old_sm9_priv_decode(EVP_PKEY *pkey,
	const unsigned char **pder, int derlen)
{
	SM9PrivateKey *sm9;
	if ((sm9 = d2i_SM9PrivateKey(NULL, pder, derlen)) == NULL) {
		SM9err(SM9_F_OLD_SM9_PRIV_DECODE, SM9_R_DECODE_ERROR);
		return 0;
	}
	EVP_PKEY_assign_SM9PrivateKey(pkey, sm9);
	return 1;
}

static int old_sm9_priv_encode(const EVP_PKEY *pkey, unsigned char **pder)
{
	return i2d_SM9PrivateKey(pkey->pkey.sm9, pder);
}

const EVP_PKEY_ASN1_METHOD sm9_asn1_meth = {
	EVP_PKEY_SM9,		/* pkey_id */
	EVP_PKEY_SM9,		/* pkey_base_id */
	0,			/* pkey_flags */
	"SM9",			/* pem_str */
	"GmSSL SM9 algorithm",	/* info */
	sm9_pub_decode,		/* pub_decode */
	sm9_pub_encode,		/* pub_encode */
	sm9_pub_cmp,		/* pub_cmp */
	sm9_pub_print,		/* pub_print */
	sm9_priv_decode,	/* priv_decode */
	sm9_priv_encode,	/* priv_encode */
	sm9_priv_print,		/* priv_print */
	int_sm9_size,		/* pkey_size */
	sm9_bits,		/* pkey_bits */
	sm9_security_bits,	/* pkey_security_bits */
	NULL,			/* param_decode */
	NULL,			/* param_encode */
	NULL,			/* param_missing */
	NULL,			/* param_copy */
	NULL,			/* param_cmp */
	NULL,			/* param_print */
	NULL,			/* sig_print */
	int_sm9_free,		/* pkey_free */
	sm9_pkey_ctrl,		/* pkey_ctrl */
	old_sm9_priv_decode,	/* old_priv_decode */
	old_sm9_priv_encode,	/* old_priv_encode */
	NULL,			/* item_verify */
	NULL,			/* item_sign */
};
