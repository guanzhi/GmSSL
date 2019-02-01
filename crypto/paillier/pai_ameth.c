/* ====================================================================
 * Copyright (c) 2015 - 2017 The GmSSL Project.  All rights reserved.
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
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/asn1t.h>
#include <openssl/objects.h>
#include <openssl/paillier.h>
#include "internal/cryptlib.h"
#include "internal/asn1_int.h"
#include "internal/evp_int.h"
#include "pai_lcl.h"


static int paillier_pub_encode(X509_PUBKEY *pubkey, const EVP_PKEY *pkey)
{
	unsigned char *penc = NULL;
	int penclen;

	if ((penclen = i2d_PaillierPublicKey(pkey->pkey.paillier, &penc)) <= 0) {
		return 0;
	}
	if (X509_PUBKEY_set0_param(pubkey, OBJ_nid2obj(EVP_PKEY_PAILLIER),
		V_ASN1_NULL, NULL, penc, penclen)) {
		return 1;
	}

	OPENSSL_free(penc);
	return 0;
}

static int paillier_pub_decode(EVP_PKEY *pkey, X509_PUBKEY *pubkey)
{
	const unsigned char *cp;
	int len;
	PAILLIER *paillier = NULL;

	if (!X509_PUBKEY_get0_param(NULL, &cp, &len, NULL, pubkey)) {
		return 0;
	}
	if (!(paillier = d2i_PaillierPublicKey(NULL, &cp, len))) {
		PAILLIERerr(PAILLIER_F_PAILLIER_PUB_DECODE, ERR_R_PAILLIER_LIB);
		return 0;
	}

	EVP_PKEY_assign_PAILLIER(pkey, paillier);
	return 1;
}

static int paillier_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b)
{
	if (BN_cmp(a->pkey.paillier->n, b->pkey.paillier->n) != 0) {
		return 0;
	}
	return 1;
}

static int do_paillier_print(BIO *bp, const PAILLIER *x, int off, int priv)
{
	char *str;
	int ret = 0;
	int bits;

	if (!BIO_indent(bp, off, 128))
		goto end;

	bits = x->bits;
	if (bits == 0)
		bits = BN_num_bytes(x->n) * 8;

	if (priv && x->lambda) {
		if (BIO_printf(bp, "Private-Key: (%d bit)\n", bits) <= 0)
			goto end;
		str = "modulus";
	} else {
		if (BIO_printf(bp, "Public-Key: (%d bit)\n", bits) <= 0)
			goto end;
		str = "Modulus";
	}

	if (!ASN1_bn_print(bp, str, x->n, NULL, off))
		goto end;
	if (priv) {
		if (!ASN1_bn_print(bp, "lambda:", x->lambda, NULL, off))
			goto end;
		if (x->x && !ASN1_bn_print(bp, "x:", x->x, NULL, off))
			goto end;
	}
	ret = 1;

end:
	return ret;
}

static int paillier_pub_print(BIO *bp, const EVP_PKEY *pkey, int indent,
	ASN1_PCTX *ctx)
{
	return do_paillier_print(bp, pkey->pkey.paillier, indent, 0);
}

static int paillier_priv_print(BIO *bp, const EVP_PKEY *pkey, int indent,
	ASN1_PCTX *ctx)
{
	return do_paillier_print(bp, pkey->pkey.paillier, indent, 1);
}

static int paillier_priv_decode(EVP_PKEY *pkey, const PKCS8_PRIV_KEY_INFO *p8)
{
	const unsigned char *p;
	int pklen;
	PAILLIER *paillier;

	if (!PKCS8_pkey_get0(NULL, &p, &pklen, NULL, p8))
		return 0;
	if (!(paillier = d2i_PaillierPrivateKey(NULL, &p, pklen))) {
		PAILLIERerr(PAILLIER_F_PAILLIER_PRIV_DECODE, ERR_R_PAILLIER_LIB);
		return 0;
	}
	paillier->bits = BN_num_bytes(paillier->n) * 8;
	EVP_PKEY_assign_PAILLIER(pkey, paillier);
	return 1;
}

static int paillier_priv_encode(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pkey)
{
	unsigned char *rk = NULL;
	int rklen;

	if ((rklen = i2d_PaillierPrivateKey(pkey->pkey.paillier, &rk)) <= 0) {
		PAILLIERerr(PAILLIER_F_PAILLIER_PRIV_ENCODE, ERR_R_MALLOC_FAILURE);
		return 0;
	}

	if (!PKCS8_pkey_set0(p8, OBJ_nid2obj(NID_paillier), 0, V_ASN1_NULL, NULL,
		rk, rklen)) {
		PAILLIERerr(PAILLIER_F_PAILLIER_PRIV_ENCODE, ERR_R_MALLOC_FAILURE);
		return 0;
	}

	return 1;
}

static int int_paillier_size(const EVP_PKEY *pkey)
{
	return PAILLIER_size(pkey->pkey.paillier);
}

static int paillier_bits(const EVP_PKEY *pkey)
{
	return pkey->pkey.paillier->bits;
}

static int paillier_security_bits(const EVP_PKEY *pkey)
{
	return PAILLIER_security_bits(pkey->pkey.paillier);
}

static void int_paillier_free(EVP_PKEY *pkey)
{
	PAILLIER_free(pkey->pkey.paillier);
}

static int paillier_pkey_ctrl(EVP_PKEY *pkey, int op, long arg1, void *arg2)
{
	return -2;
}

static int old_paillier_priv_decode(EVP_PKEY *pkey,
	const unsigned char **pder, int derlen)
{
	PAILLIER *pai;
	if ((pai = d2i_PaillierPrivateKey(NULL, pder, derlen)) == NULL) {
		PAILLIERerr(PAILLIER_F_OLD_PAILLIER_PRIV_DECODE,
			PAILLIER_R_DECODE_ERROR);
		return 0;
	}
	EVP_PKEY_assign_PAILLIER(pkey, pai);
	return 1;
}

static int old_paillier_priv_encode(const EVP_PKEY *pkey, unsigned char **pder)
{
	return i2d_PaillierPrivateKey(pkey->pkey.paillier, pder);
}

const EVP_PKEY_ASN1_METHOD paillier_asn1_meth = {
	EVP_PKEY_PAILLIER,		/* pkey_id */
	EVP_PKEY_PAILLIER,		/* pkey_base_id */
	0,				/* pkey_flags */
	"PAILLIER",			/* pem_str */
	"GmSSL Paillier algorithm",	/* info */
	paillier_pub_decode,		/* pub_decode */
	paillier_pub_encode,		/* pub_encode */
	paillier_pub_cmp,		/* pub_cmp */
	paillier_pub_print,		/* pub_print */
	paillier_priv_decode,		/* priv_decode */
	paillier_priv_encode,		/* priv_encode */
	paillier_priv_print,		/* priv_print */
	int_paillier_size,		/* pkey_size */
	paillier_bits,			/* pkey_bits */
	paillier_security_bits,		/* pkey_security_bits */
	NULL,				/* param_decode */
	NULL,				/* param_encode */
	NULL,				/* param_missing */
	NULL,				/* param_copy */
	NULL,				/* param_cmp */
	NULL,				/* param_print */
	NULL,				/* sig_print */
	int_paillier_free,		/* pkey_free */
	paillier_pkey_ctrl,		/* pkey_ctrl */
	old_paillier_priv_decode,	/* old_priv_decode */
	old_paillier_priv_encode,	/* old_priv_encode */
	NULL,				/* item_verify */
	NULL,				/* item_sign */
};
