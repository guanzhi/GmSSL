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
#include <openssl/asn1t.h>
#include <openssl/paillier.h>
#include "internal/cryptlib.h"
#include "internal/asn1_int.h"
#include "internal/evp_int.h"


static int paillier_pub_encode(X509_PUBKEY *pubkey, const EVP_PKEY *pkey)
{
	unsigned char *penc = NULL;
	int penclen;

	if ((penclen = i2d_PAILLIER_PUBLIC_KEY(pkey->pkey.paillier, &penc)) < = 0) {
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

	if (!(paillier = d2i_PAILLIER_PUBLIC_KEY(NULL, &cp, len))) {
		PAILLIERerr(PAILLIER_F_PAILLIER_PUB_DECODE, ERR_R_PAILLIER_LIB);
		return 0;
	}

	EVP_PKEY_assign_PAILLIER(pkey, paillier);
	return 1;
}

static int paillier_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b)
{
	return -1;
}

const EVP_PKEY_ASN1_METHOD paillier_asn1_meth = {
	EVP_PKEY_PAILLIER,
	EVP_PKEY_PAILLIER,
	0, //FIXME

	"PAILLIER",
	"OpenSSL PAILLIER algorithm",

	paillier_pub_decode,
	paillier_pub_encode,
	paillier_pub_cmp,
	paillier_pub_print,

	paillier_priv_decode,
	paillier_priv_encode,
	paillier_priv_print,

	int_paillier_size,
	paillier_bits,
	paillier_security_bits,

	0, 0, 0, 0, 0, 0,
	0,

	int_paillier_free,
	paillier_pkey_ctrl,
	old_paillier_priv_decode,
	old_paillier_priv_encode
};
