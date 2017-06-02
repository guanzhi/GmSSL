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

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>
#include <openssl/pem.h>
#include <openssl/pem3.h>
#include <openssl/paillier.h>

/*
extern PAILLIER *EVP_PKEY_get1_PAILLIER(EVP_PKEY *key);
extern int i2d_PAILLIER_PUBKEY(PAILLIER *a, unsigned char **p);
extern PAILLIER *d2i_PAILLIER_PUBKEY(PAILLIER **a, const unsigned char **p, long len);
*/

#ifndef OPENSSL_NO_PAILLIER
static PAILLIER *pkey_get_paillier(EVP_PKEY *key, PAILLIER **paillier)
{
	PAILLIER *rtmp;
	if (!key)
		return NULL;
	rtmp = EVP_PKEY_get1_PAILLIER(key);
	EVP_PKEY_free(key);
	if (!rtmp)
		return NULL;
	if (paillier) {
		PAILLIER_free(*paillier);
		*paillier = rtmp;
	}
	return rtmp;
}

PAILLIER *PEM_read_bio_PaillierPrivateKey(BIO *bp, PAILLIER **paillier,
	pem_password_cb *cb, void *u)
{
	EVP_PKEY *pktmp;
	pktmp = PEM_read_bio_PrivateKey(bp, NULL, cb, u);
	return pkey_get_paillier(pktmp, paillier);
}

# ifndef OPENSSL_NO_STDIO
PAILLIER *PEM_read_PaillierPrivateKey(FILE *fp, PAILLIER **paillier,
	pem_password_cb *cb, void *u)
{
	EVP_PKEY *pktmp;
	pktmp = PEM_read_PrivateKey(fp, NULL, cb, u);
	return pkey_get_paillier(pktmp, paillier);
}

# endif

IMPLEMENT_PEM_write_cb_const(PaillierPrivateKey, PAILLIER, PEM_STRING_PAILLIER,
	PaillierPrivateKey)
IMPLEMENT_PEM_rw_const(PaillierPublicKey, PAILLIER, PEM_STRING_PAILLIER_PUBLIC,
	PaillierPublicKey)
IMPLEMENT_PEM_rw(PAILLIER_PUBKEY, PAILLIER, PEM_STRING_PUBLIC, PAILLIER_PUBKEY)

#endif
