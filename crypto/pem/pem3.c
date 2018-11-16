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
#ifndef OPENSSL_NO_PKCS7
# include <openssl/pkcs7.h>
#endif
#include <openssl/pem.h>
#ifndef OPENSSL_NO_PAILLIER
# include <openssl/paillier.h>
#endif
#ifndef OPENSSL_NO_SM9
# include <openssl/sm9.h>
#endif


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

#endif /* OPENSSL_NO_PAILLIER */

#ifndef OPENSSL_NO_SM9
static SM9_MASTER_KEY *pkey_get_sm9_master(EVP_PKEY *key, SM9_MASTER_KEY **sm9_master)
{
	SM9_MASTER_KEY *rtmp;
	if (!key)
		return NULL;
	rtmp = EVP_PKEY_get1_SM9_MASTER(key);
	EVP_PKEY_free(key);
	if (!rtmp)
		return NULL;
	if (sm9_master) {
		SM9_MASTER_KEY_free(*sm9_master);
		*sm9_master = rtmp;
	}
	return rtmp;
}

SM9_MASTER_KEY *PEM_read_bio_SM9MasterSecret(BIO *bp, SM9_MASTER_KEY **sm9_master,
	pem_password_cb *cb, void *u)
{
	EVP_PKEY *pktmp;
	pktmp = PEM_read_bio_PrivateKey(bp, NULL, cb, u);
	return pkey_get_sm9_master(pktmp, sm9_master);
}

static SM9_KEY *pkey_get_sm9(EVP_PKEY *key, SM9_KEY **sm9)
{
	SM9_KEY *rtmp;
	if (!key)
		return NULL;
	rtmp = EVP_PKEY_get1_SM9(key);
	EVP_PKEY_free(key);
	if (!rtmp)
		return NULL;
	if (sm9) {
		SM9_KEY_free(*sm9);
		*sm9 = rtmp;
	}
	return rtmp;
}

SM9_KEY *PEM_read_bio_SM9PrivateKey(BIO *bp, SM9_KEY **sm9,
	pem_password_cb *cb, void *u)
{
	EVP_PKEY *pktmp;
	pktmp = PEM_read_bio_PrivateKey(bp, NULL, cb, u);
	return pkey_get_sm9(pktmp, sm9);
}

# ifndef OPENSSL_NO_STDIO
SM9_MASTER_KEY *PEM_read_SM9MasterSecret(FILE *fp, SM9_MASTER_KEY **sm9_master,
	pem_password_cb *cb, void *u)
{
	EVP_PKEY *pktmp;
	pktmp = PEM_read_PrivateKey(fp, NULL, cb, u);
	return pkey_get_sm9_master(pktmp, sm9_master);
}

SM9_KEY *PEM_read_SM9PrivateKey(FILE *fp, SM9_KEY **sm9,
	pem_password_cb *cb, void *u)
{
	EVP_PKEY *pktmp;
	pktmp = PEM_read_PrivateKey(fp, NULL, cb, u);
	return pkey_get_sm9(pktmp, sm9);
}
# endif

IMPLEMENT_PEM_write_cb_const(SM9MasterSecret, SM9_MASTER_KEY,
	PEM_STRING_SM9_MASTER, SM9MasterSecret)
IMPLEMENT_PEM_rw_const(SM9PublicParameters, SM9_MASTER_KEY,
	PEM_STRING_SM9_MASTER_PUBLIC, SM9PublicParameters)
IMPLEMENT_PEM_rw(SM9_MASTER_PUBKEY, SM9_MASTER_KEY,
	PEM_STRING_PUBLIC, SM9_MASTER_PUBKEY)

IMPLEMENT_PEM_write_cb_const(SM9PrivateKey, SM9_KEY,
	PEM_STRING_SM9, SM9PrivateKey)
IMPLEMENT_PEM_rw_const(SM9PublicKey, SM9_KEY,
	PEM_STRING_SM9_PUBLIC, SM9PublicKey)
IMPLEMENT_PEM_rw(SM9_PUBKEY, SM9_KEY,
	PEM_STRING_PUBLIC, SM9_PUBKEY)

#endif /* OPENSSL_NO_SM9 */
