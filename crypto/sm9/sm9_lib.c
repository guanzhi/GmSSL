/* ====================================================================
 * Copyright (c) 2016 The GmSSL Project.  All rights reserved.
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

#include <string.h>
#include <openssl/err.h>
#include <openssl/sm9.h>
#include <openssl/crypto.h>
#include <openssl/bn_hash.h>
#include "sm9_lcl.h"


#if 0
typedef struct {
	int nid;
	int nid;
} sm9_algor_table;


static const sm9_algor_table sm9encrypt_scheme_table[] = {
	{NID_sm9encrypt_with_sm3, NID_sm3},
	{NID_sm9encrypt_with_sha256, NID_sha256},
};

static const sm9_algoro_table sm9sign_scheme_table[] = {
	{NID_sm9sign_with_sm3, NID_sm3},
	{NID_sm9sign_with_sha256, NID_sha256},
};

static const sm9_algor_table sm9_encrypt_table[] = {
	{sm9encrypt-with-sm3-xor, NID_sm3, NID_undef},
	{sm9encrypt-with-sm3-sms4-cbc, NID_sm3, NID_sms4_cbc},
	{sm9encrypt-with-sm3-sms4-ctr, NID_sm3, NID_sms4_ctr},
};

static const sm9_algor sm9_hash1[] = {
	{NID_sm9hash1_with_sm3, NID_sm3},
	{NID_sm9hash1_with_sha256, NID_sha256},
	{NID_sm9kdf_with_sm3, NID_sm3},
	{NID_sm9kdf_with_sha256, NID_sha256},
};
#endif


SM9_MASTER_KEY *SM9_MASTER_KEY_new(void)
{
	SM9_MASTER_KEY *ret = NULL;

	if (!(ret = OPENSSL_zalloc(sizeof(*ret)))) {
		SM9err(SM9_F_SM9_MASTER_KEY_NEW, ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	return ret;
}

void SM9_MASTER_KEY_free(SM9_MASTER_KEY *key)
{
	if (key) {
		ASN1_OBJECT_free(key->pairing);
		ASN1_OBJECT_free(key->scheme);
		ASN1_OBJECT_free(key->hash1);
		ASN1_OCTET_STRING_free(key->pointPpub);
		BN_clear_free(key->masterSecret);
	}
	OPENSSL_clear_free(key, sizeof(*key));
}

SM9_KEY *SM9_KEY_new(void)
{
	SM9_KEY *ret = NULL;

	if (!(ret = OPENSSL_zalloc(sizeof(*ret)))) {
		SM9err(SM9_F_SM9_KEY_NEW, ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	return ret;
}

void SM9_KEY_free(SM9_KEY *key)
{
	if (key) {
		ASN1_OBJECT_free(key->pairing);
		ASN1_OBJECT_free(key->scheme);
		ASN1_OBJECT_free(key->hash1);
		ASN1_OCTET_STRING_free(key->pointPpub);
		ASN1_OCTET_STRING_free(key->identity);
		ASN1_OCTET_STRING_free(key->publicPoint);
	}
	OPENSSL_clear_free(key, sizeof(*key));
}


int SM9PrivateKey_get_gmtls_public_key(SM9PublicParameters *mpk,
	SM9PrivateKey *sk, unsigned char pub_key[1024])
{
	return 0;
}

int SM9PublicKey_get_gmtls_encoded(SM9PublicParameters *mpk,
	SM9PublicKey *pk, unsigned char encoded[1024])
{
	return 0;
}


int SM9_hash2(const EVP_MD *md, BIGNUM **r,
	const unsigned char *data, size_t datalen,
	const unsigned char *elem, size_t elemlen,
	const BIGNUM *range, BN_CTX *ctx)
{
	unsigned char *buf;

	if (!(buf = OPENSSL_malloc(datalen + elemlen))) {
		return 0;
	}
	memcpy(buf, data, datalen);
	memcpy(buf + datalen, elem, elemlen);

	if (!BN_hash_to_range(md, r, buf, datalen + elemlen, range, ctx)) {
		OPENSSL_free(buf);
		return 0;
	}

	OPENSSL_free(buf);
	return 1;
}

int SM9_DigestInit(EVP_MD_CTX *ctx, unsigned char prefix,
	const EVP_MD *md, ENGINE *impl)
{
	if (!EVP_DigestInit_ex(ctx, md, impl)
		|| !EVP_DigestUpdate(ctx, &prefix, 1)) {
		ERR_print_errors_fp(stderr);
		return 0;
	}
	return 1;
}

int SM9_MASTER_KEY_up_ref(SM9_MASTER_KEY *msk)
{
	int i;

	if (CRYPTO_atomic_add(&msk->references, 1,  &i, msk->lock) <= 0)
		return 0;

	REF_PRINT_COUNT("SM9_MASTER_KEY", msk);
	REF_ASSERT_ISNT(i < 2);
	return ((i > 1) ? 1 : 0);
}

int SM9_KEY_up_ref(SM9_KEY *sk)
{
	int i;

	if (CRYPTO_atomic_add(&sk->references, 1,  &i, sk->lock) <= 0)
		return 0;

	REF_PRINT_COUNT("SM9_KEY", sk);
	REF_ASSERT_ISNT(i < 2);
	return ((i > 1) ? 1 : 0);
}

int sm9_check_pairing(int nid)
{
	return 1;
}

int sm9_check_scheme(int nid)
{
	return 1;
}

int sm9_check_hash1(int nid)
{
	return 1;
}

int sm9_check_encrypt_scheme(int nid)
{
	return 1;
}

int sm9_check_sign_scheme(int nid)
{
	return 1;
}
