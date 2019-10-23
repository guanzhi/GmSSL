/*
 * Copyright (c) 2017 - 2018 The GmSSL Project.  All rights reserved.
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
 */

/* +build cgo */
package gmssl

/*
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/ec.h>
#include <openssl/sm2.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/objects.h>
#include <openssl/opensslconf.h>

extern long _BIO_get_mem_data(BIO *bio, char **pp);

EVP_PKEY_CTX *new_pkey_keygen_ctx(const char *alg, ENGINE *e) {
	EVP_PKEY_CTX *ret = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	const EVP_PKEY_ASN1_METHOD *ameth;
	ENGINE *eng = NULL;
	int pkey_id;

	if (!(ameth = EVP_PKEY_asn1_find_str(&eng, alg, -1))) {
		return NULL;
	}
	EVP_PKEY_asn1_get0_info(&pkey_id, NULL, NULL, NULL, NULL, ameth);
	ENGINE_finish(eng);
	if (!(ctx = EVP_PKEY_CTX_new_id(pkey_id, e))) {
		goto end;
	}
	ret = ctx;
	ctx = NULL;
end:
	EVP_PKEY_CTX_free(ctx);
	return ret;
}

EVP_PKEY *pem_read_bio_pubkey(BIO *bio) {
	return PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
}

int pem_write_bio_pubkey(BIO *bio, EVP_PKEY *pkey) {
	return PEM_write_bio_PUBKEY(bio, pkey);
}

int pem_write_bio_privatekey(BIO *bio, EVP_PKEY *pkey,
	const EVP_CIPHER *cipher, const char *pass) {
	return PEM_write_bio_PrivateKey(bio, pkey, cipher, NULL, 0, NULL, (void *)pass);
}

int sign_nids[] = {
#ifndef OPENSSL_NO_SM2
	NID_sm2sign,
#endif
	NID_ecdsa_with_Recommended,
#ifndef OPENSSL_NO_SHA
	NID_ecdsa_with_SHA1,
	NID_ecdsa_with_SHA256,
	NID_ecdsa_with_SHA512,
# ifndef OPENSSL_NO_RSA
	NID_sha1WithRSAEncryption,
	NID_sha256WithRSAEncryption,
	NID_sha512WithRSAEncryption,
# endif
# ifndef OPENSSL_NO_DSA
	NID_dsaWithSHA1,
# endif
#endif
};

static int get_sign_info(const char *alg, int *ppkey_type,
	const EVP_MD **pmd, int *pec_scheme)
{
	int pkey_type;
	const EVP_MD *md = NULL;
	int ec_scheme = -1;

	switch (OBJ_txt2nid(alg)) {
	case NID_sm2sign:
		pkey_type = EVP_PKEY_EC;
		ec_scheme = NID_sm_scheme;
		break;
	case NID_ecdsa_with_Recommended:
		pkey_type = EVP_PKEY_EC;
		ec_scheme = NID_secg_scheme;
		break;
	case NID_ecdsa_with_SHA1:
		pkey_type = EVP_PKEY_EC;
		md = EVP_sha1();
		ec_scheme = NID_secg_scheme;
		break;
	case NID_ecdsa_with_SHA256:
		pkey_type = EVP_PKEY_EC;
		md = EVP_sha256();
		ec_scheme = NID_secg_scheme;
		break;
	case NID_ecdsa_with_SHA512:
		pkey_type = EVP_PKEY_EC;
		md = EVP_sha512();
		ec_scheme = NID_secg_scheme;
		break;
	case NID_sha1WithRSAEncryption:
		pkey_type = EVP_PKEY_RSA;
		md = EVP_sha1();
		break;
	case NID_sha256WithRSAEncryption:
		pkey_type = EVP_PKEY_RSA;
		md = EVP_sha256();
		break;
	case NID_sha512WithRSAEncryption:
		pkey_type = EVP_PKEY_RSA;
		md = EVP_sha512();
		break;
	case NID_dsaWithSHA1:
		pkey_type = EVP_PKEY_DSA;
		md = EVP_sha1();
		break;
	default:
		return 0;
	}

	*ppkey_type = pkey_type;
	*pmd = md;
	*pec_scheme = ec_scheme;

	return 1;
}

int pke_nids[] = {
#ifndef OPENSSL_NO_RSA
	NID_rsaesOaep,
#endif
#ifndef OPENSSL_NO_ECIES
	NID_ecies_recommendedParameters,
	NID_ecies_specifiedParameters,
# ifndef OPENSSL_NO_SHA
	NID_ecies_with_x9_63_sha1_xor_hmac,
	NID_ecies_with_x9_63_sha256_xor_hmac,
	NID_ecies_with_x9_63_sha512_xor_hmac,
	NID_ecies_with_x9_63_sha1_aes128_cbc_hmac,
	NID_ecies_with_x9_63_sha256_aes128_cbc_hmac,
	NID_ecies_with_x9_63_sha512_aes256_cbc_hmac,
	NID_ecies_with_x9_63_sha256_aes128_ctr_hmac,
	NID_ecies_with_x9_63_sha512_aes256_ctr_hmac,
	NID_ecies_with_x9_63_sha256_aes128_cbc_hmac_half,
	NID_ecies_with_x9_63_sha512_aes256_cbc_hmac_half,
	NID_ecies_with_x9_63_sha256_aes128_ctr_hmac_half,
	NID_ecies_with_x9_63_sha512_aes256_ctr_hmac_half,
	NID_ecies_with_x9_63_sha1_aes128_cbc_cmac,
	NID_ecies_with_x9_63_sha256_aes128_cbc_cmac,
	NID_ecies_with_x9_63_sha512_aes256_cbc_cmac,
	NID_ecies_with_x9_63_sha256_aes128_ctr_cmac,
	NID_ecies_with_x9_63_sha512_aes256_ctr_cmac,
# endif
#endif
#ifndef OPENSSL_NO_SM2
	NID_sm2encrypt_with_sm3,
# ifndef OPENSSL_NO_SHA
	NID_sm2encrypt_with_sha1,
	NID_sm2encrypt_with_sha256,
	NID_sm2encrypt_with_sha512,
# endif
#endif
};

static int get_pke_info(const char *alg, int *ppkey_type,
	int *pec_scheme, int *pec_encrypt_param)
{
	int pkey_type = 0;
	int ec_scheme = 0;
	int ec_encrypt_param = 0;

	switch (OBJ_txt2nid(alg)) {
	case NID_rsaesOaep:
		pkey_type = EVP_PKEY_RSA;
		break;
	case NID_ecies_recommendedParameters:
	case NID_ecies_specifiedParameters:
	case NID_ecies_with_x9_63_sha1_xor_hmac:
	case NID_ecies_with_x9_63_sha256_xor_hmac:
	case NID_ecies_with_x9_63_sha512_xor_hmac:
	case NID_ecies_with_x9_63_sha1_aes128_cbc_hmac:
	case NID_ecies_with_x9_63_sha256_aes128_cbc_hmac:
	case NID_ecies_with_x9_63_sha512_aes256_cbc_hmac:
	case NID_ecies_with_x9_63_sha256_aes128_ctr_hmac:
	case NID_ecies_with_x9_63_sha512_aes256_ctr_hmac:
	case NID_ecies_with_x9_63_sha256_aes128_cbc_hmac_half:
	case NID_ecies_with_x9_63_sha512_aes256_cbc_hmac_half:
	case NID_ecies_with_x9_63_sha256_aes128_ctr_hmac_half:
	case NID_ecies_with_x9_63_sha512_aes256_ctr_hmac_half:
	case NID_ecies_with_x9_63_sha1_aes128_cbc_cmac:
	case NID_ecies_with_x9_63_sha256_aes128_cbc_cmac:
	case NID_ecies_with_x9_63_sha512_aes256_cbc_cmac:
	case NID_ecies_with_x9_63_sha256_aes128_ctr_cmac:
	case NID_ecies_with_x9_63_sha512_aes256_ctr_cmac:
		pkey_type = EVP_PKEY_EC;
		ec_scheme = NID_secg_scheme;
		ec_encrypt_param = OBJ_txt2nid(alg);
		break;
	case NID_sm2encrypt_with_sm3:
		pkey_type = EVP_PKEY_EC;
		ec_scheme = NID_sm_scheme;
		ec_encrypt_param = NID_sm3;
		break;
	case NID_sm2encrypt_with_sha1:
		pkey_type = EVP_PKEY_EC;
		ec_scheme = NID_sm_scheme;
		ec_encrypt_param = NID_sha1;
		break;
	case NID_sm2encrypt_with_sha256:
		pkey_type = EVP_PKEY_EC;
		ec_scheme = NID_sm_scheme;
		ec_encrypt_param = NID_sha256;
		break;
	case NID_sm2encrypt_with_sha512:
		pkey_type = EVP_PKEY_EC;
		ec_scheme = NID_sm_scheme;
		ec_encrypt_param = NID_sha512;
		break;
	default:
		return 0;
	}

	*ppkey_type = pkey_type;
	*pec_scheme = ec_scheme;
	*pec_encrypt_param = ec_encrypt_param;

	return 1;
}

int exch_nids[] = {
#ifndef OPENSSL_NO_SM2
	NID_sm2exchange,
#endif
#ifndef OPENSSL_NO_SHA
	NID_dhSinglePass_stdDH_sha1kdf_scheme,
	NID_dhSinglePass_stdDH_sha224kdf_scheme,
	NID_dhSinglePass_stdDH_sha256kdf_scheme,
	NID_dhSinglePass_stdDH_sha384kdf_scheme,
	NID_dhSinglePass_stdDH_sha512kdf_scheme,
	NID_dhSinglePass_cofactorDH_sha1kdf_scheme,
	NID_dhSinglePass_cofactorDH_sha224kdf_scheme,
	NID_dhSinglePass_cofactorDH_sha256kdf_scheme,
	NID_dhSinglePass_cofactorDH_sha384kdf_scheme,
	NID_dhSinglePass_cofactorDH_sha512kdf_scheme,
#endif
#ifndef OPENSSL_NO_DH
	NID_dhKeyAgreement,
#endif
};

static int get_exch_info(const char *alg, int *ppkey_type, int *pec_scheme,
	int *pecdh_cofactor_mode, int *pecdh_kdf_type, int *pecdh_kdf_md,
	int *pecdh_kdf_outlen, char **pecdh_kdf_ukm, int *pecdh_kdf_ukmlen)
{
	int pkey_type = 0;
	int ec_scheme = 0;
	int ecdh_cofactor_mode = 0;
	int ecdh_kdf_type = 0;
	int ecdh_kdf_md = 0;
	int ecdh_kdf_outlen = 0;
	char *ecdh_kdf_ukm = NULL;
	int ecdh_kdf_ukmlen = 0;

	switch (OBJ_txt2nid(alg)) {
	case NID_sm2exchange:
		pkey_type = EVP_PKEY_EC;
		ec_scheme = NID_sm_scheme;
		ecdh_kdf_md = NID_sm3;
		break;
	case NID_dhSinglePass_stdDH_sha1kdf_scheme:
		pkey_type = EVP_PKEY_EC;
		ec_scheme = NID_secg_scheme;
		ecdh_cofactor_mode = 0;
		ecdh_kdf_type = NID_sha1;
		break;
	case NID_dhSinglePass_stdDH_sha224kdf_scheme:
		pkey_type = EVP_PKEY_EC;
		ec_scheme = NID_secg_scheme;
		ecdh_cofactor_mode = 0;
		ecdh_kdf_type = NID_sha224;
		break;
	case NID_dhSinglePass_stdDH_sha256kdf_scheme:
		pkey_type = EVP_PKEY_EC;
		ec_scheme = NID_secg_scheme;
		ecdh_cofactor_mode = 0;
		ecdh_kdf_type = NID_sha256;
		break;
	case NID_dhSinglePass_stdDH_sha384kdf_scheme:
		pkey_type = EVP_PKEY_EC;
		ec_scheme = NID_secg_scheme;
		ecdh_cofactor_mode = 0;
		ecdh_kdf_type = NID_sha384;
		break;
	case NID_dhSinglePass_stdDH_sha512kdf_scheme:
		pkey_type = EVP_PKEY_EC;
		ec_scheme = NID_secg_scheme;
		ecdh_cofactor_mode = 0;
		ecdh_kdf_type = NID_sha512;
		break;
	case NID_dhSinglePass_cofactorDH_sha1kdf_scheme:
		pkey_type = EVP_PKEY_EC;
		ec_scheme = NID_secg_scheme;
		ecdh_cofactor_mode = 1;
		ecdh_kdf_type = NID_sha1;
		break;
	case NID_dhSinglePass_cofactorDH_sha224kdf_scheme:
		pkey_type = EVP_PKEY_EC;
		ec_scheme = NID_secg_scheme;
		ecdh_cofactor_mode = 1;
		ecdh_kdf_type = NID_sha224;
		break;
	case NID_dhSinglePass_cofactorDH_sha256kdf_scheme:
		pkey_type = EVP_PKEY_EC;
		ec_scheme = NID_secg_scheme;
		ecdh_cofactor_mode = 1;
		ecdh_kdf_type = NID_sha256;
		break;
	case NID_dhSinglePass_cofactorDH_sha384kdf_scheme:
		pkey_type = EVP_PKEY_EC;
		ec_scheme = NID_secg_scheme;
		ecdh_cofactor_mode = 1;
		ecdh_kdf_type = NID_sha384;
		break;
	case NID_dhSinglePass_cofactorDH_sha512kdf_scheme:
		ec_scheme = NID_secg_scheme;
		ecdh_cofactor_mode = 1;
		ecdh_kdf_type = NID_sha512;
		break;
	case NID_dhKeyAgreement:
		pkey_type = EVP_PKEY_DH;
		break;
	default:
		return 0;
	}

	*ppkey_type = pkey_type;
	*pec_scheme = ec_scheme;
	*pecdh_cofactor_mode = ecdh_cofactor_mode;
	*pecdh_kdf_type = ecdh_kdf_type;
	*pecdh_kdf_md = ecdh_kdf_md;
	*pecdh_kdf_outlen = ecdh_kdf_outlen;
	*pecdh_kdf_ukm = ecdh_kdf_ukm;
	*pecdh_kdf_ukmlen = ecdh_kdf_ukmlen;

	return 1;
}

unsigned char *pk_encrypt(EVP_PKEY *pk, const char *alg, const unsigned char *in,
	size_t inlen, size_t *outlen, ENGINE *e) {
	unsigned char *ret = NULL;
	int pkey_id, ec_scheme, ec_encrypt_param;
	EVP_PKEY_CTX *ctx = NULL;
	unsigned char *buf = NULL;

	if (!get_pke_info(alg, &pkey_id, &ec_scheme, &ec_encrypt_param)) {
		return NULL;
	}
	if (pkey_id != EVP_PKEY_id(pk)) {
		return NULL;
	}
	if (!(ctx = EVP_PKEY_CTX_new(pk, e))) {
		return NULL;
	}
	if (EVP_PKEY_encrypt_init(ctx) <= 0) {
		goto end;
	}
	if (EVP_PKEY_id(pk) == EVP_PKEY_EC && EC_GROUP_get_curve_name(
		EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(pk))) == NID_sm2p256v1) {
		if (EVP_PKEY_CTX_set_ec_scheme(ctx, ec_scheme) <= 0
			|| EVP_PKEY_CTX_set_ec_encrypt_param(ctx, ec_encrypt_param) <= 0) {
			goto end;
		}
	}
	if (EVP_PKEY_encrypt(ctx, NULL, outlen, in, inlen) <= 0) {
		goto end;
	}
	if (!(buf = OPENSSL_zalloc(*outlen))) {
		goto end;
	}
	if (EVP_PKEY_encrypt(ctx, buf, outlen, in, inlen) <= 0) {
		goto end;
	}
	ret = buf;
	buf = NULL;

end:
	EVP_PKEY_CTX_free(ctx);
	OPENSSL_free(buf);
	return ret;
}

unsigned char *sk_decrypt(EVP_PKEY *sk, const char *alg, const unsigned char *in,
	size_t inlen, size_t *outlen, ENGINE *e) {
	unsigned char *ret = NULL;
	int pkey_id, ec_scheme, ec_encrypt_param;
	EVP_PKEY_CTX *ctx = NULL;
	unsigned char *buf = NULL;

	if (!get_pke_info(alg, &pkey_id, &ec_scheme, &ec_encrypt_param)) {
		return NULL;
	}
	if (pkey_id != EVP_PKEY_id(sk)) {
		return NULL;
	}
	if (!(ctx = EVP_PKEY_CTX_new(sk, e))) {
		return NULL;
	}
	if (EVP_PKEY_decrypt_init(ctx) <= 0) {
		goto end;
	}
	if (EVP_PKEY_id(sk) == EVP_PKEY_EC && EC_GROUP_get_curve_name(
		EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(sk))) == NID_sm2p256v1) {
		if (EVP_PKEY_CTX_set_ec_scheme(ctx, ec_scheme) <= 0
			|| EVP_PKEY_CTX_set_ec_encrypt_param(ctx, ec_encrypt_param) <= 0) {
			goto end;
		}
	}
	if (EVP_PKEY_decrypt(ctx, NULL, outlen, in, inlen) <= 0) {
		goto end;
	}
	if (!(buf = OPENSSL_zalloc(*outlen))) {
		goto end;
	}
	if (EVP_PKEY_decrypt(ctx, buf, outlen, in, inlen) <= 0) {
		goto end;
	}
	ret = buf;
	buf = NULL;
end:
	EVP_PKEY_CTX_free(ctx);
	OPENSSL_free(buf);
	return ret;
}

unsigned char *sk_sign(EVP_PKEY *sk, const char *alg, const unsigned char *dgst,
	size_t dgstlen, size_t *siglen, ENGINE *e) {
	unsigned char *ret = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	unsigned char *sig = NULL;

	if (!(ctx = EVP_PKEY_CTX_new(sk, e))) {
		return NULL;
	}
	if (EVP_PKEY_sign_init(ctx) <= 0) {
		goto end;
	}
	if (EVP_PKEY_id(sk) == EVP_PKEY_EC && EC_GROUP_get_curve_name(
		EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(sk))) == NID_sm2p256v1) {
		if (EVP_PKEY_CTX_set_ec_scheme(ctx, NID_sm_scheme) <= 0) {
			goto end;
		}
	}
	if (EVP_PKEY_size(sk) <= 0) {
		goto end;
	}
	if (!(sig = OPENSSL_zalloc(EVP_PKEY_size(sk)))) {
		goto end;
	}
	*siglen = EVP_PKEY_size(sk);
	if (EVP_PKEY_sign(ctx, sig, siglen, dgst, dgstlen) <= 0) {
		goto end;
	}
	ret = sig;
	sig = NULL;
end:
	EVP_PKEY_CTX_free(ctx);
	OPENSSL_free(sig);
	return ret;
}

int pk_verify(EVP_PKEY *pk, const char *alg, const unsigned char *dgst,
	size_t dgstlen, const unsigned char *sig, size_t siglen, ENGINE *e) {
	int ret = -1;
	EVP_PKEY_CTX *ctx = NULL;

	if (!(ctx = EVP_PKEY_CTX_new(pk, e))) {
		printf("%s %d: error\n", __FILE__, __LINE__);
		goto end;
	}
	if (!EVP_PKEY_verify_init(ctx)) {
		printf("%s %d: error\n", __FILE__, __LINE__);
		goto end;
	}

	if (EVP_PKEY_id(pk) == EVP_PKEY_EC && EC_GROUP_get_curve_name(
		EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(pk))) == NID_sm2p256v1) {
		if (EVP_PKEY_CTX_set_ec_scheme(ctx, NID_sm_scheme) <= 0) {
			goto end;
		}
	}
	if ((ret = EVP_PKEY_verify(ctx, sig, siglen, dgst, dgstlen)) <= 0) {
		printf("ret = %d\n", ret);
		ERR_print_errors_fp(stderr);
		goto end;
	}
end:
	EVP_PKEY_CTX_free(ctx);
	return ret;
}

unsigned char *sk_derive(EVP_PKEY *sk, const char *alg, EVP_PKEY *peer,
	size_t *outlen, ENGINE *e) {
	return NULL;
}

*/
import "C"

import (
	"unsafe"
	"errors"
	"runtime"
)

func GetPublicKeyAlgorithmNames() []string {
	return []string{
		"DH",
		"DSA",
		"RSA",
		"EC",
		"X25519",
	}
}

func GetSignAlgorithmNames(pkey string) ([]string, error) {
	if pkey == "EC" {
		return []string{
			"sm2sign",
			"ecdsa-with-Recommended",
			"ecdsa-with-SHA1",
			"ecdsa-with-SHA256",
			"ecdsa-with-SHA512",
		}, nil
	} else if pkey == "RSA" {
		return []string{
			"RSA-SHA1",
			"RSA-SHA256",
			"RSA-SHA512",
		}, nil
	} else if pkey == "DSA" {
		return []string{
			"DSA-SHA1",
		}, nil
	} else {
		return nil, errors.New("Invalid public key algorithm")
	}
}

func GetPublicKeyEncryptionNames(pkey string) ([]string, error) {
	if pkey == "RSA" {
		return []string{
			"RSAES-OAEP",
		}, nil
	} else if pkey == "EC" {
		return []string {
			"ecies-recommendedParameters",
			"ecies-specifiedParameters",
			"ecies-with-x9-63-sha1-xor-hmac",
			"ecies-with-x9-63-sha256-xor-hmac",
			"ecies-with-x9-63-sha512-xor-hmac",
			"ecies-with-x9-63-sha1-aes128-cbc-hmac",
			"ecies-with-x9-63-sha256-aes128-cbc-hmac",
			"ecies-with-x9-63-sha512-aes256-cbc-hmac",
			"ecies-with-x9-63-sha256-aes128-ctr-hmac",
			"ecies-with-x9-63-sha512-aes256-ctr-hmac",
			"ecies-with-x9-63-sha256-aes128-cbc-hmac-half",
			"ecies-with-x9-63-sha512-aes256-cbc-hmac-half",
			"ecies-with-x9-63-sha256-aes128-ctr-hmac-half",
			"ecies-with-x9-63-sha512-aes256-ctr-hmac-half",
			"ecies-with-x9-63-sha1-aes128-cbc-cmac",
			"ecies-with-x9-63-sha256-aes128-cbc-cmac",
			"ecies-with-x9-63-sha512-aes256-cbc-cmac",
			"ecies-with-x9-63-sha256-aes128-ctr-cmac",
			"ecies-with-x9-63-sha512-aes256-ctr-cmac",
			"sm2encrypt-with-sm3",
			"sm2encrypt-with-sha1",
			"sm2encrypt-with-sha256",
			"sm2encrypt-with-sha512",
		}, nil
	} else {
		return nil, errors.New("Invalid public key algorithm")
	}
}

func GetDeriveKeyAlgorithmNames(pkey string) ([]string, error) {
	if pkey == "EC" {
		return []string{
			"sm2exchange",
		}, nil
	} else if pkey == "DH" {
		return []string{
			"dhSinglePass-stdDH-sha1kdf-scheme",
			"dhSinglePass-stdDH-sha224kdf-scheme",
			"dhSinglePass-stdDH-sha256kdf-scheme",
			"dhSinglePass-stdDH-sha384kdf-scheme",
			"dhSinglePass-stdDH-sha512kdf-scheme",
			"dhSinglePass-cofactorDH-sha1kdf-scheme",
			"dhSinglePass-cofactorDH-sha224kdf-scheme",
			"dhSinglePass-cofactorDH-sha256kdf-scheme",
			"dhSinglePass-cofactorDH-sha384kdf-scheme",
			"dhSinglePass-cofactorDH-sha512kdf-scheme",
			"dhKeyAgreement",
		}, nil
	} else {
		return nil, errors.New("No algorithm supported")
	}
}

type PublicKey struct {
	pkey *C.EVP_PKEY
}

type PrivateKey struct {
	pkey *C.EVP_PKEY
}

func GeneratePrivateKey(alg string, args [][2]string, eng *Engine) (*PrivateKey, error) {
	calg := C.CString(alg)
	defer C.free(unsafe.Pointer(calg))

	ctx := C.new_pkey_keygen_ctx(calg, nil)
	defer C.EVP_PKEY_CTX_free(ctx)

	/*
	if eng != nil {
		ctx := C.new_pkey_keygen_ctx(calg, eng.engine)
	}
	*/

	if ctx == nil {
		return nil, GetErrors()
	}
	var pkey *C.EVP_PKEY

	if alg == "DH" || alg == "DSA" {

		if 1 != C.EVP_PKEY_paramgen_init(ctx) {
			return nil, GetErrors()
		}
		for _, arg := range args {
			name := arg[0]
			value := arg[1]
			cname := C.CString(name)
			defer C.free(unsafe.Pointer(cname))
			cvalue := C.CString(value)
			defer C.free(unsafe.Pointer(cvalue))
			if C.EVP_PKEY_CTX_ctrl_str(ctx, cname, cvalue) <= 0 {
				return nil, GetErrors()
			}
		}
		if 1 != C.EVP_PKEY_paramgen(ctx, &pkey) {
			return nil, GetErrors()
		}
		if 1 != C.EVP_PKEY_keygen_init(ctx) {
			return nil, GetErrors()
		}
		if 1 != C.EVP_PKEY_keygen(ctx, &pkey) {
			return nil, GetErrors()
		}

	} else {
		if 1 != C.EVP_PKEY_keygen_init(ctx) {
			return nil, GetErrors()
		}

		for _, arg := range args {
			name := arg[0]
			value := arg[1]
			cname := C.CString(name)
			defer C.free(unsafe.Pointer(cname))
			cvalue := C.CString(value)
			defer C.free(unsafe.Pointer(cvalue))
			if C.EVP_PKEY_CTX_ctrl_str(ctx, cname, cvalue) <= 0 {
				return nil, GetErrors()
			}
		}

		if 1 != C.EVP_PKEY_keygen(ctx, &pkey) {
			return nil, GetErrors()
		}
	}

	sk := &PrivateKey{pkey}
	runtime.SetFinalizer(sk, func(sk *PrivateKey) {
		C.EVP_PKEY_free(sk.pkey)
	})

	return sk, nil
}

func NewPrivateKeyFromPEM(pem string, pass string) (*PrivateKey, error) {
	cpem := C.CString(pem)
	defer C.free(unsafe.Pointer(cpem))
	cpass := C.CString(pass)
	defer C.free(unsafe.Pointer(cpass))
	bio := C.BIO_new_mem_buf(unsafe.Pointer(cpem), -1)
	if bio == nil {
		return nil, GetErrors()
	}
	defer C.BIO_free(bio)
	pkey := C.PEM_read_bio_PrivateKey(bio, nil, nil, unsafe.Pointer(cpass))
	if pkey == nil {
		return nil, GetErrors()
	}
	sk := &PrivateKey{pkey}
	runtime.SetFinalizer(sk, func(sk *PrivateKey) {
		C.EVP_PKEY_free(sk.pkey)
	})
	return sk, nil
}

func (sk *PrivateKey) GetPEM(cipher string, pass string) (string, error) {
	ccipher := C.CString(cipher)
	defer C.free(unsafe.Pointer(ccipher))
	cpass := C.CString(pass)
	defer C.free(unsafe.Pointer(cpass))

	bio := C.BIO_new(C.BIO_s_mem())
	if bio == nil {
		return "", GetErrors()
	}
	defer C.BIO_free(bio)

	enc := C.EVP_get_cipherbyname(ccipher)
	if enc == nil {
		return "", GetErrors()
	}

	/* FIXME: PKCS #5 can not use SM4 */
	if 1 != C.PEM_write_bio_PrivateKey(bio, sk.pkey,
		C.EVP_des_ede3_cbc(), nil, C.int(0), nil, unsafe.Pointer(cpass)) {
		C.ERR_print_errors_fp(C.stderr)
		return "", GetErrors()
	}

	var p *C.char
	len := C._BIO_get_mem_data(bio, &p)
	if len <= 0 {
		return "", GetErrors()
	}

	return C.GoString(p)[:len], nil
}

func (sk *PrivateKey) GetPublicKeyPEM() (string, error) {
	bio := C.BIO_new(C.BIO_s_mem())
	if bio == nil {
		return "", GetErrors()
	}
	defer C.BIO_free(bio)
	if 1 != C.pem_write_bio_pubkey(bio, sk.pkey) {
		return "", GetErrors()
	}
	var p *C.char
	len := C._BIO_get_mem_data(bio, &p)
	if len <= 0 {
		return "", GetErrors()
	}
	return C.GoString(p)[:len], nil
}

func (sk *PrivateKey) GetText() (string, error) {
	bio := C.BIO_new(C.BIO_s_mem())
	if bio == nil {
		return "", GetErrors()
	}
	defer C.BIO_free(bio)
	/* FIMME: some times this will failed */
	if 1 != C.EVP_PKEY_print_private(bio, sk.pkey, 0, nil) {
		return "", GetErrors()
	}
	var p *C.char
	len := C._BIO_get_mem_data(bio, &p)
	if len <= 0 {
		return "", GetErrors()
	}
	return C.GoString(p)[:len], nil
}

func NewPublicKeyFromPEM(pem string)(*PublicKey, error) {
	cpem := C.CString(pem)
	defer C.free(unsafe.Pointer(cpem))
	bio := C.BIO_new_mem_buf(unsafe.Pointer(cpem), -1)
	if bio == nil {
		return nil, GetErrors()
	}
	defer C.BIO_free(bio)
	pkey := C.pem_read_bio_pubkey(bio)
	if pkey == nil {
		return nil, GetErrors()
	}
	pk := &PublicKey{pkey}
	runtime.SetFinalizer(pk, func(pk *PublicKey) {
		C.EVP_PKEY_free(pk.pkey)
	})
	return pk, nil
}

func (pk *PublicKey) GetPEM() (string, error) {
	bio := C.BIO_new(C.BIO_s_mem())
	if bio == nil {
		return "", GetErrors()
	}
	defer C.BIO_free(bio)
	if 1 != C.pem_write_bio_pubkey(bio, pk.pkey) {
		return "", GetErrors()
	}
	var p *C.char
	len := C._BIO_get_mem_data(bio, &p)
	if len <= 0 {
		return "", GetErrors()
	}
	return C.GoString(p)[:len], nil
}

func (pk *PublicKey) GetText() (string, error) {
	bio := C.BIO_new(C.BIO_s_mem())
	if bio == nil {
		return "", GetErrors()
	}
	defer C.BIO_free(bio)
	if 1 != C.EVP_PKEY_print_public(bio, pk.pkey, 4, nil) {
		return "", GetErrors()
	}
	var p *C.char
	len := C._BIO_get_mem_data(bio, &p)
	if len <= 0 {
		return "", GetErrors()
	}
	return C.GoString(p)[:len], nil
}

func (pk *PublicKey) Encrypt(alg string, in []byte, eng *Engine) ([]byte, error) {
	calg := C.CString(alg)
	defer C.free(unsafe.Pointer(calg))
	var outlen C.size_t
	out := C.pk_encrypt(pk.pkey, calg, (*C.uchar)(&in[0]),
		C.size_t(len(in)), &outlen, nil)
	if out == nil {
		return nil, GetErrors()
	}
	defer C.free(unsafe.Pointer(out))
	return C.GoBytes(unsafe.Pointer(out), C.int(outlen)), nil
}

func (sk *PrivateKey) Decrypt(alg string, in []byte, eng *Engine) ([]byte, error) {
	calg := C.CString(alg)
	defer C.free(unsafe.Pointer(calg))
	var outlen C.size_t
	out := C.sk_decrypt(sk.pkey, calg, (*C.uchar)(&in[0]),
		C.size_t(len(in)), &outlen, nil)
	if out == nil {
		return nil, GetErrors()
	}
	defer C.free(unsafe.Pointer(out))
	return C.GoBytes(unsafe.Pointer(out), C.int(outlen)), nil
}

func (sk *PrivateKey) Sign(alg string, dgst []byte, eng *Engine) ([]byte, error) {
	calg := C.CString(alg)
	defer C.free(unsafe.Pointer(calg))
	var siglen C.size_t
	sig := C.sk_sign(sk.pkey, calg, (*C.uchar)(&dgst[0]),
		C.size_t(len(dgst)), &siglen, nil)
	if sig == nil {
		C.ERR_print_errors_fp(C.stderr)
		return nil, GetErrors()
	}
	defer C.free(unsafe.Pointer(sig))
	return C.GoBytes(unsafe.Pointer(sig), C.int(siglen)), nil
}

func (pk *PublicKey) Verify(alg string, dgst, sig []byte, eng *Engine) error {
	calg := C.CString(alg)
	defer C.free(unsafe.Pointer(calg))

	if 1 != C.pk_verify(pk.pkey, calg, (*C.uchar)(&dgst[0]), C.size_t(len(dgst)),
		(*C.uchar)(&sig[0]), C.size_t(len(sig)), nil) {
		C.ERR_print_errors_fp(C.stderr)
		return GetErrors()
	}
	return nil
}

func (sk *PrivateKey) DeriveKey(alg string, peer PublicKey, eng *Engine) ([]byte, error) {
	calg := C.CString(alg)
	defer C.free(unsafe.Pointer(calg))
	var keylen C.size_t
	key := C.sk_derive(sk.pkey, calg, peer.pkey, &keylen, eng.engine)
	if key == nil {
		return nil, GetErrors()
	}
	defer C.free(unsafe.Pointer(key))
	return C.GoBytes(unsafe.Pointer(key), C.int(keylen)), nil
}

func (pk *PublicKey) ComputeSM2IDDigest(id string) ([]byte, error) {
	if C.EVP_PKEY_EC != C.EVP_PKEY_id(pk.pkey) {
		return nil, errors.New("Invalid public key type")
	}
	cid := C.CString(id)
	defer C.free(unsafe.Pointer(cid))
	outbuf := make([]byte, 64)
	outlen := C.size_t(len(outbuf))
	if 1 != C.SM2_compute_id_digest(C.EVP_sm3(), cid, C.size_t(len(id)),
		(*C.uchar)(&outbuf[0]), &outlen, C.EVP_PKEY_get0_EC_KEY(pk.pkey)) {
		return nil, GetErrors()
	}
	return outbuf[:32], nil
}

func (sk *PrivateKey) ComputeSM2IDDigest(id string) ([]byte, error) {
	if C.EVP_PKEY_EC != C.EVP_PKEY_id(sk.pkey) {
		return nil, errors.New("Invalid public key type")
	}
	cid := C.CString(id)
	defer C.free(unsafe.Pointer(cid))
	outbuf := make([]byte, 64)
	outlen := C.size_t(len(outbuf))
	if 1 != C.SM2_compute_id_digest(C.EVP_sm3(), cid, C.size_t(len(id)),
		(*C.uchar)(&outbuf[0]), &outlen, C.EVP_PKEY_get0_EC_KEY(sk.pkey)) {
		return nil, GetErrors()
	}
	return outbuf[:32], nil
}
