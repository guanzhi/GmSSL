/*
 * Copyright (c) 2021 - 2021 The GmSSL Project.  All rights reserved.
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/ec.h>
#include <gmssl/oid.h>
#include <gmssl/asn1.h>
#include <gmssl/error.h>




static uint32_t oid_sm3[] = { 1,2,156,10197,1,401 };
static uint32_t oid_md5[] = { 1,2,840,113549,2,5 };
static uint32_t oid_sha1[] = { 1,3,14,3,2,26 };
static uint32_t oid_sha256[] = { 2,16,840,1,101,3,4,2,1 };
static uint32_t oid_sha384[] = { 2,16,840,1,101,3,4,2,2 };
static uint32_t oid_sha512[] = { 2,16,840,1,101,3,4,2,3 };
static uint32_t oid_sha224[] = { 2,16,840,1,101,3,4,2,4 };

static const ASN1_OID_INFO x509_digest_algors[] = {
	{ OID_sm3, "sm3", oid_sm3, sizeof(oid_sm3)/sizeof(int) },
	{ OID_md5, "md5", oid_md5, sizeof(oid_md5)/sizeof(int) },
	{ OID_sha1, "sha1", oid_sha1, sizeof(oid_sha1)/sizeof(int) },
	{ OID_sha224, "sha224", oid_sha224, sizeof(oid_sha224)/sizeof(int) },
	{ OID_sha256, "sha256", oid_sha256, sizeof(oid_sha256)/sizeof(int) },
	{ OID_sha384, "sha384", oid_sha384, sizeof(oid_sha384)/sizeof(int) },
	{ OID_sha512, "sha512", oid_sha512, sizeof(oid_sha512)/sizeof(int) },
};

static const int x509_digest_algors_count =
	sizeof(x509_digest_algors)/sizeof(x509_digest_algors[0]);

const char *x509_digest_algor_name(int oid)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_oid(x509_digest_algors, x509_digest_algors_count, oid))) {
		error_print();
		return NULL;
	}
	return info->name;
}

int x509_digest_algor_from_name(const char *name)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_name(x509_digest_algors, x509_digest_algors_count, name))) {
		error_print();
		return OID_undef;
	}
	return info->oid;
}

int x509_digest_algor_to_der(int oid, uint8_t **out, size_t *outlen)
{
	const ASN1_OID_INFO *info;
	size_t len = 0;
	if (!(info = asn1_oid_info_from_oid(x509_digest_algors, x509_digest_algors_count, oid))) {
		error_print();
		return -1;
	}
	if (asn1_object_identifier_to_der(info->nodes, info->nodes_cnt, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_object_identifier_to_der(info->nodes, info->nodes_cnt, out,  outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_digest_algor_from_der(int *oid, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *p;
	size_t len;
	const ASN1_OID_INFO *info;

	*oid = 0;
	if ((ret = asn1_sequence_from_der(&p, &len, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if ((ret = asn1_oid_info_from_der(&info, x509_digest_algors, x509_digest_algors_count, &p, &len)) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return ret;
	}
	*oid = info->oid;
	return 1;
}

int x509_digest_algor_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	const ASN1_OID_INFO *info;
	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (asn1_oid_info_from_der(&info, x509_digest_algors, x509_digest_algors_count, &d, &dlen) != 1) goto err;
	format_print(fp, fmt, ind, "algorithm: %s\n", info->name);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}


static uint32_t oid_sm4_cbc[] =  { 1,2,156,10197,1,104,2 };
static uint32_t oid_aes128_cbc[] = { 2,16,840,1,101,3,4,1,2 };
static uint32_t oid_aes192_cbc[] = { 2,16,840,1,101,3,4,1,22 };
static uint32_t oid_aes256_cbc[] = { 2,16,840,1,101,3,4,1,42 };

static const ASN1_OID_INFO x509_enc_algors[] = {
	{ OID_sm4_cbc, "sm4-cbc", oid_sm4_cbc, sizeof(oid_sm4_cbc)/sizeof(int) },
	{ OID_aes128_cbc, "aes128-cbc", oid_aes128_cbc, sizeof(oid_aes128_cbc)/sizeof(int) },
	{ OID_aes192_cbc, "aes192-cbc", oid_aes192_cbc, sizeof(oid_aes192_cbc)/sizeof(int) },
	{ OID_aes256_cbc, "aes256-cbc", oid_aes256_cbc, sizeof(oid_aes256_cbc)/sizeof(int) },
};

static const int x509_enc_algors_count =
	sizeof(x509_enc_algors)/sizeof(x509_enc_algors[0]);

const char *x509_encryption_algor_name(int oid)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_oid(x509_enc_algors, x509_enc_algors_count, oid))) {
		error_print();
		return NULL;
	}
	return info->name;
}

int x509_encryption_algor_from_name(const char *name)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_name(x509_enc_algors, x509_enc_algors_count, name))) {
		error_print();
		return OID_undef;
	}
	return info->oid;
}

int x509_encryption_algor_to_der(int oid, const uint8_t *iv, size_t ivlen,
	uint8_t **out, size_t *outlen)
{
	const ASN1_OID_INFO *info;
	size_t len = 0;

	if (!(info = asn1_oid_info_from_oid(x509_enc_algors, x509_enc_algors_count, oid))) {
		error_print();
		return -1;
	}
	if (asn1_object_identifier_to_der(info->nodes, info->nodes_cnt, NULL, &len) != 1
		|| asn1_octet_string_to_der(iv, ivlen, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_object_identifier_to_der(info->nodes, info->nodes_cnt, out, outlen) != 1
		|| asn1_octet_string_to_der(iv, ivlen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_encryption_algor_from_der(int *oid, const uint8_t **iv, size_t *ivlen,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *p;
	size_t len;
	const ASN1_OID_INFO *info;

	*oid = OID_undef;
	*iv = NULL;
	*ivlen = 0;

	if ((ret = asn1_sequence_from_der(&p, &len, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_oid_info_from_der(&info, x509_enc_algors, x509_enc_algors_count, &p, &len) != 1
		|| asn1_octet_string_from_der(iv, ivlen, &p, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	if (!(*iv) || *ivlen != 16) {
		error_print();
		return -1;
	}
	*oid = info->oid;
	return 1;
}

int x509_encryption_algor_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	const ASN1_OID_INFO *info;
	const uint8_t *iv;
	size_t ivlen;
	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (asn1_oid_info_from_der(&info, x509_enc_algors, x509_enc_algors_count, &d, &dlen) != 1) goto err;
	format_print(fp, fmt, ind, "algorithm: %s\n", info->name);
	if (asn1_octet_string_from_der(&iv, &ivlen, &d, &dlen) != 1) goto err;
	format_bytes(fp, fmt, ind, "iv: ", iv, ivlen);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}


static uint32_t oid_sm2sign_with_sm3[] = { 1,2,156,10197,1,501 };
static uint32_t oid_rsasign_with_sm3[] = { 1,2,156,10197,1,504 };
static uint32_t oid_ecdsa_with_sha1[] = { 1,2,840,10045,4,1 };
static uint32_t oid_ecdsa_with_sha224[] = { 1,2,840,10045,4,3,1 };
static uint32_t oid_ecdsa_with_sha256[] = { 1,2,840,10045,4,3,2 };
static uint32_t oid_ecdsa_with_sha384[] = { 1,2,840,10045,4,3,3 };
static uint32_t oid_ecdsa_with_sha512[] = { 1,2,840,10045,4,3,4 };
static uint32_t oid_rsasign_with_sha1[] = { 1,2,840,113549,1,1,5 };
static uint32_t oid_rsasign_with_sha224[] = { 1,2,840,113549,1,1,14 };
static uint32_t oid_rsasign_with_sha256[] = { 1,2,840,113549,1,1,11 };
static uint32_t oid_rsasign_with_sha384[] = { 1,2,840,113549,1,1,12 };
static uint32_t oid_rsasign_with_sha512[] = { 1,2,840,113549,1,1,13 };

#define X509_ALGOR_OPT_NULL_PARAM 1

static const ASN1_OID_INFO x509_sign_algors[] = {
	{ OID_sm2sign_with_sm3, "sm2sign-with-sm3", oid_sm2sign_with_sm3, sizeof(oid_sm2sign_with_sm3)/sizeof(int), 0 },
	{ OID_rsasign_with_sm3, "rsasign-with-sm3", oid_rsasign_with_sm3, sizeof(oid_rsasign_with_sm3)/sizeof(int), X509_ALGOR_OPT_NULL_PARAM },
	{ OID_ecdsa_with_sha1, "ecdsa-with-sha1", oid_ecdsa_with_sha1, sizeof(oid_ecdsa_with_sha1)/sizeof(int), 0 },
	{ OID_ecdsa_with_sha224, "ecdsa-with-sha224", oid_ecdsa_with_sha224, sizeof(oid_ecdsa_with_sha224)/sizeof(int), 0} ,
	{ OID_ecdsa_with_sha256, "ecdsa-with-sha256", oid_ecdsa_with_sha256, sizeof(oid_ecdsa_with_sha256)/sizeof(int), 0},
	{ OID_ecdsa_with_sha384, "ecdsa-with-sha384", oid_ecdsa_with_sha384, sizeof(oid_ecdsa_with_sha384)/sizeof(int), 0 },
	{ OID_ecdsa_with_sha512, "ecdsa-with-sha512", oid_ecdsa_with_sha512, sizeof(oid_ecdsa_with_sha512)/sizeof(int), 0 },
	{ OID_rsasign_with_sha1, "sha1WithRSAEncryption", oid_rsasign_with_sha1, sizeof(oid_rsasign_with_sha1)/sizeof(int), 0 },
	{ OID_rsasign_with_sha224, "sha224WithRSAEncryption", oid_rsasign_with_sha224, sizeof(oid_rsasign_with_sha224)/sizeof(int), X509_ALGOR_OPT_NULL_PARAM },
	{ OID_rsasign_with_sha256, "sha256WithRSAEncryption", oid_rsasign_with_sha256, sizeof(oid_rsasign_with_sha256)/sizeof(int), X509_ALGOR_OPT_NULL_PARAM },
	{ OID_rsasign_with_sha384, "sha384WithRSAEncryption", oid_rsasign_with_sha384, sizeof(oid_rsasign_with_sha384)/sizeof(int), X509_ALGOR_OPT_NULL_PARAM },
	{ OID_rsasign_with_sha512, "sha512WithRSAEncryption", oid_rsasign_with_sha512, sizeof(oid_rsasign_with_sha512)/sizeof(int), X509_ALGOR_OPT_NULL_PARAM },
};

static const int x509_sign_algors_count =
	sizeof(x509_sign_algors)/sizeof(x509_sign_algors[0]);

const char *x509_signature_algor_name(int oid)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_oid(x509_sign_algors, x509_sign_algors_count, oid))) {
		error_print();
		return NULL;
	}
	return info->name;
}

int x509_signature_algor_from_name(const char *name)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_name(x509_sign_algors, x509_sign_algors_count, name))) {
		error_print();
		return OID_undef;
	}
	return info->oid;
}

int x509_signature_algor_to_der(int oid, uint8_t **out, size_t *outlen)
{
	const ASN1_OID_INFO *info;
	size_t len = 0;
	if (!(info = asn1_oid_info_from_oid(x509_sign_algors, x509_sign_algors_count, oid))) {
		error_print();
		return -1;
	}
	if (asn1_object_identifier_to_der(info->nodes, info->nodes_cnt, NULL, &len) != 1
		|| (info->flags && asn1_null_to_der(NULL, &len) != 1)
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_object_identifier_to_der(info->nodes, info->nodes_cnt, out, outlen) != 1
		|| (info->flags && asn1_null_to_der(out, outlen) != 1)) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_signature_algor_from_der(int *oid, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *p;
	size_t len;
	const ASN1_OID_INFO *info;
	int has_null_obj;
	int i;

	*oid = OID_undef;
	if ((ret = asn1_sequence_from_der(&p, &len, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_oid_info_from_der(&info, x509_sign_algors, x509_sign_algors_count, &p, &len) != 1
		|| (info->flags && asn1_null_from_der(&p, &len) < 0)
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	*oid = info->oid;
	return 1;
}

int x509_signature_algor_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	const ASN1_OID_INFO *info;
	int null_param;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (asn1_oid_info_from_der(&info, x509_sign_algors, x509_sign_algors_count, &d, &dlen) != 1)  goto err;
	format_print(fp, fmt, ind, "algorithm: %s\n", info->name);
	if ((null_param = asn1_null_from_der(&d, &dlen)) < 0) goto err;
	if (null_param) format_print(fp, fmt, ind, "parameters: %s\n", asn1_tag_name(ASN1_TAG_NULL));
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

/*
sm2encrypt: no parameters

rsaes_oaep: from rfc 3560
RSAES-OAEP-params  ::=  SEQUENCE  {
	hashFunc    [0] AlgorithmIdentifier DEFAULT sha1Identifier,
	maskGenFunc [1] AlgorithmIdentifier DEFAULT mgf1SHA1Identifier,
	pSourceFunc [2] AlgorithmIdentifier DEFAULT
*/

static uint32_t oid_sm2encrypt[] = { 1,2,156,10197,1,301,2 };
static uint32_t oid_rsa_encryption[] = { 1,2,840,113549,1,1,1 };
static uint32_t oid_rsaes_oaep[] = { 1,2,840,113549,1,1,7 };

static const ASN1_OID_INFO x509_pke_algors[] = {
	{ OID_sm2encrypt, "sm2encrypt", oid_sm2encrypt, sizeof(oid_sm2encrypt)/sizeof(int) },
	{ OID_rsa_encryption, "rsaEncryption", oid_rsa_encryption, sizeof(oid_rsa_encryption)/sizeof(int) },
	{ OID_rsaes_oaep, "rsaesOAEP", oid_rsaes_oaep, sizeof(oid_rsaes_oaep)/sizeof(int) },
};

static const int x509_pke_algors_count =
	sizeof(x509_pke_algors)/sizeof(x509_pke_algors[0]);

const char *x509_public_key_encryption_algor_name(int oid)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_oid(x509_pke_algors, x509_pke_algors_count, oid))) {
		error_print();
		return NULL;
	}
	return info->name;
}

int x509_public_key_encryption_algor_from_name(const char *name)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_name(x509_pke_algors, x509_pke_algors_count, name))) {
		error_print();
		return OID_undef;
	}
	return info->oid;
}

int x509_public_key_encryption_algor_to_der(int oid, uint8_t **out, size_t *outlen)
{
	const ASN1_OID_INFO *info;
	size_t len = 0;

	if (oid != OID_sm2encrypt) {
		error_print();
		return -1;
	}
	if (!(info = asn1_oid_info_from_oid(x509_pke_algors, x509_pke_algors_count, oid))) {
		error_print();
		return -1;
	}
	if (asn1_object_identifier_to_der(info->nodes, info->nodes_cnt, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_object_identifier_to_der(info->nodes, info->nodes_cnt, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_public_key_encryption_algor_from_der(int *oid, const uint8_t **params, size_t *params_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *p;
	size_t len;
	const ASN1_OID_INFO *info;

	*oid = OID_undef;
	*params = NULL;
	*params_len = 0;

	if ((ret = asn1_sequence_from_der(&p, &len, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_oid_info_from_der(&info, x509_pke_algors, x509_pke_algors_count, &p, &len) != 1) {
		error_print();
		return -1;
	}
	*oid = info->oid;
	if (asn1_length_is_zero(len) != 1) {
		if (info->oid == OID_sm2encrypt) {
			error_print();
			return -1;
		}
		*params = p;
		*params_len = len;
	}
	return 1;
}

int x509_public_key_encryption_algor_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	const ASN1_OID_INFO *info;
	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (asn1_oid_info_from_der(&info, x509_pke_algors, x509_pke_algors_count, &d, &dlen) != 1) goto err;
	format_print(fp, fmt, ind, "algorithm: %s\n", info->name);
	if (asn1_length_is_zero(dlen) != 1) {
		if (info->oid == OID_sm2encrypt) goto err;
		format_bytes(fp, fmt, ind, "parameters: ", d, dlen);
	}
	return 1;
err:
	error_print();
	return -1;
}





static uint32_t oid_ec_public_key[] = { oid_x9_62,2,1 };
//static uint32_t oid_rsa_encryption[] = { 1,2,840,113549,1,1,1 };

static const ASN1_OID_INFO x509_public_key_algors[] = {
	{ OID_ec_public_key, "ecPublicKey", oid_ec_public_key, sizeof(oid_ec_public_key)/sizeof(int), 0, "X9.62 ecPublicKey" },
	{ OID_rsa_encryption, "rsaEncryption", oid_rsa_encryption, sizeof(oid_rsa_encryption)/sizeof(int), 0, "RSAEncryption" },
};

static const int x509_public_key_algors_count =
	sizeof(x509_public_key_algors)/sizeof(x509_public_key_algors[0]);

const char *x509_public_key_algor_name(int oid)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_oid(x509_public_key_algors, x509_public_key_algors_count, oid))) {
		error_print();
		return NULL;
	}
	return info->name;
}

int x509_public_key_algor_from_name(const char *name)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_name(x509_public_key_algors, x509_public_key_algors_count, name))) {
		error_print();
		return OID_undef;
	}
	return info->oid;
}

int x509_public_key_algor_to_der(int oid, int curve_or_null, uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	switch (oid) {
	case OID_ec_public_key:
		if (asn1_object_identifier_to_der(oid_ec_public_key, sizeof(oid_ec_public_key)/sizeof(int), NULL, &len) != 1
			|| ec_named_curve_to_der(curve_or_null, NULL, &len) != 1
			|| asn1_sequence_header_to_der(len, out, outlen) != 1
			|| asn1_object_identifier_to_der(oid_ec_public_key, sizeof(oid_ec_public_key)/sizeof(int), out, outlen) != 1
			|| ec_named_curve_to_der(curve_or_null, out, outlen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_rsa_encryption:
		if (asn1_object_identifier_to_der(oid_rsa_encryption, sizeof(oid_rsa_encryption)/sizeof(int), NULL, &len) != 1
			|| asn1_null_to_der(NULL, &len) != 1
			|| asn1_sequence_header_to_der(len, out, outlen) != 1
			|| asn1_object_identifier_to_der(oid_rsa_encryption, sizeof(oid_rsa_encryption)/sizeof(int), out, outlen) != 1
			|| asn1_null_to_der(out, outlen) != 1) {
			error_print();
			return -1;
		}
		break;
	default:
		error_print();
		return -1;
	}
	return 1;
}

int x509_public_key_algor_from_der(int *oid , int *curve_or_null, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;
	const ASN1_OID_INFO *info;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}

	if (asn1_oid_info_from_der(&info, x509_public_key_algors, x509_public_key_algors_count, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	*oid = info->oid;

	switch (*oid) {
	case OID_ec_public_key:
		if (ec_named_curve_from_der(curve_or_null, &d, &dlen) != 1
			|| asn1_length_is_zero(dlen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_rsa_encryption:
		if ((*curve_or_null = asn1_null_from_der(&d, &dlen)) < 0
			|| asn1_length_is_zero(dlen) != 1) {
			error_print();
			return -1;
		}
		break;
	default:
		error_print();
		return -1;
	}
	return 1;
}

int x509_public_key_algor_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	const ASN1_OID_INFO *info;
	int val;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (asn1_oid_info_from_der(&info, x509_public_key_algors, x509_public_key_algors_count, &d, &dlen) != 1) goto err;
	format_print(fp, fmt, ind, "algorithm: %s\n", info->name);

	switch (info->oid) {
	case OID_ec_public_key:
		if (ec_named_curve_from_der(&val, &d, &dlen) != 1) goto err;
		format_print(fp, fmt, ind, "namedCurve: %s\n", ec_named_curve_name(val));
		break;
	case OID_rsa_encryption:
		if ((val = asn1_null_from_der(&d, &dlen)) < 0) goto err;
		else if (val) format_print(fp, fmt, ind, "parameters: %s\n", asn1_null_name());
		break;
	default:
		error_print();
		return -1;
	}
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}
