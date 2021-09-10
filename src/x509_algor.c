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
#include <gmssl/oid.h>
#include <gmssl/asn1.h>
#include <gmssl/error.h>


typedef struct {
	int algor;
	char *name;
	const uint32_t *nodes;
	size_t nodes_count;
	int has_params;
} X509_ALGOR_INFO;


static const uint32_t oid_sm3[] = {1, 2, 156, 10197, 1, 401};
static const uint32_t oid_md5[] = {1, 2, 840, 113549, 2, 5};
static const uint32_t oid_sha1[] = {1, 3, 14, 3, 2, 26};
static const uint32_t oid_sha256[] = {2, 16, 840, 1, 101, 3, 4, 2, 1};
static const uint32_t oid_sha384[] = {2, 16, 840, 1, 101, 3, 4, 2, 2};
static const uint32_t oid_sha512[] = {2, 16, 840, 1, 101, 3, 4, 2, 3};
static const uint32_t oid_sha224[] = {2, 16, 840, 1, 101, 3, 4, 2, 4};

static X509_ALGOR_INFO x509_digest_algors[] = {
	{ OID_sm3, "sm3", oid_sm3, sizeof(oid_sm3)/sizeof(int), 0 },
	{ OID_md5, "md5", oid_md5, sizeof(oid_md5)/sizeof(int), 0 },
	{ OID_sha1, "sha1", oid_sha1, sizeof(oid_sha1)/sizeof(int), 0 },
	{ OID_sha224, "sha224", oid_sha224, sizeof(oid_sha224)/sizeof(int), 0 },
	{ OID_sha256, "sha256", oid_sha256, sizeof(oid_sha256)/sizeof(int), 0 },
	{ OID_sha384, "sha384", oid_sha384, sizeof(oid_sha384)/sizeof(int), 0 },
	{ OID_sha512, "sha512", oid_sha512, sizeof(oid_sha512)/sizeof(int), 0 },
};

static const int x509_digest_algors_count =
	sizeof(x509_digest_algors)/sizeof(x509_digest_algors[0]);

const char *x509_digest_algor_name(int algor)
{
	int i;
	for (i = 0; i < x509_digest_algors_count; i++) {
		if (algor == x509_digest_algors[i].algor) {
			return x509_digest_algors[i].name;
		}
	}
	return NULL;
}

int x509_digest_algor_from_name(const char *name)
{
	int i;
	for (i = 0; i < x509_digest_algors_count; i++) {
		if (strcmp(name, x509_digest_algors[i].name) == 0) {
			return x509_digest_algors[i].algor;
		}
	}
	return OID_undef;
}

int x509_digest_algor_to_der(int algor, uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	const uint32_t *nodes = NULL;
	size_t nodes_count;
	int i;

	for (i = 0; i < x509_digest_algors_count; i++) {
		if (algor == x509_digest_algors[i].algor) {
			nodes = x509_digest_algors[i].nodes;
			nodes_count = x509_digest_algors[i].nodes_count;
			break;
		}
	}
	if (!nodes) {
		error_print();
		return -1;
	}

	if (asn1_object_identifier_to_der(OID_undef, nodes, nodes_count, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_object_identifier_to_der(OID_undef, nodes, nodes_count, out,  outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_digest_algor_from_der(int *algor, uint32_t *nodes, size_t *nodes_count,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;
	int i;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return -1;
	}
	if (asn1_object_identifier_from_der(NULL, nodes, nodes_count, &data, &datalen) != 1
		|| asn1_length_is_zero(datalen) != 1) {
		error_print();
		return -1;
	}

	for (i = 0; i < x509_digest_algors_count; i++) {
		if (*nodes_count == x509_digest_algors[i].nodes_count
			&& memcmp(nodes, x509_digest_algors[i].nodes, (*nodes_count) * sizeof(int)) == 0) {
			*algor = x509_digest_algors[i].algor;
			return 1;
		}
	}
	*algor = OID_undef;
	error_print();
	return -1;
}


static uint32_t oid_sm4_cbc[] = {1, 2, 156, 10197, 1, 104, 2};
static uint32_t oid_aes128_cbc[] = {2, 16, 840, 1, 101, 3, 4, 1, 2};
static uint32_t oid_aes192_cbc[] = {2, 16, 840, 1, 101, 3, 4, 1, 22};
static uint32_t oid_aes256_cbc[] = {2, 16, 840, 1, 101, 3, 4, 1, 42};

static const X509_ALGOR_INFO x509_encryption_algors[] = {
	{ OID_sm4_cbc, "sm4-cbc", oid_sm4_cbc, sizeof(oid_sm4_cbc)/sizeof(int), 1 },
	{ OID_aes128_cbc, "aes128-cbc", oid_aes128_cbc, sizeof(oid_aes128_cbc)/sizeof(int), 1 },
	{ OID_aes192_cbc, "aes192-cbc", oid_aes192_cbc, sizeof(oid_aes192_cbc)/sizeof(int), 1 },
	{ OID_aes256_cbc, "aes256-cbc", oid_aes256_cbc, sizeof(oid_aes256_cbc)/sizeof(int), 1 },
};

static const int x509_encryption_algors_count =
	sizeof(x509_encryption_algors)/sizeof(x509_encryption_algors[0]);

const char *x509_encryption_algor_name(int algor)
{
	int i;
	for (i = 0; i < x509_encryption_algors_count; i++) {
		if (algor == x509_encryption_algors[i].algor) {
			return x509_encryption_algors[i].name;
		}
	}
	return NULL;
}

int x509_encryption_algor_from_name(const char *name)
{
	int i;
	for (i = 0; i < x509_encryption_algors_count; i++) {
		if (strcmp(name, x509_encryption_algors[i].name) == 0) {
			return x509_encryption_algors[i].algor;
		}
	}
	return 0;
}

int x509_encryption_algor_to_der(int algor, const uint8_t *iv, size_t ivlen,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	const uint32_t *nodes = NULL;
	size_t nodes_count;
	int i;

	for (i = 0; i < x509_encryption_algors_count; i++) {
		if (algor == x509_encryption_algors[i].algor) {
			nodes = x509_encryption_algors[i].nodes;
			nodes_count = x509_encryption_algors[i].nodes_count;
			break;
		}
	}
	if (i >= x509_encryption_algors_count ) {
		error_print();
		return -1;
	}

	if (asn1_object_identifier_to_der(OID_undef, nodes, nodes_count, NULL, &len) != 1
		|| asn1_octet_string_to_der(iv, ivlen, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_object_identifier_to_der(OID_undef, nodes, nodes_count, out, outlen) != 1
		|| asn1_octet_string_to_der(iv, ivlen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_encryption_algor_from_der(int *algor, uint32_t *nodes, size_t *nodes_count,
	const uint8_t **iv, size_t *ivlen,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;
	int i;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_object_identifier_from_der(NULL, nodes, nodes_count, &data, &datalen) != 1
		|| asn1_octet_string_from_der(iv, ivlen, &data, &datalen) != 1
		|| asn1_length_is_zero(datalen) != 1) {
		error_print();
		return -1;
	}
	if (!(*iv) || *ivlen != 16) {
		error_print();
		return -1;
	}
	for (i = 0; i < x509_encryption_algors_count; i++) {
		if (*nodes_count == x509_encryption_algors[i].nodes_count
			&& memcmp(nodes, x509_encryption_algors[i].nodes, (*nodes_count) * sizeof(int)) == 0) {
			*algor = x509_encryption_algors[i].algor;
			return 1;
		}
	}

	*algor = OID_undef;
	error_print();
	return -1;
}


static uint32_t oid_sm2sign_with_sm3[] = {1, 2, 156, 10197, 1, 501};
static uint32_t oid_rsasign_with_sm3[] = {1, 2, 156, 10197, 1, 504};
static uint32_t oid_ecdsa_with_sha1[] = {1, 2, 840, 10045, 4, 1};
static uint32_t oid_ecdsa_with_sha224[] = {1, 2, 840, 10045, 4, 3, 1};
static uint32_t oid_ecdsa_with_sha256[] = {1, 2, 840, 10045, 4, 3, 2};
static uint32_t oid_ecdsa_with_sha384[] = {1, 2, 840, 10045, 4, 3, 3};
static uint32_t oid_ecdsa_with_sha512[] = {1, 2, 840, 10045, 4, 3, 4};
static uint32_t oid_rsasign_with_sha1[] = {1, 2,840, 113549, 1, 1, 5};
static uint32_t oid_rsasign_with_sha224[] = {1, 2, 840, 113549, 1, 1, 14};
static uint32_t oid_rsasign_with_sha256[] = {1, 2, 840, 113549, 1, 1, 11};
static uint32_t oid_rsasign_with_sha384[] = {1, 2, 840, 113549, 1, 1, 12};
static uint32_t oid_rsasign_with_sha512[] = {1, 2, 840, 113549, 1, 1, 13};

static const X509_ALGOR_INFO x509_sign_algors[] = {
	{ OID_sm2sign_with_sm3, "sm2sign-with-sm3", oid_sm2sign_with_sm3, sizeof(oid_sm2sign_with_sm3)/sizeof(int), 0 },
	{ OID_rsasign_with_sm3, "rsasign-with-sm3", oid_rsasign_with_sm3, sizeof(oid_rsasign_with_sm3)/sizeof(int), 1 },
	{ OID_ecdsa_with_sha1, "ecdsa-with-sha1", oid_ecdsa_with_sha1, sizeof(oid_ecdsa_with_sha1)/sizeof(int), 0 },
	{ OID_ecdsa_with_sha224, "ecdsa-with-sha224", oid_ecdsa_with_sha224, sizeof(oid_ecdsa_with_sha224)/sizeof(int), 0} ,
	{ OID_ecdsa_with_sha256, "ecdsa-with-sha256", oid_ecdsa_with_sha256, sizeof(oid_ecdsa_with_sha256)/sizeof(int), 0},
	{ OID_ecdsa_with_sha384, "ecdsa-with-sha384", oid_ecdsa_with_sha384, sizeof(oid_ecdsa_with_sha384)/sizeof(int), 0 },
	{ OID_ecdsa_with_sha512, "ecdsa-with-sha512", oid_ecdsa_with_sha512, sizeof(oid_ecdsa_with_sha512)/sizeof(int), 0 },
	{ OID_rsasign_with_sha1, "sha1WithRSAEncryption", oid_rsasign_with_sha1, sizeof(oid_rsasign_with_sha1)/sizeof(int), 0 },
	{ OID_rsasign_with_sha224, "sha224WithRSAEncryption", oid_rsasign_with_sha224, sizeof(oid_rsasign_with_sha224)/sizeof(int), 1 },
	{ OID_rsasign_with_sha256, "sha256WithRSAEncryption", oid_rsasign_with_sha256, sizeof(oid_rsasign_with_sha256)/sizeof(int), 1 },
	{ OID_rsasign_with_sha384, "sha384WithRSAEncryption", oid_rsasign_with_sha384, sizeof(oid_rsasign_with_sha384)/sizeof(int), 1 },
	{ OID_rsasign_with_sha512, "sha512WithRSAEncryption", oid_rsasign_with_sha512, sizeof(oid_rsasign_with_sha512)/sizeof(int), 1 },
};

static const int x509_sign_algors_count =
	sizeof(x509_sign_algors)/sizeof(x509_sign_algors[0]);

const char *x509_signature_algor_name(int algor)
{
	int i;
	for (i = 0; i < x509_sign_algors_count; i++) {
		if (algor == x509_sign_algors[i].algor) {
			return x509_sign_algors[i].name;
		}
	}
	return NULL;
}

int x509_signature_algor_from_name(const char *name)
{
	int i;
	for (i = 0; i < x509_sign_algors_count; i++) {
		if (strcmp(name, x509_sign_algors[i].name) == 0) {
			return x509_sign_algors[i].algor;
		}
	}
	return OID_undef;
}

int x509_signature_algor_to_der(int algor, uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	const uint32_t *nodes;
	size_t nodes_count;
	int has_null_obj;
	int i;

	for (i = 0; i < x509_sign_algors_count; i++) {
		if (algor == x509_sign_algors[i].algor) {
			nodes = x509_sign_algors[i].nodes;
			nodes_count = x509_sign_algors[i].nodes_count;
			has_null_obj = x509_sign_algors[i].has_params;
			break;
		}
	}
	if (i >= x509_sign_algors_count) {
		error_print();
		return -1;
	}

	if (asn1_object_identifier_to_der(OID_undef, nodes, nodes_count, NULL, &len) != 1
		|| (has_null_obj && asn1_null_to_der(NULL, &len) != 1)
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_object_identifier_to_der(OID_undef, nodes, nodes_count, out, outlen) != 1
		|| (has_null_obj && asn1_null_to_der(out, outlen) != 1)) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_signature_algor_from_der(int *algor, uint32_t *nodes, size_t *nodes_count,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;
	int has_null_obj;
	int i;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		if (ret == 0) error_print();
		return ret;
	}
	if (asn1_object_identifier_from_der(algor, nodes, nodes_count, &data, &datalen) != 1) {
		error_print();
		return -1;
	}
	for (i = 0; i < x509_sign_algors_count; i++) {
		if (*nodes_count == x509_sign_algors[i].nodes_count
			&& memcmp(nodes, x509_sign_algors[i].nodes, (*nodes_count) * sizeof(int)) == 0) {
			*algor = x509_sign_algors[i].algor;
			has_null_obj = x509_sign_algors[i].has_params;
			break;
		}
	}
	if (i >= x509_sign_algors_count) {
		error_print();
		return -1;
	}

	if (has_null_obj && asn1_null_from_der(&data, &datalen) != 1) {
		error_print();
		return -1;
	}
	if (datalen) {
		error_print();
		return -1;
	}
	return 1;
}

/*
from rfc 3560:
RSAES-OAEP-params  ::=  SEQUENCE  {
	hashFunc    [0] AlgorithmIdentifier DEFAULT sha1Identifier,
	maskGenFunc [1] AlgorithmIdentifier DEFAULT mgf1SHA1Identifier,
	pSourceFunc [2] AlgorithmIdentifier DEFAULT

SM2公钥加密算法参数默认为SM3，本实现在to_der时不编码参数
在from_der时，将参数直接返回给应用，不做处理
*/

static uint32_t oid_sm2encrypt[] = {1, 2, 156, 10197, 1, 301, 2};
static uint32_t oid_rsa_encryption[] = {1, 2, 840, 113549, 1, 1, 1};
static uint32_t oid_rsaes_oaep[] = {1, 2, 840, 113549, 1, 1, 7};

static const X509_ALGOR_INFO x509_pke_algors[] = {
	{ OID_sm2encrypt, "sm2encrypt", oid_sm2encrypt, sizeof(oid_sm2encrypt)/sizeof(int) },
	{ OID_rsa_encryption, "rsaEncryption", oid_rsa_encryption, sizeof(oid_rsa_encryption)/sizeof(int) },
	{ OID_rsaes_oaep, "rsaesOAEP", oid_rsaes_oaep, sizeof(oid_rsaes_oaep)/sizeof(int) },
};

static const int x509_pke_algors_count =
	sizeof(x509_pke_algors)/sizeof(x509_pke_algors[0]);

const char *x509_public_key_encryption_algor_name(int algor)
{
	int i;
	for (i = 0; i < x509_pke_algors_count; i++) {
		if (algor == x509_pke_algors[i].algor) {
			return x509_pke_algors[i].name;
		}
	}
	return NULL;
}

int x509_public_key_encryption_algor_from_name(const char *name)
{
	int i;
	for (i = 0; i < x509_pke_algors_count; i++) {
		if (strcmp(name, x509_pke_algors[i].name) == 0) {
			return x509_pke_algors[i].algor;
		}
	}
	return OID_undef;
}

int x509_public_key_encryption_algor_to_der(int algor, uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	const uint32_t *nodes;
	size_t nodes_count;
	int i;

	for (i = 0; i < x509_pke_algors_count; i++) {
		if (algor == x509_pke_algors[i].algor) {
			nodes = x509_pke_algors[i].nodes;
			nodes_count = x509_pke_algors[i].nodes_count;
			break;
		}
	}
	if (i >= x509_pke_algors_count) {
		error_print();
		return -1;
	}

	if (asn1_object_identifier_to_der(OID_undef, nodes, nodes_count, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_object_identifier_to_der(OID_undef, nodes, nodes_count, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_public_key_encryption_algor_from_der(int *algor, uint32_t *nodes, size_t *nodes_count,
	const uint8_t **params, size_t *params_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;
	int i;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_object_identifier_from_der(NULL, nodes, nodes_count, &data, &datalen) != 1) {
		error_print();
		return -1;
	}

	for (i = 0; i < x509_pke_algors_count; i++) {
		if (*nodes_count == x509_pke_algors[i].nodes_count
			&& memcmp(nodes, x509_pke_algors[i].nodes, (*nodes_count) * sizeof(int)) == 0) {
			*algor = x509_pke_algors[i].algor;
			break;
		}
	}
	if (i >= x509_pke_algors_count) {
		error_print();
		return -1;
	}
	if (datalen) {
		*params = data;
		*params_len = datalen;
	}
	return 1;
}
