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


static const uint32_t DER_sm3[] = {1, 2, 156, 10197, 1, 401};
static const uint32_t DER_md5[] = {1, 2, 840, 113549, 2, 5};
static const uint32_t DER_sha1[] = {1, 3, 14, 3, 2, 26};
static const uint32_t DER_sha256[] = {2, 16, 840, 1, 101, 3, 4, 2, 1};
static const uint32_t DER_sha384[] = {2, 16, 840, 1, 101, 3, 4, 2, 2};
static const uint32_t DER_sha512[] = {2, 16, 840, 1, 101, 3, 4, 2, 3};
static const uint32_t DER_sha224[] = {2, 16, 840, 1, 101, 3, 4, 2, 4};

static struct {
	int oid;
	char *name;
	const uint32_t *nodes;
	size_t nodes_count;
} digest_table[] = {
	{ OID_sm3, "sm3", DER_sm3, sizeof(DER_sm3)/sizeof(int) },
	{ OID_md5, "md5", DER_md5, sizeof(DER_md5)/sizeof(int) },
	{ OID_sha1, "sha1", DER_sha1, sizeof(DER_sha1)/sizeof(int) },
	{ OID_sha224, "sha224", DER_sha224, sizeof(DER_sha224)/sizeof(int) },
	{ OID_sha256, "sha256", DER_sha256, sizeof(DER_sha256)/sizeof(int) },
	{ OID_sha384, "sha384", DER_sha384, sizeof(DER_sha384)/sizeof(int) },
	{ OID_sha512, "sha512", DER_sha512, sizeof(DER_sha512)/sizeof(int) },
};

const char *x509_digest_algor_name(int oid)
{
	int i;
	for (i = 0; i < sizeof(digest_table)/sizeof(digest_table[0]); i++) {
		if (oid == digest_table[i].oid) {
			return digest_table[i].name;
		}
	}
	return NULL;
}

int x509_digest_algor_to_der(int oid, uint8_t **out, size_t *outlen)
{
	size_t len;

	if (oid != OID_sm3) {
		error_print();
		return -1;
	}
	if (asn1_object_identifier_to_der(oid, NULL, 0, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_object_identifier_to_der(oid, NULL, 0, out,  outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_digest_algor_from_der(int *oid, uint32_t *nodes, size_t *nodes_count,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return -1;
	}
	if (asn1_object_identifier_from_der(oid, nodes, nodes_count, &data, &datalen) != 1) {
		error_print();
		return -1;
	}
	if (*oid != OID_undef && *oid != OID_sm3) {
		error_print();
		return -1;
	}
	if (datalen) {
		error_print();
		return -1;
	}
	return 1;
}


static uint32_t sm4_cbc_nodes[] = { 1, 2, 156, 10197, 1, 104, 2 };
static size_t sm4_cbc_nodes_count = sizeof(sm4_cbc_nodes)/sizeof(sm4_cbc_nodes[0]);


int x509_encryption_algor_to_der(int cipher, const uint8_t *iv, size_t ivlen,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (cipher != OID_sm4_cbc || ivlen != 16) {
		error_print();
		return -1;
	}
	if (asn1_object_identifier_to_der(OID_undef, sm4_cbc_nodes, sm4_cbc_nodes_count, NULL, &len) != 1
		|| asn1_octet_string_to_der(iv, ivlen, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_object_identifier_to_der(OID_undef, sm4_cbc_nodes, sm4_cbc_nodes_count, out, outlen) != 1
		|| asn1_octet_string_to_der(iv, ivlen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_encryption_algor_from_der(int *cipher,
	const uint8_t **iv, size_t *ivlen,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;
	uint32_t nodes[32];
	size_t nodes_count;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_object_identifier_from_der(cipher, nodes, &nodes_count, &data, &datalen) != 1
		|| asn1_octet_string_from_der(iv, ivlen, &data, &datalen) != 1
		|| datalen > 0) {
		error_print();
		return -1;
	}
	if (*cipher == OID_undef) {
		if (nodes_count == sm4_cbc_nodes_count
			&& memcmp(nodes, sm4_cbc_nodes, sizeof(sm4_cbc_nodes)) == 0) {
			*cipher = OID_sm4_cbc;
		} else {
			size_t i;
			error_puts("unknown cipher oid :");
			for (i = 0; i < nodes_count; i++) {
				fprintf(stderr, " %d", nodes[i]);
			}
			fprintf(stderr, "\n");
			return -1;
		}
	}

	// FIXME: 检查ivlen					
	return 1;
}

int x509_signature_algor_to_der(int oid, uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	int has_null_obj = 0;

	switch (oid) {
	// ECDSA/SM2 parameters MUST be omitted
	//case OID_ecdsa_with_sha1:
	//case OID_ecdsa_with_sha224
	//case OID_ecdsa_with_sha256:
	//case OID_ecdsa_with_sha384:
	//case OID_ecdsa_with_sha512:
	case OID_sm2sign_with_sm3:
		has_null_obj = 0;
		break;
	// RSA parameters MUST be ASN1_NULL
	//case OID_sha1WithRSAEncryption:
	//case OID_sha224WithRSAEncryption:
	//case OID_sha256WithRSAEncryption:
	//case OID_sha384WithRSAEncryption:
	//case OID_sha512WithRSAEncryption:
	case OID_rsasign_with_sm3:
		has_null_obj = 1;
		break;
	default:
		error_print();
		return -1;
	}

	if (asn1_object_identifier_to_der(oid, NULL, 0, NULL, &len) != 1) {
		error_print();
		return -1;
	}

	if (has_null_obj) {
		if (asn1_null_to_der(NULL, &len) != 1) {
			error_print();
			return -1;
		}
	}

	if (asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_object_identifier_to_der(oid, NULL, 0, out, outlen) != 1) {
		error_print();
		return -1;
	}

	if (has_null_obj) {
		if (asn1_null_to_der(out, outlen) != 1) {
			error_print();
			return -1;
		}
	}

	return 1;
}

int x509_signature_algor_from_der(int *oid, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;
	uint32_t nodes[32];
	size_t nodes_count;
	int has_null_obj;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		return ret;
	}
	if (asn1_object_identifier_from_der(oid, nodes, &nodes_count, &data, &datalen) != 1) {
		error_print();
		return -1;
	}
	if ((has_null_obj = asn1_null_from_der(&data, &datalen)) < 0) {
		error_print();
		return -1;
	}
	if (datalen > 0) {
		error_print_msg("datalen = %zu", datalen);
		error_print();
		return -1;
	}

	switch (*oid) {
	//case OID_ecdsa_with_sha1:
	//case OID_ecdsa_with_sha224
	//case OID_ecdsa_with_sha256:
	//case OID_ecdsa_with_sha384:
	//case OID_ecdsa_with_sha512:
	case OID_sm2sign_with_sm3:
		if (has_null_obj) {
			fprintf(stderr, "WARN: %s %d: AlgorithmIdentifier.parameters SHOULD be omitted for ECDSA/SM2\n", __FILE__, __LINE__);
		}
		break;
	//case OID_sha1WithRSAEncryption:
	//case OID_sha224WithRSAEncryption:
	//case OID_sha256WithRSAEncryption:
	//case OID_sha384WithRSAEncryption:
	//case OID_sha512WithRSAEncryption:
	case OID_rsasign_with_sm3:
		if (!has_null_obj) {
			fprintf(stderr, "WARN: %s %d\n: parameters SHOULD be NULL object for RSA", __FILE__, __LINE__);
		}
		break;
	default:
		// print unknown OID nodes
		error_print();
		return -1;
	}

	return 1;
}


const uint32_t DER_sm2encrypt[] = {1,2,156,10197,1,301,2};

int x509_public_key_encryption_algor_to_der(int algor, uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (asn1_object_identifier_to_der(OID_undef, DER_sm2encrypt,
			sizeof(DER_sm2encrypt)/sizeof(DER_sm2encrypt[0]), NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_object_identifier_to_der(OID_undef, DER_sm2encrypt,
			sizeof(DER_sm2encrypt)/sizeof(DER_sm2encrypt[0]), out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_public_key_encryption_algor_from_der(int *algor, uint32_t *nodes, size_t *nodes_count,
	const uint8_t *params, size_t *params_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_object_identifier_from_der(algor, nodes, nodes_count, &data, &datalen) != 1) {
		error_print();
		return -1;
	}
	// FIXME: 我们需要一个读取完整obj的函数
	return 1;
}














