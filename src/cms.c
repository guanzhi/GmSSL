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

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/asn1.h>
#include <gmssl/aes.h>
#include <gmssl/sm4.h>
#include <gmssl/digest.h>
#include <gmssl/error.h>
#include <gmssl/x509.h>
#include <gmssl/x509_str.h>
#include <gmssl/x509_alg.h>
#include <gmssl/x509_ext.h>
#include <gmssl/rand.h>
#include <gmssl/cms.h>



static uint32_t oid_cms_data[] = { oid_sm2_cms,1 };
static uint32_t oid_cms_signed_data[] = { oid_sm2_cms,2 };
static uint32_t oid_cms_enveloped_data[] = { oid_sm2_cms,3 };
static uint32_t oid_cms_signed_and_enveloped_data[] = { oid_sm2_cms,4 };
static uint32_t oid_cms_encrypted_data[] = { oid_sm2_cms,5 };
static uint32_t oid_cms_key_agreement_info[] = { oid_sm2_cms,6 };

static const ASN1_OID_INFO cms_content_types[] = {
	{ OID_cms_data, "data", oid_cms_data, sizeof(oid_cms_data)/sizeof(int) },
	{ OID_cms_signed_data, "signedData", oid_cms_signed_data, sizeof(oid_cms_signed_data)/sizeof(int) },
	{ OID_cms_enveloped_data, "envelopedData", oid_cms_signed_data, sizeof(oid_cms_signed_data)/sizeof(int) },
	{ OID_cms_signed_and_enveloped_data, "signedAndEnvelopedData", oid_cms_signed_and_enveloped_data, sizeof(oid_cms_signed_and_enveloped_data)/sizeof(int) },
	{ OID_cms_encrypted_data, "encryptedData", oid_cms_encrypted_data, sizeof(oid_cms_encrypted_data)/sizeof(int) },
	{ OID_cms_key_agreement_info, "keyAgreementInfo", oid_cms_key_agreement_info, sizeof(oid_cms_key_agreement_info)/sizeof(int) }
};

static const size_t cms_content_types_count =
	sizeof(cms_content_types)/sizeof(cms_content_types[0]);

const char *cms_content_type_name(int oid)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_oid(cms_content_types, cms_content_types_count, oid))) {
		error_print();
		return NULL;
	}
	return info->name;
}

int cms_content_type_from_name(const char *name)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_name(cms_content_types, cms_content_types_count, name))) {
		error_print();
		return OID_undef;
	}
	return info->oid;
}

int cms_content_type_to_der(int oid, uint8_t **out, size_t *outlen)
{
	const ASN1_OID_INFO *info;
	size_t len = 0;
	if (!(info = asn1_oid_info_from_oid(cms_content_types, cms_content_types_count, oid))) {
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

int cms_content_type_from_der(int *oid, const uint8_t **in, size_t *inlen)
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
	if ((ret = asn1_oid_info_from_der(&info, cms_content_types, cms_content_types_count, &p, &len)) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return ret;
	}
	*oid = info->oid;
	return 1;
}

int cms_enced_content_info_to_der(
	int content_type,
	int enc_algor, const uint8_t *enc_iv, size_t enc_iv_len,
	const uint8_t *enced_content, size_t enced_content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (cms_content_type_to_der(content_type, NULL, &len) != 1
		|| x509_encryption_algor_to_der(enc_algor, enc_iv, enc_iv_len, NULL, &len) != 1
		|| asn1_implicit_octet_string_to_der(0, enced_content, enced_content_len, NULL, &len) < 0
		|| asn1_implicit_octet_string_to_der(1, shared_info1, shared_info1_len, NULL, &len) < 0
		|| asn1_implicit_octet_string_to_der(2, shared_info2, shared_info2_len, NULL, &len) < 0
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| cms_content_type_to_der(content_type, out, outlen) != 1
		|| x509_encryption_algor_to_der(enc_algor, enc_iv, enc_iv_len, out, outlen) != 1
		|| asn1_implicit_octet_string_to_der(0, enced_content, enced_content_len, out, outlen) < 0
		|| asn1_implicit_octet_string_to_der(1, shared_info1, shared_info1_len, out, outlen) < 0
		|| asn1_implicit_octet_string_to_der(2, shared_info2, shared_info2_len, out, outlen) < 0) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_enced_content_info_from_der(
	int *content_type,
	int *enc_algor, const uint8_t **enc_iv, size_t *enc_iv_len,
	const uint8_t **enced_content, size_t *enced_content_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (cms_content_type_from_der(content_type, &d, &dlen) != 1
		|| x509_encryption_algor_from_der(enc_algor, enc_iv, enc_iv_len, &d, &dlen) != 1
		|| asn1_implicit_octet_string_from_der(0, enced_content, enced_content_len, &d, &dlen) < 0
		|| asn1_implicit_octet_string_from_der(1, shared_info1, shared_info1_len, &d, &dlen) < 0
		|| asn1_implicit_octet_string_from_der(2, shared_info2, shared_info2_len, &d, &dlen) < 0
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_enced_content_info_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int ret, val;
	const uint8_t *p;
	size_t len;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (cms_content_type_from_der(&val, &d, &dlen) != 1) goto err;
	format_print(fp, fmt, ind, "contentType: %s\n", cms_content_type_name(val));
	if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) goto err;
	x509_encryption_algor_print(fp, fmt, ind, "contentEncryptionAlgorithm", p, len);
	if ((ret = asn1_implicit_octet_string_from_der(0, &p, &len, &d, &dlen)) < 0) goto err;
	if (ret) format_bytes(fp, fmt, ind, "encryptedContent", d, dlen);
	if ((ret = asn1_implicit_octet_string_from_der(1, &p, &len, &d, &dlen)) < 0) goto err;
	if (ret) format_bytes(fp, fmt, ind, "sharedInfo1", d, dlen);
	if ((ret = asn1_implicit_octet_string_from_der(2, &p, &len, &d, &dlen)) < 0) goto err;
	if (ret) format_bytes(fp, fmt, ind, "sharedInfo2", d, dlen);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

int cms_enced_content_info_encrypt_to_der(
	int content_type,
	int enc_algor, const uint8_t *iv, size_t ivlen,
	const uint8_t *content, size_t content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	const uint8_t *key, size_t keylen,
	uint8_t **out, size_t *outlen)
{
	int ret;
	SM4_KEY sm4_key;
	uint8_t enced_content[32 + content_len];
	size_t enced_content_len;

	if (enc_algor != OID_sm4_cbc || keylen != 16 || ivlen != 16) {
		error_print();
		return -1;
	}

	sm4_set_encrypt_key(&sm4_key, key);
	if (sm4_cbc_padding_encrypt(&sm4_key, iv, content, content_len,
		enced_content, &enced_content_len) != 1) {
		memset(&sm4_key, 0, sizeof(SM4_KEY));
		error_print();
		return -1;
	}
	memset(&sm4_key, 0, sizeof(SM4_KEY));

	if ((ret = cms_enced_content_info_to_der(content_type,
		enc_algor, iv, ivlen, enced_content, enced_content_len,
		shared_info1, shared_info1_len,
		shared_info2, shared_info2_len,
		out, outlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	return 1;
}

int cms_enced_content_info_decrypt_from_der(
	int *content_type,
	int *enc_algor, const uint8_t **iv, size_t *ivlen,
	uint8_t *content, size_t *content_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len,
	const uint8_t *key, size_t keylen,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	SM4_KEY sm4_key;
	const uint8_t *enced_content;
	size_t enced_content_len;

	if ((ret = cms_enced_content_info_from_der(content_type,
		enc_algor, iv, ivlen, &enced_content, &enced_content_len,
		shared_info1, shared_info1_len,
		shared_info2, shared_info2_len,
		in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}

	if (*enc_algor != OID_sm4_cbc) {
		error_print();
		return -1;
	}
	if (*ivlen != SM4_BLOCK_SIZE) {
		error_print();
		return -1;
	}
	if (keylen != SM4_KEY_SIZE) {
		error_print();
		return -1;
	}

	sm4_set_decrypt_key(&sm4_key, key);
	if (sm4_cbc_padding_decrypt(&sm4_key, *iv, enced_content, enced_content_len,
		content, content_len) != 1) {
		memset(&sm4_key, 0, sizeof(SM4_KEY));
		return -1;
	}
	memset(&sm4_key, 0, sizeof(SM4_KEY));

	return 1;
}















