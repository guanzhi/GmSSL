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
#include <gmssl/sm2.h>
#include <gmssl/digest.h>
#include <gmssl/error.h>
#include <gmssl/x509.h>
#include <gmssl/x509_str.h>
#include <gmssl/x509_alg.h>
#include <gmssl/x509_ext.h>
#include <gmssl/x509_crl.h>
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

int cms_content_info_to_der(
	int content_type,
	const uint8_t *content, size_t content_len,
	uint8_t **out, size_t *outlen)
{
	return -1;
}

int cms_content_info_from_der(
	int *content_type,
	const uint8_t **content, size_t *content_len, // 这里获得的是完整的TLV
	const uint8_t **in, size_t *inlen)
{
	return -1;
}

int cms_content_info_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	return -1;
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

int cms_encrypted_data_to_der(
	int version,
	int content_type,
	int enc_algor, const uint8_t *iv, size_t ivlen,
	const uint8_t *enced_content, size_t enced_content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (version != 1) {
		error_print();
		return -1;
	}
	if (asn1_int_to_der(version, NULL, &len) != 1
		|| cms_enced_content_info_to_der(
			content_type,
			enc_algor, iv, ivlen,
			enced_content, enced_content_len,
			shared_info1, shared_info1_len,
			shared_info2, shared_info2_len,
			NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(version, out, outlen) != 1
		|| cms_enced_content_info_to_der(
			content_type,
			enc_algor, iv, ivlen,
			enced_content, enced_content_len,
			shared_info1, shared_info1_len,
			shared_info2, shared_info2_len,
			NULL, &len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_encrypted_data_from_der(
	int *version,
	int *content_type,
	int *enc_algor, const uint8_t **iv, size_t *ivlen,
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
	if (asn1_int_from_der(version, &d, &dlen) != 1
		|| cms_enced_content_info_from_der(
			content_type,
			enc_algor, iv, ivlen,
			enced_content, enced_content_len,
			shared_info1, shared_info1_len,
			shared_info2, shared_info2_len,
			&d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	if (*version != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_encrypted_data_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int val;
	const uint8_t *p;
	size_t len;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (asn1_int_from_der(&val, &d, &dlen) != 1) goto err;
	format_print(fp, fmt, ind, "version: %d\n", val);
	if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) goto err;
	cms_enced_content_info_print(fp, fmt, ind, "encryptedContentInfo", p, len);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

int cms_encrypted_data_encrypt_to_der(
	int version,
	int content_type,
	int enc_algor, const uint8_t *iv, size_t ivlen,
	const uint8_t *content, size_t content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	const uint8_t *key, size_t keylen,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (asn1_int_to_der(version, NULL, &len) != 1
		|| cms_enced_content_info_encrypt_to_der(
			content_type,
			enc_algor, iv, ivlen,
			content, content_len,
			shared_info1, shared_info1_len,
			shared_info2, shared_info2_len,
			key, keylen,
			NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(version, out, outlen) != 1
		|| cms_enced_content_info_encrypt_to_der(
			content_type,
			enc_algor, iv, ivlen,
			content, content_len,
			shared_info1, shared_info1_len,
			shared_info2, shared_info2_len,
			key, keylen,
			out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_encrypted_data_decrypt_from_der(
	int *version,
	int *content_type,
	int *enc_algor, const uint8_t **iv, size_t *ivlen,
	uint8_t *content, size_t *content_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len,
	const uint8_t *key, size_t keylen,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_int_from_der(version, &d, &dlen) != 1
		|| cms_enced_content_info_decrypt_from_der(
			content_type,
			enc_algor, iv, ivlen,
			content, content_len,
			shared_info1, shared_info1_len,
			shared_info2, shared_info2_len,
			key, keylen,
			&d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	if (*version != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_issuer_and_serial_number_to_der(
	const uint8_t *issuer, size_t issuer_len,
	const uint8_t *serial_number, size_t serial_number_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (asn1_sequence_to_der(issuer, issuer_len, NULL, &len) != 1
		|| asn1_integer_to_der(serial_number, serial_number_len, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_sequence_to_der(issuer, issuer_len, out, outlen) != 1
		|| asn1_integer_to_der(serial_number, serial_number_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_issuer_and_serial_number_from_der(
	const uint8_t **issuer, size_t *issuer_len,
	const uint8_t **serial_number, size_t *serial_number_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_sequence_from_der(issuer, issuer_len, &d, &dlen) != 1
		|| asn1_integer_from_der(serial_number, serial_number_len, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_issuer_and_serial_number_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	const uint8_t *p;
	size_t len;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) goto err;
	x509_name_print(fp, fmt, ind, "issuer", p, len);
	if (asn1_integer_from_der(&p, &len, &d, &dlen) != 1) goto err;
	format_bytes(fp, fmt, ind, "serialNumber", p, len);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

int cms_signer_info_to_der(
	int version,
	const uint8_t *issuer, size_t issuer_len,
	const uint8_t *serial_number, size_t serial_number_len,
	int digest_algor,
	const uint8_t *authed_attrs, size_t authed_attrs_len,
	int signature_algor,
	const uint8_t *enced_digest, size_t enced_digest_len,
	const uint8_t *unauthed_attrs, size_t unauthed_attrs_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (version != 1) {
		error_print();
		return -1;
	}
	if (asn1_int_to_der(version, NULL, &len) != 1
		|| cms_issuer_and_serial_number_to_der(
			issuer, issuer_len,
			serial_number, serial_number_len, NULL, &len) != 1
		|| x509_digest_algor_to_der(digest_algor, NULL, &len) != 1
		|| asn1_implicit_set_to_der(0, authed_attrs, authed_attrs_len, NULL, &len) < 0
		|| x509_signature_algor_to_der(signature_algor, NULL, &len) != 1
		|| asn1_octet_string_to_der(enced_digest, enced_digest_len, NULL, &len) != 1
		|| asn1_implicit_set_to_der(1, unauthed_attrs, unauthed_attrs_len, NULL, &len) < 0
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(version, out, outlen) != 1
		|| cms_issuer_and_serial_number_to_der(
			issuer, issuer_len,
			serial_number, serial_number_len, out, outlen) != 1
		|| x509_digest_algor_to_der(digest_algor, out, outlen) != 1
		|| asn1_implicit_set_to_der(0, authed_attrs, authed_attrs_len, out, outlen) < 0
		|| x509_signature_algor_to_der(signature_algor, out, outlen) != 1
		|| asn1_octet_string_to_der(enced_digest, enced_digest_len, out, outlen) != 1
		|| asn1_implicit_set_to_der(1, unauthed_attrs, unauthed_attrs_len, out, outlen) < 0) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_signer_info_from_der(
	int *version,
	const uint8_t **issuer, size_t *issuer_len,
	const uint8_t **serial_number, size_t *serial_number_len,
	int *digest_algor,
	const uint8_t **authed_attrs, size_t *authed_attrs_len,
	int *signature_algor,
	const uint8_t **enced_digest, size_t *enced_digest_len,
	const uint8_t **unauthed_attrs, size_t *unauthed_attrs_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_int_from_der(version, &d, &dlen) != 1
		|| cms_issuer_and_serial_number_from_der(issuer, issuer_len,
			serial_number, serial_number_len, &d, &dlen) != 1
		|| x509_digest_algor_from_der(digest_algor, &d, &dlen) != 1
		|| asn1_implicit_set_from_der(0, authed_attrs, authed_attrs_len, &d, &dlen) < 0
		|| x509_signature_algor_from_der(signature_algor, &d, &dlen) != 1
		|| asn1_octet_string_from_der(enced_digest, enced_digest_len, &d, &dlen) != 1
		|| asn1_implicit_set_from_der(1, unauthed_attrs, unauthed_attrs_len, &d, &dlen) < 0
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_signer_info_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int ret, val;
	const uint8_t *p;
	size_t len;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (asn1_int_from_der(&val, &d, &dlen) != 1) goto err;
	format_print(fp, fmt, ind, "version: %d\n", val);
	if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) goto err;
	cms_issuer_and_serial_number_print(fp, fmt, ind, "issuerAndSerialNumber", p, len);
	if (x509_digest_algor_from_der(&val, &d, &dlen) != 1) goto err;
	format_print(fp, fmt, ind, "digestAlgorithm: %s\n", x509_digest_algor_name(val));
	if ((ret = asn1_implicit_set_from_der(0, &p, &len, &d, &dlen)) != 1) goto err;
	if (ret) x509_attributes_print(fp, fmt, ind, "authenticatedAttributes", p, len);
	if (x509_signature_algor_from_der(&val, &d, &dlen) != 1) goto err;
	format_print(fp, fmt, ind, "digestEncryptionAlgorithm: %s\n", x509_signature_algor_name(val));
	if (asn1_octet_string_from_der(&p, &len, &d, &dlen) != 1) goto err;
	format_bytes(fp, fmt, ind, "encryptedDigest", p, len);
	if ((ret = asn1_implicit_set_from_der(1, &p, &len, &d, &dlen)) != 1) goto err;
	if (ret) x509_attributes_print(fp, fmt, ind, "unauthenticatedAttributes", p, len);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

int cms_signer_info_sign_to_der(
	int version,
	const uint8_t *issuer, size_t issuer_len,
	const uint8_t *serial_number, size_t serial_number_len,
	const uint8_t *authed_attrs, size_t authed_attrs_len,
	const uint8_t *unauthed_attrs, size_t unauthed_attrs_len,
	const SM3_CTX *sm3_ctx, const SM2_KEY *sign_key,
	uint8_t **out, size_t *outlen)
{
	SM3_CTX ctx = *sm3_ctx;
	uint8_t dgst[SM3_DIGEST_SIZE];
	uint8_t sig[SM2_MAX_SIGNATURE_SIZE];
	size_t siglen;

	sm3_update(&ctx, authed_attrs, authed_attrs_len);
	sm3_finish(&ctx, dgst);
	if (sm2_sign(sign_key, dgst, sig, &siglen) != 1) {
		error_print();
		return -1;
	}

	if (cms_signer_info_to_der(version,
		issuer, issuer_len, serial_number, serial_number_len,
		OID_sm3, authed_attrs, authed_attrs_len,
		OID_sm2sign_with_sm3, sig, siglen,
		unauthed_attrs, unauthed_attrs_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_signer_info_verify_from_der(
	int *version,
	const uint8_t **issuer, size_t *issuer_len,
	const uint8_t **serial_number, size_t *serial_number_len,
	int *digest_algor,
	const uint8_t **authed_attrs, size_t *authed_attrs_len,
	int *signature_algor,
	const uint8_t **enced_digest, size_t *enced_digest_len,
	const uint8_t **unauthed_attrs, size_t *unauthed_attrs_len,
	const SM3_CTX *sm3_ctx, const SM2_KEY *sign_pub_key,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	SM3_CTX ctx = *sm3_ctx;
	uint8_t dgst[SM3_DIGEST_SIZE];

	if ((ret = cms_signer_info_from_der(version,
		issuer, issuer_len, serial_number, serial_number_len,
		digest_algor, authed_attrs, authed_attrs_len,
		signature_algor, enced_digest, enced_digest_len,
		unauthed_attrs, unauthed_attrs_len, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (*digest_algor != OID_sm3
		|| *signature_algor != OID_sm2sign_with_sm3) {
		error_print();
		return -1;
	}

	sm3_update(&ctx, *authed_attrs, *authed_attrs_len);
	sm3_finish(&ctx, dgst);

	if ((ret = sm2_verify(sign_pub_key, dgst, *enced_digest, *enced_digest_len)) != 1) {
		if (ret < 0) error_print();
		else error_print();
		return ret;
	}
	return ret;
}

int cms_signer_infos_add_signer_info(
	uint8_t *d, size_t *dlen, size_t maxlen,
	int version,
	const uint8_t *issuer, size_t issuer_len,
	const uint8_t *serial_number, size_t serial_number_len,
	const uint8_t *authed_attrs, size_t authed_attrs_len,
	const uint8_t *unauthed_attrs, size_t unauthed_attrs_len,
	const SM3_CTX *sm3_ctx, const SM2_KEY *sign_key)
{
	return -1;
}

int cms_signer_infos_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	const uint8_t *p;
	size_t len;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	while (dlen) {
		if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		cms_signer_info_print(fp, fmt, ind, "SignerInfo", p, len);
	}
	return 1;
}

int cms_crls_add_crl(uint8_t *d, size_t *dlen, size_t maxlen, const uint8_t *crl, size_t crllen)
{
	return -1;
}

int cms_crls_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	const uint8_t *p;
	size_t len;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	while (dlen) {
		if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		x509_cert_list_print(fp, fmt, ind, "CertificateRevocationList", p, len);
	}
	return 1;
}

int cms_extened_certs_add_cert(uint8_t *d, size_t *dlen, size_t maxlen, const uint8_t *cert, size_t certlen)
{
	return -1;
}

int cms_extended_certs_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	// 注意：这里可能需要解析ExtendedCertificateAndCertificate
	return -1;
}

int cms_digest_algors_to_der(const int *digest_algors, size_t digest_algors_cnt,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0, i;
	for (i = 0; i < digest_algors_cnt; i++) {
		if (x509_digest_algor_to_der(digest_algors[i], NULL, &len) != 1) {
			error_print();
			return -1;
		}
	}
	if (asn1_set_header_to_der(len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	for (i = 0; i < digest_algors_cnt; i++) {
		if (x509_digest_algor_to_der(digest_algors[i], out, outlen) != 1) {
			error_print();
			return -1;
		}
	}
	return 1;
}

int cms_digest_algors_from_der(int *digest_algors, size_t *digest_algors_cnt, size_t max_digest_algors,
	const uint8_t **in, size_t *inlen)
{
	return -1;
}

int cms_digest_algors_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	return -1;
}

int cms_signed_data_to_der(
	int version,
	const int *digest_algors, size_t digest_algors_cnt,
	const int content_type, const uint8_t *content, const size_t content_len,
	const uint8_t *certs, size_t certs_len,
	const uint8_t *crls, const size_t crls_len,
	const uint8_t *signer_infos, size_t signer_infos_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (version != 1) {
		error_print();
		return -1;
	}
	if (asn1_int_to_der(version, NULL, &len) != 1
		|| cms_digest_algors_to_der(digest_algors, digest_algors_cnt, NULL, &len) != 1
		|| cms_content_info_to_der(content_type, content, content_len, NULL, &len) != 1
		|| asn1_implicit_set_to_der(0, certs, certs_len, NULL, &len) < 0
		|| asn1_implicit_set_to_der(1, crls, crls_len, NULL, &len) < 0
		|| cms_signer_infos_to_der(signer_infos, signer_infos_len, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(version, out, outlen) != 1
		|| cms_digest_algors_to_der(digest_algors, digest_algors_cnt, out, outlen) != 1
		|| cms_content_info_to_der(content_type, content, content_len, out, outlen) != 1
		|| asn1_implicit_set_to_der(0, certs, certs_len, out, outlen) < 0
		|| asn1_implicit_set_to_der(1, crls, crls_len, out, outlen) < 0
		|| cms_signer_infos_to_der(signer_infos, signer_infos_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_signed_data_from_der(
	int *version,
	int *digest_algors, size_t *digest_algors_cnt, size_t max_digest_algors,
	int *content_type, const uint8_t **content, size_t *content_len,
	const uint8_t **certs, size_t *certs_len,
	const uint8_t **crls, size_t *crls_len,
	const uint8_t **signer_infos, size_t *signer_infos_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_int_from_der(version, &d, &dlen) != 1
		|| cms_digest_algors_from_der(digest_algors, digest_algors_cnt, max_digest_algors, &d, &dlen) != 1
		|| cms_content_info_from_der(content_type, content, content_len, &d, &dlen) != 1
		|| asn1_implicit_set_from_der(0, certs, certs_len, &d, &dlen) < 0
		|| asn1_implicit_set_from_der(1, crls, crls_len, &d, &dlen) < 0
		|| asn1_set_from_der(signer_infos, signer_infos_len, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	if (*version != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_signed_data_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int ret, val;
	const uint8_t *p;
	size_t len;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (asn1_int_from_der(&val, &d, &dlen) != 1) goto err;
	format_print(fp, fmt, ind, "version: %d\n", val);
	if (asn1_set_from_der(&p, &len, &d, &dlen) != 1) goto err;
	cms_digest_algors_print(fp, fmt, ind, "digestAlgorithms", p, len);
	if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) goto err;
	cms_content_info_print(fp, fmt, ind, "contentInfo", p, len);
	if ((ret = asn1_implicit_set_from_der(0, &p, &len, &d, &dlen)) < 0) goto err;
	if (ret) cms_extended_certs_print(fp, fmt, ind, "certificates", p, len);
	if ((ret = asn1_implicit_set_from_der(1, &p, &len, &d, &dlen)) < 0) goto err;
	if (asn1_set_from_der(&p, &len, &d, &dlen) != 1) goto err;
	cms_signer_infos_print(fp, fmt, ind, "signerInfos", p, len);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

int cms_signed_data_sign_to_der(
	int version,
	int content_type, const uint8_t *content, size_t content_len,
	const CMS_CERT_AND_KEY *signers, size_t signers_cnt,
	const uint8_t *crls, size_t crls_len,
	uint8_t **out, size_t *outlen)
{
	return -1;
}

int cms_signed_data_verify_from_der(
	int *version,
	const uint8_t *digest_algors, size_t *digest_algors_cnt, size_t max_digest_algors,
	int *content_type, const uint8_t **content, size_t *content_len,
	const uint8_t **certs, size_t *certs_len,
	const uint8_t **crls, size_t *crls_len,
	const uint8_t **signer_infos, size_t *signer_infos_len,
	const uint8_t *extra_certs, size_t extra_certs_len,
	const uint8_t *extra_crls, size_t extra_crls_len,
	const uint8_t **in, size_t *inlen)
{
	return -1;
}

int cms_recipient_info_to_der(
	int version,
	const uint8_t *issuer, size_t issuer_len,
	const uint8_t *serial_number, size_t serial_number_len,
	int public_key_enc_algor,
	const uint8_t *enced_key, size_t enced_key_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (version != 1) {
		error_print();
		return -1;
	}
	if (asn1_int_to_der(version, NULL, &len) != 1
		|| cms_issuer_and_serial_number_to_der(issuer, issuer_len,
			serial_number, serial_number_len, NULL, &len) != 1
		|| x509_public_key_encryption_algor_to_der(public_key_enc_algor, NULL, &len) != 1
		|| asn1_octet_string_to_der(enced_key, enced_key_len, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(version, out, outlen) != 1
		|| cms_issuer_and_serial_number_to_der(issuer, issuer_len,
			serial_number, serial_number_len, out, outlen) != 1
		|| x509_public_key_encryption_algor_to_der(public_key_enc_algor, out, outlen) != 1
		|| asn1_octet_string_to_der(enced_key, enced_key_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_recipient_info_from_der(
	int *version,
	const uint8_t **issuer, size_t *issuer_len,
	const uint8_t **serial_number, size_t *serial_number_len,
	int *pke_algor, const uint8_t **params, size_t *params_len,// SM2加密只使用SM3，没有默认参数，但是ECIES可能有
	const uint8_t **enced_key, size_t *enced_key_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_int_from_der(version, &d, &dlen) != 1
		|| cms_issuer_and_serial_number_from_der(issuer, issuer_len,
			serial_number, serial_number_len, &d, &dlen) != 1
		|| x509_public_key_encryption_algor_from_der(pke_algor, params, params_len, &d, &dlen) != 1
		|| asn1_octet_string_from_der(enced_key, enced_key_len, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	if (*version != 1) {
		error_print();
		return -1;
	}
	if (*pke_algor != OID_sm2encrypt) {
		error_print();
		return -1;
	}
	if (*params || *params_len) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_recipient_info_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int val;
	const uint8_t *p;
	size_t len;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (asn1_int_from_der(&val, &d, &dlen) != 1) goto err;
	format_print(fp, fmt, ind, "version: %d\n", val);
	if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) goto err;
	cms_issuer_and_serial_number_print(fp, fmt, ind, "issuerAndSerialNumber", p, len);
	if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) goto err;
	x509_public_key_encryption_algor_print(fp, fmt, ind, "keyEncryptionAlgorithm", p, len);
	if (asn1_octet_string_from_der(&p, &len, &d, &dlen) != 1) goto err;
	format_bytes(fp, fmt, ind, "encryptedKey", d, dlen);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

int cms_recipient_info_encrypt_to_der(
	int version,
	const uint8_t *issuer, size_t issuer_len,
	const uint8_t *serial_number, size_t serial_number_len,
	int public_key_enc_algor,
	const uint8_t *in, size_t inlen,
	const SM2_KEY *public_key,
	uint8_t **out, size_t *outlen)
{
	return 1;
}

int cms_recipient_info_decrypt_from_der(
	int *version,
	const uint8_t **issuer, size_t *issuer_len,
	const uint8_t **serial_number, size_t *serial_number_len,
	int *pke_algor, const uint8_t **params, size_t *paramslen,
	const uint8_t **decrypted_key, size_t *decrypted_key_len,
	const SM2_KEY *sm2_key,
	const uint8_t **in, size_t *inlen)
{
	return 1;
}

int cms_enveloped_data_to_der(
	int version,
	const uint8_t *rcpt_infos, size_t rcpt_infos_len,
	int content_type,
	int enc_algor, const uint8_t *enc_iv, size_t enc_iv_len,
	const uint8_t *enced_content, size_t enced_content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (asn1_int_to_der(version, NULL, &len) != 1
		|| asn1_set_to_der(rcpt_infos, rcpt_infos_len, NULL, &len) != 1
		|| cms_enced_content_info_to_der(content_type,
			enc_algor, enc_iv, enc_iv_len,
			enced_content, enced_content_len,
			shared_info1, shared_info1_len,
			shared_info2, shared_info2_len,
			NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(version, out, outlen) != 1
		|| asn1_set_to_der(rcpt_infos, rcpt_infos_len, out, outlen) != 1
		|| cms_enced_content_info_to_der(content_type,
			enc_algor, enc_iv, enc_iv_len,
			enced_content, enced_content_len,
			shared_info1, shared_info1_len,
			shared_info2, shared_info2_len,
			out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_enveloped_data_from_der(
	int *version,
	const uint8_t **rcpt_infos, size_t *rcpt_infos_len,
	int *content_type,
	int *enc_algor, const uint8_t **enc_iv, size_t *enc_iv_len,
	const uint8_t **enced_content, size_t *enced_content_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len,
	const uint8_t **in, size_t *inlen)
{
	return -1;
}

int cms_enveloped_data_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	return -1;
}

int cms_enveloped_data_encrypt_to_der(
	int version,
	const uint8_t *rcpt_certs, size_t rcpt_certs_len, // 当只有一个接收者的时候，这个参数类型非常方便
	int enc_algor, const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen,
	int content_type, const uint8_t *content, size_t content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	uint8_t **out, size_t *outlen)
{
	return -1;
}

int cms_enveloped_data_decrypt_from_der(
	int *version,
	const uint8_t **rcpt_infos, size_t *rcpt_infos_len,
	int *content_type, uint8_t *content, size_t *content_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len,
	const SM2_KEY *sm2_key,
	const uint8_t *issuer, size_t issuer_len,
	const uint8_t *serial_number, size_t serial_number_len,
	const uint8_t **in, size_t *inlen)
{
	return -1;
}

int cms_signed_and_enveloped_data_to_der(
	int version,
	const uint8_t *rcpt_infos, size_t rcpt_infos_len,
	const int *digest_algors, size_t digest_algors_cnt,
	int content_type,
	int enc_algor, const uint8_t *iv, size_t ivlen,
	const uint8_t *enced_content, size_t enced_content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	const uint8_t *certs, size_t certs_len,
	const uint8_t *crls, size_t crls_len,
	const uint8_t *signer_infos, size_t signer_infos_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (asn1_int_to_der(version, NULL, &len) != 1
		|| asn1_set_to_der(rcpt_infos, rcpt_infos_len, NULL, &len) != 1
		|| cms_digest_algors_to_der(digest_algors, digest_algors_cnt, NULL, &len) != 1
		|| cms_enced_content_info_to_der(content_type,
			enc_algor, iv, ivlen,
			enced_content, enced_content_len,
			shared_info1, shared_info1_len,
			shared_info2, shared_info2_len,
			NULL, &len) != 1
		|| asn1_implicit_set_to_der(0, certs, certs_len, NULL, &len) < 0
		|| asn1_implicit_set_to_der(1, crls, crls_len, NULL, &len) < 0
		|| asn1_set_to_der(signer_infos, signer_infos_len, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(version, out, outlen) != 1
		|| asn1_set_to_der(rcpt_infos, rcpt_infos_len, out, outlen) != 1
		|| cms_digest_algors_to_der(digest_algors, digest_algors_cnt, out, outlen) != 1
		|| cms_enced_content_info_to_der(content_type,
			enc_algor, iv, ivlen,
			enced_content, enced_content_len,
			shared_info1, shared_info1_len,
			shared_info2, shared_info2_len,
			out, outlen) != 1
		|| asn1_implicit_set_to_der(0, certs, certs_len, out, outlen) < 0
		|| asn1_implicit_set_to_der(1, crls, crls_len, out, outlen) < 0
		|| asn1_set_to_der(signer_infos, signer_infos_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_signed_and_enveloped_data_from_der(
	int *version,
	const uint8_t **rcpt_infos, size_t *rcpt_infos_len,
	int *digest_algors, size_t *digest_algors_cnt, size_t max_digest_algors,
	int *content_type,
	int *enc_algor, const uint8_t **enc_iv, size_t *enc_iv_len,
	const uint8_t **enced_content, size_t *enced_content_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len,
	const uint8_t **certs, size_t *certs_len,
	const uint8_t **crls, size_t *crls_len,
	const uint8_t **signer_infos, size_t *signer_infos_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_int_from_der(version, &d, &dlen) != 1
		|| asn1_set_from_der(rcpt_infos, rcpt_infos_len, &d, &dlen) != 1
		|| cms_digest_algors_from_der(digest_algors, digest_algors_cnt, max_digest_algors, &d, &dlen) != 1
		|| cms_enced_content_info_from_der(content_type,
			enc_algor, enc_iv, enc_iv_len,
			enced_content, enced_content_len,
			shared_info1, shared_info1_len,
			shared_info2, shared_info2_len,
			&d, &dlen) != 1
		|| asn1_implicit_set_from_der(0, certs, certs_len, &d, &dlen) < 0
		|| asn1_implicit_set_from_der(1, crls, crls_len, &d, &dlen) < 0
		|| asn1_set_from_der(signer_infos, signer_infos_len, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_signed_and_enveloped_data_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	return -1;
}

int cms_signed_and_enveloped_encipher_to_der(
	const CMS_CERT_AND_KEY *signers, size_t signers_cnt,
	const uint8_t *rcpt_certs, size_t rcpt_certs_len,
	int content_type, const uint8_t *content, size_t content_len,
	const uint8_t *signer_crls, size_t signer_crls_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	uint8_t **out, size_t *outlen)
{
	return 0;
}

int cms_deenvelop_and_verify_decipher_from_der(
	int *version,
	const uint8_t **rcpt_infos, size_t *rcpt_infos_len,
	const uint8_t **digest_algors, size_t *digest_algors_len,
	int *enc_algor, uint8_t *key, size_t *keylen, const uint8_t **iv, size_t *ivlen,
	int *content_type, uint8_t *content, size_t *content_len,
	const uint8_t **enced_content, size_t *enced_content_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len,
	const uint8_t **certs, size_t *certs_len,
	const uint8_t **crls, size_t *crls_len,
	const uint8_t **signer_infos, size_t *signer_infos_len,

	const SM2_KEY *rcpt_key,
	const uint8_t *rcpt_issuer, size_t rcpt_issuer_len,
	const uint8_t *rcpt_serial_number, size_t rcpt_serial_number_len,
	const uint8_t *extra_verify_certs, size_t extra_verify_certs_len,
	const uint8_t *extra_verify_crls, size_t extra_verify_crls_len,

	const uint8_t **in, size_t *inlen)
{
	return 0;
}

int cms_key_agreement_info_to_der(
	int version,
	const SM2_KEY *temp_public_key_r,
	const uint8_t *user_cert, size_t user_cert_len,
	const uint8_t *user_id, size_t user_id_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (asn1_int_to_der(version, NULL, &len) != 1
		|| sm2_public_key_info_to_der(temp_public_key_r, NULL, &len) != 1
		|| x509_cert_to_der(user_cert, user_cert_len, NULL, &len) != 1
		|| asn1_octet_string_to_der(user_id, user_id_len, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(version, out, outlen) != 1
		|| sm2_public_key_info_to_der(temp_public_key_r, out, outlen) != 1
		|| x509_cert_to_der(user_cert, user_cert_len, out, outlen) != 1
		|| asn1_octet_string_to_der(user_id, user_id_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_key_agreement_info_from_der(
	int *version,
	SM2_KEY *temp_public_key_r,
	const uint8_t **user_cert, size_t *user_cert_len,
	const uint8_t **user_id, size_t *user_id_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_int_from_der(version, &d, &dlen) != 1
		|| sm2_public_key_info_from_der(temp_public_key_r, &d, &dlen) != 1
		|| x509_cert_from_der(user_cert, user_cert_len, &d, &dlen) != 1
		|| asn1_octet_string_from_der(user_id, user_id_len, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_key_agreement_info_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int val;
	SM2_KEY pub_key;
	const uint8_t *p;
	size_t len;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (asn1_int_from_der(&val, &d, &dlen) != 1) goto err;
	format_print(fp, fmt, ind, "version: %d\n", val);
	if (sm2_public_key_info_from_der(&pub_key, &d, &dlen) != 1) goto err;
	//sm2_public_key_info_print(fp, fmt, ind, "tempPublicKeyR", &pub_key);
	if (x509_cert_from_der(&p, &len, &d, &dlen) != 1) goto err;
	x509_cert_print(fp, fmt, ind, p, len);
	if (asn1_octet_string_from_der(&p, &len, &d, &dlen) != 1) goto err;
	format_bytes(fp, fmt, ind, "userID", p, len);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

// 是否要提供一个返回长度的功能？此时不返回错误？			
int cms_set_data(uint8_t *cms, size_t *cmslen, size_t maxlen, const uint8_t *d, size_t dlen)
{
	size_t len = 0;
	*cmslen = 0;
	if (cms_content_info_to_der(OID_cms_data, d, dlen, NULL, &len) != 1
		|| asn1_length_le(len, maxlen) != 1
		|| cms_content_info_to_der(OID_cms_data, d, dlen, &cms, cmslen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_encrypt(
	int enc_algor, const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen, // 对称加密算法、密钥和IV
	int content_type, const uint8_t *content, size_t content_len, // 待加密的输入数据
	const uint8_t *shared_info1, size_t shared_info1_len, // 附加信息
	const uint8_t *shared_info2, size_t shared_info2_len, // 附加信息
	uint8_t *cms, size_t *cmslen, size_t maxlen)
{
	return -1;
}

int cms_decrypt(
	const uint8_t *key, size_t keylen, // 解密密钥（我们不知道解密算法）
	const uint8_t *cms, size_t cms_len, // 输入的ContentInfo (type encryptedData)
	const uint8_t *extra_enced_content, size_t extra_enced_content_len, // EncryptedContentInfo的密文数据为空时显示提供输入密文
	int *content_type, uint8_t *content, size_t *content_len, // 输出的解密数据类型及数据
	int *enc_algor, const uint8_t **iv, size_t *ivlen, // 解析EncryptedContentInfo得到的对称加密算法及参数
	const uint8_t **shared_info1, size_t *shared_info1_len, // 附加信息
	const uint8_t **shared_info2, size_t *shared_info2_len)
{
	return -1;
}

int cms_sign(
	const CMS_CERT_AND_KEY *signers, size_t signers_cnt, // 签名者的签名私钥和证书
	int content_type, const uint8_t *content, size_t content_len, // 待签名的输入数据
	const uint8_t *crls, size_t crls_len, // 签名者证书的CRL
	uint8_t *cms, size_t *cms_len) // 输出的ContentInfo (type signedData
{
	return -1;
}

int cms_verify(
	const uint8_t *cms, size_t cms_len, // 输入的ContentInfo (type signedData)
	const uint8_t *extra_content, size_t extra_content_len, // ContentInfo的数据为空时显示提供输入
	const uint8_t *extra_certs, size_t extra_certs_len, // 当SignedData中未提供证书时显示输入
	const uint8_t *extra_crls, size_t extra_crls_len, // 当SignedData中未提供CRL时显示输入
	int *content_type, const uint8_t **content, size_t *content_len, // 从SignedData解析得到的被签名数据
	const uint8_t **certs, size_t *certs_len, // 从SignedData解析得到的签名证书
	const uint8_t **crls, size_t *crls_len, // 从SignedData解析得到的CRL
	const uint8_t **signer_infos, size_t *signer_infos_len) // 从SignedData解析得到的SignerInfos，可用于显示验证结果
{
	return -1;
}


int cms_envelop(
	const uint8_t *rcpt_certs, size_t rcpt_certs_len, // 接收方证书，注意这个参数的类型可以容纳多个证书，但是只有在一个接受者时对调用方最方便
	int enc_algor, const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen, // 对称加密算法及参数
	int content_type, const uint8_t *content, size_t content_len, // 待加密的输入数据
	const uint8_t *shared_info1, size_t shared_info1_len, // 附加输入信息
	const uint8_t *shared_info2, size_t shared_info2_len, // 附加输入信息
	uint8_t *cms, size_t *cms_len) // 输出ContentInfo
{
	return -1;
}

int cms_deenvelop(
	const SM2_KEY *rcpt_key, const uint8_t *rcpt_cert, size_t rcpt_cert_len, // 接收方的解密私钥和对应的证书，注意只需要一个解密方
	const uint8_t *cms, size_t cms_len,
	const uint8_t *extra_enced_content, size_t extra_enced_content_len, // 显式输入的密文
	int *content_type, uint8_t *content, size_t *content_len,
	int *enc_algor, const uint8_t **iv, size_t *ivlen, // 注意，对称加密的密钥就不输出了
	const uint8_t **rcpt_infos, size_t *rcpt_infos_len, // 解析得到，用于显示
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len)
{
	return -1;
}

int cms_sign_and_envelop( // 参考cms_sign, cms_envelop
	const CMS_CERT_AND_KEY *signers, size_t signers_cnt,
	const uint8_t *rcpt_certs, size_t rcpt_certs_len,
	int enc_algor, const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen,
	int content_type, const uint8_t *content, size_t content_len,
	const uint8_t *signer_crls, size_t signer_crls_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	uint8_t *cms, size_t *cms_len)
{
	return -1;
}

int cms_deenvelop_and_verify( // 参考cms_deenvelop, cms_verify
	const SM2_KEY *rcpt_key, const uint8_t *rcpt_cert, size_t rcpt_cert_len,
	// 输入
	const uint8_t *cms, size_t cms_len,
	const uint8_t *extra_enced_content, size_t extra_enced_content_len,
	const uint8_t *extra_signer_certs, size_t extra_signer_certs_len,
	const uint8_t *extra_signer_crls, size_t extra_signer_crls_len,
	// 输出
	int *content_type, uint8_t *content, size_t *content_len,
	// 格外的解析内容输出，均为可选
	int *enc_algor, const uint8_t **iv, size_t *ivlen,
	const uint8_t **rcpt_infos, size_t rcpt_infos_len,
	const uint8_t **signer_infos, size_t *signer_infos_len,
	const uint8_t **signer_certs, size_t *signer_certs_len,
	const uint8_t **signer_crls, size_t *signer_crls_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len)
{
	return -1;
}

// 生成ContentInfo, type == keyAgreementInfo
int cms_set_key_agreement_info(
	uint8_t *cms, size_t *cms_len,
	const SM2_KEY *temp_public_key_r,
	const uint8_t *user_cert, size_t user_cert_len,
	const uint8_t *user_id, size_t user_id_len)
{
	return -1;
}

int cms_print(FILE *fp, int fmt, int ind, const uint8_t *a, size_t alen)
{
	return -1;
}
