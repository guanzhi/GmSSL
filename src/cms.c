/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/asn1.h>
#include <gmssl/aes.h>
#include <gmssl/sm4.h>
#include <gmssl/sm3.h>
#include <gmssl/sm2.h>
#include <gmssl/digest.h>
#include <gmssl/error.h>
#include <gmssl/x509.h>
#include <gmssl/x509_alg.h>
#include <gmssl/x509_ext.h>
#include <gmssl/x509_crl.h>
#include <gmssl/rand.h>
#include <gmssl/pem.h>
#include <gmssl/cms.h>



static uint32_t oid_cms_data[] = { oid_sm2_cms,1 };
static uint32_t oid_cms_signed_data[] = { oid_sm2_cms,2 };
static uint32_t oid_cms_enveloped_data[] = { oid_sm2_cms,3 };
static uint32_t oid_cms_signed_and_enveloped_data[] = { oid_sm2_cms,4 };
static uint32_t oid_cms_encrypted_data[] = { oid_sm2_cms,5 };
static uint32_t oid_cms_key_agreement_info[] = { oid_sm2_cms,6 };
#define OID_CMS_CONUNT (sizeof(oid_cms_data)/sizeof(int))

static const ASN1_OID_INFO cms_content_types[] = {
	{ OID_cms_data, "data", oid_cms_data, OID_CMS_CONUNT },
	{ OID_cms_signed_data, "signedData", oid_cms_signed_data, OID_CMS_CONUNT },
	{ OID_cms_enveloped_data, "envelopedData", oid_cms_enveloped_data, OID_CMS_CONUNT },
	{ OID_cms_signed_and_enveloped_data, "signedAndEnvelopedData", oid_cms_signed_and_enveloped_data, OID_CMS_CONUNT },
	{ OID_cms_encrypted_data, "encryptedData", oid_cms_encrypted_data, OID_CMS_CONUNT },
	{ OID_cms_key_agreement_info, "keyAgreementInfo", oid_cms_key_agreement_info, OID_CMS_CONUNT }
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

	if (oid == -1) {
		return 0;
	}
	if (!(info = asn1_oid_info_from_oid(cms_content_types, cms_content_types_count, oid))) {
		error_print();
		return -1;
	}
	if (asn1_object_identifier_to_der(info->nodes, info->nodes_cnt, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_content_type_from_der(int *oid, const uint8_t **in, size_t *inlen)
{
	int ret;
	const ASN1_OID_INFO *info;

	if ((ret = asn1_oid_info_from_der(&info, cms_content_types, cms_content_types_count, in, inlen)) != 1) {
		if (ret < 0) error_print();
		else *oid = -1;
		return ret;
	}
	*oid = info->oid;
	return 1;
}

/*
static int cms_content_info_data_header_to_der(size_t dlen, uint8_t **out, size_t *outlen)
{
	uint8_t d[1];
	size_t len = 0;
	size_t content_len = 0;
	if (asn1_octet_string_to_der(p, dlen, NULL, &content_len) != 1
		|| cms_content_type_to_der(OID_cms_data, out, outlen) != 1
		|| asn1_explicit_header_to_der(0, content_len, out, outlen) < 0
		|| asn1_octet_string_to_der(dlen, out, outlen) < 0) {
		error_print();
		return -1;
	}
	return 1;
}
*/

int cms_content_info_header_to_der(int content_type, size_t content_len, uint8_t **out, size_t *outlen)
{
	size_t len = content_len; // 注意：由于header_to_der没有输出数据，因此需要加上数据的长度，header length 才是正确的值
	/*
	if (content_type == OID_cms_data) {
		return cms_content_info_data_header_to_der(content_len, out, outlen);
	}
	*/

	if (cms_content_type_to_der(content_type, NULL, &len) != 1
		|| asn1_explicit_header_to_der(0, content_len, NULL, &len) < 0
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| cms_content_type_to_der(content_type, out, outlen) != 1
		|| asn1_explicit_header_to_der(0, content_len, out, outlen) < 0) {
		error_print();
		return -1;
	}
	return 1;
}

static int cms_content_info_data_to_der(const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	size_t content_len = 0;
	if (asn1_octet_string_to_der(d, dlen, NULL, &content_len) != 1
		|| cms_content_type_to_der(OID_cms_data, NULL, &len) != 1
		|| asn1_explicit_to_der(0, d, content_len, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| cms_content_type_to_der(OID_cms_data, out, outlen) != 1
		|| asn1_explicit_header_to_der(0, content_len, out, outlen) != 1
		|| asn1_octet_string_to_der(d, dlen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_content_info_to_der(
	int content_type, const uint8_t *content, size_t content_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (content_type == OID_cms_data) {
		return cms_content_info_data_to_der(content, content_len, out, outlen);
	}
	if (cms_content_type_to_der(content_type, NULL, &len) != 1
		|| asn1_explicit_to_der(0, content, content_len, NULL, &len) < 0
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| cms_content_type_to_der(content_type, out, outlen) != 1
		|| asn1_explicit_to_der(0, content, content_len, out, outlen) < 0) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_content_info_from_der(
	int *content_type,
	const uint8_t **content, size_t *content_len,
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
		|| asn1_explicit_from_der(0, content, content_len, &d, &dlen) < 0
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_content_info_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int ret;
	int content_type;
	const uint8_t *content;
	size_t content_len;
	const uint8_t *p;
	size_t len;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (cms_content_type_from_der(&content_type, &d, &dlen) != 1) goto err;
	format_print(fp, fmt, ind, "contentType: %s\n", cms_content_type_name(content_type));

	/*
		if (content_type == OID_cms_data) {
			if (asn1_octet_string_from_der(&p, &len, &content, &content_len) != 1) goto err;
		} else {
			if (asn1_sequence_from_der(&p, &len, &content, &content_len) != 1) goto err;
		}
	*/

	//format_bytes(stderr, 0, 0, "content", d, dlen);

	if ((ret = asn1_explicit_from_der(0, &content, &content_len, &d, &dlen)) < 0) { error_print(); goto err; }
	if (ret == 0) { error_print(); goto err; }

	if (content_type == OID_cms_data) {
		if (asn1_octet_string_from_der(&p, &len, &content, &content_len) != 1
			|| asn1_length_is_zero(content_len) != 1) {
			error_print();
			return -1;
		}
		format_bytes(fp, fmt, ind, "content", p, len);
		return 1;
	}


	if (asn1_sequence_from_der(&p, &len, &content, &content_len) != 1) { error_print(); goto err; }

	switch (content_type) {
	//case OID_cms_data: format_bytes(fp, fmt, ind, "content", p, len); break;
	case OID_cms_signed_data: cms_signed_data_print(fp, fmt, ind, "content", p, len); break;
	case OID_cms_enveloped_data: cms_enveloped_data_print(fp, fmt, ind, "content", p, len); break;
	case OID_cms_signed_and_enveloped_data: cms_signed_and_enveloped_data_print(fp, fmt, ind, "content", p, len); break;
	case OID_cms_encrypted_data: cms_encrypted_data_print(fp, fmt, ind, "content", p, len); break;
	case OID_cms_key_agreement_info: cms_key_agreement_info_print(fp, fmt, ind, "content", p, len); break;
	}
	if (asn1_length_is_zero(content_len) != 1) goto err;


	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
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
	if (ret) format_bytes(fp, fmt, ind, "encryptedContent", p, len);
	if ((ret = asn1_implicit_octet_string_from_der(1, &p, &len, &d, &dlen)) < 0) goto err;
	if (ret) format_bytes(fp, fmt, ind, "sharedInfo1", p, len);
	if ((ret = asn1_implicit_octet_string_from_der(2, &p, &len, &d, &dlen)) < 0) goto err;
	if (ret) format_bytes(fp, fmt, ind, "sharedInfo2", p, len);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

int cms_enced_content_info_encrypt_to_der(
	int enc_algor, const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen,
	int content_type, const uint8_t *content, size_t content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	uint8_t **out, size_t *outlen)
{
	int ret;
	SM4_KEY sm4_key;
	uint8_t* enced_content = NULL;							
	size_t enced_content_len = 100; // FIXME: why 100?					

	if (!(enced_content = malloc(32 + content_len))) {
		error_print();
		return -1;
	}



	if (enc_algor != OID_sm4_cbc || keylen != 16 || ivlen != 16) {
		error_print();
		if (enced_content) free(enced_content);
		return -1;
	}

	sm4_set_encrypt_key(&sm4_key, key);
	if (sm4_cbc_padding_encrypt(&sm4_key, iv, content, content_len,
		enced_content, &enced_content_len) != 1) {
		if (enced_content) free(enced_content);
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
		if (enced_content) free(enced_content);
		if (ret < 0) error_print();
		return ret;
	}

	free(enced_content); //FIXME: use goto end to clean enced_content
	return 1;
}

// 这个函数显然是有问题的，调用方根本不知道应该准备多大的buffer			
// 应该为content_len 输出给一个maxlen 的最大buffer值				
int cms_enced_content_info_decrypt_from_der(
	int *enc_algor, const uint8_t *key, size_t keylen,
	int *content_type, uint8_t *content, size_t *content_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,// 支持可选null输出	
	const uint8_t **shared_info2, size_t *shared_info2_len,// 支持可选null输出	
	const uint8_t **in, size_t *inlen)
{
	SM4_KEY sm4_key;
	const uint8_t *iv;
	size_t ivlen;
	const uint8_t *enced_content;
	size_t enced_content_len;

	if (cms_enced_content_info_from_der(content_type,
			enc_algor, &iv, &ivlen, &enced_content, &enced_content_len,
			shared_info1, shared_info1_len,
			shared_info2, shared_info2_len,
			in, inlen) != 1
		|| asn1_check(*enc_algor == OID_sm4_cbc) != 1
		|| asn1_check(ivlen == SM4_BLOCK_SIZE) != 1
		|| asn1_check(keylen == SM4_KEY_SIZE) != 1) {
		error_print();
		return -1;
	}

	sm4_set_decrypt_key(&sm4_key, key);
	if (sm4_cbc_padding_decrypt(&sm4_key, iv, enced_content, enced_content_len,
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
	int enc_algor, const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen,
	int content_type, const uint8_t *content, size_t content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (asn1_int_to_der(CMS_version_v1, NULL, &len) != 1
		|| cms_enced_content_info_encrypt_to_der(
			enc_algor, key, keylen, iv, ivlen,
			content_type, content, content_len,
			shared_info1, shared_info1_len,
			shared_info2, shared_info2_len,
			NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(CMS_version_v1, out, outlen) != 1
		|| cms_enced_content_info_encrypt_to_der(
			enc_algor, key, keylen, iv, ivlen,
			content_type, content, content_len,
			shared_info1, shared_info1_len,
			shared_info2, shared_info2_len,
			out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_encrypted_data_decrypt_from_der(
	int *enc_algor, const uint8_t *key, size_t keylen,
	int *content_type, uint8_t *content, size_t *content_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len,
	const uint8_t **in, size_t *inlen)
{
	int ret, version;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_int_from_der(&version, &d, &dlen) != 1
		|| asn1_check(version == CMS_version_v1) != 1
		|| cms_enced_content_info_decrypt_from_der(
			enc_algor, key, keylen,
			content_type, content, content_len,
			shared_info1, shared_info1_len,
			shared_info2, shared_info2_len,
			&d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
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
	if ((ret = asn1_implicit_set_from_der(0, &p, &len, &d, &dlen)) < 0) goto err;
	if (ret) x509_attributes_print(fp, fmt, ind, "authenticatedAttributes", p, len);
	if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) goto err;
	x509_signature_algor_print(fp, fmt, ind, "digestEncryptionAlgorithm", p, len);
	if (asn1_octet_string_from_der(&p, &len, &d, &dlen) != 1) goto err;
	format_bytes(fp, fmt, ind, "encryptedDigest", p, len);
	if ((ret = asn1_implicit_set_from_der(1, &p, &len, &d, &dlen)) < 0) goto err;
	if (ret) x509_attributes_print(fp, fmt, ind, "unauthenticatedAttributes", p, len);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

int cms_signer_info_sign_to_der(
	const SM3_CTX *sm3_ctx, const SM2_KEY *sign_key,
	const uint8_t *issuer, size_t issuer_len,
	const uint8_t *serial_number, size_t serial_number_len,
	const uint8_t *authed_attrs, size_t authed_attrs_len,
	const uint8_t *unauthed_attrs, size_t unauthed_attrs_len,
	uint8_t **out, size_t *outlen)
{
	SM3_CTX ctx = *sm3_ctx;
	int fixed_outlen = 1;
	uint8_t dgst[SM3_DIGEST_SIZE];
	uint8_t sig[SM2_MAX_SIGNATURE_SIZE];
	size_t siglen = SM2_signature_typical_size;

	sm3_update(&ctx, authed_attrs, authed_attrs_len);
	sm3_finish(&ctx, dgst);

	if (sm2_sign_fixlen(sign_key, dgst, siglen, sig) != 1) {
		error_print();
		return -1;
	}
	if (cms_signer_info_to_der(CMS_version_v1,
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
	const SM3_CTX *ctx, const uint8_t *certs, size_t certslen,
	const uint8_t **cert, size_t *certlen,
	const uint8_t **issuer, size_t *issuer_len,
	const uint8_t **serial, size_t *serial_len,
	const uint8_t **authed_attrs, size_t *authed_attrs_len,
	const uint8_t **unauthed_attrs, size_t *unauthed_attrs_len,
	const uint8_t **in, size_t *inlen)
{
	int version;
	int digest_algor;
	int signature_algor;
	const uint8_t *sig;
	size_t siglen;
	SM2_KEY public_key;
	SM3_CTX sm3_ctx = *ctx;
	uint8_t dgst[32];

	if (cms_signer_info_from_der(&version,
			issuer, issuer_len,
			serial, serial_len,
			&digest_algor, authed_attrs, authed_attrs_len,
			&signature_algor, &sig, &siglen,
			unauthed_attrs, unauthed_attrs_len,
			in, inlen) != 1
		|| asn1_check(version == CMS_version_v1) != 1
		|| asn1_check(digest_algor == OID_sm3) != 1
		|| asn1_check(signature_algor == OID_sm2sign_with_sm3) != 1) {
		error_print();
		return -1;
	}
	if (x509_certs_get_cert_by_issuer_and_serial_number(certs, certslen,
			*issuer, *issuer_len, *serial, *serial_len, cert, certlen) != 1
		|| x509_cert_get_subject_public_key(*cert, *certlen, &public_key) != 1) {
		error_print();
		return -1;
	}

	sm3_update(&sm3_ctx, *authed_attrs, *authed_attrs_len);
	sm3_finish(&sm3_ctx, dgst);

	if (sm2_verify(&public_key, dgst, sig, siglen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_signer_infos_add_signer_info(
	uint8_t *d, size_t *dlen, size_t maxlen,
	const SM3_CTX *sm3_ctx, const SM2_KEY *sign_key,
	const uint8_t *issuer, size_t issuer_len,
	const uint8_t *serial_number, size_t serial_number_len,
	const uint8_t *authed_attrs, size_t authed_attrs_len,
	const uint8_t *unauthed_attrs, size_t unauthed_attrs_len)
{
	size_t len = *dlen;
	d += *dlen;
	if (cms_signer_info_sign_to_der(sm3_ctx, sign_key,
			issuer, issuer_len, serial_number, serial_number_len,
			authed_attrs, authed_attrs_len,
			unauthed_attrs, unauthed_attrs_len,
			NULL, &len) != 1
		|| asn1_length_le(len, maxlen) != 1
		|| cms_signer_info_sign_to_der(sm3_ctx, sign_key,
			issuer, issuer_len, serial_number, serial_number_len,
			authed_attrs, authed_attrs_len,
			unauthed_attrs, unauthed_attrs_len,
			&d, dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
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
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_set_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}

	*digest_algors_cnt = 0;
	while (dlen) {
		if (*digest_algors_cnt > max_digest_algors) {
			error_print();
			return -1;
		}
		if (x509_digest_algor_from_der(digest_algors, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		digest_algors++;
		(*digest_algors_cnt)++;
	}
	return 1;
}

int cms_digest_algors_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int oid;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	while (dlen) {
		if (x509_digest_algor_from_der(&oid, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		format_print(fp, fmt, ind, "%s\n", x509_digest_algor_name(oid));
	}
	return 1;
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
	if (*version != CMS_version_v1) {
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
	if (ret) x509_certs_print(fp, fmt, ind, "certificates", p, len);
	if ((ret = asn1_implicit_set_from_der(1, &p, &len, &d, &dlen)) < 0) goto err;
	if (asn1_set_from_der(&p, &len, &d, &dlen) != 1) goto err;
	cms_signer_infos_print(fp, fmt, ind, "signerInfos", p, len);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

static int cms_implicit_signers_certs_to_der(int index,
	const CMS_CERTS_AND_KEY *signers, size_t signers_cnt,
	uint8_t **out, size_t *outlen)
{
	size_t i;
	size_t len = 0;
	for (i = 0; i < signers_cnt; i++) {
		if (asn1_data_to_der(signers[i].certs, signers[i].certs_len, NULL, &len) != 1) {
			error_print();
			return -1;
		}
	}
	if (asn1_implicit_header_to_der(index, len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	for (i = 0; i < signers_cnt; i++) {
		if (asn1_data_to_der(signers[i].certs, signers[i].certs_len, out, outlen) != 1) {
			error_print();
			return -1;
		}
	}
	return 1;
}

int cms_signed_data_sign_to_der(
	const CMS_CERTS_AND_KEY *signers, size_t signers_cnt,
	int content_type, const uint8_t *data, size_t datalen,
	const uint8_t *crls, size_t crls_len,
	uint8_t **out, size_t *outlen)
{
	int digest_algors[] = { OID_sm3 };
	size_t digest_algors_cnt = sizeof(digest_algors)/sizeof(int);
	uint8_t content_header[256];
	size_t content_header_len;
	size_t certs_len = 0;
	uint8_t signer_infos[512];
	size_t signer_infos_len = 0;
	SM3_CTX sm3_ctx;
	const uint8_t *issuer;
	size_t issuer_len;
	const uint8_t *serial;
	size_t serial_len;
	uint8_t *p;
	size_t len = 0;
	size_t i;


	// 当content_type == OID_cms_data 时，data是raw data，被封装为OCTET STRING编码输出
	// 而content_type为其他类型时，data均为TLV的DER数据
	// 在to_der/from_der 中已经处理，但是计算哈希值时也需要做处理
	p = content_header;
	content_header_len = 0;
	if (content_type == OID_cms_data) {
		size_t content_len = 0;
		if (asn1_octet_string_to_der(data, datalen, NULL, &content_len) != 1
			|| cms_content_info_header_to_der(content_type, content_len, &p, &content_header_len) != 1
			|| asn1_octet_string_header_to_der(datalen, &p, &content_header_len) != 1) {
			error_print();
			return -1;
		}
	} else {
		if (cms_content_info_header_to_der(content_type, datalen, &p, &content_header_len) != 1) {
			error_print();
			return -1;
		}
	}

	sm3_init(&sm3_ctx);
	sm3_update(&sm3_ctx, content_header, content_header_len);
	sm3_update(&sm3_ctx, data, datalen);

	for (i = 0; i < signers_cnt; i++) {
		if (x509_cert_get_issuer_and_serial_number(
				signers[i].certs, signers[i].certs_len,
				&issuer, &issuer_len, &serial, &serial_len) != 1
			|| cms_signer_infos_add_signer_info(
				signer_infos, &signer_infos_len, sizeof(signer_infos),
				&sm3_ctx, signers->sign_key,
				issuer, issuer_len, serial, serial_len,
				NULL, 0, NULL, 0) != 1) {
			error_print();
			return -1;
		}
	}

	if (asn1_int_to_der(CMS_version_v1, NULL, &len) != 1
		|| cms_digest_algors_to_der(digest_algors, digest_algors_cnt, NULL, &len) != 1
		|| cms_content_info_to_der(content_type, data, datalen, NULL, &len) != 1
		|| cms_implicit_signers_certs_to_der(0, signers, signers_cnt, NULL, &len) < 0
		|| asn1_implicit_set_to_der(1, crls, crls_len, NULL, &len) < 0
		|| asn1_set_to_der(signer_infos, signer_infos_len, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(CMS_version_v1, out, outlen) != 1
		|| cms_digest_algors_to_der(digest_algors, digest_algors_cnt, out, outlen) != 1
		|| cms_content_info_to_der(content_type, data, datalen, out, outlen) != 1
		|| cms_implicit_signers_certs_to_der(0, signers, signers_cnt, out, outlen) < 0
		|| asn1_implicit_set_to_der(1, crls, crls_len, out, outlen) < 0
		|| asn1_set_to_der(signer_infos, signer_infos_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_signed_data_verify_from_der(
	const uint8_t *extra_certs, size_t extra_certs_len,
	const uint8_t *extra_crls, size_t extra_crls_len,
	int *content_type, const uint8_t **content, size_t *content_len,
	const uint8_t **certs, size_t *certs_len,
	const uint8_t **crls, size_t *crls_len,
	const uint8_t **psigner_infos, size_t *psigner_infos_len,
	const uint8_t **in, size_t *inlen)
{
	int version;
	int digest_algors[4];
	size_t digest_algors_cnt;
	SM3_CTX sm3_ctx;
	uint8_t content_info_header[128];
	size_t content_info_header_len;
	uint8_t *p = content_info_header;
	const uint8_t *signer_infos;
	size_t signer_infos_len;

	if (cms_signed_data_from_der(
			&version,
			digest_algors, &digest_algors_cnt, sizeof(digest_algors)/sizeof(int),
			content_type, content, content_len,
			certs, certs_len,
			crls, crls_len,
			&signer_infos, &signer_infos_len,
			in, inlen) != 1
		|| asn1_check(version == CMS_version_v1) != 1
		|| asn1_check(digest_algors[0] == OID_sm3) != 1
		|| asn1_check(digest_algors_cnt == 1) != 1) {
		error_print();
		return -1;
	}
	*psigner_infos = signer_infos;
	*psigner_infos_len = signer_infos_len;

	content_info_header_len = 0;
	if (cms_content_info_header_to_der(*content_type, *content_len,
		&p, &content_info_header_len) != 1) {
		error_print();
		return -1;
	}
	sm3_init(&sm3_ctx);

	sm3_update(&sm3_ctx, content_info_header, content_info_header_len);
	sm3_update(&sm3_ctx, *content, *content_len);

	while (signer_infos_len) {
		const uint8_t *cert;
		size_t certlen;
		const uint8_t *issuer;
		size_t issuer_len;
		const uint8_t *serial;
		size_t serial_len;
		const uint8_t *authed_attrs;
		size_t authed_attrs_len;
		const uint8_t *unauthed_attrs;
		size_t unauthed_attrs_len;

		if (cms_signer_info_verify_from_der(
			&sm3_ctx, *certs, *certs_len,
			&cert, &certlen,
			&issuer, &issuer_len,
			&serial, &serial_len,
			&authed_attrs, &authed_attrs_len,
			&unauthed_attrs, &unauthed_attrs_len,
			&signer_infos, &signer_infos_len) != 1) {

			error_print();
			return -1;
		}
	}
	return 1;
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
	//	|| asn1_length_is_zero(dlen) != 1				
		) {
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
	format_bytes(fp, fmt, ind, "encryptedKey", p, len);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

int cms_recipient_info_encrypt_to_der(
	const SM2_KEY *public_key,
	const uint8_t *issuer, size_t issuer_len,
	const uint8_t *serial_number, size_t serial_number_len,
	const uint8_t *in, size_t inlen,
	uint8_t **out, size_t *outlen)
{
	int pke_algor = OID_sm2encrypt;
	uint8_t enced_key[SM2_MAX_CIPHERTEXT_SIZE];
	size_t enced_key_len;
	int fixed_outlen = 1;

	if (pke_algor != OID_sm2encrypt) {
		error_print();
		return -1;
	}

	if (sm2_encrypt_fixlen(public_key, in, inlen, SM2_ciphertext_typical_point_size,
		enced_key, &enced_key_len) != 1) {
		error_print();
		return -1;
	}
	if (cms_recipient_info_to_der(CMS_version_v1,
		issuer, issuer_len, serial_number, serial_number_len,
		pke_algor, enced_key, enced_key_len,
		out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_recipient_info_decrypt_from_der(
	const SM2_KEY *sm2_key,
	const uint8_t *rcpt_issuer, size_t rcpt_issuer_len,
	const uint8_t *rcpt_serial, size_t rcpt_serial_len,
	uint8_t *out, size_t *outlen, size_t maxlen,
	const uint8_t **in, size_t *inlen)
{
	int version;
	int pke_algor;
	const uint8_t *params;
	size_t params_len;
	const uint8_t *enced_key;
	size_t enced_key_len;
	const uint8_t *issuer;
	size_t issuer_len;
	const uint8_t *serial;
	size_t serial_len;
	uint8_t outbuf[SM2_MAX_PLAINTEXT_SIZE];

	if (cms_recipient_info_from_der(&version,
		&issuer, &issuer_len, &serial, &serial_len,
		&pke_algor, &params, &params_len,
		&enced_key, &enced_key_len,
		in, inlen) != 1) {
		error_print();
		return -1;
	}
	if (issuer_len != rcpt_issuer_len
		|| memcmp(issuer, rcpt_issuer, rcpt_issuer_len) != 0
		|| serial_len != rcpt_serial_len
		|| memcmp(serial, rcpt_serial, serial_len) != 0) {
		error_print();
		return 0;
	}
	if (pke_algor != OID_sm2encrypt || params || params_len) {
		error_print();
		return -1;
	}
	if (sm2_decrypt(sm2_key, enced_key, enced_key_len, outbuf, outlen) != 1) {
		error_print();
		return -1;
	}
	if (maxlen < *outlen) {
		error_print();
		return -1;
	}
	memcpy(out, outbuf, *outlen);
	return 1;
}

int cms_recipient_infos_add_recipient_info(
	uint8_t *d, size_t *dlen, size_t maxlen,
	const SM2_KEY *public_key,
	const uint8_t *issuer, size_t issuer_len,
	const uint8_t *serial, size_t serial_len,
	const uint8_t *in, size_t inlen)
{
	size_t len = *dlen;
	d += *dlen;

	if (cms_recipient_info_encrypt_to_der(
			public_key,
			issuer, issuer_len,
			serial, serial_len,
			in, inlen,
			NULL, &len) != 1
		|| asn1_length_le(len, maxlen) != 1
		|| cms_recipient_info_encrypt_to_der(
			public_key,
			issuer, issuer_len,
			serial, serial_len,
			in, inlen,
			&d, dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_recipient_infos_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
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
		cms_recipient_info_print(fp, fmt, ind, "RecipientInfo", p, len);
	}
	return 1;
}

int cms_enveloped_data_to_der(
	int version,
	const uint8_t *rcpt_infos, size_t rcpt_infos_len,
	int content_type,
	int enc_algor, const uint8_t *iv, size_t ivlen,
	const uint8_t *enced_content, size_t enced_content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (asn1_int_to_der(version, NULL, &len) != 1
		|| asn1_set_to_der(rcpt_infos, rcpt_infos_len, NULL, &len) != 1
		|| cms_enced_content_info_to_der(content_type,
			enc_algor, iv, ivlen,
			enced_content, enced_content_len,
			shared_info1, shared_info1_len,
			shared_info2, shared_info2_len,
			NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(version, out, outlen) != 1
		|| asn1_set_to_der(rcpt_infos, rcpt_infos_len, out, outlen) != 1
		|| cms_enced_content_info_to_der(content_type,
			enc_algor, iv, ivlen,
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
	const uint8_t **enced_content_info, size_t *enced_content_info_len,
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
		|| asn1_any_from_der(enced_content_info, enced_content_info_len, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_enveloped_data_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int val;
	const uint8_t *p;
	size_t len;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (asn1_int_from_der(&val, &d, &dlen) != 1) goto err;
	format_print(fp, fmt, ind, "version: %d\n", val);
	if (asn1_set_from_der(&p, &len, &d, &dlen) != 1) goto err;
	cms_recipient_infos_print(fp, fmt, ind, "recipientInfos", p, len);
	if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) goto err;
	cms_enced_content_info_print(fp, fmt, ind, "encryptedContentInfo", p, len);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

int cms_enveloped_data_encrypt_to_der(
	const uint8_t *rcpt_certs, size_t rcpt_certs_len,
	int enc_algor, const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen,
	int content_type, const uint8_t *content, size_t content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	uint8_t **out, size_t *outlen)
{
	uint8_t rcpt_infos[1024]; // 到底需要多大？				
	size_t rcpt_infos_len = 0;
	uint8_t *p = rcpt_infos;
	size_t len = 0;

	while (rcpt_certs_len) {
		const uint8_t *cert;
		size_t certlen;
		SM2_KEY public_key;
		const uint8_t *issuer;
		size_t issuer_len;
		const uint8_t *serial;
		size_t serial_len;

		if (asn1_any_from_der(&cert, &certlen, &rcpt_certs, &rcpt_certs_len) != 1
			|| x509_cert_get_issuer_and_serial_number(cert, certlen,
				&issuer, &issuer_len, &serial, &serial_len) != 1
			|| x509_cert_get_subject_public_key(cert, certlen, &public_key) != 1) {
			error_print();
			return -1;
		}
		if (cms_recipient_info_encrypt_to_der(&public_key,
				issuer, issuer_len, serial, serial_len,
				key, keylen, NULL, &len) != 1
			|| asn1_length_le(len, sizeof(rcpt_infos)) != 1
			|| cms_recipient_info_encrypt_to_der(&public_key,
				issuer, issuer_len, serial, serial_len,
				key, keylen, &p, &rcpt_infos_len) != 1) {
			error_print();
			return -1;
		}
	}
	len = 0;
	if (asn1_int_to_der(CMS_version_v1, NULL, &len) != 1
		|| asn1_set_to_der(rcpt_infos, rcpt_infos_len, NULL, &len) != 1
		|| cms_enced_content_info_encrypt_to_der(
			enc_algor, key, keylen, iv, ivlen,
			content_type, content, content_len,
			shared_info1, shared_info1_len,
			shared_info2, shared_info2_len,
			NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(CMS_version_v1, out, outlen) != 1
		|| asn1_set_to_der(rcpt_infos, rcpt_infos_len, out, outlen) != 1
		|| cms_enced_content_info_encrypt_to_der(
			enc_algor, key, keylen, iv, ivlen,
			content_type, content, content_len,
			shared_info1, shared_info1_len,
			shared_info2, shared_info2_len,
			out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_enveloped_data_decrypt_from_der(
	const SM2_KEY *sm2_key,
	const uint8_t *issuer, size_t issuer_len,
	const uint8_t *serial, size_t serial_len,
	int *content_type, uint8_t *content, size_t *content_len,
	const uint8_t **recipient_infos, size_t *recipient_infos_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len,
	const uint8_t **in, size_t *inlen)
{
	int ret = 0;
	int version;
	const uint8_t *rcpt_infos;
	size_t rcpt_infos_len;
	const uint8_t *enced_content_info;
	size_t enced_content_info_len;
	int enc_algor;
	uint8_t key[32];
	size_t keylen;

	if (cms_enveloped_data_from_der(
			&version, &rcpt_infos, &rcpt_infos_len,
			&enced_content_info, &enced_content_info_len,
			in, inlen) != 1
		|| asn1_check(version == CMS_version_v1) != 1) {
		return -1;
	}
	*recipient_infos = rcpt_infos;
	*recipient_infos_len = rcpt_infos_len;

	while (rcpt_infos_len) {
		if ((ret = cms_recipient_info_decrypt_from_der(
			sm2_key,
			issuer, issuer_len,
			serial, serial_len,
			key, &keylen, sizeof(key),
			&rcpt_infos, &rcpt_infos_len)) < 0) {
			error_print();
			return -1;
		} else if (ret) {
			break;
		}
	}
	if (!ret) {
		error_print();
		return -1;
	}

	if (cms_enced_content_info_decrypt_from_der(
		&enc_algor, key, keylen,
		content_type, content, content_len,
		shared_info1, shared_info1_len,
		shared_info2, shared_info2_len,
		&enced_content_info, &enced_content_info_len) != 1) {
		error_print();
		return -1;
	}
	return 1;
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
	const uint8_t **enced_content_info, size_t *enced_content_info_len,
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
		|| asn1_any_from_der(enced_content_info, enced_content_info_len, &d, &dlen) != 1
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
	int ret, val;
	const uint8_t *p;
	size_t len;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (asn1_int_from_der(&val, &d, &dlen) != 1) goto err;
	format_print(fp, fmt, ind, "version: %d\n", val);
	if (asn1_set_from_der(&p, &len, &d, &dlen) != 1) goto err;
	cms_recipient_infos_print(fp, fmt, ind, "recipientInfos", p, len);
	if (asn1_set_from_der(&p, &len, &d, &dlen) != 1) goto err;
	cms_digest_algors_print(fp, fmt, ind, "digestAlgorithms", p, len);
	if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) goto err;
	cms_enced_content_info_print(fp, fmt, ind, "encryptedContentInfo", p, len);
	if ((ret = asn1_implicit_set_from_der(0, &p, &len, &d, &dlen)) < 0) goto err;
	if (ret) x509_certs_print(fp, fmt, ind, "certificates", p, len);
	if ((ret = asn1_implicit_set_from_der(1, &p, &len, &d, &dlen)) < 0) goto err;
	if (ret) x509_crls_print(fp, fmt, ind, "crls", p, len);
	if (asn1_set_from_der(&p, &len, &d, &dlen) != 1) goto err;
	cms_signer_infos_print(fp, fmt, ind, "signerInfos", p, len);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

int cms_signed_and_enveloped_data_encipher_to_der(
	const CMS_CERTS_AND_KEY *signers, size_t signers_cnt,
	const uint8_t *rcpt_certs, size_t rcpt_certs_len,
	int enc_algor, const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen,
	int content_type, const uint8_t *content, size_t content_len,
	const uint8_t *signers_crls, size_t signers_crls_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	uint8_t **out, size_t *outlen)
{
	uint8_t rcpt_infos[512];
	size_t rcpt_infos_len = 0;
	int digest_algors[] = { OID_sm3 };
	size_t digest_algors_cnt = sizeof(digest_algors)/sizeof(int);
	uint8_t content_info_header[256];
	size_t content_info_header_len = 0;
	uint8_t signer_infos[512];
	size_t signer_infos_len = 0;
	SM3_CTX sm3_ctx;
	const uint8_t *issuer;
	const uint8_t *serial;
	size_t issuer_len;
	size_t serial_len;
	uint8_t *p;
	size_t len = 0;
	size_t i;

	p = rcpt_infos;
	while (rcpt_certs_len) {
		const uint8_t *cert;
		size_t certlen;
		SM2_KEY public_key;

		if (asn1_any_from_der(&cert, &certlen, &rcpt_certs, &rcpt_certs_len) != 1
			|| x509_cert_get_issuer_and_serial_number(cert, certlen,
				&issuer, &issuer_len, &serial, &serial_len) != 1
			|| x509_cert_get_subject_public_key(cert, certlen, &public_key) != 1
			|| cms_recipient_info_encrypt_to_der(&public_key,
				issuer, issuer_len, serial, serial_len,
				key, keylen, NULL, &len) != 1
			|| asn1_length_le(len, sizeof(rcpt_infos)) != 1
			|| cms_recipient_info_encrypt_to_der(&public_key,
				issuer, issuer_len, serial, serial_len,
				key, keylen, &p, &rcpt_infos_len) != 1) {
			error_print();
			return -1;
		}
	}

	p = content_info_header;
	if (cms_content_info_header_to_der(content_type, content_len,
		&p, &content_info_header_len) != 1) {
		error_print();
		return -1;
	}
	sm3_init(&sm3_ctx);
	sm3_update(&sm3_ctx, content_info_header, content_info_header_len);
	sm3_update(&sm3_ctx, content, content_len);

	for (i = 0; i < signers_cnt; i++) {
		if (x509_cert_get_issuer_and_serial_number(
				signers[i].certs, signers[i].certs_len,
				&issuer, &issuer_len, &serial, &serial_len) != 1
			|| cms_signer_infos_add_signer_info(
				signer_infos, &signer_infos_len, sizeof(signer_infos),
				&sm3_ctx, signers->sign_key,
				issuer, issuer_len, serial, serial_len,
				NULL, 0, NULL, 0) != 1) {
			error_print();
			return -1;
		}
	}

	len = 0;
	if (asn1_int_to_der(CMS_version_v1, NULL, &len) != 1
		|| asn1_set_to_der(rcpt_infos, rcpt_infos_len, NULL, &len) != 1
		|| cms_digest_algors_to_der(digest_algors, digest_algors_cnt, NULL, &len) != 1
		|| cms_enced_content_info_encrypt_to_der(
			enc_algor, key, keylen, iv, ivlen,
			content_type, content, content_len,
			shared_info1, shared_info1_len,
			shared_info2, shared_info2_len,
			NULL, &len) != 1
		|| cms_implicit_signers_certs_to_der(0, signers, signers_cnt, NULL, &len) != 1
		|| asn1_implicit_set_to_der(1, signers_crls, signers_crls_len, NULL, &len) < 0
		|| asn1_set_to_der(signer_infos, signer_infos_len, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(CMS_version_v1, out, outlen) != 1
		|| asn1_set_to_der(rcpt_infos, rcpt_infos_len, out, outlen) != 1
		|| cms_digest_algors_to_der(digest_algors, digest_algors_cnt, out, outlen) != 1
		|| cms_enced_content_info_encrypt_to_der(
			enc_algor, key, keylen, iv, ivlen,
			content_type, content, content_len,
			shared_info1, shared_info1_len,
			shared_info2, shared_info2_len,
			out, outlen) != 1
		|| cms_implicit_signers_certs_to_der(0, signers, signers_cnt, out, outlen) != 1
		|| asn1_implicit_set_to_der(1, signers_crls, signers_crls_len, out, outlen) != 1
		|| asn1_set_to_der(signer_infos, signer_infos_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_signed_and_enveloped_data_decipher_from_der(
	const SM2_KEY *rcpt_key,
	const uint8_t *rcpt_issuer, size_t rcpt_issuer_len,
	const uint8_t *rcpt_serial, size_t rcpt_serial_len,
	int *content_type, uint8_t *content, size_t *content_len,
	const uint8_t **prcpt_infos, size_t *prcpt_infos_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len,
	const uint8_t **certs, size_t *certs_len,
	const uint8_t **crls, size_t *crls_len,
	const uint8_t **psigner_infos, size_t *psigner_infos_len,
	const uint8_t *extra_certs, size_t extra_certs_len,
	const uint8_t *extra_crls, size_t extra_crls_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	int version;
	const uint8_t *rcpt_infos;
	size_t rcpt_infos_len;
	int digest_algors[4];
	size_t digest_algors_cnt;
	const uint8_t *enced_content_info;
	size_t enced_content_info_len;
	const uint8_t *signer_infos;
	size_t signer_infos_len;
	int enc_algor;
	uint8_t key[32];
	size_t keylen;
	SM3_CTX sm3_ctx;
	uint8_t content_info_header[128];
	size_t content_info_header_len = 0;
	uint8_t *p = content_info_header;

	if (cms_signed_and_enveloped_data_from_der(
			&version,
			&rcpt_infos, &rcpt_infos_len,
			digest_algors, &digest_algors_cnt, sizeof(digest_algors)/sizeof(int),
			&enced_content_info, &enced_content_info_len,
			certs, certs_len,
			crls, crls_len,
			&signer_infos, &signer_infos_len,
			in, inlen) != 1
		|| asn1_check(version == CMS_version_v1) != 1
		|| asn1_check(digest_algors[0] == OID_sm3) != 1) {
		error_print();
		return -1;
	}
	*prcpt_infos = rcpt_infos;
	*prcpt_infos_len = rcpt_infos_len;
	*psigner_infos = signer_infos;
	*psigner_infos_len = signer_infos_len;

	while (rcpt_infos_len) {
		if ((ret = cms_recipient_info_decrypt_from_der(
			rcpt_key,
			rcpt_issuer, rcpt_issuer_len,
			rcpt_serial, rcpt_serial_len,
			key, &keylen, sizeof(key),
			&rcpt_infos, &rcpt_infos_len)) < 0) {
			error_print();
			return -1;
		} else if (ret) {
			break;
		}
	}
	if (!ret) {
		error_print();
		return -1;
	}

	if (cms_enced_content_info_decrypt_from_der(
		&enc_algor, key, keylen,
		content_type, content, content_len,
		shared_info1, shared_info1_len,
		shared_info2, shared_info2_len,
		&enced_content_info, &enced_content_info_len) != 1) {
		error_print();
		return -1;
	}

	if (cms_content_info_header_to_der(*content_type, *content_len,
		&p, &content_info_header_len) != 1) {
		error_print();
		return -1;
	}
	sm3_init(&sm3_ctx);
	sm3_update(&sm3_ctx, content_info_header, content_info_header_len);
	sm3_update(&sm3_ctx, content, *content_len);

	while (signer_infos_len) {
		const uint8_t *cert;
		size_t certlen;
		const uint8_t *issuer;
		size_t issuer_len;
		const uint8_t *serial;
		size_t serial_len;
		const uint8_t *authed_attrs;
		size_t authed_attrs_len;
		const uint8_t *unauthed_attrs;
		size_t unauthed_attrs_len;

		if (cms_signer_info_verify_from_der(
			&sm3_ctx, *certs, *certs_len,
			&cert, &certlen,
			&issuer, &issuer_len,
			&serial, &serial_len,
			&authed_attrs, &authed_attrs_len,
			&unauthed_attrs, &unauthed_attrs_len,
			&signer_infos, &signer_infos_len) != 1) {
			error_print();
			return -1;
		}
	}

	return 1;
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
	sm2_public_key_print(fp, fmt, ind, "tempPublicKeyR", &pub_key);
	if (x509_cert_from_der(&p, &len, &d, &dlen) != 1) goto err;
	x509_cert_print(fp, fmt, ind, "certificate", p, len);
	if (asn1_octet_string_from_der(&p, &len, &d, &dlen) != 1) goto err;
	format_string(fp, fmt, ind, "userID", p, len);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

int cms_set_data(uint8_t *cms, size_t *cmslen, const uint8_t *d, size_t dlen)
{
	int oid = OID_cms_data;
	size_t len = 0;

	if (asn1_octet_string_to_der(d, dlen, NULL, &len) < 0) {
		error_print();
		return -1;
	}
	*cmslen = 0;
	if (!cms) {
		uint8_t data[1];
		if (cms_content_info_to_der(oid, data, len, NULL, cmslen) != 1) {
			error_print();
			return -1;
		}
		return 1;
	}
	if (cms_content_info_header_to_der(oid, len, &cms, cmslen) != 1
		|| asn1_octet_string_to_der(d, dlen, &cms, cmslen) < 0) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_encrypt(uint8_t *cms, size_t *cmslen,
	int enc_algor, const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen,
	int content_type, const uint8_t *content, size_t content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len)
{
	int oid = OID_cms_encrypted_data;
	size_t len = 0;

	if (cms_encrypted_data_encrypt_to_der(
		enc_algor, key, keylen, iv, ivlen,
		content_type, content, content_len,
		shared_info1, shared_info1_len,
		shared_info2, shared_info2_len,
		NULL, &len) != 1) {
		error_print();
		return -1;
	}
	*cmslen = 0;
	if (!cms) {
		uint8_t data[1];
		if (cms_content_info_to_der(oid, data, len, NULL, cmslen) != 1) {
			error_print();
			return -1;
		}
		return 1;
	}
	if (cms_content_info_header_to_der(oid, len, &cms, cmslen) != 1
		|| cms_encrypted_data_encrypt_to_der(
			enc_algor, key, keylen, iv, ivlen,
			content_type, content, content_len,
			shared_info1, shared_info1_len,
			shared_info2, shared_info2_len,
			&cms, cmslen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_decrypt(const uint8_t *cms, size_t cmslen,
	int *enc_algor, const uint8_t *key, size_t keylen,
	int *content_type, uint8_t *content, size_t *content_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len)
{
	int cms_type;
	const uint8_t *cms_content;
	size_t cms_content_len;

	if (cms_content_info_from_der(&cms_type, &cms_content, &cms_content_len, &cms, &cmslen) != 1
		|| asn1_check(cms_type == OID_cms_encrypted_data) != 1
		|| asn1_check(cms_content && cms_content_len) != 1
		|| asn1_length_is_zero(cmslen) != 1) {
		error_print();
		return -1;
	}
	if (cms_encrypted_data_decrypt_from_der(
			enc_algor, key, keylen,
			content_type, content, content_len,
			shared_info1, shared_info1_len,
			shared_info2, shared_info2_len,
			&cms_content, &cms_content_len) != 1
		|| asn1_length_is_zero(cms_content_len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_sign(uint8_t *cms, size_t *cmslen,
	const CMS_CERTS_AND_KEY *signers, size_t signers_cnt,
	int content_type, const uint8_t *content, size_t content_len,
	const uint8_t *crls, size_t crls_len)
{
	int oid = OID_cms_signed_data;
	size_t len = 0;

	if (cms_signed_data_sign_to_der(
		signers, signers_cnt,
		content_type, content, content_len,
		crls, crls_len,
		NULL, &len) != 1) {
		error_print();
		return -1;
	}
	*cmslen = 0;
	if (!cms) {
		uint8_t data[1];
		if (cms_content_info_to_der(oid, data, len, NULL, cmslen) != 1) {
			error_print();
			return -1;
		}
		return 1;
	}
	if (cms_content_info_header_to_der(oid, len, &cms, cmslen) != 1
		|| cms_signed_data_sign_to_der(
			signers, signers_cnt,
			content_type, content, content_len,
			crls, crls_len,
			&cms, cmslen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_verify(const uint8_t *cms, size_t cmslen,
	const uint8_t *extra_certs, size_t extra_certs_len,
	const uint8_t *extra_crls, size_t extra_crls_len,
	int *content_type, const uint8_t **content, size_t *content_len,
	const uint8_t **certs, size_t *certs_len,
	const uint8_t **crls, size_t *crls_len,
	const uint8_t **signer_infos, size_t *signer_infos_len)
{
	int cms_type;
	const uint8_t *cms_content;
	size_t cms_content_len;

	if (cms_content_info_from_der(&cms_type, &cms_content, &cms_content_len, &cms, &cmslen) != 1
		|| asn1_length_is_zero(cmslen) != 1) {
		error_print();
		return -1;
	}
	if (cms_type != OID_cms_signed_data) {
		error_print();
		return -1;
	}
	if (cms_content_len <= 0) {
		error_print();
		return -1;
	}

	if (cms_signed_data_verify_from_der(
			extra_certs, extra_certs_len,
			extra_crls, extra_crls_len,
			content_type, content, content_len,
			certs, certs_len,
			crls, crls_len,
			signer_infos, signer_infos_len,
			&cms_content, &cms_content_len) != 1
		|| asn1_length_is_zero(cms_content_len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_envelop(
	uint8_t *cms, size_t *cmslen,
	const uint8_t *rcpt_certs, size_t rcpt_certs_len,
	int enc_algor, const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen,
	int content_type, const uint8_t *content, size_t content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len)
{
	int oid = OID_cms_enveloped_data;
	size_t len = 0;

	if (cms_enveloped_data_encrypt_to_der(
		rcpt_certs, rcpt_certs_len,
		enc_algor, key, keylen, iv, ivlen,
		content_type, content, content_len,
		shared_info1, shared_info1_len,
		shared_info2, shared_info2_len,
		NULL, &len) != 1) {
		error_print();
		return -1;
	}
	*cmslen = 0;
	if (!cms) {
		uint8_t data[1];
		if (cms_content_info_to_der(oid, data, len, NULL, cmslen) != 1) {
			error_print();
			return -1;
		}
		return 1;
	}
	if (cms_content_info_header_to_der(oid, len, &cms, cmslen) != 1
		|| cms_enveloped_data_encrypt_to_der(
			rcpt_certs, rcpt_certs_len,
			enc_algor, key, keylen, iv, ivlen,
			content_type, content, content_len,
			shared_info1, shared_info1_len,
			shared_info2, shared_info2_len,
			&cms, cmslen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_deenvelop(const uint8_t *cms, size_t cmslen,
	const SM2_KEY *rcpt_key, const uint8_t *rcpt_cert, size_t rcpt_cert_len,
	int *content_type, uint8_t *content, size_t *content_len,
	const uint8_t **rcpt_infos, size_t *rcpt_infos_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len)
{
	int cms_type;
	const uint8_t *cms_content;
	size_t cms_content_len;
	const uint8_t *issuer;
	size_t issuer_len;
	const uint8_t *serial;
	size_t serial_len;
	SM2_KEY public_key;

	if (cms_content_info_from_der(&cms_type, &cms_content, &cms_content_len, &cms, &cmslen) != 1
		|| asn1_check(cms_type == OID_cms_enveloped_data) != 1
		|| asn1_check(cms_content && cms_content_len) != 1
		|| asn1_length_is_zero(cmslen) != 1) {
		error_print();
		return -1;
	}

	if (x509_cert_get_issuer_and_serial_number(rcpt_cert, rcpt_cert_len,
			&issuer, &issuer_len, &serial, &serial_len) != 1
		|| x509_cert_get_subject_public_key(rcpt_cert, rcpt_cert_len,
			&public_key) != 1) {
		error_print();
		return -1;
	}
	if (memcmp(&public_key, rcpt_key, sizeof(SM2_POINT)) != 0) {
		error_print();
		return -1;
	}

	if (cms_enveloped_data_decrypt_from_der(
			rcpt_key, issuer, issuer_len, serial, serial_len,
			content_type, content, content_len,
			rcpt_infos, rcpt_infos_len,
			shared_info1, shared_info1_len,
			shared_info2, shared_info2_len,
			&cms_content, &cms_content_len) != 1
		|| asn1_length_is_zero(cms_content_len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_sign_and_envelop(uint8_t *cms, size_t *cmslen,
	const CMS_CERTS_AND_KEY *signers, size_t signers_cnt,
	const uint8_t *rcpt_certs, size_t rcpt_certs_len,
	int enc_algor, const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen,
	int content_type, const uint8_t *content, size_t content_len,
	const uint8_t *crls, size_t crls_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len)
{
	int oid = OID_cms_signed_and_enveloped_data;
	size_t len = 0;

	if (cms_signed_and_enveloped_data_encipher_to_der(
		signers, signers_cnt,
		rcpt_certs, rcpt_certs_len,
		enc_algor, key, keylen, iv, ivlen,
		content_type, content, content_len,
		crls, crls_len,
		shared_info1, shared_info1_len,
		shared_info2, shared_info2_len,
		NULL, &len) != 1) {
		error_print();
		return -1;
	}
	*cmslen = 0;
	if (!cms) {
		uint8_t data[1];
		if (cms_content_info_to_der(oid, data, len, NULL, cmslen) != 1) {
			error_print();
			return -1;
		}
		return 1;
	}
	if (cms_content_info_header_to_der(oid, len, &cms, cmslen) != 1
		|| cms_signed_and_enveloped_data_encipher_to_der(
			signers, signers_cnt,
			rcpt_certs, rcpt_certs_len,
			enc_algor, key, keylen, iv, ivlen,
			content_type, content, content_len,
			crls, crls_len,
			shared_info1, shared_info1_len,
			shared_info2, shared_info2_len,
			&cms, cmslen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_deenvelop_and_verify(const uint8_t *cms, size_t cmslen,
	const SM2_KEY *rcpt_key, const uint8_t *rcpt_cert, size_t rcpt_cert_len,
	const uint8_t *extra_certs, size_t extra_certs_len,
	const uint8_t *extra_crls, size_t extra_crls_len,
	int *content_type, uint8_t *content, size_t *content_len,
	const uint8_t **rcpt_infos, size_t *rcpt_infos_len,
	const uint8_t **signer_infos, size_t *signer_infos_len,
	const uint8_t **certs, size_t *certs_len,
	const uint8_t **crls, size_t *crls_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len)
{
	const uint8_t *rcpt_issuer;
	size_t rcpt_issuer_len;
	const uint8_t *rcpt_serial;
	size_t rcpt_serial_len;
	SM2_KEY public_key;
	int cms_type;
	const uint8_t *cms_content;
	size_t cms_content_len;

	if (cms_content_info_from_der(&cms_type, &cms_content, &cms_content_len, &cms, &cmslen) != 1
		|| asn1_check(cms_type == OID_cms_signed_and_enveloped_data) != 1
		|| asn1_check(cms_content && cms_content_len) != 1
		|| asn1_length_is_zero(cmslen) != 1) {
		error_print();
		return -1;
	}

	if (x509_cert_get_issuer_and_serial_number(rcpt_cert, rcpt_cert_len,
			&rcpt_issuer, &rcpt_issuer_len,
			&rcpt_serial, &rcpt_serial_len) != 1
		|| x509_cert_get_subject_public_key(rcpt_cert, rcpt_cert_len,
			&public_key) != 1) {
		error_print();
		return -1;
	}
	if (memcmp(&public_key, rcpt_key, sizeof(SM2_POINT)) != 0) {
		error_print();
		return -1;
	}

	if (cms_signed_and_enveloped_data_decipher_from_der(
			rcpt_key,
			rcpt_issuer, rcpt_issuer_len,
			rcpt_serial, rcpt_serial_len,
			content_type, content, content_len,
			rcpt_infos, rcpt_infos_len,
			shared_info1, shared_info1_len,
			shared_info2, shared_info2_len,
			certs, certs_len,
			crls, crls_len,
			signer_infos, signer_infos_len,
			extra_certs, extra_certs_len,
			extra_crls, extra_crls_len,
			&cms_content, &cms_content_len) != 1
		|| asn1_length_is_zero(cms_content_len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_set_key_agreement_info(
	uint8_t *cms, size_t *cmslen,
	const SM2_KEY *temp_public_key_r,
	const uint8_t *user_cert, size_t user_cert_len,
	const uint8_t *user_id, size_t user_id_len)
{
	int oid = OID_cms_key_agreement_info;
	size_t len = 0;

	if (cms_key_agreement_info_to_der(CMS_version_v1, temp_public_key_r,
		user_cert, user_cert_len, user_id, user_id_len, NULL, &len) != 1) {
		error_print();
		return -1;
	}
	*cmslen = 0;
	if (!cms) {
		uint8_t data[1];
		if (cms_content_info_to_der(oid, data, len, NULL, cmslen) != 1) {
			error_print();
			return -1;
		}
		return 1;
	}
	if (cms_content_info_header_to_der(oid, len, &cms, cmslen) != 1
		|| cms_key_agreement_info_to_der(CMS_version_v1, temp_public_key_r,
			user_cert, user_cert_len, user_id, user_id_len, &cms, cmslen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_to_pem(const uint8_t *cms, size_t cms_len, FILE *fp)
{
	if (pem_write(fp, PEM_CMS, cms, cms_len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_from_pem(uint8_t *cms, size_t *cms_len, size_t maxlen, FILE *fp)
{
	int ret;
	if ((ret = pem_read(fp, PEM_CMS, cms, cms_len, maxlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}

	return 1;
}

int cms_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *a, size_t alen)
{
	const uint8_t *d;
	size_t dlen;


	if (asn1_sequence_from_der(&d, &dlen, &a, &alen) != 1) goto err;


	cms_content_info_print(fp, fmt, ind, label, d, dlen);
	//if (asn1_length_is_zero(alen) != 1) goto err;			
	return 1;
err:
	error_print();
	return -1;
}


