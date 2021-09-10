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
#include <gmssl/rand.h>
#include <gmssl/cms.h>

// 这个是干什么用的?
int find_cert(X509_CERTIFICATE *cert,
	const uint8_t *certs, size_t certslen,
	const X509_NAME *issuer, const uint8_t *serial_number, size_t serial_number_len)
{

	while (certslen) {
		if (x509_certificate_from_der(cert, &certs, &certslen) != 1) {
			error_print();
			return -1;
		}

		if (x509_name_equ(issuer, &cert->tbs_certificate.issuer)
			&& serial_number_len == cert->tbs_certificate.serial_number_len
			&& memcmp(serial_number, cert->tbs_certificate.serial_number, serial_number_len) == 0) {
			return 1;
		}
	}

	return 0;
}



/*
data ::= OCTET STRING
*/

int cms_data_print(FILE *fp, const uint8_t *a, size_t alen, int format, int indent)
{
	const uint8_t *data;
	size_t datalen;

	if (asn1_octet_string_from_der(&data, &datalen, &a, &alen) != 1) {
		error_print();
		return -1;
	}
	format_bytes(fp, format, indent, "data : ", data, datalen);
	if (alen > 0) {
		error_print();
		return -1;
	}
	return 1;
}


/*
EncryptedContentInfo ::= SEQUENCE {
	contentType			OBJECT IDENTIFIER,
	contentEncryptionAlgorithm	AlgorithmIdentifier,
	encryptedContent		[0] IMPLICIT OCTET STRING OPTIONAL,
	sharedInfo1			[1] IMPLICIT OCTET STRING OPTIONAL,
	sharedInfo2			[2] IMPLICIT OCTET STRING OPTIONAL,
}
*/

int cms_enced_content_info_to_der(int enc_algor, const uint8_t *enc_iv, size_t enc_iv_len,
	int content_type, const uint8_t *enced_content, size_t enced_content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (cms_content_type_to_der(content_type, NULL, &len) != 1
		|| x509_encryption_algor_to_der(enc_algor, enc_iv, enc_iv_len, NULL, &len) != 1
		|| asn1_implicit_octet_string_to_der(0, enced_content, enced_content_len, NULL, &len) < 0
		|| asn1_implicit_octet_string_to_der(1, shared_info1, shared_info1_len, NULL, &len) < 0
		|| asn1_implicit_octet_string_to_der(2, shared_info2, shared_info2_len, NULL, &len) < 0) {
		error_print();
		return -1;
	}
	if (asn1_sequence_header_to_der(len, out, outlen) != 1
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

int cms_enced_content_info_from_der(int *content_type,
	int *enc_algor, const uint8_t **enc_iv, size_t *enc_iv_len,
	const uint8_t **enced_content, size_t *enced_content_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len,
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
	if (cms_content_type_from_der(content_type, &data, &datalen) != 1
		|| x509_encryption_algor_from_der(enc_algor, nodes, &nodes_count, enc_iv, enc_iv_len, &data, &datalen) != 1
		|| asn1_implicit_octet_string_from_der(0, enced_content, enced_content_len, &data, &datalen) < 0
		|| asn1_implicit_octet_string_from_der(1, shared_info1, shared_info1_len, &data, &datalen) < 0
		|| asn1_implicit_octet_string_from_der(2, shared_info2, shared_info2_len, &data, &datalen) < 0
		|| asn1_check(datalen == 0) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_enced_content_info_print(FILE *fp,
	int content_type,
	int enc_algor, const uint8_t *enc_iv, size_t enc_iv_len,
	const uint8_t *enced_content, size_t enced_content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	int format, int indent)
{
	format_print(fp, format, indent, "EncryptedContentInfo:\n");
	indent += 4;

	format_print(fp, format, indent, "contentType: %s\n", cms_content_type_name(content_type));
	format_print(fp, format, indent, "contentEncryptionAlgorithm: %s\n", x509_encryption_algor_name(enc_algor));
	format_bytes(fp, format, indent + 4, "iv: ", enc_iv, enc_iv_len);
	format_bytes(fp, format, indent, "encryptedContent: ", enced_content, enced_content_len);
	format_bytes(fp, format, indent, "sharedInfo1: ", shared_info1, shared_info1_len);
	format_bytes(fp, format, indent, "sharedInfo2: ", shared_info2, shared_info2_len);
	return 1;
}

int cms_enced_content_info_encrypt_to_der(const SM4_KEY *sm4_key, const uint8_t iv[16],
	int content_type, const uint8_t *content, size_t content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	uint8_t **out, size_t *outlen)
{
	uint8_t enced_content[content_len + 256];
	size_t enced_content_len;

	if (sm4_cbc_padding_encrypt(sm4_key, iv, content, content_len,
		enced_content, &enced_content_len) != 1) {
		error_print();
		return -1;
	}
	if (cms_enced_content_info_to_der(OID_sm4_cbc, iv, 16,
		content_type, enced_content, enced_content_len,
		shared_info1, shared_info1_len,
		shared_info2, shared_info2_len,
		out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_enced_content_info_decrypt_from_der(const SM4_KEY *key,
	int *content_type, uint8_t *content, size_t *content_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	int enc_algor;
	const uint8_t *enc_iv;
	size_t enc_iv_len;
	const uint8_t *enced_content;
	size_t enced_content_len;

	if ((ret = cms_enced_content_info_from_der(content_type,
		&enc_algor, &enc_iv, &enc_iv_len,
		&enced_content, &enced_content_len,
		shared_info1, shared_info1_len,
		shared_info2, shared_info2_len,
		in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (sm4_cbc_padding_decrypt(key, enc_iv, enced_content, enced_content_len,
		content, content_len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

/*
EncryptedData ::= SEQUENCE {
	version				INTEGER (1),
	encryptedContentInfo		EncryptedContentInfo ::= SEQUENCE {
		contentType			OBJECT IDENTIFIER,
		contentEncryptionAlgorithm	AlgorithmIdentifier, // 包含参数IV
		encryptedContent		[0] IMPLICIT OCTET STRING OPTIONAL,
		sharedInfo1			[1] IMPLICIT OCTET STRING OPTIONAL,
		sharedInfo2			[2] IMPLICIT OCTET STRING OPTIONAL,
}
*/

int cms_encrypted_data_to_der(int enc_algor, const uint8_t *enc_iv, size_t enc_iv_len,
	int content_type, const uint8_t *enced_content, size_t enced_content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (asn1_int_to_der(CMS_version, NULL, &len) != 1
		|| cms_enced_content_info_to_der(enc_algor, enc_iv, enc_iv_len,
			content_type, enced_content, enced_content_len,
			shared_info1, shared_info1_len,
			shared_info2, shared_info2_len,
			NULL, &len) != 1) {
		error_print();
		return -1;
	}
	if (asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(CMS_version, out, outlen) != 1
		|| cms_enced_content_info_to_der(enc_algor, enc_iv, enc_iv_len,
			content_type, enced_content, enced_content_len,
			shared_info1, shared_info1_len,
			shared_info2, shared_info2_len,
			out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_encrypted_data_decrypt_from_der(const SM4_KEY *key,
	int *content_type, uint8_t *content, size_t *content_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;
	int version;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		else error_print();
		return ret;
	}
	if (asn1_int_from_der(&version, &data, &datalen) != 1
		|| version != CMS_version) {
		error_print();
		return -1;
	}

	if (cms_enced_content_info_decrypt_from_der(key,
		content_type, content, content_len,
		shared_info1, shared_info1_len,
		shared_info2, shared_info2_len,
		&data, &datalen) != 1
		|| datalen) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_encrypted_data_from_der(int *content_type,
	int *enc_algor, const uint8_t **enc_iv, size_t *enc_iv_len,
	const uint8_t **enced_content, size_t *enced_content_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;
	int version;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_int_from_der(&version, &data, &datalen) != 1
		|| cms_enced_content_info_from_der(content_type,
			enc_algor, enc_iv, enc_iv_len,
			enced_content, enced_content_len,
			shared_info1, shared_info1_len,
			shared_info2, shared_info2_len,
			&data, &datalen) != 1
		|| asn1_check(datalen == 0) != 1) {
		error_print();
		return -1;
	}
	if (version != CMS_version) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_encrypted_data_print(FILE *fp, const uint8_t *a, size_t alen, int format, int indent)
{
	int version;
	int content_type;
	int enc_algor;
	const uint8_t *enc_iv;
	size_t enc_iv_len;
	const uint8_t *enced_content;
	size_t enced_content_len;
	const uint8_t *shared_info1;
	size_t shared_info1_len;
	const uint8_t *shared_info2;
	size_t shared_info2_len;

	if (cms_encrypted_data_from_der(
		&content_type,
		&enc_algor, &enc_iv, &enc_iv_len,
		&enced_content, &enced_content_len,
		&shared_info1, &shared_info1_len,
		&shared_info2, &shared_info2_len,
		&a, &alen) != 1) {
		error_print();
		return -1;
	}

	format_print(fp, format, indent, "EncryptedData:\n");
	indent += 4;
	format_print(fp, format, indent, "Version : %d\n", version);
	cms_enced_content_info_print(fp,
		content_type,
		enc_algor, enc_iv, enc_iv_len,
		enced_content, enced_content_len,
		shared_info1, shared_info1_len,
		shared_info2, shared_info2_len,
		format, indent);

	if (alen) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_encrypted_data_encrypt_to_der(const SM4_KEY *sm4_key, const uint8_t iv[16],
	int content_type, const uint8_t *content, size_t content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (asn1_int_to_der(CMS_version, NULL, &len) != 1
		|| cms_enced_content_info_encrypt_to_der(sm4_key, iv,
			content_type, content, content_len,
			shared_info1, shared_info1_len,
			shared_info2, shared_info2_len,
			NULL, &len) != 1) {
		error_print();
		return -1;
	}

	if (asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(CMS_version, out, outlen) != 1
		|| cms_enced_content_info_encrypt_to_der(sm4_key, iv,
			content_type, content, content_len,
			shared_info1, shared_info1_len,
			shared_info2, shared_info2_len,
			out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}


/*
KeyAgreementInfo ::= SEQUENCE {
	version			INTEGER (1),
	tempPublicKeyR		SM2PublicKey,
	userCertificate		Certificate,
	userID			OCTET STRING
}
*/

int cms_key_agreement_info_to_der(const SM2_KEY *pub_key, const X509_CERTIFICATE *cert,
	const uint8_t *user_id, size_t user_id_len, uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (asn1_int_to_der(CMS_version, NULL, &len) != 1
		|| sm2_public_key_info_to_der(pub_key, NULL, &len) != 1
		|| x509_certificate_to_der(cert, NULL, &len) != 1
		|| asn1_octet_string_to_der(user_id, user_id_len, NULL, &len) != 1) {
		error_print();
		return -1;
	}
	if (asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(CMS_version, out, outlen) != 1
		|| sm2_public_key_info_to_der(pub_key, out, outlen) != 1
		|| x509_certificate_to_der(cert, out, outlen) != 1
		|| asn1_octet_string_to_der(user_id, user_id_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_key_agreement_info_from_der(SM2_KEY *pub_key, X509_CERTIFICATE *cert,
	const uint8_t **user_id, size_t *user_id_len, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;
	int version;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_int_from_der(&version, &data, &datalen) != 1
		|| sm2_public_key_info_from_der(pub_key, &data, &datalen) != 1
		|| x509_certificate_from_der(cert, &data, &datalen) != 1
		|| asn1_octet_string_from_der(user_id, user_id_len, &data, &datalen) != 1
		|| asn1_length_is_zero(datalen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_key_agreement_info_print(FILE *fp, const uint8_t *a, size_t alen, int format, int indent)
{
	SM2_KEY pub_key;
	X509_CERTIFICATE cert;
	const uint8_t *user_id;
	size_t user_id_len;

	if (cms_key_agreement_info_from_der(&pub_key, &cert, &user_id, &user_id_len, &a, &alen) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, format, indent, "KeyAgreementInfo :\n");
	indent += 4;
	format_print(fp, format, indent, "Version : 1\n");
	format_print(fp, format, indent, "tempPublicKeyR ");
		sm2_key_print(fp, &pub_key, format, indent + 4);
	format_print(fp, format, indent, "userCertificate ");
		x509_certificate_print(fp, &cert, format, indent + 4);
	format_bytes(fp, format, indent, "userID : ", user_id, user_id_len);

	if (alen) {
		error_print();
		return -1;
	}
	return 1;
}

/*
IssuerAndSerialNumber ::= SEQUENCE {
	isser		Name,
	serialNumber	INTEGER
}
*/

int cms_issuer_and_serial_number_from_certificate(const X509_NAME **issuer,
	const uint8_t **serial_number, size_t *serial_number_len,
	const X509_CERTIFICATE *cert)
{
	const X509_TBS_CERTIFICATE *tbs = &cert->tbs_certificate;
	*issuer = &tbs->issuer;
	*serial_number = tbs->serial_number;
	*serial_number_len = tbs->serial_number_len;
	return 1;
}

int cms_public_key_from_certificate(const SM2_KEY **sm2_key,
	const X509_CERTIFICATE *cert)
{
	const X509_TBS_CERTIFICATE *tbs = &cert->tbs_certificate;
	*sm2_key = &tbs->subject_public_key_info.sm2_key;
	return 1;
}

int cms_issuer_and_serial_number_to_der(const X509_NAME *issuer,
	const uint8_t *serial_number, size_t serial_number_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (x509_name_to_der(issuer, NULL, &len) != 1
		|| asn1_integer_to_der(serial_number, serial_number_len, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| x509_name_to_der(issuer, out, outlen) != 1
		|| asn1_integer_to_der(serial_number, serial_number_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_issuer_and_serial_number_from_der(X509_NAME *issuer,
	const uint8_t **serial_number, size_t *serial_number_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (x509_name_from_der(issuer, &data, &datalen) != 1
		|| asn1_integer_from_der(serial_number, serial_number_len, &data, &datalen) != 1
		|| datalen > 0) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_issuer_and_serial_number_print(FILE *fp,
	const X509_NAME *issuer,
	const uint8_t *serial_number, size_t serial_number_len,
	int format, int indent)
{
	format_print(fp, format, indent, "IssuerAndSerialNumber:\n");
	indent += 4;
	format_print(fp, format, indent, "issuer:\n");
	x509_name_print(fp, issuer, format, indent + 4);
	format_bytes(fp, format, indent, "serialNumber: ", serial_number, serial_number_len);
	return 1;
}

/*
RecipientInfo ::= SEQUENCE {
	version				INTEGER (1),
	issuerAndSerialNumber		IssuerAndSerialNumber,
	keyEncryptionAlgorithm		AlgorithmIdentifier,
	encryptedKey			OCTET STRING // 包含SM2Ciphertext的DER编码，变长数据
}
*/

int cms_recipient_info_from_x509_certificate(
	const SM2_KEY **key,
	const X509_NAME **issuer,
	const uint8_t **serial_number, size_t *serial_number_len,
	const X509_CERTIFICATE *cert)
{
	*issuer = &cert->tbs_certificate.issuer;
	*serial_number = &cert->tbs_certificate.serial_number[0];
	*serial_number_len = cert->tbs_certificate.serial_number_len;
	*key = &cert->tbs_certificate.subject_public_key_info.sm2_key;
	return 1;
}


int cms_recipient_info_to_der(const X509_NAME *issuer,
	const uint8_t *serial_number, size_t serial_number_len,
	const uint8_t *enced_key, size_t enced_key_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (asn1_int_to_der(CMS_version, NULL, &len) != 1
		|| cms_issuer_and_serial_number_to_der(issuer, serial_number, serial_number_len, NULL, &len) != 1
		|| x509_public_key_encryption_algor_to_der(OID_sm2encrypt, NULL, &len) != 1
		|| asn1_octet_string_to_der(enced_key, enced_key_len, NULL, &len) != 1) {
		error_print();
		return -1;
	}
	if (asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(CMS_version, out, outlen) != 1
		|| cms_issuer_and_serial_number_to_der(issuer, serial_number, serial_number_len, out, outlen) != 1
		|| x509_public_key_encryption_algor_to_der(OID_sm2encrypt, out, outlen) != 1
		|| asn1_octet_string_to_der(enced_key, enced_key_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_recipient_info_from_der(
	int *version,
	X509_NAME *issuer,
	const uint8_t **serial_number, size_t *serial_number_len,
	int *pke_algor, const uint8_t **params, size_t *paramslen,
	const uint8_t **enced_key, size_t *enced_key_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;
	uint32_t pke_algor_nodes[32];
	size_t pke_algor_nodes_count;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_int_from_der(version, &data, &datalen) != 1) {
		error_print();
		return -1;
	}
	if (cms_issuer_and_serial_number_from_der(issuer, serial_number, serial_number_len, &data, &datalen) != 1
		|| x509_public_key_encryption_algor_from_der(pke_algor, pke_algor_nodes, &pke_algor_nodes_count, params, paramslen, &data, &datalen) != 1) {
		error_print();
		return -1;
	}
	if (asn1_octet_string_from_der(enced_key, enced_key_len, &data, &datalen) != 1
		|| asn1_length_is_zero(datalen) != 1) {
		error_print();
		return -1;
	}
	if (*version != CMS_version) {
		error_print();
		return -1;
	}

	return 1;
}

int cms_recipient_info_print(FILE *fp,
	int version,
	const X509_NAME *issuer, const uint8_t *serial_number, size_t serial_number_len,
	int pke_algor, const uint8_t *params, size_t paramslen,
	const uint8_t *enced_key, size_t enced_key_len,
	int format, int indent)
{
	format_print(fp, format, indent, "RecipientInfo:\n");
	indent += 4;
	format_print(fp, format, indent, "Version: %d\n", version);
	cms_issuer_and_serial_number_print(fp, issuer, serial_number, serial_number_len, format, indent);
	format_print(fp, format, indent, "KeyEncryptionAlgorithm: %s\n", x509_public_key_encryption_algor_name(pke_algor));
	/*
	if (params && paramslen) {
		format_bytes(fp, format, indent + 4, "parameters: ", params, paramslen);
	}
	*/
	format_bytes(fp, format, indent, "EncryptedKey: ", enced_key, enced_key_len);
	return 1;
}


int cms_recipient_info_encrypt_to_der(const SM2_KEY *sm2_key,
	const X509_NAME *issuer, const uint8_t *serial_number, size_t serial_number_len,
	const uint8_t *key, size_t keylen,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	uint8_t buf[keylen + 256];
	size_t buflen;

	sm2_encrypt(sm2_key, key, keylen, buf, &buflen);

	cms_recipient_info_to_der(issuer, serial_number, serial_number_len,
		buf, buflen, out, outlen);

	return 1;
}

int cms_recipient_info_decrypt_from_der(const SM2_KEY *sm2_key,
	X509_NAME *issuer, const uint8_t **serial_number, size_t *serial_number_len,
	uint8_t *key, size_t *keylen,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	int version;
	int pke_algor;
	const uint8_t *pke_params;
	size_t pke_params_len;
	const uint8_t *enced_key;
	size_t enced_key_len;

	if ((ret = cms_recipient_info_from_der(&version,
			issuer, serial_number, serial_number_len,
			&pke_algor, &pke_params, &pke_params_len,
			&enced_key, &enced_key_len,
			in, inlen)) != 1
		|| asn1_check(version == CMS_version) != 1
		|| asn1_check(pke_algor == OID_sm2encrypt) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (sm2_decrypt(sm2_key, enced_key, enced_key_len, key, keylen) != 1) {
		error_print();
		return -1;
	}

	return 1;
}

/*
EnvelopedData ::= SEQUENCE {
	version			INTEGER (1),
	recipientInfos		SET OF RecipientInfo,
	encryptedContentInfo		EncryptedContentInfo ::= SEQUENCE {
		contentType			OBJECT IDENTIFIER,
		contentEncryptionAlgorithm	AlgorithmIdentifier, // 包含IV
		encryptedContent		[0] IMPLICIT OCTET STRING OPTIONAL,
		sharedInfo1			[1] IMPLICIT OCTET STRING OPTIONAL,
		sharedInfo2			[2] IMPLICIT OCTET STRING OPTIONAL,
	}
}


ContentInfo ::= SEQUENCE {
	contentType			OBJECT IDENTIFIER,
	content				[0] EXPLICIT ANY OPTIONAL

这里到底加密的是什么？

"content octets of the definite-length BER encoding of the the content field of
 ContentInfo value"

ContentInfo.content 是一个封装在explicit [0]中的一个完整的TLV的值
要加密的就是这个值（可能是另外一个ContentInfo）
只有当这个ContentInfo类型是data时，只是用来处理数据

*/

// 这个函数几乎是没有用的，因为我们用一个整体的函数去调用这个功能
int cms_enveloped_data_to_der(const uint8_t *rcpt_infos, size_t rcpt_infos_len,
	int content_type,
	int enc_algor,
	const uint8_t *enc_iv, size_t enc_iv_len,
	const uint8_t *enced_content, size_t enced_content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	const uint8_t **out, size_t *outlen)
{
	return -1;
}

int cms_enveloped_data_from_der(const uint8_t **rcpt_infos, size_t *rcpt_infos_len,
	int *content_type,
	int *enc_algor, const uint8_t **enc_iv, size_t *enc_iv_len,
	const uint8_t **enced_content, size_t *enced_content_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;
	int version;


	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_int_from_der(&version, &data, &datalen) != 1
		|| asn1_set_from_der(rcpt_infos, rcpt_infos_len, &data, &datalen) != 1
		|| cms_enced_content_info_from_der(content_type,
			enc_algor, enc_iv, enc_iv_len,
			enced_content, enced_content_len,
			shared_info1, shared_info1_len,
			shared_info2, shared_info2_len,
			&data, &datalen) != 1
		|| asn1_check(datalen == 0) != 1) {
		error_print();
		return -1;
	}
	return 1;
}


// 不做解密，打印加密的RecipientInfo和EncryptedContentInfo
int cms_enveloped_data_print(FILE *fp, const uint8_t *a, size_t alen, int format, int indent)
{
	const uint8_t *rcpt_infos;
	size_t rcpt_infos_len;
	int content_type;
	int enc_algor;
	const uint8_t *enc_iv;
	const uint8_t *enced_content;
	const uint8_t *shared_info1;
	const uint8_t *shared_info2;
	size_t enc_iv_len, enced_content_len, shared_info1_len, shared_info2_len;

	if (cms_enveloped_data_from_der(&rcpt_infos, &rcpt_infos_len,
		&content_type, &enc_algor, &enc_iv, &enc_iv_len,
		&enced_content, &enced_content_len,
		&shared_info1, &shared_info1_len,
		&shared_info2, &shared_info2_len,
		&a, &alen) != 1) {
		error_print();
		return -1;
	}

	format_print(fp, format, indent, "EnvelopedData:\n");
	indent += 4;
	format_print(fp, format, indent, "Version: %d\n", CMS_version);


	format_print(fp, format, indent, "RecipientInfos:\n");
	while (rcpt_infos_len) {
		int version;
		X509_NAME issuer;
		const uint8_t *serial_number;
		size_t serial_number_len;
		int pke_algor;
		const uint8_t *pke_params;
		size_t pke_params_len;
		const uint8_t *enced_key;
		size_t enced_key_len;

		if (cms_recipient_info_from_der(
			&version,
			&issuer, &serial_number, &serial_number_len,
			&pke_algor, &pke_params, &pke_params_len,
			&enced_key, &enced_key_len,
			&rcpt_infos, &rcpt_infos_len) != 1) {
			error_print();
			return -1;
		}
		cms_recipient_info_print(fp,
			version,
			&issuer, serial_number, serial_number_len,
			pke_algor, pke_params, pke_params_len,
			enced_key, enced_key_len,
			format, indent + 4);
	}

	cms_enced_content_info_print(fp,
		content_type,
		enc_algor, enc_iv, enc_iv_len,
		enced_content, enced_content_len,
		shared_info1, shared_info1_len,
		shared_info2, shared_info2_len,
		format, indent);

	return -1; 
}

// 这个数据长度为什么不一样？
int cms_enveloped_data_encrypt_to_der(const X509_CERTIFICATE *rcpt_certs, size_t rcpt_count,
	int content_type, const uint8_t *content, size_t content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	SM4_KEY sm4_key;
	uint8_t enc_key[16];
	uint8_t enc_iv[16];

	const SM2_KEY *sm2_key;
	const X509_NAME *issuer;
	const uint8_t *serial_number;
	size_t serial_number_len;

	size_t rcpt_infos_len = 0;
	size_t i;


	rand_bytes(enc_key, 16);
	rand_bytes(enc_iv, 16);




	/*
	每次生成的密文长度都是不同的，有SM2Ciphertext决定
	纯数据为 32 + 32 + 32 + 16
	*/

	for (i = 0; i < rcpt_count; i++) {
		cms_recipient_info_from_x509_certificate(&sm2_key,
			&issuer, &serial_number, &serial_number_len,
			&rcpt_certs[i]);

		rcpt_infos_len = 0;

		// FIXME: 预先估计的长度是不对的，因为每次SM2密文的长度都是不同的！
		cms_recipient_info_encrypt_to_der(sm2_key,
			issuer, serial_number, serial_number_len,
			enc_key, sizeof(enc_key),
			NULL, &rcpt_infos_len);
		error_print_msg("rcpt_infos_len = %zu\n", rcpt_infos_len);
	}

	if (asn1_int_to_der(CMS_version, NULL, &len) != 1
		|| asn1_set_to_der(NULL, rcpt_infos_len, NULL, &len) != 1
		|| cms_enced_content_info_encrypt_to_der(&sm4_key, enc_iv,
			content_type, content, content_len,
			shared_info1, shared_info1_len,
			shared_info2, shared_info2_len,
			NULL, &len) != 1) {
		error_print();
		return -1;
	}
	error_print_msg("len = %zu\n", len);

	error_print_msg("outlen = %zu\n", *outlen);
	if (asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(CMS_version, out, outlen) != 1
		|| asn1_set_header_to_der(rcpt_infos_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	for (i = 0; i < rcpt_count; i++) {
		if (cms_recipient_info_encrypt_to_der(sm2_key, issuer,
			serial_number, serial_number_len,
			enc_key, sizeof(enc_key),
			out, outlen) != 1) {
			error_print();
			return -1;
		}
	}
	if (cms_enced_content_info_encrypt_to_der(&sm4_key, enc_iv,
		content_type, content, content_len,
		shared_info1, shared_info1_len,
		shared_info2, shared_info2_len,
		out, outlen) != 1) {
		error_print();
		return -1;
	}
	error_print_msg("outlen = %zu\n", *outlen);
	return 1;
}

// 这里我们必须在整个RecipientInfos中找到匹配的，然后才能解密
/*
1. 扫描RecipientInfos，查看是否有和sm2_key, cert匹配的证书
2. 从找到的RecipientInfo，从加密算法中获取IV，对数据进行私钥解密后得到被加密的对称密钥key
3. 用key, iv对被加密的content进行解密
*/
int cms_enveloped_data_decrypt_from_der(
	const SM2_KEY *sm2_key, //解密方只有一个私钥，因此不管接收哪来的消息，只能用自己的私钥去尝试解密
	const X509_CERTIFICATE *cert, // 证书用于提供IssuerAndSerialNumber，从RecipientInfos中找到私钥对应的那个
	int *content_type, uint8_t *content, size_t *content_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len,
	const uint8_t **in, size_t *inlen)
{
	const uint8_t *rcpt_infos;
	size_t rcpt_infos_len;
	int enc_algor;
	uint32_t enc_algor_nodes[32];
	size_t enc_algor_nodes_count;
	const uint8_t *enced_content;
	size_t enced_content_len;
	uint8_t enc_key[64];
	size_t enc_key_len;

	const uint8_t *enc_iv;
	size_t enc_iv_len;
	SM4_KEY sm4_key;


	const X509_NAME *cert_issuer;
	const uint8_t *cert_serial;
	size_t cert_serial_len;

	if (cms_issuer_and_serial_number_from_certificate(&cert_issuer,
		&cert_serial, &cert_serial_len, cert) != 1) {
		error_print();
		return -1;
	}

	printf("input lenght = %zu\n", *inlen);

	if (cms_enveloped_data_from_der(&rcpt_infos, &rcpt_infos_len,
			content_type, &enc_algor,
			&enc_iv, &enc_iv_len,
			&enced_content, &enced_content_len,
			shared_info1, shared_info1_len,
			shared_info2, shared_info2_len,
			in, inlen) != 1) {
		error_print();
		return -1;
	}
	if (enc_algor != OID_sm4_cbc) {
		error_print();
		return -1;
	}
	if (!enc_iv || enc_iv_len != 16) {
		error_print();
		return -1;
	}

	while (rcpt_infos_len) {
		int version;
		X509_NAME issuer;
		const uint8_t *serial_number;
		size_t serial_number_len;
		int pke_algor;
		const uint8_t *pke_params;
		size_t pke_params_len;
		const uint8_t *enced_key;
		size_t enced_key_len;

		if (cms_recipient_info_from_der(
				&version,
				&issuer,
				&serial_number, &serial_number_len,
				&pke_algor, &pke_params, &pke_params_len,
				&enced_key, &enced_key_len,
				&rcpt_infos, &rcpt_infos_len) != 1) {
			error_print();
			return -1;
		}
		// 这里应该检查一下公钥类型到底对不对




		if (cert_serial_len != serial_number_len
			|| memcmp(serial_number, cert_serial, cert_serial_len)
			|| x509_name_equ(cert_issuer, &issuer) != 1) {
			continue;
		}

		if (sm2_decrypt(sm2_key, enced_key, enced_key_len, enc_key, &enc_key_len) != 1) {
			error_print();
			return -1;
		}
	}

	sm4_set_decrypt_key(&sm4_key, enc_key);
	if (sm4_cbc_padding_decrypt(
			&sm4_key, enc_iv,
			enced_content, enced_content_len,
			content, content_len) != 1) {
		error_print();
		return -1;
	}


	return 1;
}


// 注意，由于SignedData中包含ContentInfo，因此需要提前给出ContentInfo的基本编解码

/*
ContentType OIDs
 */

static const uint32_t OID_cms_data[]				= {1,2,156,10197,6,1,4,2,1};
static const uint32_t OID_cms_signed_data[]			= {1,2,156,10197,6,1,4,2,2};
static const uint32_t OID_cms_enveloped_data[]			= {1,2,156,10197,6,1,4,2,3};
static const uint32_t OID_cms_signed_and_enveloped_data[]	= {1,2,156,10197,6,1,4,2,4};
static const uint32_t OID_cms_encrypted_data[]			= {1,2,156,10197,6,1,4,2,5};
static const uint32_t OID_cms_key_agreement_info[]		= {1,2,156,10197,6,1,4,2,6};


const char *cms_content_type_name(int type)
{
	switch (type) {
	case CMS_data: return "data";
	case CMS_signed_data: return "signedData";
	case CMS_enveloped_data: return "envelopedData";
	case CMS_signed_and_enveloped_data: return "signedAndEnvelopedData";
	case CMS_encrypted_data: return "encryptedData";
	case CMS_key_agreement_info: return "keyAgreementInfo";
	}
	return NULL;
}

int cms_content_type_to_der(int type, uint8_t **out, size_t *outlen)
{
	uint32_t cms_nodes[9] = {1,2,156,10197,6,1,4,2,0};

	if (!cms_content_type_name(type)) {
		error_print();
		return -1;
	}
	cms_nodes[8] = type;
	if (asn1_object_identifier_to_der(OID_undef, cms_nodes, 9, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_content_type_from_der(int *type, const uint8_t **in, size_t *inlen)
{
	const uint32_t cms_nodes[] = {1,2,156,10197,6,1,4,2,0};
	int ret;

	uint32_t nodes[32];
	size_t nodes_count;

	if (( ret = asn1_object_identifier_from_der(type, nodes, &nodes_count, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}

	if (*type == OID_undef) {
		if (nodes_count != 9) {
			error_print();
			return -1;
		}
		if (memcmp(nodes, cms_nodes, 8) != 0) {
			error_print();
			return -1;
		}
		if (cms_content_type_name(nodes[8]) == NULL) {
			error_print();
			return -1;
		}
		*type = nodes[8];
	}
	return 1;
}


/*
ContentInfo ::= SEQUENCE {
	contentType			OBJECT IDENTIFIER,
	content				[0] EXPLICIT ANY OPTIONAL
}
*/

int cms_content_info_to_der(int content_type, const uint8_t *content, size_t content_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (content_type == CMS_data) {
		size_t octets_len = 0;
		if (asn1_octet_string_to_der(content, content_len, NULL, &octets_len) != 1
			|| cms_content_type_to_der(content_type, NULL, &len) != 1
			|| asn1_explicit_to_der(0, NULL, octets_len, NULL, &len) != 1
			|| asn1_sequence_header_to_der(len, out, outlen) != 1
			|| cms_content_type_to_der(content_type, out, outlen) != 1
			|| asn1_explicit_header_to_der(0, octets_len, out, outlen) != 1
			|| asn1_octet_string_to_der(content, content_len, out, outlen) != 1) {
			error_print();
			return -1;
		}
	} else {
		if (cms_content_type_to_der(content_type, NULL, &len) != 1
			|| asn1_explicit_to_der(0, content, content_len, NULL, &len) != 1
			|| asn1_sequence_header_to_der(len, out, outlen) != 1
			|| cms_content_type_to_der(content_type, out, outlen) != 1
			|| asn1_explicit_to_der(0, content, content_len, out, outlen) != 1) {
			error_print();
			return -1;
		}
	}
	return 1;
}

int cms_content_info_from_der(int *content_type, const uint8_t **content, size_t *content_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (cms_content_type_from_der(content_type, &data, &datalen) != 1
		|| asn1_explicit_from_der(0, content, content_len, &data, &datalen) != 1
		|| datalen > 0) {
		error_print();
		return -1;
	}
	return 1;
}

/*
SignerInfo ::= SEQUENCE {
	version				INTEGER (1),
	issuerAndSerialNumber		IssuerAndSerialNumber,
	digestAlgorithm			AlgorithmIdentifier,
	authenticatedAttributes		[0] IMPLICIT SET OF Attribute OPTINOAL,
	digestEncryptionAlgorithm	AlgorithmIdentifier,
	encryptedDigest			OCTET STRING, // 变长字符串
	unauthenticatedAttributes       [1] IMPLICIT SET OF Attribute OPTINOAL,
}
*/

int cms_signer_info_to_der(
	const X509_NAME *issuer,
	const uint8_t *serial_number, size_t serial_number_len,
	int digest_algor,
	const uint8_t *authed_attrs, size_t authed_attrs_len,
	const uint8_t *enced_digest, size_t enced_digest_len,
	const uint8_t *unauthed_attrs, size_t unauthed_attrs_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (asn1_int_to_der(CMS_version, NULL, &len) != 1
		|| cms_issuer_and_serial_number_to_der(issuer, serial_number, serial_number_len, NULL, &len) != 1
		|| x509_digest_algor_to_der(OID_sm3, NULL, &len) != 1
		|| asn1_implicit_set_to_der(0, authed_attrs, authed_attrs_len, NULL, &len) < 0
		|| x509_signature_algor_to_der(OID_sm2sign_with_sm3, NULL, &len) != 1
		|| asn1_octet_string_to_der(enced_digest, enced_digest_len, NULL, &len) != 1
		|| asn1_implicit_set_to_der(1, unauthed_attrs, unauthed_attrs_len, NULL, &len) < 0) {
		error_print();
		return -1;
	}
	if (asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(CMS_version, out, outlen) != 1
		|| cms_issuer_and_serial_number_to_der(issuer, serial_number, serial_number_len, out, outlen) != 1
		|| x509_digest_algor_to_der(OID_sm3, out, outlen) != 1) {
		error_print();
		return -1;
	}
	if (0
		|| asn1_implicit_set_to_der(0, authed_attrs, authed_attrs_len, out, outlen) < 0) {
		error_print();
		return -1;
	}
	if (0
		|| x509_signature_algor_to_der(OID_sm2sign_with_sm3, out, outlen) != 1) {
		error_print();
		return -1;
	}
	if (0
		|| asn1_octet_string_to_der(enced_digest, enced_digest_len, out, outlen) != 1
		|| asn1_implicit_set_to_der(1, unauthed_attrs, unauthed_attrs_len, out, outlen) < 0) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_signer_info_from_der(X509_NAME *issuer,
	const uint8_t **serial_number, size_t *serial_number_len,
	int *digest_algor,
	const uint8_t **authed_attrs, size_t *authed_attrs_len,
	int *sign_algor,
	const uint8_t **enced_digest, size_t *enced_digest_len,
	const uint8_t **unauthed_attrs, size_t *unauthed_attrs_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;
	int version;
	uint32_t nodes[32];
	size_t nodes_count;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_int_from_der(&version, &data, &datalen) != 1
		|| cms_issuer_and_serial_number_from_der(issuer, serial_number, serial_number_len, &data, &datalen) != 1
		|| x509_digest_algor_from_der(digest_algor, nodes, &nodes_count, &data, &datalen) != 1
		|| asn1_implicit_set_from_der(0, authed_attrs, authed_attrs_len, &data, &datalen) < 0
		|| x509_signature_algor_from_der(sign_algor, nodes, &nodes_count, &data, &datalen) != 1
		|| asn1_octet_string_from_der(enced_digest, enced_digest_len, &data, &datalen) != 1
		|| asn1_implicit_set_from_der(1, unauthed_attrs, unauthed_attrs_len, &data, &datalen) < 0
		|| datalen) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_signer_info_print(FILE *fp,
	int version,
	const X509_NAME *issuer, const uint8_t *serial_number, size_t serial_number_len,
	int digest_algor, const uint8_t *digest_params, size_t digest_params_len,
	const uint8_t *authed_attrs, size_t authed_attrs_len,
	int sign_algor, const uint8_t *sign_params, size_t sign_params_len,
	const uint8_t *sig, size_t siglen,
	const uint8_t *unauthed_attrs, size_t unauthed_attrs_len,
	int format, int indent)
{
	format_print(fp, format, indent, "SignerInfo:\n");
	indent += 4;
	format_print(fp, format, indent, "Version: %d\n", version);
	cms_issuer_and_serial_number_print(fp, issuer, serial_number, serial_number_len, format, indent);
	format_print(fp, format, indent, "digestAlgorithm: %s\n", x509_digest_algor_name(digest_algor));

	if (digest_params && digest_params_len)
		format_bytes(fp, format, indent, "Parameters: ", digest_params, digest_params_len);
	if (authed_attrs && authed_attrs_len) {
		format_bytes(fp, format, indent, "AuthenticatedAttributes: ", authed_attrs, authed_attrs_len);
	}
	
	format_print(fp, format, indent, "digestEncryptionAlgorithm: %s\n", x509_signature_algor_name(sign_algor));
	format_bytes(fp, format, indent, "encryptedDigest: ", sig, siglen);
	if (unauthed_attrs && unauthed_attrs_len) {
		format_bytes(fp, format, indent, "AuthenticatedAttributes: ", unauthed_attrs, unauthed_attrs_len);
	}
	return 1;
}

int cms_signer_info_sign_to_der(const SM2_KEY *sm2_key, const SM3_CTX *sm3_ctx,
	const X509_NAME *issuer, const uint8_t *serial_number, size_t serial_number_len,
	const uint8_t *authed_attrs, size_t authed_attrs_len,
	const uint8_t *unauthed_attrs, size_t unauthed_attrs_len,
	uint8_t **out, size_t *outlen)
{
	SM3_CTX ctx;
	uint8_t dgst[32];
	uint8_t sig[SM2_MAX_SIGNATURE_SIZE];
	size_t sig_len;

	memcpy(&ctx, sm3_ctx, sizeof(SM3_CTX));
	if (authed_attrs) {
		uint8_t header[8];
		uint8_t *p = header;
		size_t header_len = 0;
		asn1_set_header_to_der(authed_attrs_len, &p, &header_len);
		sm3_update(&ctx, header, header_len);
		sm3_update(&ctx, authed_attrs, authed_attrs_len);
	}
	sm3_finish(&ctx, dgst);
	sm2_sign(sm2_key, dgst, sig, &sig_len);

	if (cms_signer_info_to_der(issuer, serial_number, serial_number_len,
		OID_sm3, authed_attrs, authed_attrs_len, sig, sig_len,
		unauthed_attrs, unauthed_attrs_len,
		out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

/*
1. 解析SignerInfo获得IssuerAndSerialNumber
2. 查找SignedData中的Certificates获得签名公钥
3. 计算ContentInfo获得杂凑状态
4. 加入AuthedAttributes得到杂凑值
5. 验证签名
*/
int cms_signer_info_verify(
	const SM2_KEY *sm2_key, const SM3_CTX *sm3_ctx,
	const uint8_t *authed_attrs, size_t authed_attrs_len,
	const uint8_t *sig, size_t siglen)
{
	int ret;
	SM3_CTX ctx;
	uint8_t dgst[32];

	memcpy(&ctx, sm3_ctx, sizeof(SM3_CTX));
	if (*authed_attrs) {
		uint8_t header[8];
		uint8_t *p = header;
		size_t header_len = 0;
		asn1_set_header_to_der(authed_attrs_len, &p, &header_len);
		sm3_update(&ctx, header, header_len);
		sm3_update(&ctx, authed_attrs, authed_attrs_len);
	}
	sm3_finish(&ctx, dgst);

	if ((ret = sm2_verify(sm2_key, dgst, sig, siglen)) != 1) {
		error_print();
		return -1;
	}

	return ret;
}

static int x509_digest_algors_print(FILE *fp, const uint8_t *p, size_t len, int format, int indent)
{
	int dgst_algor;
	uint32_t dgst_algor_nodes[32];
	size_t dgst_algor_nodes_count;

	format_print(fp, format, indent, "DigestAlgorithms:\n");

	while (len) {
		if (x509_digest_algor_from_der(&dgst_algor,
				dgst_algor_nodes, &dgst_algor_nodes_count,
				&p, &len) != 1) {
			error_print();
			return -1;
		}
		format_print(fp, format, indent + 4, "%s\n", x509_digest_algor_name(dgst_algor));
	}
	return 1;
}


static int x509_certificates_print(FILE *fp, const uint8_t *p, size_t len, int format, int indent)
{
	X509_CERTIFICATE cert;

	format_print(fp, format, indent, "Certificates:\n");
	indent += 4;

	while (len) {
		if (x509_certificate_from_der(&cert, &p, &len) != 1) {
			error_print();
			return -1;
		}
		x509_certificate_print(fp, &cert, format, indent);
	}
	return 1;
}

static int x509_crls_print(FILE *fp, const uint8_t *p, size_t len, int format, int indent)
{
	/*
	X509_CRL crl;
	while (len) {
		if (x509_crl_from_der(&crl, &p, &len) != 1) {
			error_print();
			return -1;
		}
		x509_crl_print(fp, &crl, format, indent);
	}
	*/
	return 1;
}

static int cms_recipient_infos_print(FILE *fp, const uint8_t *p, size_t len, int format, int indent)
{
	format_print(fp, format, indent, "RecipientInfos:\n");
	while (len) {
		int version;
		X509_NAME issuer;
		const uint8_t *serial_number;
		size_t serial_number_len;
		int pke_algor;
		const uint8_t *pke_params;
		size_t pke_params_len;
		const uint8_t *enced_key;
		size_t enced_key_len;

		if (cms_recipient_info_from_der(
			&version,
			&issuer, &serial_number, &serial_number_len,
			&pke_algor, &pke_params, &pke_params_len,
			&enced_key, &enced_key_len,
			&p, &len) != 1) {
			error_print();
			return -1;
		}

		cms_recipient_info_print(fp,
			version,
			&issuer, serial_number, serial_number_len,
			pke_algor, pke_params, pke_params_len,
			enced_key, enced_key_len,
			format, indent + 4);
	}

	return 1;
}


static int cms_signer_infos_print(FILE *fp, const uint8_t *p, size_t len, int format, int indent)
{
	format_print(fp, format, indent, "SignerInfos:\n");
	indent += 4;

	while (len) {
		int version;
		X509_NAME issuer;
		const uint8_t *serial_number;
		size_t serial_number_len;
		int digest_algor;
		const uint8_t *digest_params;
		size_t digest_params_len;
		const uint8_t *authed_attrs; size_t authed_attrs_len;
		int sign_algor;
		const uint8_t *sign_params;
		size_t sign_params_len;
		const uint8_t *sig;
		size_t siglen;
		const uint8_t *unauthed_attrs; size_t unauthed_attrs_len;


		cms_signer_info_from_der(
			&issuer,
			&serial_number, &serial_number_len,
			&digest_algor,
			&authed_attrs, &authed_attrs_len,
			&sign_algor,
			&sig, &siglen,
			&unauthed_attrs, &unauthed_attrs_len,
			&p, &len);

		cms_signer_info_print(fp,
			version,
			&issuer,
			serial_number, serial_number_len,
			digest_algor, digest_params, digest_params_len,
			authed_attrs, authed_attrs_len,
			sign_algor, sign_params, sign_params_len,
			sig, siglen,
			unauthed_attrs, unauthed_attrs_len,
			format, indent);
	}

	return 1;
}

// 这个函数有用吗？
int cms_signed_data_to_der(
	const int *digest_algors, const size_t digest_algors_count,
	const int content_type, const uint8_t *content, const size_t content_len,
	const X509_CERTIFICATE *certs, size_t certs_count,
	const uint8_t **crls, const size_t *crls_lens, const size_t crls_count,
	const uint8_t **signer_infos, size_t *signer_infos_lens, size_t signer_infos_count,// 这个类型有点问题，意味着签名方必须把所有SignerInfo处理好才行
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	size_t digest_algors_len = 0;
	size_t certs_len = 0;
	size_t crls_len = 0;
	size_t signer_infos_len = 0;
	int i;

	for (i = 0; i < digest_algors_count; i++) {
		x509_digest_algor_to_der(digest_algors[i], NULL, &digest_algors_len);
	}
	for (i = 0; i < certs_count; i++) {
		x509_certificate_to_der(&certs[i], NULL, &certs_len);
	}
	for (i = 0; i < crls_count; i++)
		crls_len += crls_lens[i];
	for (i = 0; i < signer_infos_count; i++)
		signer_infos_len += signer_infos_lens[i];

	if (asn1_int_to_der(CMS_version, NULL, &len) != 1
		|| asn1_set_to_der(NULL, digest_algors_len, NULL, &len) != 1
		|| cms_content_info_to_der(content_type, content, content_len, NULL, &len) != 1
		|| asn1_implicit_set_to_der(0, NULL, certs_len, NULL, &len) < 0
		|| asn1_implicit_set_to_der(1, NULL, crls_len, NULL, &len) < 0
		|| asn1_set_to_der(NULL, signer_infos_len, NULL, &len) != 1) {
		error_print();
		return -1;
	}

	if (asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(CMS_version, out, outlen) != 1
		|| asn1_set_header_to_der(digest_algors_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	for (i = 0; i < digest_algors_count; i++) {
		if (x509_digest_algor_to_der(digest_algors[i], out, outlen) != 1) {
			error_print();
			return -1;
		}
	}
	if (cms_content_info_to_der(content_type, content, content_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	if (certs) {
		if (asn1_implicit_set_header_to_der(0, certs_len, out, outlen) != 1) {
			error_print();
			return -1;
		}
		for (i = 0; i < certs_count; i++) {
		}
	}
	if (crls) {
		for (i = 0; i < crls_count; i++) {
		}
	}


	if (asn1_set_header_to_der(signer_infos_len, out, outlen) != 1) {
	}
	for (i = 0; i < signer_infos_count; i++) {
		asn1_data_to_der(signer_infos[i], signer_infos_lens[i], out, outlen);
	}

	return -1;
}

int cms_signed_data_from_der(
	const uint8_t **digest_algors, size_t *digest_algors_len,
	int *content_type, const uint8_t **content, size_t *content_len,
	const uint8_t **certs, size_t *certs_len,
	const uint8_t **crls, size_t *crls_len,
	const uint8_t **signer_infos, size_t *signer_infos_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;
	int version;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}

	if (asn1_int_from_der(&version, &data, &datalen) != 1
		|| asn1_set_from_der(digest_algors, digest_algors_len, &data, &datalen) != 1
		|| cms_content_info_from_der(content_type, content, content_len, &data, &datalen) != 1) {
		error_print();
		return -1;
	}

	if ((ret = asn1_implicit_set_from_der(0, certs, certs_len, &data, &datalen)) < 0) {
		error_print();
		return -1;
	}
	if (ret == 0) {
	//	printf("no certs\n");
	}

	if ((ret = asn1_implicit_set_from_der(1, crls, crls_len, &data, &datalen)) < 0) {
		error_print();
		return -1;
	}


	if (asn1_set_from_der(signer_infos, signer_infos_len, &data, &datalen) != 1) {
		error_print();
		return -1;
	}

	if (asn1_length_is_zero(datalen) != 1) {
		error_print();
		//return -1;
	}
	if (version != CMS_version) {
		error_print();
		//return -1;
	}
	return 1;
}

static int content_info_print(FILE *fp,
	int content_type, const uint8_t *content, size_t content_len,
	int format, int indent)
{

	format_print(fp, format, indent, "ContentInfo:\n");
	indent += 4;
	format_print(fp, format, indent, "Type : %s\n", cms_content_type_name(content_type));
	switch (content_type) {
	case CMS_data: return cms_data_print(fp, content, content_len, format, indent);
	case CMS_signed_data: return cms_signed_data_print(fp, content, content_len, format, indent);
	case CMS_enveloped_data: break;
	case CMS_signed_and_enveloped_data: break;
	case CMS_encrypted_data: return cms_encrypted_data_print(fp, content, content_len, format, indent);
	case CMS_key_agreement_info: return cms_key_agreement_info_print(fp, content, content_len, format, indent);
	}
	error_print();
	return -1;
}

// 这几个类型的打印有相当多的重复部分
int cms_signed_data_print(FILE *fp, const uint8_t *a, size_t alen, int format, int indent)
{
	int version = 1;
	const uint8_t *dgst_algors;
	int content_type;
	const uint8_t *content;
	const uint8_t *certs;
	const uint8_t *crls;
	const uint8_t *signer_infos;
	size_t dgst_algors_len, content_len, certs_len, crls_len, signer_infos_len;

	if (cms_signed_data_from_der(
			&dgst_algors, &dgst_algors_len,
			&content_type, &content, &content_len,
			&certs, &certs_len,
			&crls, &crls_len,
			&signer_infos, &signer_infos_len,
			&a, &alen) != 1) {
		error_print();
	//	return -1;
	}

	format_print(fp, format, indent, "SignedData:\n");
	indent += 4;
	format_print(fp, format, indent, "Version : %d\n", version);
	x509_digest_algors_print(fp, dgst_algors, dgst_algors_len, format, indent);
	content_info_print(fp, content_type, content, content_len, format, indent);

	x509_certificates_print(fp, certs, certs_len, format, indent);


	x509_crls_print(fp, crls, crls_len, format, indent);
	cms_signer_infos_print(fp, signer_infos, signer_infos_len, format, indent);
	return 1;
}

/*
SignedData ::= SEQUENCE {
	version			INTEGER (1),
	digestAlgorithms	SET OF AlgorithmIdentifier,
	contentInfo		ContentInfo,
	certificates		[0] IMPLICIT SET OF Certificate OPTIONAL,
	crls			[1] IMPLICIT SET OF CertificateRevocationList OPTIONAL,
	signerInfos		SET OF SignerInfo
}

应该把CRL模块完成后再补全？
还是暂时不支持CRL？
*/

int cms_signed_data_sign_to_der(
	const SM2_KEY *sign_keys, const X509_CERTIFICATE *sign_certs, size_t sign_count,
	int content_type, const uint8_t *content, size_t content_len,
	const uint8_t *crls, size_t crls_len,
	uint8_t **out, size_t *outlen)
{
	uint8_t *p;
	size_t len = 0;
	uint8_t digest_algors[16]; // 这里我们只有一个哈希函数
	size_t digest_algors_len = 0;
	size_t certs_len = 0;
	size_t signer_infos_len = 0;
	uint8_t sigs[sign_count][SM2_MAX_SIGNATURE_SIZE];
	size_t siglens[sign_count];
	int i;

	// digestAlgorithms
	p = digest_algors;
	x509_digest_algor_to_der(OID_sm3, &p, &digest_algors_len);

	// certificates
	for (i = 0; i < sign_count; i++) {
		if (x509_certificate_to_der(&sign_certs[i], NULL, &certs_len) != 1) {
			error_print();
			return -1;
		}
	}

	// signerInfos
	for (i = 0; i < sign_count; i++) {
		const X509_CERTIFICATE *cert = &sign_certs[i];
		const X509_NAME *issuer = &cert->tbs_certificate.issuer;
		const uint8_t *serial_number = cert->tbs_certificate.serial_number;
		size_t serial_number_len = cert->tbs_certificate.serial_number_len;

		SM2_SIGN_CTX sign_ctx;
		sm2_sign_init(&sign_ctx, &sign_keys[i], SM2_DEFAULT_ID);
		sm2_sign_update(&sign_ctx, content, content_len); // 这里我们签名的都是content
		sm2_sign_finish(&sign_ctx, sigs[i], &siglens[i]);

		if (cms_signer_info_to_der(issuer, serial_number, serial_number_len,
			OID_sm3, NULL, 0, sigs[i], siglens[i], NULL, 0,
			NULL, &signer_infos_len) != 1) {
			error_print();
			return -1;
		}
	}


	len = 0;
	if (asn1_int_to_der(CMS_version, NULL, &len) != 1
		|| asn1_set_to_der(digest_algors, digest_algors_len, NULL, &len) != 1
		|| cms_content_info_to_der(content_type, content, content_len, NULL, &len) != 1
		|| asn1_implicit_set_to_der(0, NULL, certs_len, NULL, &len) < 0
		|| asn1_implicit_set_to_der(1, NULL, crls_len, NULL, &len) < 0
		|| asn1_set_to_der(NULL, signer_infos_len, NULL, &len) != 1) {
		error_print();
		return -1;
	}

	if (asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(CMS_version, out, outlen) != 1
		|| asn1_set_to_der(digest_algors, digest_algors_len, out, outlen) != 1
		|| cms_content_info_to_der(content_type, content, content_len, out, outlen) != 1
		|| asn1_implicit_set_header_to_der(0, certs_len, out, outlen) != 1) {
		error_print();
		return -1;
	}

	for (i = 0; i < sign_count; i++) {
		if (x509_certificate_to_der(&sign_certs[i], out, outlen) != 1) {
			error_print();
			return -1;
		}
	}
	if (crls) {
		if (asn1_implicit_set_to_der(1, crls, crls_len, out, outlen) != 1) {
			error_print();
			return -1;
		}
	}
	asn1_set_header_to_der(signer_infos_len, out, outlen);
	for (i = 0; i < sign_count; i++) {
		const X509_CERTIFICATE *cert = &sign_certs[i];
		const X509_NAME *issuer = &cert->tbs_certificate.issuer;
		const uint8_t *serial_number = cert->tbs_certificate.serial_number;
		size_t serial_number_len = cert->tbs_certificate.serial_number_len;

		if (cms_signer_info_to_der(issuer, serial_number, serial_number_len,
			OID_sm3, NULL, 0, sigs[i], siglens[i], NULL, 0, out, outlen) != 1) {
			error_print();
			return -1;
		}
	}

	return 1;
}

// 这里的主要矛盾是验证过程没有必要返回那么多数据！只能造成工作量过大，
// 如果调用方想要获得相应的数据，可以自己来解析。


int cms_signed_data_verify(
	int content_type, const uint8_t *content, size_t content_len, // 被签名的到底是什么数据？
	const uint8_t *certs, size_t certs_len,
	const uint8_t *signer_infos, size_t signer_infos_len)
{

	assert(content);
	assert(certs);
	assert(signer_infos);


	while (signer_infos_len) {

		X509_NAME issuer;
		const uint8_t *serial_number;
		size_t serial_number_len;
		const uint8_t *authed_attrs;
		size_t authed_attrs_len;
		const uint8_t *unauthed_attrs;
		size_t unauthed_attrs_len;
		const uint8_t *sig;
		size_t siglen;
		int dgst_algor, sign_algor;

		cms_signer_info_from_der(&issuer,
			&serial_number, &serial_number_len,
			&dgst_algor,
			&authed_attrs, &authed_attrs_len,
			&sign_algor,
			&sig, &siglen,
			&unauthed_attrs, &unauthed_attrs_len,
			&signer_infos, &signer_infos_len);


		// 找到对应的SM2_KEY ，并且验证签名
		X509_CERTIFICATE cert;

		// 主要的挑战就是找到对应的张数
		find_cert(&cert, certs, certs_len, &issuer, serial_number, serial_number_len);

		const SM2_KEY *sign_key = &cert.tbs_certificate.subject_public_key_info.sm2_key;

		SM2_SIGN_CTX ctx;

		sm2_verify_init(&ctx, sign_key, SM2_DEFAULT_ID);
		sm2_verify_update(&ctx, content, content_len);


		if (authed_attrs) {
			uint8_t header[8];
			uint8_t *p = header;
			size_t header_len = 0;

			asn1_set_header_to_der(*authed_attrs, &p, &header_len);
			sm2_verify_update(&ctx, header, header_len);
			sm2_verify_update(&ctx, authed_attrs, authed_attrs_len);
		}

		int ret;
		ret = sm2_verify_finish(&ctx, sig, siglen);

		if (ret != 1) {
			error_print_msg("sm2_verify_finish return %d\n", ret);
			return -1;
		}

	}

	return 1;
}


// 为什么不用这个函数
int cms_signed_data_verify_from_der(
	const uint8_t **digest_algors, size_t *digest_algors_len,
	int *content_type, const uint8_t **content, size_t *content_len,
	const uint8_t **certs, size_t *certs_len,
	const uint8_t **crls, size_t *crls_len,
	const uint8_t **signer_infos, size_t *signer_infos_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;

	if ((ret = cms_signed_data_from_der(
		digest_algors, digest_algors_len,
		content_type, content, content_len,
		certs, certs_len,
		crls, crls_len,
		signer_infos, signer_infos_len,
		in, inlen)) != 1) {

		if (ret < 0) error_print();
		return ret;
	}

	if (cms_signed_data_verify(
		*content_type, *content, *content_len,
		*certs, *certs_len,
		*signer_infos, *signer_infos_len) != 1) {
		error_print();
		return -1;
	}

	return 1;
}


/*
SignedAndEnvelopedData ::= SEQUENCE {
	version			INTEGER (1),
	recipientInfos		SET OF RecipientInfo,
	digestAlgorithms	SET OF AlgorithmIdentifier,
	encryptedContentInfo	EncryptedContentInfo ::= SEQUENCE {
		contentType			OBJECT IDENTIFIER,
		contentEncryptionAlgorithm	AlgorithmIdentifier, // 包含IV
		encryptedContent		[0] IMPLICIT OCTET STRING OPTIONAL,
		sharedInfo1			[1] IMPLICIT OCTET STRING OPTIONAL,
		sharedInfo2			[2] IMPLICIT OCTET STRING OPTIONAL,
	certificates		[0] IMPLICIT SET OF Certificate OPTIONAL,
	crls			[1] IMPLICIT SET OF CertificateRevocationList OPTIONAL,
	signerInfos		SET OF SignerInfo
}

1. 生成随机的content-encryption key (CEK)
2. 用每个接收者的公钥加密CEK
3. 并形成RecipientInfo
4. 根据签名者的算法生成content的哈希值，目前只支持SM3算法，注意涉及Z值
5. 用签名者的私钥对content的哈希值及authed_attrs进行签名，生成签名值，并且用CEK对签名值加密（可能需要填充）
6. 构造SignerInfos
7. 用CEK对ContentInfo.content中EXPLICIT [0]内部的ContentInfo的DER进行加密
8. 组成一个SignedAndEnvelopedData

注意：

- 这是一个先签名再加密的过程
- 每个签名值都被对称加密密钥独立加密了

*/

int cms_signed_and_enveloped_data_to_der(
	int version,
	const uint8_t *rcpt_infos, size_t rcpt_infos_len,
	const int *digest_algors, size_t digest_algors_count,
	int content_type,
		int enc_algor, const uint8_t *enc_iv, size_t enc_iv_len,
		const uint8_t *enced_content, size_t enced_content_len,
		const uint8_t *shared_info1, size_t shared_info1_len,
		const uint8_t *shared_info2, size_t shared_info2_len,
	const X509_CERTIFICATE *certs, size_t certs_count,
	const uint8_t *crls, size_t crls_count,
	const uint8_t signer_infos, size_t signer_infos_len)
{


	return -1;
}

int cms_signed_and_enveloped_data_from_der(
	int *version,
	const uint8_t **rcpt_infos, size_t *rcpt_infos_len,
	const uint8_t **dgst_algors, size_t *dgst_algors_len,
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
	const uint8_t *data;
	size_t datalen;


	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}

	if (asn1_int_from_der(version, &data, &datalen) != 1
		|| asn1_set_from_der(rcpt_infos, rcpt_infos_len, &data, &datalen) != 1
		|| asn1_set_from_der(dgst_algors, dgst_algors_len, &data, &datalen) != 1
		|| cms_enced_content_info_from_der(content_type,
			enc_algor, enc_iv, enc_iv_len,
			enced_content, enced_content_len,
			shared_info1, shared_info1_len,
			shared_info2, shared_info2_len,
			&data, &datalen) != 1
		|| asn1_implicit_set_from_der(0, certs, certs_len, &data, &datalen) < 0
		|| asn1_implicit_set_from_der(1, crls, crls_len, &data, &datalen) < 0
		|| asn1_set_from_der(signer_infos, signer_infos_len, &data, &datalen) != 1
		|| datalen > 0) {
		error_print();
		return -1;
	}

	return 1;
}

int cms_signed_and_enveloped_data_print(FILE *fp, const uint8_t *a, size_t alen,
	int format, int indent)
{
	int version;
	const uint8_t *rcpt_infos;
	const uint8_t *dgst_algors;
	const uint8_t *certs;
	const uint8_t *crls;
	const uint8_t *signer_infos;
	size_t rcpt_infos_len, dgst_algors_len, certs_len, crls_len, signer_infos_len;
	int content_type;
	int enc_algor;
	const uint8_t *enc_iv;
	const uint8_t *enced_content;
	const uint8_t *shared_info1;
	const uint8_t *shared_info2;
	size_t enc_iv_len, enced_content_len, shared_info1_len, shared_info2_len;

	cms_signed_and_enveloped_data_from_der(
		&version,
		&rcpt_infos, &rcpt_infos_len,
		&dgst_algors, &dgst_algors_len,
		&content_type,
			&enc_algor, &enc_iv, &enc_iv_len,
			&enced_content, &enced_content_len,
			&shared_info1, &shared_info1_len,
			&shared_info2, &shared_info2_len,
		&certs, &certs_len,
		&crls, &crls_len,
		&signer_infos, &signer_infos_len,
		&a, &alen);


	format_print(fp, format, indent, "SignedAndEnvelopedData:\n");
	indent += 4;

	format_print(fp, format, indent, "Version: %d\n", version);
	cms_recipient_infos_print(fp, rcpt_infos, rcpt_infos_len, format, indent);
	x509_digest_algors_print(fp, dgst_algors, dgst_algors_len, format, indent);
	cms_enced_content_info_print(fp,
		content_type,
		enc_algor, enc_iv, enc_iv_len,
		enced_content, enced_content_len,
		shared_info1, shared_info1_len,
		shared_info2, shared_info2_len,
		format, indent);
	x509_certificates_print(fp, certs, certs_len, format, indent);
	x509_crls_print(fp, crls, crls_len, format, indent);
	cms_signer_infos_print(fp, signer_infos, signer_infos_len, format, indent);

	return 1;
}

/*
SignedAndEnvelopedData ::= SEQUENCE {
	version			INTEGER (1),
	recipientInfos		SET OF RecipientInfo,
	digestAlgorithms	SET OF AlgorithmIdentifier,
	encryptedContentInfo	EncryptedContentInfo ::= SEQUENCE {
		contentType			OBJECT IDENTIFIER,
		contentEncryptionAlgorithm	AlgorithmIdentifier, // 包含IV
		encryptedContent		[0] IMPLICIT OCTET STRING OPTIONAL,
		sharedInfo1			[1] IMPLICIT OCTET STRING OPTIONAL,
		sharedInfo2			[2] IMPLICIT OCTET STRING OPTIONAL,
	certificates		[0] IMPLICIT SET OF Certificate OPTIONAL,
	crls			[1] IMPLICIT SET OF CertificateRevocationList OPTIONAL,
	signerInfos		SET OF SignerInfo
}


1. 生成随机的content-encryption key (CEK)
2. 用每个接收者的公钥加密CEK
3. 并形成RecipientInfo
4. 根据签名者的算法生成content的哈希值，目前只支持SM3算法，注意涉及Z值
5. 用签名者的私钥对content的哈希值及authed_attrs进行签名，生成签名值，并且用CEK对签名值加密（可能需要填充）
6. 构造SignerInfos
7. 用CEK对ContentInfo.content中EXPLICIT [0]内部的ContentInfo的DER进行加密

*/

// 这个接口是有问题的，显然签名方的证书和密钥没有给出了！
int cms_signed_and_enveloped_data_sign_encrypt_to_der(
	const SM2_KEY *sign_keys, const X509_CERTIFICATE *sign_certs, size_t sign_count,
	const uint8_t *sign_crls, const size_t sign_crls_len,
	const X509_CERTIFICATE *rcpt_certs, size_t rcpt_count,
	int content_type, const uint8_t *content, size_t content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,

	uint8_t **out, size_t *outlen)
{

	return 1;
}

/*
我们需要保证提供的私钥和证书可以和某个rcpt_infos匹配
还有一个问题是，在验签之后，我们需要返回所有的证书吗？不需要的，只要可以解析就可以了
函数保证signer_infos
*/
int cms_signed_and_enveloped_data_decrypt_verify_from_der(
	const SM2_KEY *dec_key, const X509_CERTIFICATE *dec_cert,
	const uint8_t **rcpt_infos, size_t *rcpt_infos_len,
	const uint8_t **dgst_algors, size_t *dgst_algors_len,
	int *content_type,
		int *enc_algor, const uint8_t **enc_iv, size_t *enc_iv_len,
		const uint8_t **enced_content, size_t *enced_content_len,
		const uint8_t **shared_info1, size_t *shared_info1_len,
		const uint8_t **shared_info2, size_t *shared_info2_len,
	const uint8_t **certs, size_t *certs_len,
	const uint8_t **crls, size_t *crls_len,
	const uint8_t **signer_infos, size_t *signer_infos_len)
{

	/*
	signer_info 中的签名是针对未加密的content的
	因此我们需要首先解析数据结构
	找到一个和证书、私钥匹配的recipient_info
	解密得到数据加密密钥，并解密enced_content
	然后验证所有的signer_infos

	这意味着这个函数应该可以和signed_data, enveloped_data共享某些函数
	*/











	return -1;
}

int cms_content_info_print(FILE *fp, const uint8_t *a, size_t alen, int format, int indent)
{
	int content_type;
	const uint8_t *content;
	size_t content_len;

	if (cms_content_info_from_der(&content_type, &content, &content_len, &a, &alen) != 1) {
		error_print();
		return -1;
	}
	if (content_info_print(fp, content_type, content, content_len, format, indent) != 1) {
		error_print();
		return -1;
	}
	if (alen) {
		error_print_msg("left length = %zu\n", alen);
		format_bytes(stderr, 0, 0, "left ", a, alen);
		return -1;
	}

	return 1;
}




// 下面的函数生成的都是ContentInfo
// 因此不简单是之前_to_der的封装，而是要组装成


// EncryptedData
int cms_encrypt(const uint8_t key[16], const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen)
{
	size_t len = 0;
	size_t content_len = 0;
	SM4_KEY sm4_key;
	uint8_t iv[16];

	sm4_set_encrypt_key(&sm4_key, key);
	rand_bytes(iv, sizeof(iv));

	if (cms_encrypted_data_encrypt_to_der(&sm4_key, iv,
		CMS_data, in, inlen, NULL, 0, NULL, 0,
		NULL, &content_len) != 1) {
		error_print();
		return -1;
	}

	if (cms_content_type_to_der(CMS_encrypted_data, NULL, &len) != 1
		|| asn1_explicit_to_der(0, NULL, content_len, NULL, &len) != 1) {
		error_print();
		return -1;
	}


	*outlen = 0;
	if (asn1_sequence_header_to_der(len, &out, outlen) != 1
		|| cms_content_type_to_der(CMS_encrypted_data, &out, outlen) != 1
		|| asn1_explicit_header_to_der(0, content_len, &out, outlen) != 1) {
	}

	if (cms_encrypted_data_encrypt_to_der(&sm4_key, iv, CMS_data, in, inlen,
			NULL, 0, NULL, 0, &out, outlen) != 1) {
		error_print();
		return -1;
	}

	return 1;
}

/*
一般来说，EncryptedData.EncryptedContent.contentType应该是CMS_data
但是也不排除是其他的类型，因此我们需要将这个类型反馈给调用方
如果是其他类型，那么调用方可以进一步处理
*/
int cms_decrypt(const uint8_t key[16], const uint8_t *in, size_t inlen,
	int *content_type, uint8_t *out, size_t *outlen)
{
	int cms_type;
	const uint8_t *enced_content;
	size_t enced_content_len;

	SM4_KEY sm4_key;
	const uint8_t *shared_info1;
	const uint8_t *shared_info2;
	size_t shared_info1_len, shared_info2_len;

	// decode ContentInfo
	if (cms_content_info_from_der(&cms_type, &enced_content, &enced_content_len,
		&in, &inlen) != 1) {
		error_print();
		return -1;
	}
	if (cms_type != CMS_encrypted_data) {
		error_print();
		return -1;
	}
	if (inlen) {
		error_print();
		return -1;
	}

	// decode EncryptedContentInfo

	sm4_set_decrypt_key(&sm4_key, key);
	if (cms_encrypted_data_decrypt_from_der(&sm4_key,
		content_type, out, outlen,
		&shared_info1, &shared_info1_len,
		&shared_info2, &shared_info2_len,
		&enced_content, &enced_content_len) != 1) {
		error_print();
		return -1;
	}
	if (enced_content_len) {
		error_print();
		return 0;
	}

	if (shared_info1) {
		format_bytes(stderr, 0, 0, "SharedInfo1: ", shared_info1, shared_info1_len);
	}
	if (shared_info2) {
		format_bytes(stderr, 0, 0, "SharedInfo1: ", shared_info2, shared_info2_len);
	}


	return 1;
}


// EnvelopedData，其实这个接口可能不是特别好用
/*
 首先必须考虑到底解密方的证书到底是怎么获得的？如果是多个证书，是从PEM文件中还是从什么方式获得的？

一般来说，我们在用cms命令行加密的时候，命令的输入应该是多个独立的证书文件。
那么对我们来说，我们还是直接将证书

我觉得还是提供多个独立的证书比较符合实际的需求

*/
int cms_seal(const X509_CERTIFICATE *rcpt_certs, size_t rcpt_count,
	const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen)
{
	*outlen = 0;
	if (cms_enveloped_data_encrypt_to_der(
			rcpt_certs, rcpt_count,
			CMS_data, in, inlen,
			NULL, 0, NULL, 0,
			&out, outlen) != 1) {
		error_print();
		return -1;
	}

	return 1;
}

int cms_open(const SM2_KEY *sm2_key, const X509_CERTIFICATE *cert,
	const uint8_t *in, size_t inlen,
	int *content_type, uint8_t *out, size_t *outlen)
{
	const uint8_t *shared_info1;
	const uint8_t *shared_info2;
	size_t shared_info1_len, shared_info2_len;

	if (cms_enveloped_data_decrypt_from_der(
			sm2_key, cert,
			content_type, out, outlen,
			&shared_info1, &shared_info1_len,
			&shared_info2, &shared_info2_len,
			&in, &inlen) != 1) {
		error_print();
		return -1;
	}

	if (inlen) {
		error_print();
		return -1;
	}

	return 1;
}

/*
SM2签名值由于INTEGER编码的问题可能导致编码长度不固定
因此通常情况下无法预知SignerInfo, SignedData的准确编码长度
这个问题可以通过对SM2签名模块进行修改来保证签名长度固定
即使如此，还需要在这个模块中检查signed_data_to_der两次输出长度是相同的
*/
int cms_sign(const SM2_KEY *sign_keys, const X509_CERTIFICATE *sign_certs, size_t sign_count,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	size_t len = 0;
	size_t signed_data_len = 0;
	uint8_t *crls = NULL;
	size_t crls_len = 0;

	size_t len2 = 0;

	if (cms_signed_data_sign_to_der(sign_keys, sign_certs, sign_count,
		CMS_data, in, inlen, crls, crls_len,
		NULL, &signed_data_len) != 1) {
		error_print();
		return -1;
	}
	if (cms_content_type_to_der(CMS_signed_data, NULL, &len) != 1
		|| asn1_explicit_to_der(0, NULL, signed_data_len, NULL, &len) != 1) {
		error_print();
		return -1;
	}

	*outlen = 0;
	if (asn1_sequence_header_to_der(len, &out, outlen) != 1
		|| cms_content_type_to_der(CMS_signed_data, &out, outlen) != 1
		|| asn1_explicit_header_to_der(0, signed_data_len, &out, outlen) != 1
		|| cms_signed_data_sign_to_der(sign_keys, sign_certs, sign_count,
			CMS_data, in, inlen, crls, crls_len,
			&out, &len2) != 1) {
		error_print();
		return -1;
	}

	if (len2 != signed_data_len) {
		error_print();

		error_print_msg("len = %zu\n", len2);
		error_print_msg("signed_data_len = %zu\n", signed_data_len);

		return -1;
	}

	*outlen += signed_data_len;
	return 1;
}

// SignedData 中包含被被签名数据、签名值、签名方的证书，因此是完整的
// 并且包含多个签名值
// 签名验证成功或者失败，应该返回一些信息，比如到底有哪些签名方？或者验签失败是哪个失败了？
// 我们不太容易反馈复杂的错误信息
// 如果是命令行，我们需要输出数据和签名者的信息
// 签名者除了打印名字，还应该把签名者的证书输出出来
// 这里面主要的问题是，是否需要提供部分数据呢？我看是不需要的，因此必须能够获得被签名的数据和签名者的证书
// 因此还是调用from_der比较好吧
// 我们应该把一些相关信息直接打印出来！

int cms_verify(int *content_type, const uint8_t **content, size_t *content_len,
	const uint8_t **certs, size_t *certs_len,
	const uint8_t **crls, size_t *crls_len,
	const uint8_t **signer_infos, size_t *signer_infos_len,
	const uint8_t *in, size_t inlen)
{
	int cms_type;
	const uint8_t *data;
	size_t datalen;

	const uint8_t *dgst_algors;
	size_t dgst_algors_len;


	if (cms_content_info_from_der(&cms_type, &data, &datalen, &in, &inlen) != 1) {
		error_print();
		return -1;
	}
	if (cms_type != CMS_signed_data) {
		error_print();
		return -1;
	}

	if (cms_signed_data_verify_from_der(
		&dgst_algors, &dgst_algors_len,
		content_type, content, content_len,
		certs, certs_len,
		crls, crls_len,
		signer_infos, signer_infos_len,
		&data, &datalen) != 1
		|| asn1_length_is_zero(datalen) != 1) {
		error_print();
		return -1;
	}



	return 1;
}

/*
由于这组接口提供相对简化的接口，因此不是必须的输入都被忽略了
*/
int cms_sign_and_seal(const SM2_KEY *sign_keys,
	const X509_CERTIFICATE *sign_certs, size_t sign_count,
	const X509_CERTIFICATE *rcpt_certs, size_t rcpt_count,
	const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen)
{
	int content_type = CMS_data;
	const uint8_t *shared_info1 = NULL;
	const uint8_t *shared_info2 = NULL;
	size_t shared_info1_len = 0, shared_info2_len = 0;

	const uint8_t *sign_crls = NULL;
	size_t sign_crls_len = 0;

	*outlen = 0;
	cms_signed_and_enveloped_data_sign_encrypt_to_der(
		sign_keys, sign_certs, sign_count,
		sign_crls, sign_crls_len,
		rcpt_certs, rcpt_count,
		content_type, in, inlen,
		shared_info1, shared_info1_len,
		shared_info2, shared_info2_len,
		&out, outlen);

	return 1;
}

/*
1997 int cms_signed_and_enveloped_data_decrypt_verify_from_der(
1998         const SM2_KEY *dec_key, const X509_CERTIFICATE *dec_cert,
1999         const uint8_t **rcpt_infos, size_t *rcpt_infos_len,
2000         const uint8_t **dgst_algors, size_t *dgst_algors_len,
2001         int *content_type,
2002                 int *enc_algor, const uint8_t **enc_iv, size_t *enc_iv_len,
2003                 const uint8_t **enced_content, size_t *enced_content_len,
2004                 const uint8_t **shared_info1, size_t *shared_info1_len,
2005                 const uint8_t **shared_info2, size_t *shared_info2_len,
2006         const uint8_t **certs, size_t *certs_len,
2007         const uint8_t **crls, size_t *crls_len,
2008         const uint8_t **signer_infos, size_t *signer_infos_len)
*/
int cms_open_and_verify(
	const SM2_KEY *sm2_key, const X509_CERTIFICATE *cert,
	const uint8_t *in, size_t inlen,
	int *content_type, uint8_t *out, size_t *outlen)
{

	return -1;
}

