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
#include <gmssl/asn1.h>
#include <gmssl/aes.h>
#include <gmssl/sm4.h>
#include <gmssl/digest.h>
#include <gmssl/error.h>
#include <gmssl/x509.h>
#include <gmssl/cms.h>


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

// 打印的使用场景可能是没有header的
int cms_issuer_and_serial_number_print(FILE *fp, const uint8_t *in, size_t inlen, int format, int indent)
{
	/*
	int ret;
	const uint8_t *data;
	size_t datalen;
	X509_NAME issuer;
	const uint8_t *serial_number;
	size_t serial_number_len;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	format_print(fp, format, indent, "IssuerAndSerialNumber\n");
	indent += 4;

	if (x509_name_from_der(&issuer, &data, &datalen) != 1) goto bad;
	format_print(fp, format, indent, "issuer :\n");
	x509_name_print(fp, &issuer, format, indent);

	if (asn1_integer_from_der(&serial_number, &serial_number_len, &data, &datalen) != 1) goto bad;
	format_bytes(fp, format, indent, "serialNumber : ", serial_number, serial_number_len);
	return 1;
bad:
	error_print();
	*/
	return -1;
}







static const uint32_t SM2_cms_oid[] = {1,2,156,10197,6,1,4,2};

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

int cms_content_info_to_der(int content_type, const uint8_t *content, size_t content_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (cms_content_type_to_der(content_type, NULL, &len) != 1
		|| asn1_explicit_to_der(0, content, content_len, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| cms_content_type_to_der(content_type, out, outlen) != 1
		|| asn1_explicit_to_der(0, content, content_len, out, outlen) != 1) {
		error_print();
		return -1;
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

int cms_content_info_set_data(uint8_t *content_info, size_t *content_info_len,
	const uint8_t *data, size_t datalen)
{
	size_t len = 0;
	size_t content_len = 0;

	*content_info_len = 0;
	if (cms_content_type_to_der(CMS_data, NULL, &len) != 1
		|| asn1_octet_string_to_der(data, datalen, NULL, &content_len) != 1
		|| asn1_explicit_to_der(0, NULL, content_len, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, &content_info, content_info_len) != 1
		|| cms_content_type_to_der(CMS_data, &content_info, content_info_len) != 1
		|| asn1_explicit_header_to_der(0, content_len, &content_info, content_info_len) != 1
		|| asn1_octet_string_to_der(data, datalen, &content_info, content_info_len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_content_info_get_data(const uint8_t *content_info, size_t content_info_len,
	const uint8_t **data, size_t *datalen)
{
	int ret;
	const uint8_t *p;
	size_t len;
	int content_type;
	const uint8_t *content;
	size_t content_len;

	if (asn1_sequence_from_der(&p, &len, &content_info, &content_info_len) != 1
		|| content_info_len > 0) {
		error_print();
		return ret;
	}
	if (cms_content_type_from_der(&content_type, &p, &len) != 1
		|| asn1_explicit_from_der(0, &content, &content_len, &p, &len) != 1
		|| len > 0
		|| asn1_octet_string_from_der(data, datalen, &content, &content_len) != 1
		|| content_len > 0) {
		error_print();
		return -1;
	}
	return 1;
}

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
	int *digest_algor, uint32_t *nodes, size_t *nodes_count,
	const uint8_t **authed_attrs, size_t *authed_attrs_len,
	int *sign_algor, uint32_t *sign_algor_nodes, size_t *sign_algor_nodes_count,
	const uint8_t **enced_digest, size_t *enced_digest_len,
	const uint8_t **unauthed_attrs, size_t *unauthed_attrs_len,
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
		|| cms_issuer_and_serial_number_from_der(issuer, serial_number, serial_number_len, &data, &datalen) != 1
		|| x509_digest_algor_from_der(digest_algor, nodes, nodes_count, &data, &datalen) != 1
		|| asn1_implicit_set_from_der(0, authed_attrs, authed_attrs_len, &data, &datalen) < 0
		|| x509_signature_algor_from_der(sign_algor, /*sign_algor_nodes, &sign_algor_nodes_count,*/ &data, &datalen) != 1
		|| asn1_octet_string_from_der(enced_digest, enced_digest_len, &data, &datalen) != 1
		|| asn1_implicit_set_from_der(1, unauthed_attrs, unauthed_attrs_len, &data, &datalen) < 0
		|| datalen) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_signer_info_print(FILE *fp, const uint8_t *a, size_t alen, int format, int indent)
{
	/*
	int ret;
	const uint8_t *data;
	size_t datalen;
	int version;
	X509_NAME issuer;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	format_print(fp, format, indent, "SignerInfo:\n");
	indent += 4;

	if (asn1_int_from_der(&version, &data, &datalen) != 1) goto bad;
	format_print(fp, format, indent, "Version: %d\n", version);

	if (cms_issuer_and_serial_number_from_der(&issuer, &serial_number, &serial_number_len, &data, &datalen) != 1) goto bad;
	cms_issuer_and_serial_number_print(); // 这个不能这么弄啊！

	*/
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

int cms_signer_info_verify_from_der(
	const SM2_KEY *sm2_key, const SM3_CTX *sm3_ctx,
	X509_NAME *issuer, const uint8_t **serial_number, size_t *serial_number_len,
	int *digest_algor, uint32_t *digest_algor_nodes, size_t *digest_algor_nodes_count,
	const uint8_t **authed_attrs, size_t *authed_attrs_len,
	int *sign_algor, uint32_t *sign_algor_nodes, size_t *sign_algor_nodes_count,
	const uint8_t **unauthed_attrs, size_t *unauthed_attrs_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	SM3_CTX ctx;
	uint8_t dgst[32];
	const uint8_t *sig;
	size_t sig_len;

	if (cms_signer_info_from_der(issuer, serial_number, serial_number_len,
		digest_algor, digest_algor_nodes, digest_algor_nodes_count,
		authed_attrs, authed_attrs_len,
		sign_algor, sign_algor_nodes, sign_algor_nodes_count,
		&sig, &sig_len,
		unauthed_attrs, unauthed_attrs_len,
		in, inlen) != 1) {
		error_print();
		return -1;
	}
	if (*digest_algor != OID_sm3) {
		error_print();
		return -1;
	}
	if (*sign_algor != OID_sm2sign_with_sm3) {
		error_print();
		return -1;
	}

	memcpy(&ctx, sm3_ctx, sizeof(SM3_CTX));
	if (*authed_attrs) {
		uint8_t header[8];
		uint8_t *p = header;
		size_t header_len = 0;
		asn1_set_header_to_der(*authed_attrs_len, &p, &header_len);
		sm3_update(&ctx, header, header_len);
		sm3_update(&ctx, *authed_attrs, *authed_attrs_len);
	}
	sm3_finish(&ctx, dgst);

	if ((ret = sm2_verify(sm2_key, dgst, sig, sig_len)) != 1) {
		error_print();
		return -1;
	}
	return ret;
}

int cms_signed_data_to_der(
	const int *digest_algors, const size_t digest_algors_count,
	const int content_type, const uint8_t *content, const size_t content_len,
	const X509_CERTIFICATE *certs, size_t certs_count,
	const uint8_t **crls, const size_t *crls_lens, const size_t crls_count,
	const uint8_t **signer_infos, size_t *signer_infos_lens, size_t signer_infos_count,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	size_t digest_algors_len = 0;
	size_t certs_len = 0;
	size_t crls_len = 0;
	size_t signer_infos_len = 0;
	int i;

	/*
	for (i = 0; i < digest_algors_count; i++)
		x509_digest_algor_to_der(digest_algors[i], NULL, &digest_algors_len);
	for (i = 0; i < certs_count; i++)
		x509_certificate_to_der(&certs[i], NULL, &certs_len);
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

	if (asn1_sequence_to_der(len, out, outlen) != 1
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


	if (asn1_set_to_der(signer_infos_len, out, outlen) != 1) {
	}
	for (i = 0; i < signer_infos_count; i++) {
		asn1_data_to_der(signer_infos[i], signer_infos_lens[i], out, outlen);
	}

	*/
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
		|| cms_content_info_from_der(content_type, content, content_len, &data, &datalen) != 1
		|| asn1_implicit_set_from_der(0, certs, certs_len, &data, &datalen) < 0
		|| asn1_implicit_set_from_der(1, crls, crls_len, &data, &datalen) < 0
		|| asn1_set_from_der(signer_infos, signer_infos_len, &data, &datalen) != 1
		|| datalen) {
		error_print();
		return -1;
	}
	if (version != CMS_version) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_signed_data_print(FILE *fp, const uint8_t *a, size_t alen, int format, int indent)
{
	const uint8_t *data;
	size_t datalen;

	int version;
	int algor;
	uint32_t nodes[32];
	size_t nodes_count;
	const uint8_t *certs;
	size_t certslen;
	const uint8_t *crls;
	size_t crlslen;
	const uint8_t *signer_infos;
	size_t signer_infos_len;

	if (asn1_sequence_from_der(&data, &datalen, &a, &alen) != 1) {
		error_print();
		return -1;
	}

	if (asn1_int_from_der(&version, &data, &datalen) != 1) goto bad;
	format_print(fp, format, indent, "Version : %d\n", version);

	if (x509_digest_algor_from_der(&algor, nodes, &nodes_count, &data, &datalen) != 1) goto bad;
	format_print(fp, format, indent, "DigestAlgorithm : %s\n", x509_digest_algor_name(algor));

	if (asn1_implicit_sequence_from_der(0, &certs, &certslen, &data, &datalen) < 0) goto bad;

	if (asn1_implicit_sequence_from_der(1, &crls, &crlslen, &data, &datalen) < 0) goto bad;

	if (asn1_sequence_from_der(&signer_infos, &signer_infos_len, &data, &datalen) != 1) goto bad;


bad:
	error_print();

	return -1;
}

int cms_signed_data_sign_to_der(const SM2_KEY *sign_keys,
	const X509_CERTIFICATE *sign_certs, size_t sign_count,
	int content_type, const uint8_t *content, size_t content_len,
	const uint8_t **crls, size_t *crls_lens, size_t crls_count,
	uint8_t **out, size_t *outlen)
{
	uint8_t *p;
	size_t len = 0;
	uint8_t digest_algors[16];
	size_t digest_algors_len = 0;
	size_t sign_certs_len = 0;
	size_t certs_len = 0;
	size_t crls_len = 0;
	size_t signer_infos_len = 0;
	uint8_t sigs[sign_count][SM2_MAX_SIGNATURE_SIZE];
	size_t siglens[sign_count];
	int i;

	p = digest_algors;
	x509_digest_algor_to_der(OID_sm3, &p, &digest_algors_len);
	for (i = 0; i < sign_count; i++) {
		if (x509_certificate_to_der(&sign_certs[i], NULL, &sign_certs_len) != 1) {
			error_print();
			return -1;
		}
	}
	for (i = 0; i < crls_count; i++) {
		crls_len += crls_lens[i];
	}

	for (i = 0; i < sign_count; i++) {
		const X509_CERTIFICATE *cert = &sign_certs[i];
		const X509_NAME *issuer = &cert->tbs_certificate.issuer;
		const uint8_t *serial_number = cert->tbs_certificate.serial_number;
		size_t serial_number_len = cert->tbs_certificate.serial_number_len;

		SM2_SIGN_CTX sign_ctx;
		sm2_sign_init(&sign_ctx, &sign_keys[i], SM2_DEFAULT_ID);
		sm2_sign_update(&sign_ctx, content, content_len);
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
		if (asn1_implicit_set_header_to_der(1, crls_len, out, outlen) != 1) {
			error_print();
			return -1;
		}
		for (i = 0; i < crls_count; i++) {
			asn1_data_to_der(crls[i], crls_lens[i], out, outlen);
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

int cms_signed_data_verify_from_der(const uint8_t *signed_data, size_t signed_data_len)
{
	int version;
	int content_type;
	const uint8_t *digest_algors;
	const uint8_t *content;
	const uint8_t *certs;
	const uint8_t *crls;
	const uint8_t *signer_infos;
	size_t digest_algors_len;
	size_t content_len;
	size_t certs_len;
	size_t crls_len;
	size_t signer_infos_len;

	/*
	if (asn1_sequence_from_der(&data, &datalen, &signed_data, &signed_data_len) != 1
		|| signed_data_len > 0) {
		error_print();
		return -1;
	}
	if (asn1_int_from_der(&version, &data, &datalen) != 1
		|| asn1_set_from_der(&digest_algors, &digest_algors_len, &data, &datalen) != 1
		|| cms_content_info_from_der(&content_type, &content, &content_len, &data, &datalen) != 1
		|| asn1_implicit_set_from_der(0, &certs, &certs_len, &data, &datalen) < 0
		|| asn1_implicit_set_from_der(1, &crls, &crls_len, &data, &datalen) < 0
		|| asn1_set_from_der(&signer_infos, &signer_infos_len, &data, &datalen) != 1) {
		error_print();
		return -1;
	}

	len = signer_infos_len;

	while (len > 0) {
		cms_signer_info_from_der();


		cms_signer_info_match();

		cms_signer_info_verify();

	}
	*/

	return -1;
}

int cms_sign(const SM2_KEY *sign_keys,
	const X509_CERTIFICATE *sign_certs, size_t sign_count,
	int content_type, const uint8_t *content, size_t content_len,
	const uint8_t **crls, size_t *crls_lens, size_t crls_count,
	uint8_t *content_info, size_t *content_info_len)
{
	size_t len = 0;
	size_t signed_data_len = 0;

	if (cms_signed_data_sign_to_der(sign_keys, sign_certs, sign_count,
		content_type, content, content_len, crls, crls_lens, crls_count,
		NULL, &signed_data_len) != 1) {
		error_print();
		return -1;
	}
	if (cms_content_type_to_der(CMS_signed_data, NULL, &len) != 1
		|| asn1_explicit_to_der(0, NULL, signed_data_len, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, &content_info, content_info_len) != 1
		|| cms_content_type_to_der(CMS_signed_data, &content_info, content_info_len) != 1
		|| asn1_explicit_header_to_der(0, signed_data_len, &content_info, content_info_len) != 1
		|| cms_signed_data_sign_to_der(sign_keys, sign_certs, sign_count,
			content_type, content, content_len, crls, crls_lens, crls_count,
			&content_info, content_info_len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}


int cms_verify(int *content_type, const uint8_t **content, size_t *content_len,
	const uint8_t *content_info, size_t content_info_len)
{
	return -1;
}

int cms_content_info_print(FILE *fp, const uint8_t *a, size_t alen, int format, int indent)
{
	int ret;
	int oid;
	const uint8_t *data;
	size_t datalen;
	uint32_t nodes[32];
	size_t nodes_count;
	const uint8_t *content;
	size_t content_len;

	format_print(fp, format, indent, "ContentInfo:\n");
	indent += 4;
	if ((ret = asn1_sequence_from_der(&data, &datalen, &a, &alen)) != 1) {
		error_print();
		return -1;
	}

	if (cms_content_type_from_der(&oid, &data, &datalen) != 1) goto bad;
	format_print(fp, format, indent, "Type : %s\n", cms_content_type_name(oid));
	if (asn1_explicit_from_der(0, &content, &content_len, &data, &datalen) != 1) goto bad;

	switch (oid) {
	case CMS_data: return cms_data_print(fp, content, content_len, format, indent);
	case CMS_signed_data: return cms_signed_data_print(fp, content, content_len, format, indent);
	case CMS_enveloped_data:
	case CMS_signed_and_enveloped_data:
	case CMS_encrypted_data:
	case CMS_key_agreement_info:
		break;
	}
	return 1;

bad:
	error_print();
	return -1;
}



#if 0

int cms_recipient_info_to_der(const X509_NAME *issuer,
	const uint8_t *serial_number, size_t serial_number_len,
	const uint8_t *enced_key, size_t enced_key_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (asn1_int_to_der(CMS_version, NULL, &len) != 1
		|| cms_issuer_and_serial_number_to_der(issuer, serial_number, serial_number_len, NULL, &len) != 1
		|| x509_key_encryption_algor_to_der(OID_sm2encrypt, NULL, &len) != 1
		|| asn1_octet_string_to_der(enced_key, enced_key_len, NULL, &len) != 1) {
		error_print();
		return -1;
	}
	if (asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(CMS_version, out, &outlen) != 1
		|| cms_issuer_and_serial_number_to_der(issuer, serial_number, serial_number_len, out, &outlen) != 1
		|| x509_key_encryption_algor_to_der(OID_sm2encrypt, out, &outlen) != 1
		|| asn1_octet_string_to_der(enced_key, enced_key_len, out, &outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_recipient_info_from_der(X509_NAME *issuer,
	const uint8_t **serial_number, size_t *serial_number_len,
	const uint8_t **enced_key, size_t *enced_key_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_int_from_der(&version, &data, &datalen) != 1
		|| cms_issuer_and_serial_number_from_der(issuer, serial_number, serial_number_len, &data, &datalen) != 1
		|| x509_public_key_algor_from_der(kenc_algor, enc_algor_nodes, enc_algor_nodes, &data, &datalen) != 1
		|| asn1_octet_string_from(enced_key, enced_key_len, &data, &datalen) != 1
		|| datalen) {
		error_print();
		return -1;
	}
	if (version != CMS_version) {
		error_print();
		return -1;
	}

	return -1;
}

int cms_recipient_info_print(FILE *fp, const uint8_t *a, size_t alen, int format, int indent)
{
	return -1;
}

int sm2_recipient_info_encrypt_to_der(const SM2_KEY *sm2_key,
	const X509_NAME *issuer, const uint8_t *serial_number, size_t serial_number_len,
	const uint8_t *key, size_t keylen,
	uint8_t *rcpt_info, size_t *rcpt_info_len)
{
	size_t len = 0;
	uint8_t buf[keylen + 256];
	size_t buflen;

	sm2_encrypt(sm2_key, key, keylen, buf, &buflen);

	*rcpt_info_len = 0;
	cms_recipient_info_to_der(issuer, serial_number, serial_number_len,
		buf, buflen, &rcpt_info, rcpt_info_len);

	return 1;
}

int sm2_recipient_info_decrypt_from_der(const SM2_KEY *sm2_key,
	X509_NAME *issuer, const uint8_t **serial_number, size_t *serial_number_len,
	uint8_t *key, size_t *keylen,
	const uint8_t **in, size_t *inlen)
{
	if (cms_recipient_info_from_der(issuer, serial_number, serial_number_len,
		&enced_key, &enced_key_len, &rcpt_info, &rcpt_info_len) != 1
		|| rcpt_info_len) {
		error_print();
		return -1;
	}

	sm2_decrypt(sm2_key, enced_key, enced_key_len, key, keylen);
	return -1;
}

int cms_enced_content_info_to_der(int enc_algor, const uint8_t enc_iv[16],
	int content_type, const uint8_t *enced_content, size_t enced_content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (cms_content_type_to_der(content_type, NULL, &len) != 1
		|| x509_encryption_algor_to_der(enc_algor, enc_iv, NULL, &len) != 1
		|| asn1_implicit_octet_string_to_der(0, enced_content, enced_content_len, NULL, &len) < 0
		|| asn1_implicit_octet_string_to_der(1, shared_info1, shared_info1_len, NULL, &len) < 0
		|| asn1_implicit_octet_string_to_der(2, shared_info2, shared_info2_len, NULL, &len) < 0) {
		error_print();
		return -1;
	}
	if (asn1_sequence_header_to_der(len, out, outlen) != 1
		|| cms_content_type_to_der(content_type, out, outlen) != 1
		|| x509_encryption_algor_to_der(enc_algor, enc_iv, out, outlen) != 1
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
	int *enc_algor, uint32_t *enc_algor_nodes, size_t *enc_algor_nodes_count,
	const uint8_t **enc_iv, size_t *enc_iv_len,
	const uint8_t **enced_content, size_t *enced_content_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len,
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
		|| x509_encryption_algor_from_der(enc_algor, enc_algor_nodes, enc_algor_nodes_count,
			enc_iv, enc_iv_len, &data, &datalen) != 1
		|| asn1_implicit_octet_string_from_der(0, enced_content, enced_content_len, &data, &datalen) < 0
		|| asn1_implicit_octet_string_from_der(1, shared_info1, shared_info1_len, &data, &datalen) < 0
		|| asn1_implicit_octet_string_from_der(1, shared_info2, shared_info2_len, &data, &datalen) < 0
		|| datalen) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_enced_content_info_print(FILE *fp, const uint8_t *a, size_t alen, int format, int indent)
{
	return -1;
}

int cms_enced_content_info_encrypt_to_der(const SM4_KEY *sm4_key, const uint8_t iv[16],
	int content_type, const uint8_t *content, size_t content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	uint8_t *enced_content_info, size_t *enced_content_info_len)
{
	uint8_t enced_content[content_len + 256];
	size_t enced_content_len;

	if (sm4_cbc_padding_encrypt(sm4_key, iv, content, content_len,
		enced_content, &enced_content_len) != 1) {
		error_print();
		return -1;
	}

	*enced_content_info_len = 0;
	if (cms_enced_content_info_to_der(OID_sm4_cbc, iv,
		content_type, enced_content, enced_content_len,
		shared_info1, shared_info1_len,
		shared_info2, shared_info2_len,
		&enced_content_info, enced_content_info_len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_enced_content_info_decrypt_from_der(const SM4_KEY *sm4_key,
	const uint8_t *enced_content_info, size_t enced_content_info_len,
	int *content_type, uint8_t *content, size_t *content_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len)
{
	int enc_algor;
	uint32_t enc_algor_nodes[32];
	size_t enc_algor_nodes_count;
	const uint8_t *enc_iv;
	size_t enc_iv_len;
	const uint8_t *enced_content;
	size_t enced_content_len;

	if (cms_enced_content_info_from_der(content_type,
		&enc_algor, enc_algor_nodes, &enc_algor_nodes_count,
		&enc_iv, &enc_iv_len,
		&enced_content, &enced_content_len,
		shared_info1, shared_info1_len,
		shared_info2, shared_info2_len,
		&enced_content_info, &enced_content_info_len) != 1
		|| enced_content_info_len) {
		error_print();
		return -1;
	}
	if (sm4_cbc_padding_decrypt(sm4_key, enc_iv, enced_content, enced_content_len,
		content, content_len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_enveloped_data_to_der()
{
}

int cms_enveloped_data_from_der(const uint8_t **rcpt_infos, size_t *rcpt_infos_len,
	int *content_type,
	int *enc_algor, uint32_t *enc_algor_nodes, size_t *enc_algor_nodes_count,
	const uint8_t **enc_iv, size_t *enc_iv_len,
	const uint8_t **enced_content, size_t *enced_content_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_int_from_der(&version, &data, &datalen) != 1
		|| asn1_set_from_der(rcpt_infos, rcpt_infos_len, &data, &datalen) != 1
		|| asn1_type_from_der(enced_content_info, enced_content_info_len, &data, &datalen) != 1 //FIXME:			
		|| datalen > 0) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_enveloped_data_print(FILE *fp, const uint8_t *a, size_t alen, int format, int indent)
{
	return -1;
}

int cms_enveloped_data_encrypt_to_der(const X509_CERTIFICATE *rcpt_certs, size_t rcpt_count,
	int content_type, const uint8_t *content, size_t content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	uint8_t *enveloped_data, size_t *enveloped_data_len)
{
	size_t len = 0;
	SM4_KEY sm4_key;
	uint8_t enc_key[16];
	uint8_t enc_iv[16];
	uint8_t enced_key[rcpt_count][256 + 16];
	uint8_t enced_content_info[content_len + 512];
	size_t enced_content_info_len;

	rand_bytes(enc_key, 16);
	rand_bytes(enc_iv, 16);

	for (i = 0; i < rcpt_count; i++) {
		const SM2_KEY *sm2_key = x509_certificate_get_public_key(rcpt_certs[i]);
		sm2_encrypt(sm2_key, enc_key, 16, enced_key[i], enced_key_len[i]);
	}

	for (i = 0; i < rcpt_count; i++) {
		x509_certificate_get_recipient_info(rcpt_cert,
			&issuer,
			&serial_number, &serial_number_len,
			&sm2_key);

		cms_recipient_info_encrypt_to_der(issuer,
			serial_number, serial_number_len,
			enced_key, enced_key_len,
			NULL, &rcpt_infos_len);
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

	if (asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(CMS_version, out, outlen) != 1
		|| asn1_set_header_to_der(rcpt_infos_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	for (i = 0; i < rcpt_count; i++) {
		if (cms_recipient_info_encrypt_to_der(&sm2_key, issuer,
			serial_number, serial_number_len,
			enc_key, sizeof(enc_key), out, outlen) != 1) {
			error_print();
			return -1;
		}
	}
	if (cms_enced_content_info_encrypt_to_der(&sm4_key, enc_iv,
		content_type, content, content_len,
		shared_info1, shared_info1_len,
		shared_info2, shared_info2_len,
		out, &outlen) != 1) {
		error_print();
		return -1;
	}

	return 1;
}

int cms_enveloped_data_decrypt_from_der(const SM2_KEY *sm2_key, const X509_CERTIFICATE *cert,
	const uint8_t *enveloped_data, size_t enveloped_data_len,
	int *content_type, uint8_t *content, size_t *content_len)
{
	const uint8_t *rcpt_infos;
	size_t rcpt_infos_len;
	int enc_algor;
	uint32_t enc_algor_nodes[32];
	size_t enc_algor_nodes_count;
	const uint8_t *enced_content;
	size_t enced_content_len;
	const uint8_t *shared_info1;
	size_t shared_info1_len;
	const uint8_t *shared_info2;
	size_t shared_info2_len;
	uint8_t enc_key[64];
	size_t enc_key_len;

	if (cms_enveloped_data_from_der(&rcpt_infos, &rcpt_infos_len,
		content_type, &enc_algor, enc_algor_nodes, &enc_algor_nodes_count,
		&enc_iv, &enc_iv_len,
		&enced_content, &enced_content_len, &shared_info1, &shared_info1_len,
		&shared_info2, &shared_info2_len, &enveloped_data, &enveloped_data_len) != 1
		|| enced_content_info_len > 0) {
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
		X509_NAME issuer;
		const uint8_t *serial_number;
		size_t serial_number_len;
		const uint8_t *enced_key;
		size_t enced_key_len;

		if (cms_recipient_info_from_der(&issuer, &serial_number, &serial_number_len
			&enced_key, &enced_key_len, &rcpt_infos, &rcpt_infos_len) != 1) {
			error_print();
			return -1;
		}
		if (cms_issuer_and_serial_number_match_certificate(&issuer,
			serial_number, serial_number_len, cert) != 1) {
			break;
		}
		if (sm2_decrypt(sm2_key, enced_key, enced_key_len, enc_key, &enc_key_len) != 1) {
			error_print();
			return -1;
		}
	}

	sm4_set_decrypt_key(&sm4_key, enc_key);
	if (sm4_cbc_paddnig_decrypt(&sm4_key, enc_iv, enced_content, enced_content_len,
		content, content_len) != 1) {
		error_print();
		return -1;
	}

	return -1;
}

int cms_signed_and_enveloped_data_to_der()
{
}

int cms_signed_and_enveloped_data_from_der()
{
}

int cms_signed_and_enveloped_data_print()
{
}

int cms_signed_and_enveloped_data_sign_encrypt_to_der(
	const int *digest_algors, const size_t digset_algors_count,
	const X509_CERTIFICATE *sign_certs, size_t sign_count,
	const uint8_t **crls, const size_t *crls_lens, const size_t crls_count,
	const uint8_t **signer_infos, size_t *signer_infos_lens, size_t signer_infos_count,
	const X509_CERTIFICATE *rcpt_certs, size_t rcpt_count,
	int content_type, const uint8_t *content, size_t content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	uint8_t **out, size_t *outlen)
{

	size_t len = 0;
	SM4_KEY sm4_key;
	uint8_t enc_key[16];
	uint8_t enc_iv[16];
	uint8_t enced_key[rcpt_count][256 + 16];
	uint8_t enced_content_info[content_len + 512];
	size_t enced_content_info_len;

	rand_bytes(enc_key, 16);
	rand_bytes(enc_iv, 16);

	for (i = 0; i < rcpt_count; i++) {
		const SM2_KEY *sm2_key = x509_certificate_get_public_key(rcpt_certs[i]);
		sm2_encrypt(sm2_key, enc_key, 16, enced_key[i], enced_key_len[i]);
	}

	for (i = 0; i < rcpt_count; i++) {
		x509_certificate_get_recipient_info(rcpt_cert,
			&issuer,
			&serial_number, &serial_number_len,
			&sm2_key);

		cms_recipient_info_encrypt_to_der(issuer,
			serial_number, serial_number_len,
			enced_key, enced_key_len,
			NULL, &rcpt_infos_len);
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

	if (asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(CMS_version, out, outlen) != 1
		|| asn1_set_header_to_der(rcpt_infos_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	for (i = 0; i < rcpt_count; i++) {
		if (cms_recipient_info_encrypt_to_der(&sm2_key, issuer,
			serial_number, serial_number_len,
			enc_key, sizeof(enc_key), out, outlen) != 1) {
			error_print();
			return -1;
		}
	}
	if (cms_enced_content_info_encrypt_to_der(&sm4_key, enc_iv,
		content_type, content, content_len,
		shared_info1, shared_info1_len,
		shared_info2, shared_info2_len,
		out, &outlen) != 1) {
		error_print();
		return -1;
	}

	return 1;
}

int cms_signed_and_enveloped_data_decrypt_verify_from_der()
{
	return -1;
}















int cms_enced_data_to_der(int enc_algor, const uint8_t enc_iv[16],
	int content_type, const uint8_t *enced_content, size_t enced_content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (asn1_int_to_der(CMS_version, NULL, &len) != 1
		|| cms_enced_content_info_to_der(enc_algor, enc_iv,
			content_type, enced_content, enced_content_len
			shared_info1, shared_info1_len,
			shared_info2, shared_info2_len,
			NULL, &len) != 1) {
		error_print();
		return -1;
	}
	if (asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(CMS_version, out, outlen) != 1
		|| cms_enced_content_info_to_der(enc_algor, enc_iv,
			content_type, enced_content, enced_content_len
			shared_info1, shared_info1_len,
			shared_info2, shared_info2_len,
			out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int cms_enced_data_from_der(
	int *content_type,
	int *enc_algor, uint32_t *enc_algor_nodes, size_t *enc_algor_nodes_count,
	const uint8_t **enc_iv, size_t *enc_iv_len,
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
			enc_algor, enc_algor_nodes, enc_algor_nodes_count,
			enc_iv, enc_iv_len,
			enced_content, enced_content_len,
			shared_info1, shared_info1_len,
			shared_info2, shared_info2_len,
			&data, &datalen) != 1
		|| datalen > 0) {
		error_print();
		return -1;
	}
	if (version != CMS_version) {
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
		|| cms_encrypted_content_info_to_der(sm4_key, iv,
			content_type, content, content_len,
			shared_info1, shared_info1_len,
			shared_info2, shared_info2_len,
			NULL, &len) != 1) {
		error_print();
		return -1;
	}
	if (asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(CMS_version, out, outlen) != 1
		|| cms_encrypted_content_info_to_der(sm4_key, iv,
			content_type, content, content_len,
			shared_info1, shared_info1_len,
			shared_info2, shared_info2_len,
			out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

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
		|| asn1_int_to_der(CMS_version, out, &outlen) != 1
		|| sm2_public_key_info_to_der(pub_key, out, &outlen) != 1
		|| x509_certificate_to_der(cert, out, &outlen) != 1
		|| asn1_octet_string_to_der(user_id, user_id_len, out, &outlen) != 1) {
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

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_int_from_der(&version, &data, &datalen) != 1
		|| sm2_public_key_info_from_der(pub_key, &data, &datalen) != 1
		|| x509_certificate_from_der(cert, &data, &datalen) != 1
		|| asn1_octet_string_from_der(user_id, user_id_len, &data, &datalen) != 1
		|| datalen > 0) {
		error_print();
		return -1;
	}
	return 1;
}


#endif
