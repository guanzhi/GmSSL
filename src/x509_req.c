/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <gmssl/mem.h>
#include <gmssl/sm2.h>
#include <gmssl/oid.h>
#include <gmssl/asn1.h>
#include <gmssl/error.h>
#include <gmssl/x509.h>
#include <gmssl/pem.h>
#include <gmssl/x509_req.h>
#include <gmssl/x509_ext.h>
#include <gmssl/x509_alg.h>


int x509_request_info_to_der(
	int version,
	const uint8_t *subject, size_t subject_len,
	const SM2_KEY *subject_public_key,
	const uint8_t *attrs, size_t attrs_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (version != X509_version_v1) {
		error_print();
		return -1;
	}
	if (asn1_int_to_der(version, NULL, &len) != 1
		|| asn1_sequence_to_der(subject, subject_len, NULL, &len) != 1
		|| x509_public_key_info_to_der(subject_public_key, NULL, &len) != 1
		|| asn1_implicit_set_to_der(0, attrs, attrs_len, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(version, out, outlen) != 1
		|| asn1_sequence_to_der(subject, subject_len, out, outlen) != 1
		|| x509_public_key_info_to_der(subject_public_key, out, outlen) != 1
		|| asn1_implicit_set_to_der(0, attrs, attrs_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_request_info_from_der(
	int *version,
	const uint8_t **subject, size_t *subject_len,
	SM2_KEY *subject_public_key,
	const uint8_t **attrs, size_t *attrs_len,
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
		|| asn1_sequence_from_der(subject, subject_len, &d, &dlen) != 1
		|| x509_public_key_info_from_der(subject_public_key, &d, &dlen) != 1
		|| asn1_implicit_set_from_der(0, attrs, attrs_len, &d, &dlen) < 0
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	/*
	if (*version != X509_version_v1) {
		error_print();
		return -1;
	}
	*/
	return 1;
}

int x509_request_info_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int ret, ival;
	const uint8_t *p;
	size_t len;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (asn1_int_from_der(&ival, &d, &dlen) != 1) goto err;
	format_print(fp, fmt, ind, "version: %s (%d)\n", x509_version_name(ival), ival);
	if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) goto err;
	x509_name_print(fp, fmt, ind, "subject", p, len);
	if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) goto err;
	x509_public_key_info_print(fp, fmt, ind, "subjectPublicKeyInfo", p, len);
	if ((ret = asn1_implicit_set_from_der(0, &p, &len, &d, &dlen)) < 0) goto err;
	if (ret) x509_attributes_print(fp, fmt, ind, "attributes", p, len);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

static int x509_request_from_der(
	int *version,
	const uint8_t **subject, size_t *subject_len,
	SM2_KEY *subject_public_key,
	const uint8_t **attrs, size_t *attrs_len,
	int *signature_algor,
	const uint8_t **sig, size_t *siglen,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (x509_request_info_from_der(version, subject, subject_len, subject_public_key,
			attrs, attrs_len, &d, &dlen) != 1
		|| x509_signature_algor_from_der(signature_algor, &d, &dlen) != 1
		|| asn1_bit_octets_from_der(sig, siglen, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

static int x509_request_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	const uint8_t *p;
	size_t len;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) goto err;
	x509_request_info_print(fp, fmt, ind, "certificationRequestInfo", p, len);
	if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) goto err;
	x509_signature_algor_print(fp, fmt, ind, "signatureAlgorithm", p, len);
	if (asn1_bit_octets_from_der(&p, &len, &d, &dlen) != 1) goto err;
	format_bytes(fp, fmt, ind, "signature: ", p, len);
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}

int x509_req_sign_to_der(
	int version,
	const uint8_t *subject, size_t subject_len,
	const SM2_KEY *subject_public_key,
	const uint8_t *attrs, size_t attrs_len,
	int signature_algor,
	const SM2_KEY *sign_key, const char *signer_id, size_t signer_id_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	uint8_t *tbs;
	int sig_alg = OID_sm2sign_with_sm3;
	uint8_t sig[SM2_MAX_SIGNATURE_SIZE];
	size_t siglen = SM2_signature_typical_size;

	if (x509_request_info_to_der(version, subject, subject_len, subject_public_key,
			attrs, attrs_len, NULL, &len) != 1
		|| x509_signature_algor_to_der(sig_alg, NULL, &len) != 1
		|| asn1_bit_octets_to_der(sig, siglen, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	if (out && *out) {
		tbs = *out;
	}
	if (x509_request_info_to_der(version, subject, subject_len, subject_public_key,
			attrs, attrs_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	if (out && *out) {
		SM2_SIGN_CTX sign_ctx;
		if (sm2_sign_init(&sign_ctx, sign_key, signer_id, signer_id_len) != 1
			|| sm2_sign_update(&sign_ctx, tbs, *out - tbs) != 1
			|| sm2_sign_finish_fixlen(&sign_ctx, siglen, sig) != 1) {
			gmssl_secure_clear(&sign_ctx, sizeof(sign_ctx));
			error_print();
			return -1;
		}
		gmssl_secure_clear(&sign_ctx, sizeof(sign_ctx));
	}
	if (x509_signature_algor_to_der(sig_alg, out, outlen) != 1
		|| asn1_bit_octets_to_der(sig, siglen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_req_verify(const uint8_t *a, size_t alen, const char *signer_id, size_t signer_id_len)
{
	SM2_KEY public_key;

	if (x509_req_get_details(a, alen,
		NULL, NULL, NULL, &public_key, NULL, NULL, NULL, NULL, NULL) != 1) {
		error_print();
		return -1;
	}
	if (x509_signed_verify(a, alen, &public_key, signer_id, signer_id_len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_req_get_details(const uint8_t *a, size_t alen,
	int *version,
	const uint8_t **subject, size_t *subject_len,
	SM2_KEY *subject_public_key,
	const uint8_t **attributes, size_t *attributes_len,
	int *signature_algor,
	const uint8_t **signature, size_t *signature_len)
{
	int ver;
	const uint8_t *subj;
	size_t subj_len;
	SM2_KEY pub_key;
	const uint8_t *attrs;
	size_t attrs_len;
	int sig_alg;
	const uint8_t *sig;
	size_t siglen;

	if (x509_request_from_der(&ver, &subj, &subj_len, &pub_key, &attrs, &attrs_len,
			&sig_alg, &sig, &siglen, &a, &alen) != 1
		|| asn1_length_is_zero(alen) != 1) {
		error_print();
		return -1;
	}
	if (version) *version = ver;
	if (subject) *subject = subj;
	if (subject_len) *subject_len = subj_len;
	if (subject_public_key) *subject_public_key = pub_key;
	if (attributes) *attributes = attrs;
	if (attributes_len) *attributes_len = attrs_len;
	if (signature_algor) *signature_algor = sig_alg;
	if (signature) *signature = sig;
	if (signature_len) *signature_len = siglen;
	return 1;
}

int x509_req_to_der(const uint8_t *a, size_t alen, uint8_t **out, size_t *outlen)
{
	int ret;
	if (x509_req_get_details(a, alen,
		NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL) != 1) {
		error_print();
		return -1;
	}
	if ((ret = asn1_any_to_der(a, alen, out, outlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	return 1;
}

int x509_req_from_der(const uint8_t **a, size_t *alen, const uint8_t **in, size_t *inlen)
{
	int ret;
	if ((ret = asn1_any_from_der(a, alen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (x509_req_get_details(*a, *alen,
		NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_req_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *a, size_t alen)
{
	const uint8_t *d;
	size_t dlen;

	if (asn1_sequence_from_der(&d, &dlen, &a, &alen) != 1
		|| asn1_length_is_zero(alen) != 1) {
		error_print();
		return -1;
	}
	x509_request_print(fp, fmt, ind, label, d, dlen);
	return 1;
}

int x509_req_to_pem(const uint8_t *a, size_t alen, FILE *fp)
{
	if (x509_req_get_details(a, alen,
		NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL) != 1) {
		error_print();
		return -1;
	}
	if (pem_write(fp, "CERTIFICATE REQUEST", a, alen) <= 0) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_req_from_pem(uint8_t *a, size_t *alen, size_t maxlen, FILE *fp)
{
	if (pem_read(fp, "CERTIFICATE REQUEST", a, alen, maxlen) != 1) {
		error_print();
		return -1;
	}
	if (x509_req_get_details(a, *alen,
		NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL) != 1) {
		error_print();
		return -1;
	}
	return 1;
}
