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
#include <gmssl/oid.h>
#include <gmssl/x509.h>
#include <gmssl/x509_crl.h>
#include <gmssl/x509_alg.h>
#include <gmssl/x509_ext.h>
#include <gmssl/error.h>

static const char *x509_crl_reason_names[] = {
	"unspecified",
	"keyCompromise",
	"cACompromise",
	"affiliationChanged",
	"superseded",
	"cessationOfOperation",
	"certificateHold",
	"notAssigned",
	"removeFromCRL",
	"privilegeWithdrawn",
	"aACompromise",
};

static const size_t x509_crl_reason_names_count =
	sizeof(x509_crl_reason_names)/sizeof(x509_crl_reason_names[0]);

const char *x509_crl_reason_name(int reason)
{
	if (reason < 0 || reason >= x509_crl_reason_names_count) {
		error_print();
		return NULL;
	}
	return x509_crl_reason_names[reason];
}

int x509_crl_reason_from_name(int *reason, const char *name)
{
	int i;
	for (i = 0; i < x509_crl_reason_names_count; i++) {
		if (strcmp(name, x509_crl_reason_names[i]) == 0) {
			*reason = i;
			return 1;
		}
	}
	return 0;
}

int x509_crl_reason_to_der(int reason, uint8_t **out, size_t *outlen)
{
	if (reason >= 0 && !x509_crl_reason_name(reason)) {
		error_print();
		return -1;
	}
	return asn1_enumerated_to_der(reason, out, outlen);
}

int x509_crl_reason_from_der(int *reason, const uint8_t **in, size_t *inlen)
{
	return asn1_enumerated_from_der(reason, in, inlen);
}


static uint32_t oid_ce_crl_reasons[] = { oid_ce,21 };
static uint32_t oid_ce_invalidity_date[] = { oid_ce,24 };
static uint32_t oid_ce_certificate_issuer[] = { oid_ce,29 };

static const ASN1_OID_INFO x509_crl_entry_exts[] = {
	{ OID_ce_crl_reasons, "CRLReasons", oid_ce_crl_reasons, sizeof(oid_ce_crl_reasons)/sizeof(int) },
	{ OID_ce_invalidity_date, "InvalidityDate", oid_ce_invalidity_date, sizeof(oid_ce_invalidity_date)/sizeof(int) },
	{ OID_ce_certificate_issuer, "CertificateIssuer", oid_ce_certificate_issuer, sizeof(oid_ce_certificate_issuer)/sizeof(int) },
};

static const int x509_crl_entry_exts_count =
	sizeof(x509_crl_entry_exts)/sizeof(x509_crl_entry_exts[0]);

const char *x509_crl_entry_ext_id_name(int oid)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_oid(x509_crl_entry_exts, x509_crl_entry_exts_count, oid))) {
		error_print();
		return NULL;
	}
	return info->name;
}

int x509_crl_entry_ext_id_from_name(const char *name)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_name(x509_crl_entry_exts, x509_crl_entry_exts_count, name))) {
		error_print();
		return OID_undef;
	}
	return info->oid;
}

int x509_crl_entry_ext_id_to_der(int oid, uint8_t **out, size_t *outlen)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_oid(x509_crl_entry_exts, x509_crl_entry_exts_count, oid))) {
		error_print();
		return -1;
	}
	if (asn1_object_identifier_to_der(info->nodes, info->nodes_cnt, out,  outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_crl_entry_ext_id_from_der(int *oid, const uint8_t **in, size_t *inlen)
{
	int ret;
	const ASN1_OID_INFO *info;

	if ((ret = asn1_oid_info_from_der(&info, x509_crl_entry_exts, x509_crl_entry_exts_count, in, inlen)) != 1) {
		if (ret < 0) error_print();
		else *oid = -1;
		return ret;
	}
	*oid = info->oid;
	return 1;
}

int x509_crl_entry_exts_add_reason(uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical, int reason)
{
	int oid = OID_ce_crl_reasons;
	size_t curlen = *extslen;
	uint8_t val[16];
	uint8_t *p = val;
	size_t vlen = 0;

	if (x509_crl_reason_to_der(reason, &p, &vlen) != 1
		|| x509_ext_to_der(oid, critical, val, vlen, NULL, &curlen) != 1
		|| asn1_length_le(curlen, maxlen) != 1
		|| x509_ext_to_der(oid, critical, val, vlen, &exts, extslen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_crl_entry_exts_add_invalidity_date(uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical, time_t tv)
{
	int oid = OID_ce_invalidity_date;
	size_t curlen = *extslen;
	uint8_t val[16];
	uint8_t *p = val;
	size_t vlen = 0;

	if (asn1_generalized_time_to_der(tv, &p, &vlen) != 1
		|| x509_ext_to_der(oid, critical, val, vlen, NULL, &curlen) != 1
		|| asn1_length_le(curlen, maxlen) != 1
		|| x509_ext_to_der(oid, critical, val, vlen, &exts, extslen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_crl_entry_exts_add_certificate_issuer(uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical, const uint8_t *d, size_t dlen)
{
	int oid = OID_ce_certificate_issuer;
	return x509_exts_add_sequence(exts, extslen, maxlen, oid, critical, d, dlen);
}

int x509_crl_entry_exts_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	error_print();				
	return -1;
}

int x509_revoked_cert_to_der(
	const uint8_t *serial, size_t serial_len,
	time_t revoke_date,
	const uint8_t *entry_exts, size_t entry_exts_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (asn1_integer_to_der(serial, serial_len, NULL, &len) != 1
		|| asn1_generalized_time_to_der(revoke_date, NULL, &len) != 1
		|| asn1_sequence_to_der(entry_exts, entry_exts_len, NULL, &len) < 0
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_integer_to_der(serial, serial_len, out, outlen) != 1
		|| asn1_generalized_time_to_der(revoke_date, out, outlen) != 1
		|| asn1_sequence_to_der(entry_exts, entry_exts_len, out, outlen) < 0) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_revoked_cert_from_der(
	const uint8_t **serial, size_t *serial_len,
	time_t *revoke_date,
	const uint8_t **entry_exts, size_t *entry_exts_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_integer_from_der(serial, serial_len, &d, &dlen) != 1
		|| asn1_generalized_time_from_der(revoke_date, &d, &dlen) != 1
		|| asn1_sequence_from_der(entry_exts, entry_exts_len, &d, &dlen) < 0
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_revoked_cert_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int ret;
	const uint8_t *p;
	size_t len;
	time_t tv;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (asn1_integer_from_der(&p, &len, &d, &dlen) != 1) goto err;
	format_bytes(fp, fmt, ind, "userCertificate", p, len);
	if (asn1_generalized_time_from_der(&tv, &d, &dlen) != 1) goto err;
	format_print(fp, fmt, ind, "revocationDate: %s\n", ctime(&tv));
	if ((ret = asn1_sequence_from_der(&p, &len, &d, &dlen)) < 0) goto err;
	if (ret) x509_crl_entry_exts_print(fp, fmt, ind, "crlEntryExtensions", p, len); // 这里需要一个函数能够处理		
	if (asn1_length_is_zero(dlen) != 1) goto err;
	return 1;
err:
	error_print();
	return -1;
}


static uint32_t oid_ce_authority_key_identifier[] = { oid_ce,35 };
static uint32_t oid_ce_issuer_alt_name[] = { oid_ce,18 };
static uint32_t oid_ce_crl_number[] = { oid_ce,20 };
static uint32_t oid_ce_delta_crl_indicator[] = { oid_ce,27 };
static uint32_t oid_ce_issuing_distribution_point[] = { oid_ce,28 };

static const ASN1_OID_INFO x509_crl_exts[] = {
	{ OID_ce_authority_key_identifier, "AuthorityKeyIdentifier", oid_ce_authority_key_identifier, sizeof(oid_ce_authority_key_identifier)/sizeof(int) },
	{ OID_ce_issuer_alt_name, "IssuerAltName", oid_ce_issuer_alt_name, sizeof(oid_ce_issuer_alt_name)/sizeof(int) },
	{ OID_ce_crl_number, "CRLNumber", oid_ce_crl_number, sizeof(oid_ce_crl_number)/sizeof(int) },
	{ OID_ce_delta_crl_indicator, "DeltaCRLIndicator", oid_ce_delta_crl_indicator, sizeof(oid_ce_delta_crl_indicator)/sizeof(int) },
	{ OID_ce_issuing_distribution_point, "IssuingDistributionPoint", oid_ce_issuing_distribution_point, sizeof(oid_ce_issuing_distribution_point)/sizeof(int) }
};

static const int x509_crl_exts_count =
	sizeof(x509_crl_exts)/sizeof(x509_crl_exts[0]);

const char *x509_crl_ext_id_name(int oid)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_oid(x509_crl_exts, x509_crl_exts_count, oid))) {
		error_print();
		return NULL;
	}
	return info->name;
}

int x509_crl_ext_id_from_name(const char *name)
{
	const ASN1_OID_INFO *info;
	if (!(info = asn1_oid_info_from_name(x509_crl_exts, x509_crl_exts_count, name))) {
		error_print();
		return OID_undef;
	}
	return info->oid;
}

int x509_crl_ext_id_to_der(int oid, uint8_t **out, size_t *outlen)
{
	const ASN1_OID_INFO *info;
	size_t len = 0;
	if (!(info = asn1_oid_info_from_oid(x509_crl_exts, x509_crl_exts_count, oid))) {
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

int x509_crl_ext_id_from_der(int *oid, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *p;
	size_t len;
	const ASN1_OID_INFO *info;

	*oid = 0;
	if ((ret = asn1_oid_info_from_der(&info, x509_crl_exts, x509_crl_exts_count, in, inlen)) != 1) {
		error_print();
		return -1;
	}
	*oid = info->oid;
	return ret;
}

int x509_crl_exts_add_authority_key_identifier(
	uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical,
	const uint8_t *keyid, size_t keyid_len,
	const uint8_t *issuer, size_t issuer_len,
	const uint8_t *serial, size_t serial_len)
{
	error_print();
	return -1;
}

int x509_crl_exts_add_issuer_alt_name(
	uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical,
	const uint8_t *d, size_t dlen)
{
	error_print();
	return -1;
}

int x509_crl_exts_add_crl_number(
 	uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical,
	int num)
{
	error_print();
	return -1;
}

int x509_crl_exts_add_delta_crl_indicator(
	uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical,
	int num)
{
	error_print();
	return -1;
}

int x509_crl_exts_add_issuing_distribution_point(
	uint8_t *exts, size_t *extslen, size_t maxlen,
	int critical,
	const uint8_t *dist_point, size_t dist_point_len,
	int only_contains_user_certs,
	int only_contains_ca_certs,
	int only_some_reasons,
	int indirect_crl,
	int only_contains_attr_certs)
{
	error_print();
	return -1;
}

int x509_crl_exts_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	error_print();
	return -1;
}

int x509_tbs_crl_to_der(
	int version,
	int signature_algor,
	const uint8_t *issuer, size_t issuer_len,
	time_t this_update, time_t next_update,
	const uint8_t *revoked_certs, size_t revoked_certs_len,
	const uint8_t *exts, size_t exts_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (asn1_int_to_der(version, NULL, &len) < 0
		|| x509_signature_algor_to_der(signature_algor, NULL, &len) < 0
		|| asn1_sequence_to_der(issuer, issuer_len, NULL, &len) != 1
		|| x509_time_to_der(this_update, NULL, &len) != 1
		|| x509_time_to_der(next_update, NULL, &len) < 0
		|| asn1_sequence_to_der(revoked_certs, revoked_certs_len, NULL, &len) < 0
		|| asn1_sequence_to_der(exts, exts_len, NULL, &len) < 0
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(version, out, outlen) < 0
		|| x509_signature_algor_to_der(signature_algor, out, outlen) < 0
		|| asn1_sequence_to_der(issuer, issuer_len, out, outlen) != 1
		|| x509_time_to_der(this_update, out, outlen) != 1
		|| x509_time_to_der(next_update, out, outlen) < 0
		|| asn1_sequence_to_der(revoked_certs, revoked_certs_len, out, outlen) < 0
		|| asn1_sequence_to_der(exts, exts_len, out, outlen) < 0) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_tbs_crl_from_der(
	int *version,
	int *signature_algor,
	const uint8_t **issuer, size_t *issuer_len,
	time_t *this_update,
	time_t *next_update,
	const uint8_t **revoked_certs, size_t *revoked_certs_len,
	const uint8_t **exts, size_t *exts_len,
	uint8_t **in, size_t *inlen)
{
	error_print();
	return -1;
}

int x509_tbs_crl_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	error_print();
	return -1;
}

int x509_cert_list_to_der(const uint8_t *tbs_crl, size_t tbs_crl_len,
	int signature_algor, const uint8_t *sig, size_t siglen,
	uint8_t **out, size_t *outlen)
{
	error_print();
	return -1;
}

int x509_cert_list_from_der(const uint8_t **tbs_crl, size_t *tbs_crl_len,
	int *signature_algor, const uint8_t **sig, size_t *siglen,
	const uint8_t **in, size_t *inlen)
{
	error_print();
	return -1;
}

int x509_cert_list_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	error_print();
	return -1;
}

int x509_crl_to_pem(const uint8_t *a, size_t *alen, FILE *fp)
{
	return 1;
}

int x509_crl_from_pem(uint8_t *a, size_t *alen, size_t maxlen, FILE *fp)
{
	return 1;
}

int x509_crl_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	return 1;
}

int x509_tbs_crl_sign(
	int version,
	int signature_algor,
	const uint8_t *issuer, size_t issuer_len,
	time_t this_update, time_t next_update,
	const uint8_t *revoked_certs, size_t revoked_certs_len,
	const uint8_t *exts, size_t exts_len,
	const SM2_KEY *sign_key, const char *signer_id, size_t signer_id_len,
	uint8_t *crl, size_t *crl_len)
{
	uint8_t tbs[512];
	size_t tbslen;
	SM2_SIGN_CTX sign_ctx;
	uint8_t sig[SM2_MAX_SIGNATURE_SIZE];
	size_t siglen;
	uint8_t *p = tbs;
	size_t len = 0;
	uint8_t *out = crl;
	size_t outlen = 0;

	if (x509_tbs_crl_to_der(version, signature_algor, issuer, issuer_len,
		this_update, next_update, revoked_certs, revoked_certs_len,
		exts, exts_len, &p, &tbslen) != 1) {
		error_print();
		return -1;
	}
	if (sm2_sign_init(&sign_ctx, sign_key, signer_id, signer_id_len) != 1
		|| sm2_sign_update(&sign_ctx, tbs, tbslen) != 1
		|| sm2_sign_finish(&sign_ctx, sig, &siglen) != 1) {
		error_print();
		return -1;
	}
	if (asn1_data_to_der(tbs, tbslen, NULL, &len) != 1
		|| x509_signature_algor_to_der(signature_algor, NULL, &len) != 1
		|| asn1_bit_octets_to_der(sig, siglen, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, &out, &outlen) != 1
		|| asn1_data_to_der(tbs, tbslen, &out, &outlen) != 1
		|| x509_signature_algor_to_der(signature_algor, &out, &outlen) != 1
		|| asn1_bit_octets_to_der(sig, siglen, &out, &outlen) != 1) {
		error_print();
		return -1;
	}
	*crl_len = outlen;
	return 1;
}

int x509_crl_verify(const uint8_t *a, size_t alen,
	const SM2_KEY *signer_key, const char *signer_id, size_t signer_id_len)
{
	error_print();
	return -1;
}

int x509_crl_get_details(const uint8_t *crl, size_t crl_len,
	int *version,
	const uint8_t **issuer, size_t *issuer_len,
	time_t *this_update,
	time_t *next_update,
	const uint8_t **revoked_certs, size_t *revoked_certs_len,
	int *signature_algor,
	const uint8_t *sig, size_t *siglen)
{
	error_print();
	return -1;
}

int x509_crl_get_revoked_cert_by_serial_number(const uint8_t *a, size_t alen,
	const uint8_t *serial, size_t serial_len,
	time_t *revoke_date,
	const uint8_t **entry_exts, size_t *entry_exts_len)
{
	return 1;
}

int x509_crls_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
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
