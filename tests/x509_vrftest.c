/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/oid.h>
#include <gmssl/x509_alg.h>
#include <gmssl/x509_ext.h>
#include <gmssl/x509.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>


static int set_x509_name(uint8_t *name, size_t *namelen, size_t maxlen)
{
	*namelen = 0;
	if (x509_name_add_country_name(name, namelen, maxlen, "CN") != 1
		|| x509_name_add_locality_name(name, namelen, maxlen, ASN1_TAG_PrintableString, (uint8_t *)"Haidian", strlen("Haidian")) != 1
		|| x509_name_add_state_or_province_name(name, namelen, maxlen, ASN1_TAG_PrintableString, (uint8_t *)"Beijing", strlen("Beijing")) != 1
		|| x509_name_add_organization_name(name, namelen, maxlen, ASN1_TAG_PrintableString, (uint8_t *)"PKU", strlen("PKU")) != 1
		|| x509_name_add_organizational_unit_name(name, namelen, maxlen, ASN1_TAG_PrintableString, (uint8_t *)"CS", strlen("CS")) != 1
		|| x509_name_add_common_name(name, namelen, maxlen, ASN1_TAG_PrintableString, (uint8_t *)"CA", strlen("CA")) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

static int set_x509_name_cn(uint8_t *name, size_t *namelen, size_t maxlen, const char *cn)
{
	*namelen = 0;
	if (x509_name_add_country_name(name, namelen, maxlen, "CN") != 1
		|| x509_name_add_common_name(name, namelen, maxlen,
			ASN1_TAG_PrintableString, (uint8_t *)cn, strlen(cn)) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

static int test_x509_cert_check_subject(void)
{
	int algor = OID_ec_public_key;
	int algor_param = OID_sm2;
	uint8_t serial[20] = { 0x01, 0x00 };
	uint8_t issuer[256];
	size_t issuer_len = 0;
	time_t not_before, not_after;
	uint8_t empty_subject[1] = {0};
	X509_KEY x509_key;
	uint8_t gns[256];
	size_t gnslen;
	uint8_t exts[512];
	size_t extslen;
	uint8_t cert[1024];
	uint8_t *p;
	size_t certlen;
	int path_len_constraint;

	set_x509_name(issuer, &issuer_len, sizeof(issuer));
	time(&not_before);
	x509_validity_add_days(&not_after, not_before, 365);

	if (x509_key_generate(&x509_key, algor, &algor_param, sizeof(algor_param)) != 1) {
		error_print();
		return -1;
	}

	gnslen = 0;
	extslen = 0;
	p = cert;
	certlen = 0;
	if (x509_general_names_add_dns_name(gns, &gnslen, sizeof(gns), "www.example.com") != 1
		|| x509_exts_add_subject_alt_name(exts, &extslen, sizeof(exts),
			X509_critical, gns, gnslen) != 1
		|| x509_cert_sign_to_der(
			X509_version_v3,
			serial, sizeof(serial),
			OID_sm2sign_with_sm3,
			issuer, issuer_len,
			not_before, not_after,
			empty_subject, 0,
			&x509_key,
			NULL, 0,
			NULL, 0,
			exts, extslen,
			&x509_key, SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID),
			&p, &certlen) != 1
		|| x509_cert_check_subject(cert, certlen, 0) != 1
		|| x509_cert_check(cert, certlen, X509_cert_server_auth, &path_len_constraint) != 1) {
		error_print();
		return -1;
	}

	gnslen = 0;
	extslen = 0;
	p = cert;
	certlen = 0;
	if (x509_general_names_add_dns_name(gns, &gnslen, sizeof(gns), "www.example.com") != 1
		|| x509_exts_add_subject_alt_name(exts, &extslen, sizeof(exts),
			X509_non_critical, gns, gnslen) != 1
		|| x509_cert_sign_to_der(
			X509_version_v3,
			serial, sizeof(serial),
			OID_sm2sign_with_sm3,
			issuer, issuer_len,
			not_before, not_after,
			empty_subject, 0,
			&x509_key,
			NULL, 0,
			NULL, 0,
			exts, extslen,
			&x509_key, SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID),
			&p, &certlen) != 1) {
		error_print();
		return -1;
	}
	if (x509_cert_check_subject(cert, certlen, 0) == 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int make_root_cert(uint8_t *cert, size_t *certlen, size_t maxlen,
	const uint8_t *name, size_t name_len, X509_KEY *key,
	const uint8_t *serial, size_t serial_len,
	const uint8_t *ski, size_t ski_len)
{
	time_t not_before, not_after;
	uint8_t exts[512];
	size_t extslen = 0;
	uint8_t *p = cert;

	time(&not_before);
	x509_validity_add_days(&not_after, not_before, 365);

	if (x509_exts_add_basic_constraints(exts, &extslen, sizeof(exts),
			X509_critical, 1, -1) != 1
		|| x509_exts_add_key_usage(exts, &extslen, sizeof(exts),
			X509_critical, X509_KU_KEY_CERT_SIGN) != 1) {
		error_print();
		return -1;
	}
	if (ski && ski_len) {
		if (x509_exts_add_subject_key_identifier(exts, &extslen, sizeof(exts),
			X509_non_critical, ski, ski_len) != 1) {
			error_print();
			return -1;
		}
	}

	*certlen = 0;
	if (x509_cert_sign_to_der(
		X509_version_v3,
		serial, serial_len,
		OID_sm2sign_with_sm3,
		name, name_len,
		not_before, not_after,
		name, name_len,
		key,
		NULL, 0,
		NULL, 0,
		exts, extslen,
		key, SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID),
		&p, certlen) != 1
		|| *certlen > maxlen) {
		error_print();
		return -1;
	}
	return 1;
}

static int make_leaf_cert(uint8_t *cert, size_t *certlen, size_t maxlen,
	const uint8_t *issuer, size_t issuer_len,
	const uint8_t *subject, size_t subject_len,
	X509_KEY *subject_key, X509_KEY *sign_key, int with_aki,
	const uint8_t *aki_issuer, size_t aki_issuer_len,
	const uint8_t *aki_serial, size_t aki_serial_len)
{
	uint8_t serial[20] = { 0x02, 0x00 };
	time_t not_before, not_after;
	uint8_t exts[512];
	size_t extslen = 0;
	uint8_t keyid[32];
	uint8_t *p = cert;

	time(&not_before);
	x509_validity_add_days(&not_after, not_before, 365);

	if (with_aki) {
		if (x509_public_key_digest(sign_key, keyid) != 1
			|| x509_exts_add_authority_key_identifier(exts, &extslen,
				sizeof(exts), X509_non_critical,
				keyid, sizeof(keyid),
				aki_issuer, aki_issuer_len,
				aki_serial, aki_serial_len) != 1) {
			error_print();
			return -1;
		}
	}

	*certlen = 0;
	if (x509_cert_sign_to_der(
		X509_version_v3,
		serial, sizeof(serial),
		OID_sm2sign_with_sm3,
		issuer, issuer_len,
		not_before, not_after,
		subject, subject_len,
		subject_key,
		NULL, 0,
		NULL, 0,
		exts, extslen,
		sign_key, SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID),
		&p, certlen) != 1
		|| *certlen > maxlen) {
		error_print();
		return -1;
	}
	return 1;
}

static int test_x509_cert_is_signed_by_root_ca_cert(void)
{
	int algor = OID_ec_public_key;
	int algor_param = OID_sm2;
	X509_KEY root_key;
	X509_KEY other_key;
	X509_KEY leaf_key;
	uint8_t root_name[256];
	size_t root_name_len;
	uint8_t other_name[256];
	size_t other_name_len;
	uint8_t leaf_name[256];
	size_t leaf_name_len;
	uint8_t root_serial[20] = { 0x01, 0x00 };
	uint8_t other_serial[20] = { 0x01, 0x01 };
	uint8_t root_ski[32];
	uint8_t other_ski[32];
	uint8_t root_authority[256];
	size_t root_authority_len = 0;
	uint8_t other_authority[256];
	size_t other_authority_len = 0;
	uint8_t good_root[2048];
	size_t good_root_len;
	uint8_t root_without_ski[2048];
	size_t root_without_ski_len;
	uint8_t wrong_name_root[2048];
	size_t wrong_name_root_len;
	uint8_t wrong_ski_root[2048];
	size_t wrong_ski_root_len;
	uint8_t wrong_key_root[2048];
	size_t wrong_key_root_len;
	uint8_t wrong_serial_root[2048];
	size_t wrong_serial_root_len;
	uint8_t leaf[2048];
	size_t leaf_len;
	uint8_t leaf_wrong_aki_issuer[2048];
	size_t leaf_wrong_aki_issuer_len;

	if (set_x509_name_cn(root_name, &root_name_len, sizeof(root_name), "Root CA") != 1
		|| set_x509_name_cn(other_name, &other_name_len, sizeof(other_name), "Other Root CA") != 1
		|| set_x509_name_cn(leaf_name, &leaf_name_len, sizeof(leaf_name), "Leaf") != 1
		|| x509_key_generate(&root_key, algor, &algor_param, sizeof(algor_param)) != 1
		|| x509_key_generate(&other_key, algor, &algor_param, sizeof(algor_param)) != 1
		|| x509_key_generate(&leaf_key, algor, &algor_param, sizeof(algor_param)) != 1
		|| x509_public_key_digest(&root_key, root_ski) != 1
		|| x509_public_key_digest(&other_key, other_ski) != 1
		|| x509_general_names_add_directory_name(root_authority, &root_authority_len,
			sizeof(root_authority), root_name, root_name_len) != 1
		|| x509_general_names_add_directory_name(other_authority, &other_authority_len,
			sizeof(other_authority), other_name, other_name_len) != 1
		|| make_root_cert(good_root, &good_root_len, sizeof(good_root),
			root_name, root_name_len, &root_key,
			root_serial, sizeof(root_serial), root_ski, sizeof(root_ski)) != 1
		|| make_root_cert(root_without_ski, &root_without_ski_len, sizeof(root_without_ski),
			root_name, root_name_len, &root_key,
			root_serial, sizeof(root_serial), NULL, 0) != 1
		|| make_root_cert(wrong_name_root, &wrong_name_root_len, sizeof(wrong_name_root),
			other_name, other_name_len, &root_key,
			root_serial, sizeof(root_serial), root_ski, sizeof(root_ski)) != 1
		|| make_root_cert(wrong_ski_root, &wrong_ski_root_len, sizeof(wrong_ski_root),
			root_name, root_name_len, &other_key,
			root_serial, sizeof(root_serial), other_ski, sizeof(other_ski)) != 1
		|| make_root_cert(wrong_key_root, &wrong_key_root_len, sizeof(wrong_key_root),
			root_name, root_name_len, &other_key,
			root_serial, sizeof(root_serial), root_ski, sizeof(root_ski)) != 1
		|| make_root_cert(wrong_serial_root, &wrong_serial_root_len, sizeof(wrong_serial_root),
			root_name, root_name_len, &root_key,
			other_serial, sizeof(other_serial), root_ski, sizeof(root_ski)) != 1
		|| make_leaf_cert(leaf, &leaf_len, sizeof(leaf),
			root_name, root_name_len, leaf_name, leaf_name_len,
			&leaf_key, &root_key, 1,
			root_authority, root_authority_len,
			root_serial, sizeof(root_serial)) != 1
		|| make_leaf_cert(leaf_wrong_aki_issuer, &leaf_wrong_aki_issuer_len, sizeof(leaf_wrong_aki_issuer),
			root_name, root_name_len, leaf_name, leaf_name_len,
			&leaf_key, &root_key, 1,
			other_authority, other_authority_len,
			root_serial, sizeof(root_serial)) != 1) {
		error_print();
		return -1;
	}

	if (x509_cert_is_signed_by_root_ca_cert(leaf, leaf_len, good_root, good_root_len,
			SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID)) != 1
		|| x509_cert_is_signed_by_root_ca_cert(leaf, leaf_len, wrong_name_root, wrong_name_root_len,
			SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID)) != 0
		|| x509_cert_is_signed_by_root_ca_cert(leaf, leaf_len, root_without_ski, root_without_ski_len,
			SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID)) != 0
		|| x509_cert_is_signed_by_root_ca_cert(leaf, leaf_len, wrong_ski_root, wrong_ski_root_len,
			SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID)) != 0
		|| x509_cert_is_signed_by_root_ca_cert(leaf, leaf_len, wrong_key_root, wrong_key_root_len,
			SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID)) != 0
		|| x509_cert_is_signed_by_root_ca_cert(leaf, leaf_len, wrong_serial_root, wrong_serial_root_len,
			SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID)) != 0
		|| x509_cert_is_signed_by_root_ca_cert(leaf_wrong_aki_issuer, leaf_wrong_aki_issuer_len,
			good_root, good_root_len,
			SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID)) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (test_x509_cert_check_subject() != 1) goto err;
	if (test_x509_cert_is_signed_by_root_ca_cert() != 1) goto err;

	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
