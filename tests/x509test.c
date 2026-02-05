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
#include <gmssl/x509.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>


static int test_x509_version(void)
{

	// X509v1 cert has no version, so version in X509v2, X509v3 is explicit
	// version = -1 means do not encode version (for X509v1)
	int tests[] = {
		X509_version_v1,
		X509_version_v2,
		X509_version_v3,
		-1,
	};
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	int i;

	format_print(stderr, 0, 4, "EXPLICIT Version(s) to DER\n");
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (x509_explicit_version_to_der(i, tests[i], &p, &len) < 0) {
			error_print();
			return -1;
		}
		format_bytes(stderr, 0, 8, "", buf, len);
	}

	format_print(stderr, 0, 4, "EXPLICIT Version from DER\n");
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		int ver;
		if (x509_explicit_version_from_der(i, &ver, &cp, &len) < 0
			|| asn1_check(ver == tests[i]) != 1) {
			error_print();
			return -1;
		}
		format_print(stderr, 0, 8, "%s\n", x509_version_name(ver));
	}
	(void)asn1_length_is_zero(len);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}


static int test_x509_validity(void)
{
	time_t not_before, not_before_;
	time_t not_after, not_after_;
	time_t now;
	int days = 365;
	int max_secs = 60 * 60 * 24 * days;
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	time(&not_before);

	if (x509_validity_add_days(&not_after, not_before, days) != 1
		|| x509_validity_to_der(not_before, not_after, &p, &len) != 1) {
		error_print();
		return -1;
	}
	format_bytes(stderr, 0, 4, "Validity (DER)", buf, len);

	if (x509_validity_from_der(&not_before_, &not_after_, &cp, &len) != 1
		|| asn1_check(not_before == not_before_) != 1
		|| asn1_check(not_after == not_after_) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}

	time(&now);
	if (x509_validity_check(not_before, not_after, now, max_secs) != 1) {
		error_print();
		return -1;
	}

	// x509_validity_print need the V(Value) of Validity TLV
	{
		const uint8_t *d;
		size_t dlen;

		cp = buf;
		len = sizeof(buf);
		if (asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1) {
			error_print();
			return -1;
		}
		x509_validity_print(stderr, 0, 4, "Validity", d, dlen);
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_attr_type_and_value(void)
{
	int oid;
	int tag;
	const uint8_t *d;
	size_t dlen;
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	format_print(stderr, 0, 4, "AttributeTypeAndValue\n");
	if (x509_attr_type_and_value_to_der(OID_at_locality_name, ASN1_TAG_PrintableString, (uint8_t *)"Haidian", strlen("Haidian"), &p, &len) != 1) {
		error_print();
		return -1;
	}
	format_bytes(stderr, 0, 4, "", buf, len);
	if (x509_attr_type_and_value_from_der(&oid, &tag, &d, &dlen, &cp, &len) != 1
		|| asn1_check(oid == OID_at_locality_name) != 1
		|| asn1_check(tag == ASN1_TAG_PrintableString) != 1
		|| asn1_check(dlen == strlen("Haidian")) != 1
		|| asn1_check(memcmp("Haidian", d, dlen) == 0) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	format_print(stderr, 0, 4, "%s : %s ", x509_name_type_name(oid), asn1_tag_name(tag));
	format_string(stderr, 0, 0, "", d, dlen);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_rdn(void)
{
	int oid;
	int tag;
	const uint8_t *d;
	size_t dlen;
	const uint8_t *more;
	size_t morelen;
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	format_print(stderr, 0, 4, "RDN\n");
	if (x509_rdn_to_der(OID_at_locality_name, ASN1_TAG_PrintableString,
		(uint8_t *)"Haidian", strlen("Haidian"), NULL, 0, &p, &len) != 1) {
		error_print();
		return -1;
	}
	format_bytes(stderr, 0, 4, "", buf, len);
	if (x509_rdn_from_der(&oid, &tag, &d, &dlen, &more, &morelen, &cp, &len) != 1
		|| asn1_check(oid == OID_at_locality_name) != 1
		|| asn1_check(tag == ASN1_TAG_PrintableString) != 1
		|| asn1_check(dlen == strlen("Haidian")) != 1
		|| asn1_check(memcmp("Haidian", d, dlen) == 0) != 1
		|| asn1_check(more == NULL) != 1
		|| asn1_check(morelen == 0) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	format_print(stderr, 0, 4, "%s : %s ", x509_name_type_name(oid), asn1_tag_name(tag));
	format_string(stderr, 0, 0, "", d, dlen);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_name(void)
{
	uint8_t name[512];
	size_t namelen = 0;
	uint8_t buf[1024];
	const uint8_t *cp = buf;
	uint8_t *p = buf;
	size_t len = 0;

	if (x509_name_add_country_name(name, &namelen, sizeof(name), "CN") != 1
		|| format_bytes(stderr, 0, 4, "", name, namelen) > 2
		|| x509_name_add_locality_name(name, &namelen, sizeof(name), ASN1_TAG_PrintableString, (uint8_t *)"Haidian", strlen("Haidian")) != 1
		|| format_bytes(stderr, 0, 4, "", name, namelen) > 2
		|| x509_name_add_state_or_province_name(name, &namelen, sizeof(name), ASN1_TAG_PrintableString, (uint8_t *)"Beijing", strlen("Beijing")) != 1
		|| format_bytes(stderr, 0, 4, "", name, namelen) > 2
		|| x509_name_add_organization_name(name, &namelen, sizeof(name), ASN1_TAG_PrintableString, (uint8_t *)"PKU", strlen("PKU")) != 1
		|| format_bytes(stderr, 0, 4, "", name, namelen) > 2
		|| x509_name_add_organizational_unit_name(name, &namelen, sizeof(name), ASN1_TAG_PrintableString, (uint8_t *)"CS", strlen("CS")) != 1
		|| format_bytes(stderr, 0, 4, "", name, namelen) > 2
		|| x509_name_add_common_name(name, &namelen, sizeof(name), ASN1_TAG_PrintableString, (uint8_t *)"CA", strlen("CA")) != 1
		|| format_bytes(stderr, 0, 4, "", name, namelen) > 2
		) {
		error_print();
		return -1;
	}
	format_bytes(stdout, 0, 4, "der ", name, namelen);
	x509_name_print(stdout, 0, 4, "Name", name, namelen);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_public_key_info(void)
{
	int algor = OID_ec_public_key;
	int algor_param = OID_sm2;
	X509_KEY x509_key;
	X509_KEY pub_key;
	uint8_t buf[256];
	const uint8_t *cp = buf;
	uint8_t *p = buf;
	size_t len = 0;
	const uint8_t *d;
	size_t dlen;

	if (x509_key_generate(&x509_key, algor, &algor_param, sizeof(algor_param)) != 1) {
		error_print();
		return -1;
	}
	if (x509_public_key_info_to_der(&x509_key, &p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	x509_public_key_info_print(stdout, 0, 4, "PublicKeyInfo", d, dlen);

	if (x509_key_generate(&x509_key, algor, &algor_param, sizeof(algor_param)) != 1) {
		error_print();
		return -1;
	}
	if (x509_public_key_info_to_der(&x509_key, &p, &len) != 1
		|| x509_public_key_info_from_der(&pub_key, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	x509_public_key_print(stdout, 0, 4, "ECPublicKey", &pub_key);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

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

static int test_x509_tbs_cert(void)
{
	int algor = OID_ec_public_key;
	int algor_param = OID_sm2;
	uint8_t serial[20] = { 0x01, 0x00 };
	uint8_t issuer[256];
	size_t issuer_len = 0;
	time_t not_before, not_after;
	uint8_t subject[256];
	size_t subject_len = 0;
	X509_KEY x509_key;
	uint8_t buf[1024] = {0};
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	const uint8_t *d;
	size_t dlen;

	set_x509_name(issuer, &issuer_len, sizeof(issuer));
	time(&not_before);
	x509_validity_add_days(&not_after, not_before, 365);
	set_x509_name(subject, &subject_len, sizeof(subject));

	if (x509_key_generate(&x509_key, algor, &algor_param, sizeof(algor_param)) != 1) {
		error_print();
		return -1;
	}

	if (x509_tbs_cert_to_der(
		X509_version_v3,
		serial, sizeof(serial),
		OID_sm2sign_with_sm3,
		issuer, issuer_len,
		not_before, not_after,
		subject, subject_len,
		&x509_key,
		NULL, 0,
		NULL, 0,
		NULL, 0,
		&p, &len) != 1) {
		error_print();
		return -1;
	}
	format_bytes(stderr, 0, 4, "tbs_cert", buf, len);
	if (asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	x509_tbs_cert_print(stderr, 0, 4, "TBSCertificate", d, dlen);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_cert_get(const uint8_t *cert, size_t certlen)
{
	const uint8_t *serial;
	size_t serial_len;
	const uint8_t *issuer;
	size_t issuer_len;
	const uint8_t *subject;
	size_t subject_len;
	X509_KEY public_key;

	if (x509_cert_get_issuer_and_serial_number(cert, certlen, &issuer, &issuer_len, &serial, &serial_len) != 1
		|| x509_cert_get_subject(cert, certlen, &subject, &subject_len) != 1
		|| x509_cert_get_subject_public_key(cert, certlen, &public_key) != 1) {
		error_print();
		return -1;
	}
	format_bytes(stderr, 0, 4, "SerialNumber", serial, serial_len);
	x509_name_print(stderr, 0, 4, "Issuer", issuer, issuer_len);
	x509_name_print(stderr, 0, 4, "Subject", subject, subject_len);
	x509_public_key_print(stderr, 0, 4, "SubjectPublicKey", &public_key);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_cert(void)
{
	int algor = OID_ec_public_key;
	int algor_param = OID_sm2;
	uint8_t serial[20] = { 0x01, 0x00 };
	uint8_t issuer[256];
	size_t issuer_len = 0;
	time_t not_before, not_after;
	uint8_t subject[256];
	size_t subject_len = 0;
	X509_KEY x509_key;
	uint8_t cert[1024] = {0};
	uint8_t *p = cert;
	const uint8_t *cp = cert;
	size_t certlen = 0;

	set_x509_name(issuer, &issuer_len, sizeof(issuer));
	time(&not_before);
	x509_validity_add_days(&not_after, not_before, 365);
	set_x509_name(subject, &subject_len, sizeof(subject));

	if (x509_key_generate(&x509_key, algor, &algor_param, sizeof(algor_param)) != 1) {
		error_print();
		return -1;
	}

	if (x509_cert_sign_to_der(
		X509_version_v3,
		serial, sizeof(serial),
		OID_sm2sign_with_sm3,
		issuer, issuer_len,
		not_before, not_after,
		subject, subject_len,
		&x509_key,
		NULL, 0,
		NULL, 0,
		NULL, 0,
		&x509_key, SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID),
		&p, &certlen) != 1) {
		error_print();
		return -1;
	}
	format_bytes(stderr, 0, 4, "cert", cert, certlen);
	x509_cert_print(stderr, 0, 4, "Certificate", cert, certlen);

	/*
	// TODO: use the same cert to verify?
	if (x509_cert_verify(cert, certlen, &sm2_key, SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID)) != 1) {
		error_print();
		return -1;
	}
	printf("x509_cert_verify() success\n");
	*/

	test_x509_cert_get(cert, certlen);


	FILE *fp;

	if (!(fp = fopen("cert.pem", "w"))) {
		error_print();
		return -1;
	}

	x509_cert_to_pem(cert, certlen, fp);
	x509_cert_to_pem(cert, certlen, stderr);
	fclose(fp);


	if (!(fp = fopen("cert.pem", "r"))) {
		error_print();
		return -1;
	}

	memset(cert, 0, sizeof(cert));
	if (x509_cert_from_pem(cert, &certlen, sizeof(cert), fp) != 1) {
		error_print();
		return -1;
	}
	x509_cert_print(stderr, 0, 4, "Certificate", cert, certlen);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (test_x509_version() != 1) goto err;
	if (test_x509_validity() != 1) goto err;
	if (test_x509_attr_type_and_value() != 1) goto err;
	if (test_x509_rdn() != 1) goto err;
	if (test_x509_name() != 1) goto err;
	if (test_x509_public_key_info() != 1) {
		error_print();
		goto err;
	}
	if (test_x509_tbs_cert() != 1) goto err;
	if (test_x509_cert() != 1) goto err;

	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
