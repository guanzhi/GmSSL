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

int main(void)
{
	if (test_x509_cert_check_subject() != 1) goto err;

	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
