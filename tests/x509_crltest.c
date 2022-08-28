/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
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
#include <gmssl/x509_oid.h>
#include <gmssl/x509_crl.h>
#include <gmssl/x509.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>


static int test_x509_crl_reason(void)
{
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	int reason;
	int i;

	for (i = 0; i < 11; i++) {
		if (x509_crl_reason_to_der(i, &p, &len) != 1) {
			error_print();
			return -1;
		}
		format_bytes(stderr, 0, 4, "", buf, len);
	}
	for (i = 0; i < 11; i++) {
		if (x509_crl_reason_from_der(&reason, &cp, &len) != 1
			|| asn1_check(reason == i) != 1) {
			error_print();
			return -1;
		}
		format_print(stderr, 0, 4, "%s (%d)\n", x509_crl_reason_name(reason), reason);
	}
	(void)asn1_length_is_zero(len);
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_crl_entry_ext(void)
{
	int exts[] = {
		OID_ce_crl_reasons,
		OID_ce_invalidity_date,
		OID_ce_certificate_issuer,
	};
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	int oid;
	int i;

	for (i = 0; i < sizeof(exts)/sizeof(exts[0]); i++) {
		if (x509_crl_entry_ext_id_to_der(exts[i], &p, &len) != 1) {
			error_print();
			return -1;
		}
		format_bytes(stderr, 0, 4, "", buf, len);
	}
	for (i = 0; i < sizeof(exts)/sizeof(exts[0]); i++) {
		if (x509_crl_entry_ext_id_from_der(&oid, &cp, &len) != 1
			|| asn1_check(oid == exts[i]) != 1) {
			error_print();
			return -1;
		}
		format_print(stderr, 0, 4, "%s\n", x509_crl_entry_ext_id_name(oid));
	}
	(void)asn1_length_is_zero(len);
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_crl_entry_exts(void)
{
	uint8_t exts[256];
	size_t extslen = 0;
	int reason = X509_cr_key_compromise;
	time_t tv;
	uint8_t issuer[256];
	size_t issuer_len = 0;
	int critical = 1;

	uint8_t buf[512];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	time(&tv);
	if (x509_crl_entry_exts_add_reason(exts, &extslen, sizeof(exts), critical, reason) != 1
		|| x509_crl_entry_exts_add_invalidity_date(exts, &extslen, sizeof(exts), critical, tv) != 1
		|| x509_crl_entry_exts_add_certificate_issuer(exts, &extslen, sizeof(exts), critical, issuer, issuer_len) != 1
		|| x509_crl_entry_exts_to_der(exts, extslen, &p, &len) != 1) {
		error_print();
		return -1;
	}
	x509_crl_entry_exts_print(stderr, 0, 0, "CRLEntryExtensions", exts, extslen);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_revoked_cert(void)
{
	uint8_t serial[20] = { 0x01,0x02 };
	time_t revoke_date;

	uint8_t buf[512];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	const uint8_t *d;
	size_t dlen;

	time(&revoke_date);
	if (x509_revoked_cert_to_der(serial, sizeof(serial), revoke_date, NULL, 0, &p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	x509_revoked_cert_print(stderr, 0, 0, "RevokedCertificate", d, dlen);

	return 1;
}


int main(void)
{
	if (test_x509_crl_reason() != 1) goto err;
	if (test_x509_crl_entry_ext() != 1) goto err;
	if (test_x509_crl_entry_exts() != 1) goto err;
	if (test_x509_revoked_cert() != 1) goto err;
	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
