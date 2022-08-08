/*
 * Copyright (c) 2014 - 2021 The GmSSL Project.  All rights reserved.
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
