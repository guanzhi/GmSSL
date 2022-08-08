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
#include <gmssl/x509_oid.h>
#include <gmssl/x509.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>


static int test_x509_name_type()
{
	char *names[] = {
		"name",
		"surname",
		"givenName",
		"initials",
		"generationQualifier",
		"commonName",
		"localityName",
		"stateOrProvinceName",
		"organizationName",
		"organizationalUnitName",
		"title",
		"dnQualifier",
		"countryName",
		"serialNumber",
		"pseudonym",
		"domainComponent",
	};
	int oid;
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	int i;

	format_print(stderr, 0, 0, "DER\n");
	for (i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
		oid = x509_name_type_from_name(names[i]);
		if (asn1_check(oid != OID_undef) != 1
			|| x509_name_type_to_der(oid, &p, &len) != 1) {
			error_print();
			return -1;
		}
		format_bytes(stderr, 0, 4, "", buf, len);
	}

	format_print(stderr, 0, 0, "OID\n");
	for (i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
		if (x509_name_type_from_der(&oid, &cp, &len) != 1) {
			error_print();
			return -1;
		}
		if (oid != x509_name_type_from_name(names[i])) {
			error_print();
			return -1;
		}
		format_print(stderr, 0, 4, "%s\n", x509_name_type_name(oid));
	}
	if (len != 0) {
		error_print();
		return -1;
	}
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_ext_id()
{
	char *names[] = {
		"AuthorityKeyIdentifier",
		"SubjectKeyIdentifier",
		"KeyUsage",
		"CertificatePolicies",
		"PolicyMappings",
		"SubjectAltName",
		"IssuerAltName",
		"SubjectDirectoryAttributes",
		"BasicConstraints",
		"NameConstraints",
		"PolicyConstraints",
		"ExtKeyUsage",
		"CRLDistributionPoints",
		"InhibitAnyPolicy",
		"FreshestCRL",
	};
	int oid;
	uint32_t nodes[32];
	size_t nodes_cnt;
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	int i;

	format_print(stderr, 0, 0, "DER\n");
	for (i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
		oid = x509_ext_id_from_name(names[i]);
		if (asn1_check(oid != OID_undef) != 1
			|| x509_ext_id_to_der(oid, &p, &len) != 1) {
			error_print();
			return -1;
		}
		format_bytes(stderr, 0, 4, "", buf, len);
	}

	format_print(stderr, 0, 0, "ExtnID\n");
	for (i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
		if (x509_ext_id_from_der(&oid, nodes, &nodes_cnt, &cp, &len) != 1) {
			error_print();
			return -1;
		}
		if (oid != x509_ext_id_from_name(names[i])) {
			error_print();
			return -1;
		}
		format_print(stderr, 0, 4, "%s\n", x509_ext_id_name(oid));
	}
	if (len != 0) {
		error_print();
		return -1;
	}
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_qualifier_id(void)
{
	char *names[] = {
		"CPS",
		"userNotice",
	};
	int oid;
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	int i;

	format_print(stderr, 0, 0, "DER\n");
	for (i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
		oid = x509_qualifier_id_from_name(names[i]);
		if (asn1_check(oid != OID_undef) != 1
			|| x509_qualifier_id_to_der(oid, &p, &len) != 1) {
			error_print();
			return -1;
		}
		format_bytes(stderr, 0, 4, "", buf, len);
	}

	format_print(stderr, 0, 0, "OID\n");
	for (i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
		if (x509_qualifier_id_from_der(&oid, &cp, &len) != 1) {
			error_print();
			return -1;
		}
		if (asn1_check(oid == x509_qualifier_id_from_name(names[i])) != 1) {
			error_print();
			return -1;
		}
		format_print(stderr, 0, 4, "%s\n", x509_qualifier_id_name(oid));
	}
	if (len != 0) {
		error_print();
		return -1;
	}
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_cert_policy_id(void)
{
	char *names[] = {
		"anyPolicy",
	};
	int oid;
	uint32_t nodes[32];
	size_t nodes_cnt;
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	int i;

	format_print(stderr, 0, 0, "DER\n");
	for (i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
		oid = x509_cert_policy_id_from_name(names[i]);
		if (asn1_check(oid != OID_undef) != 1
			|| x509_cert_policy_id_to_der(oid, NULL, 0, &p, &len) != 1) {
			error_print();
			return -1;
		}
		format_bytes(stderr, 0, 4, "", buf, len);
	}

	format_print(stderr, 0, 0, "OID\n");
	for (i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
		if (x509_cert_policy_id_from_der(&oid, nodes, &nodes_cnt, &cp, &len) != 1) {
			error_print();
			return -1;
		}
		if (oid != x509_cert_policy_id_from_name(names[i])) {
			error_print();
			return -1;
		}
		format_print(stderr, 0, 4, "%s\n", x509_cert_policy_id_name(oid));
	}
	if (len != 0) {
		error_print();
		return -1;
	}
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_key_purpose(void)
{
	char *names[] = {
		"serverAuth",
		"clientAuth",
		"codeSigning",
		"emailProtection",
		"timeStamping",
		"OCSPSigning",
	};
	int oid;
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	int i;

	format_print(stderr, 0, 0, "DER\n");
	for (i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
		oid = x509_key_purpose_from_name(names[i]);
		if (asn1_check(oid != OID_undef) != 1
			|| x509_key_purpose_to_der(oid, &p, &len) != 1) {
			error_print();
			return -1;
		}
		format_bytes(stderr, 0, 4, "", buf, len);
	}

	format_print(stderr, 0, 0, "OID\n");
	for (i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
		if (x509_key_purpose_from_der(&oid, &cp, &len) != 1) {
			error_print();
			return -1;
		}
		if (oid != x509_key_purpose_from_name(names[i])) {
			error_print();
			return -1;
		}
		format_print(stderr, 0, 4, "%s\n", x509_key_purpose_name(oid));
	}
	if (len != 0) {
		error_print();
		return -1;
	}
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (test_x509_name_type() != 1) goto err;
	if (test_x509_ext_id() != 1) goto err;
	if (test_x509_qualifier_id() != 1) goto err;
	if (test_x509_cert_policy_id() != 1) goto err;
	if (test_x509_key_purpose() != 1) goto err;
	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
