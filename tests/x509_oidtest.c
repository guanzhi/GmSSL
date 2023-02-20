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
#include <gmssl/x509.h>
#include <gmssl/x509_ext.h>
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
