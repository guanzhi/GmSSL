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
#include <gmssl/x509.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>


static int test_x509_validity(void)
{
	int err = 0;
	X509_VALIDITY validity;
	uint8_t buf[64] = {0};
	const uint8_t *cp = buf;
	uint8_t *p = buf;
	size_t len = 0;
	size_t i;

	printf("%s\n", __FUNCTION__);
	memset(&validity, 0, sizeof(X509_VALIDITY));

	x509_validity_set_days(&validity, time(NULL), 365 * 10);
	x509_validity_to_der(&validity, &p, &len);
	print_der(buf, len);
	printf("\n");

	memset(&validity, 0, sizeof(X509_VALIDITY));
	x509_validity_from_der(&validity, &cp, &len);
	x509_validity_print(stdout, &validity, 0, 0);

	printf("\n");
	return err;
}

static int test_x509_name(void)
{
	int err = 0;
	X509_NAME name;
	uint8_t buf[1024];
	const uint8_t *cp = buf;
	uint8_t *p = buf;
	size_t len = 0;

	printf("%s\n", __FUNCTION__);

	memset(&name, 0, sizeof(X509_NAME));
	x509_name_add_rdn(&name, OID_at_countryName, ASN1_TAG_PrintableString, "CN");
	x509_name_add_rdn(&name, OID_at_stateOrProvinceName, ASN1_TAG_PrintableString, "Beijing");
	x509_name_add_rdn(&name, OID_at_organizationName, ASN1_TAG_PrintableString, "PKU");
	x509_name_add_rdn(&name, OID_at_organizationalUnitName, ASN1_TAG_PrintableString, "CS");
	x509_name_add_rdn(&name, OID_at_commonName, ASN1_TAG_PrintableString, "infosec");

	if (x509_name_to_der(&name, &p, &len) != 1) {
		error_print();
		err++;
		goto end;
	}
	print_der(buf, len);
	printf("\n");

	if (x509_name_from_der(&name, &cp, &len) != 1
		|| len > 0) {
		error_print();
		err++;
		goto end;
	}
	x509_name_print(stdout, &name, 0, 0);

end:
	printf("\n");
	return err;
}

static int test_x509_signature_algor(int oid)
{
	int err = 0;
	int tests[] = {OID_sm2sign_with_sm3, OID_rsasign_with_sm3};
	int val;
	uint32_t nodes[32];
	size_t nodes_count;
	uint8_t buf[128];
	const uint8_t *cp = buf;
	uint8_t *p = buf;
	size_t len = 0;
	size_t i;

	printf("%s\n", __FUNCTION__);
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		printf("%s\n", asn1_object_identifier_name(tests[i]));
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (x509_signature_algor_to_der(tests[i], &p, &len) != 1) {
			error_print();
			err++;
			goto end;
		}
		print_der(buf, len);
		printf("\n");
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (x509_signature_algor_from_der(&val, nodes, &nodes_count, &cp, &len) != 1) {
			error_print();
			err++;
			goto end;
		}
		if (val != tests[i]) {
			error_print();
			err++;
			goto end;
		}
		printf("%s\n", asn1_object_identifier_name(tests[i]));
	}

end:
	printf("\n");
	return err;
}

static int test_x509_public_key_info(void)
{
	int err = 0;
	SM2_KEY key;
	X509_PUBLIC_KEY_INFO pkey_info;
	uint8_t buf[256];
	const uint8_t *cp = buf;
	uint8_t *p = buf;
	size_t len = 0;

	printf("%s\n", __FUNCTION__);

	sm2_keygen(&key);
	x509_public_key_info_set_sm2(&pkey_info, &key);

	if (x509_public_key_info_to_der(&pkey_info, &p, &len) != 1) {
		error_print();
		return -1;
	}
	print_der(buf, len);
	printf("\n");

	if (x509_public_key_info_from_der(&pkey_info, &cp, &len) != 1
		|| len > 0) {
		error_print();
		return -1;
	}

	x509_public_key_info_print(stdout, &pkey_info, 0, 0);

	printf("\n");
	return err;
}

static int test_x509_certificate(void)
{
	int err = 0;
	X509_CERTIFICATE _cert, *cert = &_cert;
	int rv;
	int version = X509_version_v3;
	uint8_t sn[12];
	X509_NAME issuer;
	X509_NAME subject;
	time_t not_before;

	SM2_KEY key;

	uint8_t buf[2048] = {0};
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	printf("%s\n", __FUNCTION__);

	memset(cert, 0, sizeof(X509_CERTIFICATE));

	rand_bytes(sn, sizeof(sn));

	memset(&issuer, 0, sizeof(X509_NAME));
	// add_rdn 应该用一个ex来支持长度
	x509_name_add_rdn(&issuer, OID_at_countryName, ASN1_TAG_PrintableString, "CN");
	x509_name_add_rdn(&issuer, OID_at_stateOrProvinceName, ASN1_TAG_PrintableString, "Beijing");
	x509_name_add_rdn(&issuer, OID_at_organizationName, ASN1_TAG_PrintableString, "PKU");
	x509_name_add_rdn(&issuer, OID_at_organizationalUnitName, ASN1_TAG_PrintableString, "CS");
	x509_name_add_rdn(&issuer, OID_at_commonName, ASN1_TAG_PrintableString, "CA");

	memset(&subject, 0, sizeof(X509_NAME));
	x509_name_add_rdn(&subject, OID_at_countryName, ASN1_TAG_PrintableString, "CN");
	x509_name_add_rdn(&subject, OID_at_stateOrProvinceName, ASN1_TAG_PrintableString, "Beijing");
	x509_name_add_rdn(&subject, OID_at_organizationName, ASN1_TAG_PrintableString, "PKU");
	x509_name_add_rdn(&subject, OID_at_organizationalUnitName, ASN1_TAG_PrintableString, "CS");
	x509_name_add_rdn(&subject, OID_at_commonName, ASN1_TAG_PrintableString, "infosec");

	time(&not_before);

	rv = x509_certificate_set_version(cert, version);
	rv = x509_certificate_set_serial_number(cert, sn, sizeof(sn));
	rv = x509_certificate_set_signature_algor(cert, OID_sm2sign_with_sm3); // 这个不是应该在设置公钥的时候一起设置吗？
	rv = x509_certificate_set_issuer(cert, &issuer);
	rv = x509_certificate_set_subject(cert, &subject);
	rv = x509_certificate_set_validity(cert, not_before, 365);

	sm2_keygen(&key);
	rv = x509_certificate_set_subject_public_key_info_sm2(cert, &key);


	rv = x509_certificate_generate_subject_key_identifier(cert, 1);


	rv = x509_certificate_sign_sm2(cert, &key);

	rv = x509_certificate_to_der(cert, &p, &len);
	print_der(buf, len);
	printf("\n");

	memset(cert, 0, sizeof(X509_CERTIFICATE));
	x509_certificate_from_der(cert, &cp, &len);

	x509_certificate_print(stdout, cert, 0, 0);


	return 0;
}

static int test_x509_cert_request(void)
{
	int err = 0;
	X509_CERT_REQUEST req;
	X509_NAME subject;
	SM2_KEY keypair;
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	printf("%s : \n", __func__);

	memset(&subject, 0, sizeof(X509_NAME));
	x509_name_add_rdn(&subject, OID_at_countryName, ASN1_TAG_PrintableString, "CN");
	x509_name_add_rdn(&subject, OID_at_stateOrProvinceName, ASN1_TAG_PrintableString, "Beijing");
	x509_name_add_rdn(&subject, OID_at_organizationName, ASN1_TAG_PrintableString, "PKU");
	x509_name_add_rdn(&subject, OID_at_organizationalUnitName, ASN1_TAG_PrintableString, "CS");
	x509_name_add_rdn(&subject, OID_at_commonName, ASN1_TAG_PrintableString, "infosec");

	sm2_keygen(&keypair);

	if (x509_cert_request_set_sm2(&req, &subject, &keypair) != 1
		|| x509_cert_request_sign_sm2(&req, &keypair) != 1
		|| x509_cert_request_to_der(&req, &p, &len) != 1) {
		error_print();
		err++;
		goto end;
	}
	print_der(buf, len);
	printf("\n");

	memset(&req, 0, sizeof(req));
	if (x509_cert_request_from_der(&req, &cp, &len) != 1) {
		error_print();
		err++;
		goto end;
	}

	x509_cert_request_print(stdout, &req, 0, 0);

end:
	return err;
}


int main(void)
{
	int err = 0;
	//err += test_x509_validity();
	err += test_x509_signature_algor(OID_sm2sign_with_sm3);
	err += test_x509_signature_algor(OID_rsasign_with_sm3);
	err += test_x509_name();
	err += test_x509_public_key_info();
	err += test_x509_certificate();
	err += test_x509_cert_request();
	//test_x509_extensions();
	return 1;
}
