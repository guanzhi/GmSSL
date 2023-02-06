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
#include <gmssl/x509_req.h>
#include <gmssl/x509.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>


static int test_x509_request_info(void)
{
	uint8_t subject[256];
	size_t subject_len;
	SM2_KEY sm2_key;

	uint8_t attrs_buf[512];
	size_t attrs_len = 0;

	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	const uint8_t *d;
	size_t dlen;

	int version;
	const uint8_t *subj;
	size_t subj_len;
	SM2_KEY pub_key;
	const uint8_t *attrs;

	if (sm2_key_generate(&sm2_key) != 1
		|| x509_name_set(subject, &subject_len, sizeof(subject), "CN", "Beijing", "Haidian", "PKU", "CS", "CA") != 1
		|| x509_request_info_to_der(X509_version_v1, subject, subject_len, &sm2_key, attrs_buf, attrs_len, &p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	x509_request_info_print(stderr, 0, 0, "CertificationRequestInfo", d, dlen);

	p = buf;
	cp = buf;
	len = 0;

	if (x509_request_info_to_der(X509_version_v1, subject, subject_len, &sm2_key, attrs_buf, attrs_len, &p, &len) != 1
		|| x509_request_info_from_der(&version, &subj, &subj_len, &pub_key, &attrs, &attrs_len, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	format_print(stderr, 0, 0, "CertificationRequestInfo\n");
	format_print(stderr, 0, 4, "version: %d\n", version);
	x509_name_print(stderr, 0, 4, "subject", subj, subj_len);
	sm2_public_key_print(stderr, 0, 4, "publicKey", &pub_key);
	format_bytes(stderr, 0, 4, "attributes", attrs, attrs_len);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_request(void)
{
/*
	uint8_t subject[256];
	size_t subject_len;
	SM2_KEY sm2_key;
	uint8_t signature[128] = { 0x01, 0x02 };

	uint8_t buf[512];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	const uint8_t *d;
	size_t dlen;

	int version;
	const uint8_t *subj;
	size_t subj_len;
	SM2_KEY pub_key;
	const uint8_t *attrs;
	size_t attrs_len;
	int sig_alg;
	const uint8_t *sig;
	size_t siglen;

	if (sm2_key_generate(&sm2_key) != 1
		|| x509_name_set(subject, &subject_len, sizeof(subject), "CN", "Beijing", "Haidian", "PKU", "CS", "CA") != 1
		|| x509_request_to_der(X509_version_v1, subject, subject_len, &sm2_key, NULL, 0,
			OID_sm2sign_with_sm3, signature, sizeof(signature), &p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	x509_request_print(stderr, 0, 0, "CertificationRequest", d, dlen);

	p = buf;
	cp = buf;
	len = 0;

	if (x509_request_to_der(X509_version_v1, subject, subject_len, &sm2_key, NULL, 0,
			OID_sm2sign_with_sm3, signature, sizeof(signature), &p, &len) != 1
		|| x509_request_from_der(&version, &subj, &subj_len, &pub_key, &attrs, &attrs_len,
			&sig_alg, &sig, &siglen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	format_print(stderr, 0, 0, "CertificationRequest\n");
	format_print(stderr, 0, 4, "version: %d\n", version);
	x509_name_print(stderr, 0, 4, "subject", subj, subj_len);
	sm2_public_key_print(stderr, 0, 4, "publicKey", &pub_key);
	format_bytes(stderr, 0, 4, "attributes", attrs, attrs_len);
	format_print(stderr, 0, 4, "signatureAlgor: %s\n", x509_signature_algor_name(sig_alg));
	format_bytes(stderr, 0, 4, "signature", sig, siglen);

*/
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_req(void)
{
	uint8_t subject[256];
	size_t subject_len;
	SM2_KEY sm2_key;
	uint8_t attrs[256];
	size_t attrs_len = 0;

	uint8_t req[512];
	uint8_t *p = req;
	size_t reqlen = 0;

	if (sm2_key_generate(&sm2_key) != 1
		|| x509_name_set(subject, &subject_len, sizeof(subject), "CN", "Beijing", "Haidian", "PKU", "CS", "CA") != 1
		|| x509_req_sign_to_der(
			X509_version_v1, subject, subject_len, &sm2_key, attrs, attrs_len,
			OID_sm2sign_with_sm3, &sm2_key, SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID),
			&p, &reqlen) != 1) {
		error_print();
		return -1;
	}
	x509_req_print(stderr, 0, 0, "CertificationRequest", req, reqlen);



	FILE *fp;

	if ((fp = fopen("req.pem", "w")) == NULL) {
		error_print();
		return -1;
	}
	if (x509_req_to_pem(req, reqlen, fp) != 1) {
		error_print();
		return -1;
	}
	fclose(fp);
	x509_req_to_pem(req, reqlen, stderr);


	memset(req, 0, sizeof(req));

	if ((fp = fopen("req.pem", "r")) == NULL) {
		error_print();
		return -1;
	}
	if (x509_req_from_pem(req, &reqlen, sizeof(req), fp) != 1) {
		error_print();
		return -1;
	}
	if (x509_req_verify(req, reqlen, SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID)) != 1) {
		error_print();
		return -1;
	}
	format_print(stderr, 0, 0, "x509_req_verify() success\n");





	printf("%s() ok\n", __FUNCTION__);
	return 1;
}










int main(void)
{
	if (test_x509_request_info() != 1) goto err;
	if (test_x509_request() != 1) goto err;
	if (test_x509_req() != 1) goto err;
	printf("%s all tests passed!\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}

