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
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include <gmssl/sm4.h>
#include <gmssl/cms.h>


static int test_cms_content_type(void)
{
	int tests[] = {
		OID_cms_data,
		OID_cms_signed_data,
		OID_cms_enveloped_data,
		OID_cms_signed_and_enveloped_data,
		OID_cms_encrypted_data,
		OID_cms_key_agreement_info,
	};
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	int i;

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (cms_content_type_to_der(tests[i], &p, &len) != 1) {
			error_print();
			return -1;
		}
		format_bytes(stderr, 0, 4, "", buf, len);
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		int oid;
		if (cms_content_type_from_der(&oid, &cp, &len) != 1
			|| asn1_check(oid == tests[i]) != 1) {
			error_print();
			return -1;
		}
		format_print(stderr, 0, 4, "%s\n", cms_content_type_name(oid));
	}
	(void)asn1_length_is_zero(len);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_cms_content_info(void)
{
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	uint8_t data[20] = { 0x01,0x02 };
	int oid;
	const uint8_t *d;
	size_t dlen;

	if (cms_content_info_to_der(OID_cms_data, data, sizeof(data), &p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	cms_content_info_print(stderr, 0, 0, "ContentInfo", d, dlen);

	p = buf;
	cp = buf;
	len = 0;

// 当类型为OID_cms_data, 数据是OCTET STRING，需要再解析一次

	if (cms_content_info_to_der(OID_cms_data, data, sizeof(data), &p, &len) != 1
		|| cms_content_info_from_der(&oid, &d, &dlen, &cp, &len) != 1
		|| asn1_check(oid == OID_cms_data) != 1
//		|| asn1_check(dlen == sizeof(data)) != 1
//		|| asn1_check(memcmp(data, d, dlen) == 0) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_cms_enced_content_info(void)
{
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	uint8_t iv[16] = {0};
	uint8_t enced[32] = { 0x01,0x02 };
	const uint8_t *d;
	size_t dlen;

	int oid;
	int cipher;
	const uint8_t *piv;
	size_t ivlen;
	const uint8_t *shared_info1;
	size_t shared_info1_len;
	const uint8_t *shared_info2;
	size_t shared_info2_len;

	if (cms_enced_content_info_to_der(OID_cms_data,
			OID_sm4_cbc, iv, sizeof(iv), enced, sizeof(enced),
			NULL, 0, NULL, 0, &p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	cms_enced_content_info_print(stderr, 0, 0, "EncryptedContentInfo", d, dlen);

	p = buf;
	cp = buf;
	len = 0;

	if (cms_enced_content_info_to_der(OID_cms_data,
			OID_sm4_cbc, iv, sizeof(iv), enced, sizeof(enced),
			NULL, 0, NULL, 0, &p, &len) != 1
		|| cms_enced_content_info_from_der(&oid,
			&cipher, &piv, &ivlen, &d, &dlen,
			&shared_info1, &shared_info1_len,
			&shared_info2, &shared_info2_len, &cp, &len) != 1
		|| asn1_check(oid == OID_cms_data) != 1
		|| asn1_check(cipher == OID_sm4_cbc) != 1
		|| asn1_check(ivlen == sizeof(iv)) != 1
		|| asn1_check(dlen == sizeof(enced)) != 1
		|| asn1_check(shared_info1 == NULL) != 1
		|| asn1_check(shared_info1_len == 0) != 1
		|| asn1_check(shared_info2 == NULL) != 1
		|| asn1_check(shared_info2_len == 0) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_cms_enced_content_info_encrypt(void)
{
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	uint8_t key[16] = {0};
	uint8_t iv[16] = {1};
	uint8_t data[20] = {2};

	const uint8_t *d;
	size_t dlen;

	int oid;
	int cipher;
	uint8_t data2[256];
	const uint8_t *shared_info1;
	size_t shared_info1_len;
	const uint8_t *shared_info2;
	size_t shared_info2_len;

	if (cms_enced_content_info_encrypt_to_der(
			OID_sm4_cbc,
			key, sizeof(key),
			iv, sizeof(iv),
			OID_cms_data, data, sizeof(data),
			NULL, 0,
			NULL, 0,
			&p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	cms_enced_content_info_print(stderr, 0, 0, "EncryptedContentInfo", d, dlen);

	p = buf;
	cp = buf;
	len = 0;

	if (cms_enced_content_info_encrypt_to_der(
			OID_sm4_cbc,
			key, sizeof(key),
			iv, sizeof(iv),
			OID_cms_data, data, sizeof(data),
			NULL, 0,
			NULL, 0,
			&p, &len) != 1
		// 显然这个解密函数是有问题的，在from_der的时候不知道密文的长度，因此无法知道需要的输出缓冲长度				
		|| cms_enced_content_info_decrypt_from_der(
			&cipher,
			key, sizeof(key),
			&oid, data2, &dlen,
			&shared_info1, &shared_info1_len,
			&shared_info2, &shared_info2_len,
			&cp, &len) != 1
		|| asn1_check(cipher == OID_sm4_cbc) != 1
		|| asn1_check(oid = OID_cms_data) != 1
		|| asn1_check(dlen == sizeof(data)) != 1
		|| asn1_check(memcmp(data, data2, dlen) == 0) != 1
		|| asn1_check(shared_info1 == NULL) != 1
		|| asn1_check(shared_info2 == NULL) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_cms_issuer_and_serial_number(void)
{
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	uint8_t issuer[256];
	size_t issuer_len;
	uint8_t serial[20] = {1};

	const uint8_t *d;
	size_t dlen;
	const uint8_t *pissuer;
	const uint8_t *pserial;
	size_t serial_len;

	if (x509_name_set(issuer, &issuer_len, sizeof(issuer),
			"CN", "Beijing", "Haidian", "PKU", "CS", "CA") != 1
		|| cms_issuer_and_serial_number_to_der(
			issuer, issuer_len, serial, sizeof(serial), &p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	cms_issuer_and_serial_number_print(stderr, 0, 0, "IssuerAndSerialNumber", d, dlen);

	p = buf;
	cp = buf;
	len = 0;

	if (x509_name_set(issuer, &issuer_len, sizeof(issuer),
			"CN", "Beijing", "Haidian", "PKU", "CS", "CA") != 1
		|| cms_issuer_and_serial_number_to_der(
			issuer, issuer_len, serial, sizeof(serial), &p, &len) != 1
		|| cms_issuer_and_serial_number_from_der(
			&pissuer, &issuer_len, &pserial, &serial_len, &cp, &len) != 1
		|| asn1_check(memcmp(pissuer, issuer, issuer_len) == 0) != 1
		|| asn1_check(serial_len == sizeof(serial)) != 1
		|| asn1_check(memcmp(serial, pserial, serial_len) == 0) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_cms_signer_info(void)
{
	uint8_t buf[512];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	const uint8_t *d;
	size_t dlen;

	uint8_t issuer_buf[256];
	size_t issuer_len;
	uint8_t serial_buf[20];
	uint8_t sig_buf[256];
	size_t siglen = sizeof(sig_buf);

	int version;
	const uint8_t *issuer;
	const uint8_t *serial;
	size_t serial_len;
	int digest_alg;
	const uint8_t *auth_attrs;
	size_t auth_attrs_len;
	int sig_alg;
	const uint8_t *sig;
	const uint8_t *unauth_attrs;
	size_t unauth_attrs_len;


	if (x509_name_set(issuer_buf, &issuer_len, sizeof(issuer_buf),
		"CN", "Beijing", "Haidian", "PKU", "CS", "CA") != 1) {
		error_print();
		return -1;
	}

	if (cms_signer_info_to_der(
			CMS_version_v1,
			issuer_buf, issuer_len,
			serial_buf, sizeof(serial_buf),
			OID_sm3,
			NULL, 0,
			OID_sm2sign_with_sm3,
			sig_buf, siglen,
			NULL, 0,
			&p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	cms_signer_info_print(stderr, 0, 0, "SignerInfo", d, dlen);

	cp = p = buf; len = 0;
	if (cms_signer_info_to_der(
			CMS_version_v1,
			issuer_buf, issuer_len,
			serial_buf, sizeof(serial_buf),
			OID_sm3,
			NULL, 0,
			OID_sm2sign_with_sm3,
			sig_buf, siglen,
			NULL, 0,
			&p, &len) != 1
		|| cms_signer_info_from_der(
			&version,
			&issuer, &issuer_len,
			&serial, &serial_len,
			&digest_alg,
			&auth_attrs, &auth_attrs_len,
			&sig_alg,
			&sig, &siglen,
			&unauth_attrs, &unauth_attrs_len,
			&cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_cms_signer_info_sign(void)
{
	uint8_t buf[1024];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	const uint8_t *d;
	size_t dlen;

	SM2_KEY sm2_key;
	uint8_t serial_buf[20];
	uint8_t name[256];
	size_t namelen;
	time_t not_before, not_after;
	uint8_t certs[1024];
	size_t certslen = 0;
	uint8_t *pcerts = certs;

	SM3_CTX sm3_ctx;

	const uint8_t *cert;
	size_t certlen;
	const uint8_t *serial;
	const uint8_t *issuer;
	const uint8_t *auth_attrs;
	const uint8_t *unauth_attrs;
	size_t serial_len, issuer_len, auth_attrs_len, unauth_attrs_len;

	if (sm2_key_generate(&sm2_key) != 1
		|| rand_bytes(serial_buf, sizeof(serial_buf)) != 1
		|| x509_name_set(name, &namelen, sizeof(name), "CN", "Beijing", "Haidian", "PKU", "CS", "Alice") != 1
		|| time(&not_before) == -1
		|| x509_validity_add_days(&not_after, not_before, 365) != 1
		|| x509_cert_sign_to_der(
			X509_version_v3, serial_buf, sizeof(serial_buf),
			OID_sm2sign_with_sm3,
			name, namelen,
			not_before, not_after,
			name, namelen,
			&sm2_key, NULL, 0, NULL, 0, NULL, 0,
			&sm2_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH,
			&pcerts, &certslen) != 1) {
		error_print();
		return -1;
	}

	sm3_init(&sm3_ctx);
	sm3_update(&sm3_ctx, (uint8_t *)"hello", 5);

	cp = p = buf; len = 0;
	if (cms_signer_info_sign_to_der(
			&sm3_ctx, &sm2_key,
			name, namelen, serial_buf, sizeof(serial_buf),
			NULL, 0, NULL, 0,
			&p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	cms_signer_info_print(stderr, 0, 0, "SignerInfo", d, dlen);

	cp = p = buf; len = 0;
	if (cms_signer_info_sign_to_der(
			&sm3_ctx, &sm2_key,
			name, namelen, serial_buf, sizeof(serial_buf),
			NULL, 0, NULL, 0,
			&p, &len) != 1
		|| cms_signer_info_verify_from_der(
			&sm3_ctx, certs, certslen,
			&cert, &certlen,
			&issuer, &issuer_len,
			&serial, &serial_len,
			&auth_attrs, &auth_attrs_len,
			&unauth_attrs, &unauth_attrs_len,
			&cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_cms_signer_infos(void)
{
	uint8_t buf[1280];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	const uint8_t *d;
	size_t dlen;

	uint8_t signer_infos[1024];
	size_t signer_infos_len = 0;

	SM3_CTX sm3_ctx;
	SM2_KEY sm2_key;

	uint8_t issuer_buf[256];
	size_t issuer_len;
	uint8_t serial_buf[20];

	sm2_key_generate(&sm2_key);
	sm3_init(&sm3_ctx);
	sm3_update(&sm3_ctx, (uint8_t *)"hello", 5);
	x509_name_set(issuer_buf, &issuer_len, sizeof(issuer_buf), "CN", "Beijing", "Haidian", "PKU", "CS", "CA");


	if (cms_signer_infos_add_signer_info(
			signer_infos, &signer_infos_len, sizeof(signer_infos),
			&sm3_ctx, &sm2_key,
			issuer_buf, issuer_len,
			serial_buf, sizeof(serial_buf),
			NULL, 0,
			NULL, 0) != 1
		|| cms_signer_infos_add_signer_info(
			signer_infos, &signer_infos_len, sizeof(signer_infos),
			&sm3_ctx, &sm2_key,
			issuer_buf, issuer_len,
			serial_buf, sizeof(serial_buf),
			NULL, 0,
			NULL, 0) != 1
		|| cms_signer_infos_add_signer_info(
			signer_infos, &signer_infos_len, sizeof(signer_infos),
			&sm3_ctx, &sm2_key,
			issuer_buf, issuer_len,
			serial_buf, sizeof(serial_buf),
			NULL, 0,
			NULL, 0) != 1
		|| cms_signer_infos_to_der(signer_infos, signer_infos_len, &p, &len) != 1
		|| cms_signer_infos_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1){
		error_print();
		return -1;
	}
	cms_signer_infos_print(stderr, 0, 0, "SET OF SignerInfo", d, dlen);


	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_cms_digest_algors(void)
{
	uint8_t buf[512];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	const uint8_t *d;
	size_t dlen;

	int oids[] = {
		OID_sm3,
		OID_md5,
		OID_sha1,
		OID_sha256,
		OID_sha512,
	};

	int algs[16];
	size_t algs_cnt;

	if (cms_digest_algors_to_der(oids, sizeof(oids)/sizeof(oids[0]), &p, &len) != 1
		|| asn1_set_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	cms_digest_algors_print(stderr, 0, 0, "digestAlgorithms", d, dlen);

	if (cms_digest_algors_to_der(oids, sizeof(oids)/sizeof(oids[0]), &p, &len) != 1
		|| cms_digest_algors_from_der(algs, &algs_cnt, sizeof(algs)/sizeof(algs[0]), &cp, &len) != 1
		|| asn1_check(algs_cnt == sizeof(oids)/sizeof(oids[0])) != 1
		|| asn1_check(memcmp(algs, oids, sizeof(oids)) == 0) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_cms_signed_data(void)
{
	SM2_KEY sm2_key;
	uint8_t cert[4096];
	size_t certlen = 0;
	CMS_CERTS_AND_KEY signers[1];
	uint8_t data[48] = {0};
	uint8_t buf[4096];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	const uint8_t *d;
	size_t dlen;

	sm2_key_generate(&sm2_key);

	{
		uint8_t serial[20];
		size_t serial_len = sizeof(serial);
		uint8_t name[256];
		size_t namelen = 0;
		time_t not_before, not_after;
		size_t subject_len = 0;
		uint8_t *p = cert;
		const uint8_t *cp = cert;

		rand_bytes(serial, sizeof(serial));
		x509_name_set(name, &namelen, sizeof(name), "CN", "Beijing", "Haidian", "PKU", "CS", "CA");
		time(&not_before);
		x509_validity_add_days(&not_after, not_before, 365);

		if (x509_cert_sign_to_der(
			X509_version_v3,
			serial, sizeof(serial),
			OID_sm2sign_with_sm3,
			name, namelen,
			not_before, not_after,
			name, namelen,
			&sm2_key,
			NULL, 0,
			NULL, 0,
			NULL, 0,
			&sm2_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH,
			&p, &certlen) != 1) {
			error_print();
			return -1;
		}
	}

	signers[0].certs = cert;
	signers[0].certs_len = certlen;
	signers[0].sign_key = &sm2_key;

	if (cms_signed_data_sign_to_der(
			signers, sizeof(signers)/sizeof(signers[0]),
			OID_cms_data, data, sizeof(data),
			NULL, 0,
			&p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	cms_signed_data_print(stderr, 0, 0, "SignedData", d, dlen);

	cp = p = buf; len = 0;
	{
		int content_type;
		const uint8_t *content;
		size_t content_len;
		const uint8_t *certs;
		size_t certslen;
		const uint8_t *crls;
		size_t crlslen;
		const uint8_t *signer_infos;
		size_t signer_infos_len;

		if (cms_signed_data_sign_to_der(
				signers, sizeof(signers)/sizeof(signers[0]),
				OID_cms_data, data, sizeof(data),
				NULL, 0,
				&p, &len) != 1
			|| cms_signed_data_verify_from_der(
				NULL, 0,
				NULL, 0,
				&content_type, &content, &content_len,
				&certs, &certslen,
				&crls, &crlslen,
				&signer_infos, &signer_infos_len,
				&cp, &len) != 1
			|| asn1_length_is_zero(len) != 1) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_cms_recipient_info(void)
{
	SM2_KEY sm2_key;
	uint8_t name[256];
	size_t namelen;
	uint8_t serial_buf[20];
	uint8_t in[16];

	uint8_t buf[1024];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	const uint8_t *d;
	size_t dlen;

	int version;
	const uint8_t *issuer;
	size_t issuer_len;
	const uint8_t *serial;
	size_t serial_len;
	int pke_algor;
	const uint8_t *params;
	size_t params_len;
	const uint8_t *enced_key;
	size_t enced_key_len;

	uint8_t out[sizeof(in)];
	size_t outlen;

	sm2_key_generate(&sm2_key);
	x509_name_set(name, &namelen, sizeof(name), "US", "CA", NULL, "BB", "AA", "CC");
	rand_bytes(serial_buf, sizeof(serial_buf));
	rand_bytes(in, sizeof(in));

	if (cms_recipient_info_encrypt_to_der(&sm2_key,
			name, namelen,
			serial_buf, sizeof(serial_buf),
			in, sizeof(in),
			&p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	cms_recipient_info_print(stderr, 0, 0, "RecipientInfo", d, dlen);


	cp = p = buf; len = 0;
	if (cms_recipient_info_encrypt_to_der(&sm2_key,
			name, namelen,
			serial_buf, sizeof(serial_buf),
			in, sizeof(in),
			&p, &len) != 1
		|| cms_recipient_info_from_der(
			&version,
			&issuer, &issuer_len,
			&serial, &serial_len,
			&pke_algor, &params, &params_len,
			&enced_key, &enced_key_len,
			&cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}


	cp = p = buf; len = 0;
	if (cms_recipient_info_encrypt_to_der(
			&sm2_key,
			name, namelen,
			serial_buf, sizeof(serial_buf),
			in, sizeof(in),
			&p, &len) != 1
		|| cms_recipient_info_decrypt_from_der(
			&sm2_key,
			name, namelen,
			serial_buf, sizeof(serial_buf),
			out, &outlen, sizeof(out),
			&cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	if (sizeof(in) != outlen
		|| memcmp(in, out, outlen) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int test_cms_enveloped_data(void)
{
	SM2_KEY sm2_key1;
	uint8_t name1[256];
	size_t name1_len;
	uint8_t serial1[20];

	SM2_KEY sm2_key2;
	uint8_t name2[256];
	size_t name2_len;
	uint8_t serial2[20];

	time_t not_before, not_after;

	uint8_t certs[2048];
	size_t certslen;

	uint8_t key[16];
	uint8_t iv[16];

	uint8_t in[80];
	uint8_t out[256];
	size_t outlen;

	uint8_t buf[4096];
	uint8_t *p;
	const uint8_t *cp;
	size_t len;
	const uint8_t *d;
	size_t dlen;

	// prepare keys and certs

	if (time(&not_before) == -1
		|| x509_validity_add_days(&not_after, not_before, 365) != 1) {
		error_print();
		return -1;
	}

	p = certs;
	certslen = 0;

	if (sm2_key_generate(&sm2_key1) != 1
		|| rand_bytes(serial1, sizeof(serial1)) != 1
		|| x509_name_set(name1, &name1_len, sizeof(name1), "CN", "Beijing", "Haidian", "PKU", "CS", "Alice") != 1
		|| x509_cert_sign_to_der(
			X509_version_v3,
			serial1, sizeof(serial1),
			OID_sm2sign_with_sm3,
			name1, name1_len,
			not_before, not_after,
			name1, name1_len,
			&sm2_key1, NULL, 0, NULL, 0, NULL, 0,
			&sm2_key1, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH,
			&p, &certslen) != 1) {
		error_print();
		return -1;
	}

	if (sm2_key_generate(&sm2_key2) != 1
		|| rand_bytes(serial2, sizeof(serial2)) != 1
		|| x509_name_set(name2, &name2_len, sizeof(name2), "CN", "Beijing", "Haidian", "PKU", "CS", "Bob") != 1
		|| x509_cert_sign_to_der(
			X509_version_v3,
			serial2, sizeof(serial2),
			OID_sm2sign_with_sm3,
			name2, name2_len,
			not_before, not_after,
			name2, name2_len,
			&sm2_key2, NULL, 0, NULL, 0, NULL, 0,
			&sm2_key2, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH,
			&p, &certslen) != 1) {
		error_print();
		return -1;
	}

	rand_bytes(key, sizeof(key));
	rand_bytes(iv, sizeof(iv));
	rand_bytes(in, sizeof(in));

	// test

	cp = p = buf; len = 0;
	if (cms_enveloped_data_encrypt_to_der(
			certs, certslen,
			OID_sm4_cbc, key, sizeof(key), iv, sizeof(iv),
			OID_cms_data, in, sizeof(in),
			NULL, 0, NULL, 0,
			&p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	cms_enveloped_data_print(stderr, 0, 0, "EnvelopedData", d, dlen);


	int content_type;


	cp = p = buf; len = 0;
	if (cms_enveloped_data_encrypt_to_der(
			certs, certslen,
			OID_sm4_cbc, key, sizeof(key), iv, sizeof(iv),
			OID_cms_data, in, sizeof(in),
			NULL, 0, NULL, 0,
			&p, &len) != 1) {
		error_print();
		return -1;
	}

	const uint8_t *rcpt_infos;
	const uint8_t *shared_info1;
	const uint8_t *shared_info2;
	size_t rcpt_infos_len, shared_info1_len, shared_info2_len;

	if (cms_enveloped_data_decrypt_from_der(
			&sm2_key1,
			name1, name1_len,
			serial1, sizeof(serial1),
			&content_type, out, &outlen,
			&rcpt_infos, &rcpt_infos_len,
			&shared_info1, &shared_info1_len,
			&shared_info2, &shared_info2_len,
			&cp, &len) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_cms_signed_and_enveloped_data(void)
{
/*
	SM2_KEY sign_key;
	SM2_KEY decr_key;



	uint8_t sign_serial[20];
	uint8_t sign_name[256];
	size_t sign_name_len;
*/

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_cms_key_agreement_info(void)
{
	SM2_KEY sm2_key;
	uint8_t name[256];
	size_t namelen;
	uint8_t serial[20];
	time_t not_before, not_after;
	uint8_t cert[2048];
	size_t certlen = 0;

	uint8_t buf[4096];
	uint8_t *p;
	const uint8_t *cp;
	size_t len;
	const uint8_t *d;
	size_t dlen;

	int version;
	SM2_KEY public_key;
	const uint8_t *pcert;
	size_t pcertlen;
	const uint8_t *id;
	size_t idlen;

	p = cert;
	if (sm2_key_generate(&sm2_key) != 1
		|| rand_bytes(serial, sizeof(serial)) != 1
		|| x509_name_set(name, &namelen, sizeof(name), "CN", "Beijing", "Haidian", "PKU", "CS", "Alice") != 1
		|| time(&not_before) == - 1
		|| x509_validity_add_days(&not_after, not_before, 365) != 1
		|| x509_cert_sign_to_der(
			X509_version_v3,
			serial, sizeof(serial),
			OID_sm2sign_with_sm3,
			name, namelen,
			not_before, not_after,
			name, namelen,
			&sm2_key, NULL, 0, NULL, 0, NULL, 0,
			&sm2_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH,
			&p, &certlen) != 1) {
		error_print();
		return -1;
	}

	cp = p = buf; len = 0;
	if (cms_key_agreement_info_to_der(
			CMS_version_v1,
			&sm2_key,
			cert, certlen,
			(uint8_t *)SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH,
			&p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	cms_key_agreement_info_print(stderr, 0, 0, "KeyAgreementInfo", d, dlen);


	cp = p = buf; len = 0;
	if (cms_key_agreement_info_to_der(
			CMS_version_v1,
			&sm2_key,
			cert, certlen,
			(uint8_t *)SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH,
			&p, &len) != 1
		|| cms_key_agreement_info_from_der(
			&version,
			&public_key,
			&pcert, &pcertlen,
			&id, &idlen,
			&cp, &len) != 1
		|| asn1_check(version == CMS_version_v1) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	if (sm2_public_key_equ(&sm2_key, &public_key) != 1) {
		error_print();
		return -1;
	}
	if (pcertlen != certlen
		|| memcmp(pcert, cert, certlen) != 0
		|| idlen != SM2_DEFAULT_ID_LENGTH
		|| memcmp(SM2_DEFAULT_ID, id, idlen) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(int argc, char **argv)
{
	if (test_cms_content_type() != 1) goto err;
	if (test_cms_content_info() != 1) goto err;
	if (test_cms_enced_content_info() != 1) goto err;
	if (test_cms_enced_content_info_encrypt() != 1) goto err;
	if (test_cms_issuer_and_serial_number() != 1) goto err;
	if (test_cms_signer_info() != 1) goto err;
	if (test_cms_signer_info_sign() != 1) goto err;
	if (test_cms_signer_infos() != 1) goto err;
	if (test_cms_digest_algors() != 1) goto err;
	if (test_cms_signed_data() != 1) goto err;
	if (test_cms_recipient_info() != 1) goto err;
	if (test_cms_enveloped_data() != 1) goto err;
	if (test_cms_key_agreement_info() != 1) goto err;

	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return -1;
}
