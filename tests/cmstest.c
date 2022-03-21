/*
 * Copyright (c) 2021 - 2021 The GmSSL Project.  All rights reserved.
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
	return 0;
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
	return 0;
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
	return 0;
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
	const uint8_t *piv;
	size_t ivlen;
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
	return 0;
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
	return 0;
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
	size_t siglen;

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
	return 0;
}

static int test_cms_signer_info_sign(void)
{
	uint8_t buf[512];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	const uint8_t *d;
	size_t dlen;

	SM3_CTX sm3_ctx;
	SM2_KEY sm2_key;

	uint8_t issuer_buf[256];
	size_t issuer_len;
	uint8_t serial_buf[20];
	uint8_t auth_attrs_buf[80];

	// 这个函数的验证是需要证书的			
	uint8_t certs[1024];
	size_t certslen;
	const uint8_t *cert;
	size_t certlen;

	const uint8_t *issuer;
	const uint8_t *serial;
	size_t serial_len;
	const uint8_t *auth_attrs;
	size_t auth_attrs_len;
	const uint8_t *unauth_attrs;
	size_t unauth_attrs_len;


	sm2_key_generate(&sm2_key);
	sm3_init(&sm3_ctx);
	sm3_update(&sm3_ctx, (uint8_t *)"hello", 5);

	x509_name_set(issuer_buf, &issuer_len, sizeof(issuer_buf), "CN", "Beijing", "Haidian", "PKU", "CS", "CA");

	if (cms_signer_info_sign_to_der(
			&sm3_ctx, &sm2_key,
			issuer_buf, issuer_len,
			serial_buf, sizeof(serial_buf),
			NULL, 0,
			NULL, 0,
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
			issuer_buf, issuer_len,
			serial_buf, sizeof(serial_buf),
			NULL, 0,
			NULL, 0,
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
	return 0;
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
	return 0;
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
	return 0;
}

static int test_cms_signed_data(void)
{
	// 这个函数需要证书了，我们需要一个很容易生成证书的函数。

	return -1;
}

















int main(int argc, char **argv)
{
	int err;
	err += test_cms_content_type();
	err += test_cms_content_info();
	err += test_cms_enced_content_info();
	err += test_cms_enced_content_info_encrypt();
	err += test_cms_issuer_and_serial_number();
	err += test_cms_signer_info();
	err += test_cms_signer_info_sign();
	err += test_cms_signer_infos();
	err += test_cms_digest_algors();
	return err;
}
