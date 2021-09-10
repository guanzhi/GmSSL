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

static int test_cms_data(void)
{
	uint8_t data[20];
	uint8_t der[512];
	uint8_t *p = der;
	size_t len = 0;
	int i;

	memset(data, 'A', sizeof(data));
	if (cms_content_info_to_der(CMS_data, data, sizeof(data), &p, &len) != 1
		|| cms_content_info_print(stdout, der, len, 0, 0) != 1) {
		error_print();
		return -1;
	}
	return 0;
}

static int test_cms_enced_content_info(void)
{
	SM4_KEY sm4_key;
	uint8_t key[16] = {0};
	uint8_t iv[16] = {0};
	uint8_t data[] = "Hello!";
	uint8_t buf[512];
	const uint8_t *cp = buf;
	uint8_t *p = buf;
	size_t len = 0;
	int content_type;
	uint8_t content[512] = {0};
	const uint8_t *shared_info1;
	const uint8_t *shared_info2;
	size_t content_len;
	size_t shared_info1_len;
	size_t shared_info2_len;

	sm4_set_encrypt_key(&sm4_key, key);
	if (cms_enced_content_info_encrypt_to_der(&sm4_key, iv,
		CMS_data, data, sizeof(data),
		NULL, 0, NULL, 0, &p, &len) != 1) {
		error_print();
		return -1;
	}

	sm4_set_decrypt_key(&sm4_key, key);
	if (cms_enced_content_info_decrypt_from_der(&sm4_key, &content_type, content, &content_len,
		&shared_info1, &shared_info1_len,
		&shared_info2, &shared_info2_len,
		&cp, &len) != 1) {
		error_print();
		return -1;
	}

	printf("ContentType: %s\n", cms_content_type_name(content_type));
	printf("Content: %s\n", (char *)content);
	printf("SharedInfo1: %s\n", (char *)shared_info1);
	printf("SharedInfo2: %s\n", (char *)shared_info2);
	return 0;
}

static int test_cms_encrypt(void)
{
	uint8_t key[16];
	uint8_t msg[] = "Hello world!";
	uint8_t cbuf[512];
	uint8_t mbuf[512] = {0};
	size_t clen, mlen;
	int content_type = 0;
	const uint8_t *shared_info1 = NULL;
	const uint8_t *shared_info2 = NULL;
	size_t shared_info1_len, shared_info2_len;

	printf("%s()\n", __FUNCTION__);

	if (cms_encrypt(key, msg, sizeof(msg), cbuf, &clen) != 1) {
		error_print();
		return -1;
	}
	cms_content_info_print(stdout, cbuf, clen, 0, 0);

	if (cms_decrypt(key, cbuf, clen, &content_type, mbuf, &mlen) != 1) {
		error_print();
		return -1;
	}
	printf(" ContentType : %s\n", cms_content_type_name(content_type));
	printf(" Content: %s\n", mbuf);
	return 0;
}

static int test_cms_key_agreement_info(void)
{
	SM2_KEY sm2_key;
	X509_CERTIFICATE cert;
	FILE *key_fp = fopen("sign_key.pem", "r");
	FILE *cert_fp = fopen("sign_cert.pem", "r");
	uint8_t buf[512];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	const uint8_t *id;
	size_t idlen;

	if (sm2_private_key_from_pem(&sm2_key, key_fp) != 1) {
		error_print();
		return -1;
	}
	if (x509_certificate_from_pem(&cert, cert_fp) != 1) {
		error_print();
		return -1;
	}

	if (cms_key_agreement_info_to_der(&sm2_key, &cert, (uint8_t *)"Alice", strlen("Alice"), &p, &len) != 1) {
		error_print();
		return -1;
	}
	cms_key_agreement_info_print(stdout, buf, len, 0, 0);
	if (cms_key_agreement_info_from_der(&sm2_key, &cert, &id, &idlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}

	return 0;
}

static int test_cms_issuer_and_serial_number(void)
{
	FILE *cert_fp = fopen("sign_cert.pem", "r");
	X509_CERTIFICATE cert;

	X509_NAME issuer;
	const X509_NAME *issuer_ptr;
	const uint8_t *serial_number;
	size_t serial_number_len;
	const SM2_KEY *sm2_key;

	uint8_t buf[512];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;


	if (x509_certificate_from_pem(&cert, cert_fp) != 1) {
		error_print();
		return -1;
	}

	if (cms_issuer_and_serial_number_from_certificate(&issuer_ptr,
		&serial_number, &serial_number_len, &cert) != 1) {
		error_print();
		return -1;
	}

	if (cms_issuer_and_serial_number_to_der(issuer_ptr, serial_number, serial_number_len, &p, &len) != 1) {
		error_print();
		return -1;
	}

	if (cms_issuer_and_serial_number_from_der(&issuer, &serial_number, &serial_number_len, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	cms_issuer_and_serial_number_print(stdout, &issuer, serial_number, serial_number_len, 0, 0);

	return 0;
}

// 从这个测试可以看出，由于CMS类型非常复杂，因此最好能够将其打包称为一个struct，但是要区分指针类型和存储类型
static int test_cms_recipient_info(void)
{
	FILE *key_fp = fopen("sign_key.pem", "r");
	FILE *cert_fp = fopen("sign_cert.pem", "r");
	X509_CERTIFICATE cert;

	X509_NAME issuer;
	SM2_KEY sm2_key;

	const X509_NAME *issuer_ptr;
	const uint8_t *serial_number;
	size_t serial_number_len;
	const SM2_KEY *pub_key;

	uint8_t key[128] = {1,2,3};
	size_t keylen = 16;


	uint8_t buf[512];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;


	if (x509_certificate_from_pem(&cert, cert_fp) != 1) {
		error_print();
		return -1;
	}
	if (cms_public_key_from_certificate(&pub_key, &cert) != 1) {
		error_print();
		return -1;
	}
	sm2_key_print(stdout, pub_key, 0, 0);

	if (cms_recipient_info_from_x509_certificate(&pub_key, &issuer_ptr, &serial_number, &serial_number_len, &cert) != 1) {
		error_print();
		return -1;
	}

	if (cms_recipient_info_encrypt_to_der(pub_key, issuer_ptr, serial_number, serial_number_len, key, keylen, &p, &len) != 1) {
		error_print();
		return -1;
	}

	int version;
	int pke_algor;
	const uint8_t *params;
	size_t paramslen;
	const uint8_t *enced_key;
	size_t enced_key_len;

	/*
	// 这个函数导致cp, len的长度发生变化		
	if (cms_recipient_info_from_der(&version, &issuer, &serial_number, &serial_number_len,
		&pke_algor, &params, &paramslen,
		&enced_key, &enced_key_len,
		&cp, &len) != 1) {

		error_print();
		return -1;
	}

	cms_recipient_info_print(stdout,
		version, &issuer, serial_number, serial_number_len,
		pke_algor, params, paramslen,
		enced_key, enced_key_len,
		0, 0);
	*/

	if (sm2_private_key_from_pem(&sm2_key, key_fp) != 1) {
		error_print();
		return -1;
	}
	sm2_key_print(stdout, &sm2_key, 0, 0);


	if (cms_recipient_info_decrypt_from_der(&sm2_key, &issuer, &serial_number, &serial_number_len, key, &keylen, &cp, &len) != 1) {
		error_print();
		return -1;
	}
	format_bytes(stdout, 0, 0, "decrypted_key : ", key, keylen);

	return 0;

}


static int test_cms_enveloped_data(void)
{

	FILE *key_fp = fopen("sign_key.pem", "r");
	FILE *cert_fp = fopen("sign_cert.pem", "r");
	X509_CERTIFICATE cert;

	X509_NAME issuer;
	SM2_KEY sm2_key;

	const X509_NAME *issuer_ptr;
	const uint8_t *serial_number;
	size_t serial_number_len;
	const SM2_KEY *pub_key;

	uint8_t key[128] = {1,2,3};
	size_t keylen = 16;


	uint8_t buf[512];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;


	if (x509_certificate_from_pem(&cert, cert_fp) != 1) {
		error_print();
		return -1;
	}

	uint8_t data[8];

	if (cms_enveloped_data_encrypt_to_der(&cert, 1,
		CMS_data, data, sizeof(data),
		NULL, 0, NULL, 0, &p, &len) != 1) {
		error_print();
		return -1;
	}
	error_print_msg("len = %zu\n", len);

	//cms_enveloped_data_print(stdout, cp, len, 0, 0);
	//return 0;

	if (sm2_private_key_from_pem(&sm2_key, key_fp) != 1) {
		error_print();
		return -1;
	}
	int content_type;
	uint8_t content[512];
	size_t content_len;
	const uint8_t *shared_info1, *shared_info2;
	size_t shared_info1_len, shared_info2_len;

	if (cms_enveloped_data_decrypt_from_der(
		&sm2_key, &cert,
		&content_type, content, &content_len,
		&shared_info1, &shared_info1_len,
		&shared_info2, &shared_info2_len,
		&cp, &len) != 1) {
		error_print();
		return -1;
	}


	return 0;
}


static int test_cms_signer_info(void)
{
	FILE *key_fp = fopen("sign_key.pem", "r");
	FILE *cert_fp = fopen("sign_cert.pem", "r");
	X509_CERTIFICATE cert;

	X509_NAME issuer;
	SM2_KEY sm2_key;

	const X509_NAME *issuer_ptr;
	const uint8_t *serial_number;
	size_t serial_number_len;
	const SM2_KEY *pub_key;

	uint8_t key[128] = {1,2,3};
	size_t keylen = 16;

	uint8_t buf[512];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	if (x509_certificate_from_pem(&cert, cert_fp) != 1) {
		error_print();
		return -1;
	}

	if (cms_issuer_and_serial_number_from_certificate(&issuer_ptr,
		&serial_number, &serial_number_len, &cert) != 1) {
		error_print();
		return -1;
	}

	uint8_t attrs[10];

	if (cms_signer_info_to_der(
		issuer_ptr,
		serial_number, serial_number_len,
		OID_sm3,
		attrs, sizeof(attrs),
		attrs, sizeof(attrs),
		attrs, sizeof(attrs),
		&p, &len) != 1) {
		error_print();
		return -1;
	}

	const uint8_t *authed_attrs, *unauthed_attrs, *sig;
	size_t authed_attrs_len, unauthed_attrs_len, siglen;
	int dgst_algor, sign_algor;

	if (cms_signer_info_from_der(
		&issuer,
		&serial_number, &serial_number_len,
		&dgst_algor,
		&authed_attrs, &authed_attrs_len,
		&sign_algor,
		&sig, &siglen,
		&unauthed_attrs, &unauthed_attrs_len,
		&cp, &len) != 1) {
		error_print();
		return -1;
	}


	cms_signer_info_print(stdout,
		1,
		&issuer, serial_number, serial_number_len,
		dgst_algor, NULL, 0,
		authed_attrs, authed_attrs_len,
		sign_algor, NULL, 0,
		sig, siglen,
		unauthed_attrs, unauthed_attrs_len,
		0, 0);

	p = buf;
	cp = buf;
	len = 0;

	SM3_CTX sm3_ctx;

	// 这里根本没有测试验证过程

/*
270 int cms_signer_info_from_der(X509_NAME *issuer,
271         const uint8_t **serial_number, size_t *serial_number_len,
272         int *digest_algor,
273         const uint8_t **authed_attrs, size_t *authed_attrs_len,
274         int *sign_algor,
275         const uint8_t **enced_digest, size_t *enced_digest_len,
276         const uint8_t **unauthed_attrs, size_t *unauthed_attrs_len,
277         const uint8_t **in, size_t *inlen);
*/




	return 0;
}

static int test_cms_signed_data(void)
{
	FILE *key_fp = fopen("sign_key.pem", "r");
	FILE *cert_fp = fopen("sign_cert.pem", "r");
	X509_CERTIFICATE cert;

	X509_NAME issuer;
	SM2_KEY sm2_key;

	const X509_NAME *issuer_ptr;
	const uint8_t *serial_number;
	size_t serial_number_len;
	const SM2_KEY *pub_key;

	uint8_t key[128] = {1,2,3};
	size_t keylen = 16;

	uint8_t buf[1512];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	uint8_t data[10] = {0};


	if (x509_certificate_from_pem(&cert, cert_fp) != 1) {
		error_print();
		return -1;
	}
	if (sm2_private_key_from_pem(&sm2_key, key_fp) != 1) {
		error_print();
		return -1;
	}


	if (cms_signed_data_sign_to_der(&sm2_key, &cert, 1,
		CMS_data, data, sizeof(data),
		NULL, 0,
		&p, &len) != 1) {
		error_print();
		return -1;
	}

	cms_signed_data_print(stdout, buf, len, 0, 0);

	// 这个函数有问题，因为from_der返回的0和验证签名返回的0可能产生冲突
	// 还是应该直接提供一个函数，只做verify，不做from_der


	int content_type;
	const uint8_t *dgst_algors, *content, *certs, *crls, *signer_infos;
	size_t dgst_algors_len, content_len, certs_len, crls_len, signer_infos_len;

	if (cms_signed_data_from_der(
		&dgst_algors, &dgst_algors_len,
		&content_type, &content, &content_len,
		&certs, &certs_len,
		&crls, &crls_len,
		&signer_infos, &signer_infos_len,
		&cp, &len) != 1) {
		error_print();
		return -1;
	}

	if (cms_signed_data_verify(
		content_type, content, content_len,
		certs, certs_len,
		signer_infos, signer_infos_len) != 1) {
		error_print();
		return -1;
	}


	return 0;

}



static int test_cms_sign(void)
{
	SM2_KEY sign_key;
	X509_CERTIFICATE sign_cert;
	uint8_t in[20];
	uint8_t out[1024];
	size_t outlen = 0;

	FILE *key_fp = fopen("sign_key.pem", "r");
	FILE *cert_fp = fopen("sign_cert.pem", "r");

	if (sm2_private_key_from_pem(&sign_key, key_fp) != 1) {
		error_print();
		return -1;
	}
	if (x509_certificate_from_pem(&sign_cert, cert_fp) != 1) {
		error_print();
		return -1;
	}

	if (cms_sign(&sign_key, &sign_cert, 1, in, sizeof(in), out, &outlen) != 1) {
		error_print();
		return -1;
	}

	cms_content_info_print(stdout, out, outlen, 0, 0);

	int content_type;
	const uint8_t *content, *certs, *crls, *signer_infos;
	size_t content_len, certs_len, crls_len, signer_infos_len;

	if (cms_verify(&content_type, &content, &content_len,
		&certs, &certs_len,
		&crls, &crls_len,
		&signer_infos, &signer_infos_len,
		out, outlen) != 1) {
		error_print();
		return -1;
	}


	return 1;
}









int main(void)
{
	//test_cms_data();
	//test_cms_enced_content_info();
	//test_cms_encrypt();
	//test_cms_key_agreement_info();
	//test_cms_issuer_and_serial_number();
	//test_cms_recipient_info();
	//test_cms_signer_info();
	//test_cms_signed_data();
	test_cms_enveloped_data();
	//test_cms_sign();
	return 0;
}
