/* 
 *   Copyright 2014-2021 The GmSSL Project Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
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
	uint8_t content_info[512];
	size_t content_info_len = sizeof(content_info);
	size_t len = 0;
	int i;

	memset(data, 'A', sizeof(data));

	cms_content_info_set_data(content_info, &content_info_len, data, sizeof(data));
	cms_content_info_print(stdout, content_info, content_info_len, 0, 0);
	return 1;
}

static int test_cms_sign(void)
{
	SM2_KEY sign_key;
	X509_CERTIFICATE sign_cert;
	uint8_t data[20];
	uint8_t content_info[1024];
	size_t content_info_len = 0;

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
	if (cms_sign(&sign_key, &sign_cert, 1, CMS_data, data, 20, NULL, NULL, 0, content_info, &content_info_len) != 1) {
		error_print();
		return -1;
	}
	cms_content_info_print(stdout, content_info, content_info_len, 0, 0);

	return 1;
}


static int test_cms_enced_content_info(void)
{
	uint8_t buf[512];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	uint8_t iv[16];
	uint8_t enced_content[30];

	if (cms_enced_content_info_to_der(OID_sm4_cbc, iv, sizeof(iv),
		CMS_data, enced_content, sizeof(enced_content),
		NULL, 0,
		NULL, 0,
		&p, &len) != 1) {
		error_print();
		return -1;
	}

	int content_type;
	int enc_algor;
	const uint8_t *enc_iv;
	size_t enc_iv_len;
	const uint8_t *penced_content;
	size_t enced_content_len;
	const uint8_t *shared_info1, *shared_info2;
	size_t shared_info1_len, shared_info2_len;

	if (cms_enced_content_info_from_der(&content_type,
		&enc_algor, &enc_iv, &enc_iv_len,
		&penced_content, &enced_content_len,
		&shared_info1, &shared_info1_len,
		&shared_info2, &shared_info2_len,
		&cp, &len) != 1) {
		error_print();
		return -1;
	}



	return 1;
}


static int test_cms_encrypt(void)
{
	uint8_t key[16];
	uint8_t msg[] = "Hello world!";
	uint8_t cbuf[512];
	uint8_t mbuf[512];
	size_t clen, mlen;
	int content_type = 0;
	const uint8_t *shared_info1 = NULL;
	const uint8_t *shared_info2 = NULL;
	size_t shared_info1_len, shared_info2_len;

	if (cms_encrypt(key, msg, sizeof(msg), cbuf, &clen) != 1) {
		error_print();
		return -1;
	}

	format_bytes(stderr, 0, 0, "EncryptedData\n", cbuf, clen);


	if (cms_decrypt(key, cbuf, clen, &content_type, mbuf, &mlen,
		&shared_info1, &shared_info1_len,
		&shared_info2, &shared_info2_len) != 1) {
		error_print();
		return -1;
	}

	return 1;
}

int main(void)
{
	// 很可能x509_algor.c中有错误！
	test_cms_enced_content_info();
	//test_cms_encrypt();
	//test_cms_data();
	//test_cms_sign();
	return 0;
}
