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
#include <gmssl/tls.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>

static int test_tls_encode(void)
{
	uint8_t a1 = 200;
	uint16_t a2 = 30000;
	uint24_t a3 = 4000000;
	uint32_t a4 = 4000000000;
	uint8_t data[] = {1, 2, 3, 4, 5, 6, 7, 8};

	uint8_t r1;
	uint16_t r2;
	uint24_t r3;
	uint32_t r4;
	const uint8_t *pdata;
	size_t datalen;

	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	tls_uint8_to_bytes(a1, &p, &len);
	tls_uint16_to_bytes(a2, &p, &len);
	tls_uint24_to_bytes(a3, &p, &len);
	tls_uint32_to_bytes(a4, &p, &len);
	tls_uint8array_to_bytes(data, 5, &p, &len);
	tls_uint16array_to_bytes(data, 6, &p, &len);
	tls_uint24array_to_bytes(data, 7, &p, &len);

	if (tls_uint8_from_bytes(&r1, &cp, &len) != 1 || r1 != a1
		|| tls_uint16_from_bytes(&r2, &cp, &len) != 1 || r2 != a2
		|| tls_uint24_from_bytes(&r3, &cp, &len) != 1 || r3 != a3
		|| tls_uint32_from_bytes(&r4, &cp, &len) != 1 || r4 != a4
		|| tls_uint8array_from_bytes(&pdata, &datalen, &cp, &len) != 1 || datalen != 5 || memcmp(pdata, data, 5) != 0
		|| tls_uint16array_from_bytes(&pdata, &datalen, &cp, &len) != 1 || datalen != 6 || memcmp(pdata, data, 6) != 0
		|| tls_uint24array_from_bytes(&pdata, &datalen, &cp, &len) != 1 || datalen != 7 || memcmp(pdata, data, 7) != 0
		|| len > 0) {
		error_print();
		return 1;
	}

	return 0;
}

static int test_tls_cbc(void)
{
	uint8_t key[32];
	SM3_HMAC_CTX hmac_ctx;
	SM4_KEY sm4_key;
	uint8_t seq_num[8] = { 0,0,0,0,0,0,0,1 };
	uint8_t header[5];
	uint8_t in[] = "hello world";
	uint8_t out[256];
	uint8_t buf[256] = {0};
	size_t len;
	size_t buflen;

	sm3_hmac_init(&hmac_ctx, key, 32);
	sm4_set_encrypt_key(&sm4_key, key);

	tls_cbc_encrypt(&hmac_ctx, &sm4_key, seq_num, header, in, sizeof(in), out, &len);

	printf("%zu\n", len);
	print_der(out, len);
	printf("\n");

	sm3_hmac_init(&hmac_ctx, key, 32);
	sm4_set_decrypt_key(&sm4_key, key);

	tls_cbc_decrypt(&hmac_ctx, &sm4_key, seq_num, header, out, len, buf, &buflen);

	printf("%s\n", buf);


	return 1;
}

static int test_tls_random(void)
{
	uint8_t random[32];
	tls_random_generate(random);
	tls_random_print(stdout, random, 0, 0);
	return 0;
}

static int test_tls_client_hello(void)
{
	uint8_t record[512];
	size_t recordlen = 0;

	int version = TLS_version_tlcp;
	uint8_t random[32];
	uint16_t cipher_suites[] = {
		TLCP_cipher_ecc_sm4_cbc_sm3,
		TLCP_cipher_ecc_sm4_gcm_sm3,
		TLCP_cipher_ecdhe_sm4_cbc_sm3,
		TLCP_cipher_ecdhe_sm4_gcm_sm3,
		TLCP_cipher_ibsdh_sm4_cbc_sm3,
		TLCP_cipher_ibsdh_sm4_gcm_sm3,
		TLCP_cipher_ibc_sm4_cbc_sm3,
		TLCP_cipher_ibc_sm4_gcm_sm3,
		TLCP_cipher_rsa_sm4_cbc_sm3,
		TLCP_cipher_rsa_sm4_gcm_sm3,
		TLCP_cipher_rsa_sm4_cbc_sha256,
		TLCP_cipher_rsa_sm4_gcm_sha256,
	};
	uint8_t comp_meths[] = {0};

	tls_record_set_handshake_client_hello(record, &recordlen,
		version,
		random,
		NULL, 0,
		cipher_suites, sizeof(cipher_suites)/2,
		NULL, 0);

	tls_client_hello_print(stdout, record + 5 + 4, recordlen - 5 -4, 0, 4);
	return 0;
}

static int test_tls_server_hello(void)
{
	uint8_t record[512];
	size_t recordlen = 0;


	uint8_t version[2] = {1,1};
	uint8_t random[32];
	uint16_t cipher_suite = TLCP_cipher_ecdhe_sm4_cbc_sm3;
	uint8_t comp_meth = 0;

	tls_record_set_handshake_server_hello(record, &recordlen,
		version,
		random,
		NULL, 0,
		cipher_suite,
		comp_meth,
		NULL, 0);

	tls_server_hello_print(stdout, record + 5 + 4, recordlen - 5 -4, 0, 0);

	return 0;
}

static int test_tls_certificate(void)
{
	uint8_t record[1024];
	size_t recordlen = 0;
	FILE *fp = NULL;

	if (!(fp = fopen("cacerts.pem", "r"))) {
		error_print();
		return -1;
	}
	if (tls_record_set_handshake_certificate_from_pem(record, &recordlen, fp) != 1) {
		error_print();
		return -1;
	}
	tls_certificate_print(stdout, record + 9, recordlen - 9, 0, 0);
	return 0;
}

static int test_tls_server_key_exchange(void)
{
	uint8_t record[1024];
	size_t recordlen = 0;
	const uint8_t version[] = {1,1};
	uint8_t sig[77];
	size_t siglen;

	tls_record_set_version(record, version);
	if (tlcp_record_set_handshake_server_key_exchange_pke(record, &recordlen, sig, sizeof(sig)) != 1) {
		error_print();
		return -1;
	}
	if (tlcp_record_get_handshake_server_key_exchange_pke(record, sig, &siglen) != 1) {
		error_print();
		return -1;
	}
	tls_server_key_exchange_print(stdout, sig, siglen, 0, 0);
	return 1;
}

static int test_tls_certificate_verify(void)
{
	uint8_t record[1024];
	size_t recordlen = 0;
	const uint8_t version[] = {1,1};
	uint8_t sig[77];
	size_t siglen;

	tls_record_set_version(record, version);
	if (tls_record_set_handshake_certificate_verify(record, &recordlen, sig, sizeof(sig)) != 1) {
		error_print();
		return -1;
	}
	if (tls_record_get_handshake_certificate_verify(record, sig, &siglen) != 1) {
		error_print();
		return -1;
	}
	tls_certificate_verify_print(stdout, sig, siglen, 0, 0);
	return 1;
}

static int test_tls_finished(void)
{
	uint8_t record[1024];
	size_t recordlen = 0;
	uint8_t verify_data[12];

	if (tls_record_set_handshake_finished(record, &recordlen, verify_data) != 1) {
		error_print();
		return -1;
	}
	if (tls_record_get_handshake_finished(record, verify_data) != 1) {
		error_print();
		return -1;
	}
	tls_finished_print(stdout, verify_data, 12, 0, 0);
	return 1;
}

static int test_tls_alert(void)
{
	uint8_t record[1024];
	size_t recordlen = 0;
	int level;
	int reason;

	if (tls_record_set_alert(record, &recordlen, TLS_alert_level_fatal, TLS_alert_close_notify) != 1) {
		error_print();
		return -1;
	}
	if (tls_record_get_alert(record, &level, &reason) != 1) {
		error_print();
		return -1;
	}
	tls_alert_print(stdout, record + 5, recordlen - 5, 0, 0);
	return 1;
}

static int test_tls_change_cipher_spec(void)
{
	uint8_t record[1024];
	size_t recordlen = 0;

	if (tls_record_set_change_cipher_spec(record, &recordlen) != 1) {
		error_print();
		return -1;
	}
	if (tls_record_get_change_cipher_spec(record) != 1) {
		error_print();
		return -1;
	}
	tls_change_cipher_spec_print(stdout, record + 5, recordlen - 5, 0, 0);
	return 1;
}

static int test_tls_application_data(void)
{
	uint8_t record[1024];
	size_t recordlen = 0;
	uint8_t data[88];
	const uint8_t *p;
	size_t len;

	if (tls_record_set_application_data(record, &recordlen, data, sizeof(data)) != 1) {
		error_print();
		return -1;
	}
	if (tls_record_get_application_data(record, &p, &len) != 1) {
		error_print();
		return -1;
	}
	tls_application_data_print(stdout, p, len, 0, 0);
	return 1;
}

int main(void)
{
	int err = 0;
	err += test_tls_encode();
	err += test_tls_cbc();
	err += test_tls_random();
	err += test_tls_client_hello();
	err += test_tls_server_hello();
	err += test_tls_certificate();
	err += test_tls_server_key_exchange();
	err += test_tls_certificate_verify();
	err += test_tls_finished();
	err += test_tls_alert();
	err += test_tls_change_cipher_spec();
	err += test_tls_application_data();
	return 0;
}

