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
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_tls_null_to_bytes(void)
{
	uint8_t buf[10];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	tls_uint16array_to_bytes(buf, sizeof(buf), NULL, &len);

	// this will segment fault
	//p = NULL;
	//tls_uint16array_to_bytes(buf, sizeof(buf), &p, &len);

	return 1;
}

static int test_tls_cbc(void)
{
	uint8_t key[32] = {0};
	HMAC_CTX hmac_ctx;
	BLOCK_CIPHER_KEY sm4_key;
#if defined(ENABLE_AES) && defined(ENABLE_SHA2)
	BLOCK_CIPHER_KEY aes_key;
	uint8_t aes_out[256];
	uint8_t aes_buf[256] = {0};
	size_t aes_len;
	size_t aes_buflen;
#endif
	uint8_t seq_num[8] = { 0,0,0,0,0,0,0,1 };
	uint8_t header[5];
	uint8_t in[] = "hello world";
	uint8_t out[256];
	uint8_t buf[256] = {0};
	size_t len;
	size_t buflen;

	header[0] = TLS_record_handshake;
	header[1] = TLS_protocol_tls12 >> 8;
	header[2] = TLS_protocol_tls12 & 0xff;
	header[3] = sizeof(in) >> 8;
	header[4] = sizeof(in) & 0xff;

	hmac_init(&hmac_ctx, DIGEST_sm3(), key, 32);
	block_cipher_set_encrypt_key(&sm4_key, BLOCK_CIPHER_sm4(), key);
	tls_cbc_encrypt(&hmac_ctx, &sm4_key, seq_num, header, in, sizeof(in), out, &len);

	hmac_init(&hmac_ctx, DIGEST_sm3(), key, 32);
	block_cipher_set_decrypt_key(&sm4_key, BLOCK_CIPHER_sm4(), key);

	tls_cbc_decrypt(&hmac_ctx, &sm4_key, seq_num, header, out, len, buf, &buflen);
	if (buflen != sizeof(in) || memcmp(buf, in, sizeof(in)) != 0) {
		error_print();
		return -1;
	}

#if defined(ENABLE_AES) && defined(ENABLE_SHA2)
	hmac_init(&hmac_ctx, DIGEST_sha256(), key, sizeof(key));
	block_cipher_set_encrypt_key(&aes_key, BLOCK_CIPHER_aes128(), key);
	if (tls_cbc_encrypt(&hmac_ctx, &aes_key, seq_num, header, in, sizeof(in), aes_out, &aes_len) != 1) {
		error_print();
		return -1;
	}

	hmac_init(&hmac_ctx, DIGEST_sha256(), key, sizeof(key));
	block_cipher_set_decrypt_key(&aes_key, BLOCK_CIPHER_aes128(), key);
	if (tls_cbc_decrypt(&hmac_ctx, &aes_key, seq_num, header, aes_out, aes_len, aes_buf, &aes_buflen) != 1) {
		error_print();
		return -1;
	}
	if (aes_buflen != sizeof(in) || memcmp(aes_buf, in, sizeof(in)) != 0) {
		error_print();
		return -1;
	}
#endif

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

#ifdef ENABLE_AES_CCM
static int test_tls_ccm(void)
{
	uint8_t key[16] = {0};
	BLOCK_CIPHER_KEY aes_key;
	uint8_t fixed_iv[4] = {0x10, 0x11, 0x12, 0x13};
	uint8_t seq_num[8] = {0,0,0,0,0,0,0,1};
	uint8_t record[5 + 32];
	uint8_t enced_record[256];
	uint8_t buf[256];
	size_t recordlen;
	size_t enced_recordlen;
	size_t buflen;

	record[0] = TLS_record_handshake;
	record[1] = TLS_protocol_tls12 >> 8;
	record[2] = TLS_protocol_tls12 & 0xff;
	record[3] = 0;
	record[4] = 12;
	memcpy(record + 5, "hello world", 12);
	recordlen = 5 + 12;

	block_cipher_set_encrypt_key(&aes_key, BLOCK_CIPHER_aes128(), key);
	if (tls_ccm_encrypt(&aes_key, fixed_iv, seq_num, record,
		record + 5, 12, enced_record + 5, &enced_recordlen) != 1) {
		error_print();
		return -1;
	}
	enced_record[0] = record[0];
	enced_record[1] = record[1];
	enced_record[2] = record[2];
	enced_record[3] = (uint8_t)(enced_recordlen >> 8);
	enced_record[4] = (uint8_t)enced_recordlen;
	enced_recordlen += 5;

	if (tls_record_decrypt(TLS_cipher_ecdhe_ecdsa_with_aes_128_ccm, NULL, &aes_key, fixed_iv, seq_num,
		enced_record, enced_recordlen, buf, &buflen) != 1
		|| buflen != recordlen
		|| memcmp(buf, record, recordlen) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}
#endif

static int test_tls_random(void)
{
	uint8_t random[32];
	tls_random_generate(random);
	tls_random_print(stdout, random, 0, 0);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_tls_client_hello(void)
{
	uint8_t record[512];
	size_t recordlen = 0;

	int version = TLS_protocol_tlcp;
	uint8_t random[32];
	int cipher_suites[] = {
		TLS_cipher_ecc_sm4_cbc_sm3,
		TLS_cipher_ecc_sm4_gcm_sm3,
		TLS_cipher_ecdhe_sm4_cbc_sm3,
		TLS_cipher_ecdhe_sm4_gcm_sm3,
		TLS_cipher_ibsdh_sm4_cbc_sm3,
		TLS_cipher_ibsdh_sm4_gcm_sm3,
		TLS_cipher_ibc_sm4_cbc_sm3,
		TLS_cipher_ibc_sm4_gcm_sm3,
		TLS_cipher_rsa_sm4_cbc_sm3,
		TLS_cipher_rsa_sm4_gcm_sm3,
		TLS_cipher_rsa_sm4_cbc_sha256,
		TLS_cipher_rsa_sm4_gcm_sha256,
	};
	int comp_meths[] = {0};

	tls_record_set_protocol(record, TLS_protocol_tlcp);
	if (tls_record_set_handshake_client_hello(record, &recordlen,
		version,
		random,
		NULL, 0,
		cipher_suites, sizeof(cipher_suites)/sizeof(cipher_suites[0]),
		NULL, 0) != 1) {
		error_print();
		return -1;
	}
	tls_client_hello_print(stdout, record + 5 + 4, recordlen - 5 -4, 0, 4);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_tls_server_hello(void)
{
	uint8_t record[512];
	size_t recordlen = 0;

	uint8_t random[32];
	uint16_t cipher_suite = TLS_cipher_ecdhe_sm4_cbc_sm3;


	tls_record_set_protocol(record, TLS_protocol_tlcp);
	if (tls_record_set_handshake_server_hello(record, &recordlen,
		TLS_protocol_tlcp,
		random,
		NULL, 0,
		cipher_suite,
		NULL, 0) != 1) {
		error_print();
		return -1;
	}
	tls_server_hello_print(stdout, record + 5 + 4, recordlen - 5 -4, 0, 0);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_tls_certificate(void)
{
	size_t recordlen = 0;
	FILE *fp = NULL;

	/*
	if (!(fp = fopen("cacert.pem", "r"))) {
		error_print();
		return -1;
	}
	if (tls_record_set_handshake_certificate_from_pem(record, &recordlen, fp) != 1) {
		error_print();
		return -1;
	}
	tls_certificate_print(stdout, record + 9, recordlen - 9, 0, 0);
	*/

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_tls_server_key_exchange(void)
{
	uint8_t record[1024];
	size_t recordlen = 0;
	uint8_t sig[SM2_MAX_SIGNATURE_SIZE] = {0xAA, 0xBB};
	const uint8_t *psig;
	size_t siglen;

	tls_record_set_protocol(record, TLS_protocol_tlcp);
	if (tlcp_record_set_handshake_server_key_exchange_ecc(record, &recordlen, sig, sizeof(sig)) != 1) {
		error_print();
		return -1;
	}
	if (tlcp_record_get_handshake_server_key_exchange_ecc(record, &psig, &siglen) != 1) {
		error_print();
		return -1;
	}
	format_bytes(stdout, 0, 0, "server_key_exchange siganture", psig, siglen);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_tls_certificate_verify(void)
{
	uint8_t record[1024];
	size_t recordlen = 0;
	uint8_t sig[SM2_MAX_SIGNATURE_SIZE];
	const uint8_t *psig;
	size_t siglen;

	tls_record_set_protocol(record, TLS_protocol_tls12);
	if (tls_record_set_handshake_certificate_verify(record, &recordlen, sig, sizeof(sig)) != 1) {
		error_print();
		return -1;
	}
	if (tls_record_get_handshake_certificate_verify(record, &psig, &siglen) != 1) {
		error_print();
		return -1;
	}
	tls_certificate_verify_print(stdout, psig, siglen, 0, 0);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_tls_finished(void)
{
	uint8_t record[1024];
	size_t recordlen = 0;
	uint8_t verify_data[12];
	const uint8_t *verify_data_ptr;
	size_t verify_data_len;

	if (tls_record_set_handshake_finished(record, &recordlen, verify_data, sizeof(verify_data)) != 1) {
		error_print();
		return -1;
	}
	if (tls_record_get_handshake_finished(record, &verify_data_ptr, &verify_data_len) != 1) {
		error_print();
		return -1;
	}
	tls_finished_print(stdout, verify_data_ptr, verify_data_len, 0, 0);

	printf("%s() ok\n", __FUNCTION__);
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

	printf("%s() ok\n", __FUNCTION__);
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

	printf("%s() ok\n", __FUNCTION__);
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

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_tls_status_request_ext(void)
{
	uint8_t ocsp_response[5];
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	memset(ocsp_response, 0xff, sizeof(ocsp_response));



	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_tls_trusted_ca_keys_ext(void)
{
	uint8_t name[256];
	size_t namelen = 0;
	uint8_t der_name[256];
	uint8_t *p = der_name;
	size_t der_name_len = 0;
	uint8_t hash[20];
	uint8_t authorities[512];
	uint8_t *pa = authorities;
	size_t authorities_len = 0;
	uint8_t ext[512];
	const uint8_t *ext_data;
	size_t ext_datalen;
	int ext_type;
	const uint8_t *list;
	size_t list_len;
	const uint8_t *cp;
	size_t len;

	memset(hash, 0x5a, sizeof(hash));
	if (x509_name_set(name, &namelen, sizeof(name),
		"CN", "Beijing", "Haidian", "PKU", "CS", "CA") != 1
		|| asn1_sequence_to_der(name, namelen, &p, &der_name_len) != 1) {
		error_print();
		return -1;
	}

	if (tls_trusted_authority_to_bytes(TLS_trusted_authority_pre_agreed,
		NULL, 0, &pa, &authorities_len) != 1
		|| tls_trusted_authority_to_bytes(TLS_trusted_authority_key_sha1_hash,
		hash, sizeof(hash), &pa, &authorities_len) != 1
		|| tls_trusted_authority_to_bytes(TLS_trusted_authority_x509_name,
		der_name, der_name_len, &pa, &authorities_len) != 1
		|| tls_trusted_authority_to_bytes(TLS_trusted_authority_cert_sha1_hash,
		hash, sizeof(hash), &pa, &authorities_len) != 1) {
		error_print();
		return -1;
	}

	p = ext;
	len = 0;
	if (tls_trusted_ca_keys_ext_to_bytes(authorities, authorities_len, &p, &len) != 1) {
		error_print();
		return -1;
	}
	cp = ext;
	if (tls_ext_from_bytes(&ext_type, &ext_data, &ext_datalen, &cp, &len) != 1
		|| ext_type != TLS_extension_trusted_ca_keys
		|| len != 0
		|| tls_trusted_authorities_from_bytes(&list, &list_len, ext_data, ext_datalen) != 1
		|| list_len != authorities_len) {
		error_print();
		return -1;
	}

	{
		int type;
		const uint8_t *data;
		size_t datalen;

		if (tls_trusted_authority_from_bytes(&type, &data, &datalen, &list, &list_len) != 1
			|| type != TLS_trusted_authority_pre_agreed
			|| data != NULL || datalen != 0
			|| tls_trusted_authority_from_bytes(&type, &data, &datalen, &list, &list_len) != 1
			|| type != TLS_trusted_authority_key_sha1_hash
			|| datalen != sizeof(hash) || memcmp(data, hash, sizeof(hash)) != 0
			|| tls_trusted_authority_from_bytes(&type, &data, &datalen, &list, &list_len) != 1
			|| type != TLS_trusted_authority_x509_name
			|| datalen != der_name_len || memcmp(data, der_name, der_name_len) != 0
			|| tls_trusted_authority_from_bytes(&type, &data, &datalen, &list, &list_len) != 1
			|| type != TLS_trusted_authority_cert_sha1_hash
			|| datalen != sizeof(hash) || memcmp(data, hash, sizeof(hash)) != 0
			|| list_len != 0) {
			error_print();
			return -1;
		}
	}

	tls_trusted_authorities_print(stdout, 0, 0, ext_data, ext_datalen);
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_tls_certificate_request_print(void)
{
	uint8_t tlcp_data[] = {
		1, TLS_cert_type_ecdsa_sign,
		0, 0,
	};
	uint8_t tls12_data[] = {
		1, TLS_cert_type_ecdsa_sign,
		0, 2, TLS_sig_sm2sig_sm3 >> 8, TLS_sig_sm2sig_sm3 & 0xff,
		0, 0,
	};
	uint8_t handshake[32];
	uint8_t *p;
	size_t len;

	p = handshake;
	len = 0;
	tls_uint8_to_bytes(TLS_handshake_certificate_request, &p, &len);
	tls_uint24array_to_bytes(tlcp_data, sizeof(tlcp_data), &p, &len);
	if (tls_handshake_print(stderr, 0, 0, TLS_protocol_tlcp,
		0, handshake, len) != 1) {
		error_print();
		return -1;
	}

	p = handshake;
	len = 0;
	tls_uint8_to_bytes(TLS_handshake_certificate_request, &p, &len);
	tls_uint24array_to_bytes(tls12_data, sizeof(tls12_data), &p, &len);
	if (tls_handshake_print(stderr, 0, 0, TLS_protocol_tls12,
		0, handshake, len) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (test_tls_null_to_bytes() != 1) goto err;
#ifdef ENABLE_AES_CCM
	if (test_tls_ccm() != 1) goto err;
#endif
	/*
	if (test_tls_encode() != 1) goto err;
	if (test_tls_cbc() != 1) goto err;
	if (test_tls_random() != 1) goto err;
	if (test_tls_client_hello() != 1) goto err;
	if (test_tls_server_hello() != 1) goto err;
	if (test_tls_certificate() != 1) goto err;
	if (test_tls_server_key_exchange() != 1) goto err;
	if (test_tls_certificate_verify() != 1) goto err;
	//if (test_tls_finished() != 1) goto err; //FIXME
	if (test_tls_alert() != 1) goto err;
	if (test_tls_change_cipher_spec() != 1) goto err;
	if (test_tls_application_data() != 1) goto err;
	*/
	if (test_tls_certificate_request_print() != 1) goto err;
	if (test_tls_trusted_ca_keys_ext() != 1) goto err;
	if (test_tls_status_request_ext() != 1) goto err;
	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return -1;
}
