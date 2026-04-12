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



static int test_tls_ext(void)
{
	uint8_t ext_data[30];
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	if (tls_ext_to_bytes(TLS_extension_max_fragment_length, NULL, sizeof(ext_data), &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (len != 4 + sizeof(ext_data)) {
		error_print();
		return -1;
	}
	if (p != buf + 4 + sizeof(ext_data)) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}


static int test_tls13_gcm(void)
{

	BLOCK_CIPHER_KEY block_key;
	uint8_t key[16];
	uint8_t iv[12];
	uint8_t seq_num[8] = {0,0,0,0,0,0,0,1};
	int record_type = TLS_record_handshake;
	uint8_t in[40];
	size_t padding_len = 8;
	uint8_t out[256];
	size_t outlen;
	uint8_t buf[256];
	size_t buflen;

	rand_bytes(key, sizeof(key));
	rand_bytes(iv, sizeof(iv));
	rand_bytes(in, sizeof(in));

	memset(out, 1, sizeof(out));
	outlen = 0;
	memset(buf, 1, sizeof(buf));
	buflen = 0;

	if (block_cipher_set_encrypt_key(&block_key, BLOCK_CIPHER_sm4(), key) != 1) {
		error_print();
		return -1;
	}

	if (tls13_gcm_encrypt(&block_key, iv, seq_num, record_type, in, sizeof(in), padding_len, out, &outlen) != 1) {
		error_print();
		return -1;
	}
	if (tls13_gcm_decrypt(&block_key, iv, seq_num, out, outlen, &record_type, buf, &buflen) != 1) {
		error_print();
		return -1;
	}

	if (buflen != sizeof(in)) {
		error_print();
		return -1;
	}
	if (memcmp(in, buf, buflen) != 0) {
		error_print();
		return -1;
	}
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_tls13_supported_versions_ext(void)
{
	const int client_versions[] = { TLS_protocol_tls13, TLS_protocol_tls12, TLS_protocol_tlcp };
	const int server_versions[] = { TLS_protocol_tls12, TLS_protocol_tls13, TLS_protocol_tlcp };
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	int ext_type;
	const uint8_t *ext_data;
	size_t ext_datalen;
	int common_versions[2];
	size_t common_versions_cnt;
	int selected_version;

	// server => client
	if (tls13_client_supported_versions_ext_to_bytes(client_versions,
		sizeof(client_versions)/sizeof(client_versions[0]), &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (tls_ext_from_bytes(&ext_type, &ext_data, &ext_datalen, &cp, &len) != 1
		|| ext_type != TLS_extension_supported_versions
		|| tls_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	format_print(stderr, 0, 4, "ClientHello.exts.supported_versions\n");
	tls13_client_supported_versions_print(stderr, 0, 8, ext_data, ext_datalen);

	// client process
	if (tls13_process_client_supported_versions(ext_data, ext_datalen,
		server_versions, sizeof(server_versions)/sizeof(server_versions[0]),
		common_versions, &common_versions_cnt,
		sizeof(common_versions)/sizeof(common_versions[0])) != 1) {
		error_print();
		return -1;
	}
	if (common_versions[0] != TLS_protocol_tls12
		|| common_versions[1] != TLS_protocol_tls13
		|| common_versions_cnt != 2) {
		error_print();
		return -1;
	}

	// client => server
	if (tls13_server_supported_versions_ext_to_bytes(common_versions[0], &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (tls_ext_from_bytes(&ext_type, &ext_data, &ext_datalen, &cp, &len) != 1
		|| ext_type != TLS_extension_supported_versions
		|| tls_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	format_print(stderr, 0, 4, "ServerHello.exts.supported_versions\n");
	tls13_server_supported_versions_print(stderr, 0, 8, ext_data, ext_datalen);

	// server process
	if (tls13_process_server_supported_versions(
		client_versions, sizeof(client_versions)/sizeof(client_versions[0]),
		ext_data, ext_datalen, &selected_version) != 1) {
		error_print();
		return -1;
	}
	if (selected_version != TLS_protocol_tls12) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_tls13_key_share_ext(void)
{
	const int curve_oid[] = {
		OID_sm2,
		OID_secp256r1,
	};

	uint8_t buf[512];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	int ext_type;
	const uint8_t *ext_data;
	size_t ext_datalen;


	X509_KEY x509_key[2];
	int group;
	const uint8_t *key_exchange;
	size_t key_exchange_len;
	int common_groups[] = {
		TLS_curve_secp256r1,
		TLS_curve_sm2p256v1,
	};
	size_t i;

	for (i = 0; i < sizeof(curve_oid)/sizeof(curve_oid[0]); i++) {
		if (x509_key_generate(&x509_key[i], OID_ec_public_key,
			&curve_oid[i], sizeof(curve_oid[i])) != 1) {
			error_print();
			return -1;
		}
	}

	// KeyShareEntry
	if (tls13_key_share_entry_to_bytes(&x509_key[0], &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (tls13_key_share_entry_from_bytes(&group, &key_exchange, &key_exchange_len, &cp, &len) != 1
		|| tls_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	if (group != tls_named_curve_from_oid(curve_oid[0])
		|| !key_exchange || key_exchange_len != 65) {
		error_print();
		return -1;
	}



	// KeyShareClientHello
	if (tls13_key_share_client_hello_ext_to_bytes(x509_key,
		sizeof(curve_oid)/sizeof(curve_oid[0]), &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (tls_ext_from_bytes(&ext_type, &ext_data, &ext_datalen, &cp, &len) != 1
		|| tls_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	tls13_key_share_client_hello_print(stderr, 0, 4, ext_data, ext_datalen);
	if (tls13_process_key_share_client_hello(ext_data, ext_datalen,
		common_groups, sizeof(common_groups)/sizeof(common_groups[0]),
		&group, &key_exchange, &key_exchange_len) != 1) {
		error_print();
		return -1;
	}
	if (group != common_groups[0]) {
		error_print();
		return -1;
	}
	format_print(stderr, 0, 4, "group: %s\n", tls_named_curve_name(group));
	format_bytes(stderr, 0, 4, "key_exchange", key_exchange, key_exchange_len);


	// KeyShareServerHello

	X509_KEY server_key;

	int server_curve;

	server_curve = tls_named_curve_oid(group);

	if (server_curve == OID_undef) {
		error_print();
		return -1;
	}

	if (x509_key_generate(&server_key, OID_ec_public_key, &server_curve, sizeof(server_curve)) != 1) {
		error_print();
		return -1;
	}
	if (tls13_key_share_server_hello_ext_to_bytes(&server_key, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (tls_ext_from_bytes(&ext_type, &ext_data, &ext_datalen, &cp, &len) != 1
		|| tls_length_is_zero(len) != 1
		|| ext_type != TLS_extension_key_share) {
		error_print();
		return -1;
	}
	tls13_key_share_server_hello_print(stderr, 0, 4, ext_data, ext_datalen);

	if (tls13_key_share_server_hello_from_bytes(&group, &key_exchange, &key_exchange_len,
		ext_data, ext_datalen) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}



static int test_tls13_certificate_authorities_ext(void)
{

	// 首先生成多个证书，并且将证书写入到一个PEM文件中

	// 从证书文件中读取名字


	// 然后生成这个扩展


	return 1;
}


static int test_tls_supported_groups_ext(void)
{
	const int client_groups[] = {
		TLS_curve_sm2p256v1,
		TLS_curve_secp256r1,
	};
	const size_t client_groups_cnt = sizeof(client_groups)/sizeof(client_groups[0]);
	const int server_groups[] = {
		TLS_curve_secp256r1,
		TLS_curve_sm2p256v1,
	};
	const size_t server_groups_cnt = sizeof(server_groups)/sizeof(server_groups[0]);
	int common_groups[2];
	size_t common_groups_cnt;

	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	int ext_type;
	const uint8_t *ext_data;
	size_t ext_datalen;
	size_t i;

	if (tls_supported_groups_ext_to_bytes(client_groups, client_groups_cnt, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (tls_ext_from_bytes(&ext_type, &ext_data, &ext_datalen, &cp, &len) != 1
		|| tls_length_is_zero(len) != 1
		|| ext_type != TLS_extension_supported_groups) {
		error_print();
		return -1;
	}
	tls_supported_groups_print(stderr, 0, 4, ext_data, ext_datalen);

	if (tls_process_supported_groups(ext_data, ext_datalen,
		server_groups, server_groups_cnt, common_groups, &common_groups_cnt,
		sizeof(common_groups)/sizeof(common_groups[0])) != 1) {
		error_print();
		return -1;
	}
	format_print(stderr, 0, 4, "common_groups\n");
	for (i = 0; i < common_groups_cnt; i++) {
		format_print(stderr, 0, 8, "%s\n", tls_named_curve_name(common_groups[i]));
	}

	if (common_groups[0] != server_groups[0]) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_tls_signature_algorithms_ext(void)
{
	const int server_sig_algs[] = {
		TLS_sig_sm2sig_sm3,
		TLS_sig_ecdsa_secp256r1_sha256,
	};
	const size_t server_sig_algs_cnt = sizeof(server_sig_algs)/sizeof(server_sig_algs[0]);
	const int client_sig_algs[] = {
		TLS_sig_sm2sig_sm3,
		TLS_sig_ecdsa_secp256r1_sha256,
	};
	const size_t client_sig_algs_cnt = sizeof(client_sig_algs)/sizeof(client_sig_algs[0]);

	int common_sig_algs[2];
	size_t common_sig_algs_cnt;

	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	int ext_type;
	const uint8_t *ext_data;
	size_t ext_datalen;
	size_t i;

	if (tls_signature_algorithms_ext_to_bytes(client_sig_algs, client_sig_algs_cnt, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (tls_ext_from_bytes(&ext_type, &ext_data, &ext_datalen, &cp, &len) != 1
		|| tls_length_is_zero(len) != 1
		|| ext_type != TLS_extension_signature_algorithms) {
		error_print();
		return -1;
	}
	tls_signature_algorithms_print(stderr, 0, 4, ext_data, ext_datalen);

	if (tls_process_signature_algorithms(ext_data, ext_datalen,
		server_sig_algs, server_sig_algs_cnt,
		common_sig_algs, &common_sig_algs_cnt,
		sizeof(common_sig_algs)/sizeof(common_sig_algs[0])) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_tls13_signature_algorithms_cert_ext(void)
{
	const int server_sig_algs[] = {
		TLS_sig_sm2sig_sm3,
		TLS_sig_ecdsa_secp256r1_sha256,
	};
	const size_t server_sig_algs_cnt = sizeof(server_sig_algs)/sizeof(server_sig_algs[0]);
	const int client_sig_algs[] = {
		TLS_sig_sm2sig_sm3,
		TLS_sig_ecdsa_secp256r1_sha256,
	};
	const size_t client_sig_algs_cnt = sizeof(client_sig_algs)/sizeof(client_sig_algs[0]);

	int common_sig_algs[2];
	size_t common_sig_algs_cnt;

	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	int ext_type;
	const uint8_t *ext_data;
	size_t ext_datalen;
	size_t i;

	if (tls13_signature_algorithms_cert_ext_to_bytes(
		client_sig_algs, client_sig_algs_cnt, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (tls_ext_from_bytes(&ext_type, &ext_data, &ext_datalen, &cp, &len) != 1
		|| tls_length_is_zero(len) != 1
		|| ext_type != TLS_extension_signature_algorithms_cert) {
		error_print();
		return -1;
	}
	tls13_signature_algorithms_cert_print(stderr, 0, 4, ext_data, ext_datalen);

	if (tls_process_signature_algorithms(ext_data, ext_datalen,
		server_sig_algs, server_sig_algs_cnt,
		common_sig_algs, &common_sig_algs_cnt,
		sizeof(common_sig_algs)/sizeof(common_sig_algs[0])) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}


int tls13_ticket_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);
int tls13_encrypt_ticket(const SM4_KEY *key, const uint8_t resumption_master_secret[48],
	int protocol_version, int cipher_suite, uint32_t ticket_issue_time,  uint32_t ticket_lifetime,
	uint8_t *out, size_t *outlen);
int tls13_decrypt_ticket(const SM4_KEY *key, const uint8_t *in, size_t inlen,
	uint8_t resumption_master_secret[48], int *protocol_version, int *cipher_suite,
	uint32_t *ticket_issue_time, uint32_t *ticket_lifetime);



static int test_tls13_ticket(void)
{
	SM4_KEY server_session_ticket_key;
	uint8_t raw_key[16] = {0};

	uint8_t resumption_master_secret[48] = { 1, 2, 3, };
	int protocol_version = TLS_protocol_tls13;
	int cipher_suite = TLS_cipher_sm4_gcm_sm3;
	uint32_t ticket_issue_time = time(NULL);
	uint32_t ticket_lifetime = 60 * 60 * 24;

	uint8_t ticket[12 + 60 + 16];
	size_t ticketlen;

	uint8_t _resumption_master_secret[48];
	int _protocol_version;
	int _cipher_suite;
	uint32_t _ticket_issue_time;
	uint32_t _ticket_lifetime;

	sm4_set_encrypt_key(&server_session_ticket_key, raw_key);

	if (tls13_encrypt_ticket(&server_session_ticket_key,
		resumption_master_secret, protocol_version, cipher_suite,
		ticket_issue_time, ticket_lifetime,
		ticket, &ticketlen) != 1) {
		error_print();
		return -1;
	}

	if (tls13_decrypt_ticket(&server_session_ticket_key,
		ticket, ticketlen,
		_resumption_master_secret, &_protocol_version, &_cipher_suite,
		&_ticket_issue_time, &_ticket_lifetime) != 1) {
		error_print();
		return -1;
	}

	if (memcmp(_resumption_master_secret, resumption_master_secret, 48) != 0
		|| _protocol_version != protocol_version
		|| _cipher_suite != cipher_suite
		|| _ticket_issue_time != ticket_issue_time
		|| _ticket_lifetime != ticket_lifetime) {
		error_print();
		return -1;
	}


	printf("%s() ok\n", __FUNCTION__);
	return 1;
}


#if 0
static int test_tls13_psk_key_exchange_modes(void)
{
	int modes[] = {
		TLS_psk_key_exchange_modes_psk_dhe,
		TLS_psk_key_exchange_modes_psk_only,
		TLS_psk_key_exchange_modes_both,
	};

	uint8_t buf[128];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	size_t i;

	for (i = 0; i < sizeof(modes)/sizeof(modes[0]); i++) {
		if (tls13_psk_key_exchange_modes_ext_to_bytes(modes[i], &p, &len) != 1) {
			error_print();
			return -1;
		}
	}

	for (i = 0; i < sizeof(modes)/sizeof(modes[0]); i++) {
		int type;
		const uint8_t *d;
		size_t dlen;
		int mode;

		if (tls_ext_from_bytes(&type, &d, &dlen, &cp, &len) != 1) {
			error_print();
			return -1;
		}
		if (type != TLS_extension_psk_key_exchange_modes) {
			error_print();
			return -1;
		}
		format_print(stderr, 0, 4, "psk_key_exchange_modes\n");
		tls13_psk_key_exchange_modes_print(stderr, 0, 8, d, dlen);

		if (tls13_psk_key_exchange_modes_from_bytes(&mode, d, dlen) != 1) {
			error_print();
			return -1;
		}
		if (mode != modes[i]) {
			error_print();
			return -1;
		}

	}
	if (len) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}
#endif

static int test_tls_server_name_ext(void)
{
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	int ext_type;
	const uint8_t *ext_data;
	size_t ext_datalen;
	const uint8_t *hostname;
	size_t hostname_len;


	if (tls_server_name_ext_to_bytes((uint8_t *)"www.pku.edu.cn", sizeof("www.pku.edu.cn"), &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (tls_ext_from_bytes(&ext_type, &ext_data, &ext_datalen, &cp, &len) != 1
		|| tls_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	if (tls_server_name_from_bytes(&hostname, &hostname_len, ext_data, ext_datalen) != 1) {
		error_print();
		return -1;
	}
	tls_server_name_print(stderr, 0, 0, ext_data, ext_datalen);


	// 这里应该补充一个包含多个host_name的例子





	printf("%s() ok\n", __FUNCTION__);
	return 1;
}




































int main(void)
{
	if (test_tls_ext() != 1) goto err;
	if (test_tls13_gcm() != 1) goto err;
	if (test_tls13_supported_versions_ext() != 1) goto err;
	if (test_tls13_key_share_ext() != 1) goto err;
	if (test_tls_supported_groups_ext() != 1) goto err;
	if (test_tls_signature_algorithms_ext() != 1) goto err;
	if (test_tls13_signature_algorithms_cert_ext() != 1) goto err;
//	if (test_tls13_ticket() != 1) goto err;
//	if (test_tls13_psk_key_exchange_modes() != 1) goto err;


	if (test_tls_server_name_ext() != 1) goto err;

	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return -1;
}
