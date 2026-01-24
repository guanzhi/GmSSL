/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmssl/rand.h>
#include <gmssl/x509.h>
#include <gmssl/error.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/pem.h>
#include <gmssl/mem.h>
#include <gmssl/tls.h>


enum {
	TLS_state_client_hello,
	TLS_state_server_hello,
	TLS_state_server_certificate,
	TLS_state_server_key_exchange,
	TLS_state_server_certificate_request,
	TLS_state_server_hello_done,
	TLS_state_client_certificate,
	TLS_state_client_key_exchange,
	TLS_state_client_certificate_verify,
	TLS_state_client_change_cipher_spec,
	TLS_state_client_finished,
	TLS_state_server_change_cipher_spec,
	TLS_state_server_finished,
};

static const int tls12_ciphers[] = {
	TLS_cipher_ecdhe_sm4_cbc_sm3,
};

int tls_send_client_hello(TLS_CONNECT *conn)
{
	const int ec_point_formats[] = { TLS_point_uncompressed };
	size_t ec_point_formats_cnt = sizeof(ec_point_formats)/sizeof(ec_point_formats[0]);
	const int supported_groups[] = { TLS_curve_sm2p256v1 };
	size_t supported_groups_cnt = sizeof(supported_groups)/sizeof(supported_groups[0]);
	const int signature_algors[] = { TLS_sig_sm2sig_sm3 };
	size_t signature_algors_cnt = sizeof(signature_algors)/sizeof(signature_algors[0]);

	uint8_t *record;
	size_t recordlen;
	uint8_t client_random[32];
	uint8_t client_exts[TLS_MAX_EXTENSIONS_SIZE];
	size_t client_exts_len;
	uint8_t *p;

	record = conn->record;

	tls_record_set_protocol(record, TLS_protocol_tls1);

	sm3_init(&conn->sm3_ctx);
	if (conn->client_certs_len)
		sm2_sign_init(&conn->sign_ctx, &conn->sign_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH);


	tls_random_generate(client_random);

	p = client_exts;
	client_exts_len = 0;
	tls_ec_point_formats_ext_to_bytes(ec_point_formats, ec_point_formats_cnt, &p, &client_exts_len);
	tls_supported_groups_ext_to_bytes(supported_groups, supported_groups_cnt, &p, &client_exts_len);
	tls_signature_algorithms_ext_to_bytes(signature_algors, signature_algors_cnt, &p, &client_exts_len);

	if (tls_record_set_handshake_client_hello(conn->record, &recordlen,
		conn->protocol, client_random, NULL, 0,
		tls12_ciphers, sizeof(tls12_ciphers)/sizeof(tls12_ciphers[0]),
		client_exts, client_exts_len) != 1) {
		error_print();
		return -1;
	}
	tls_trace("send ClientHello\n");
	tls12_record_trace(stderr, record, recordlen, 0, 0);
	if (tls_record_send(record, recordlen, conn->sock) != 1) {
		error_print();
		return -1;
	}
	sm3_update(&conn->sm3_ctx, record + 5, recordlen - 5);
	if (conn->client_certs_len) {
		sm2_sign_update(&conn->sign_ctx, record + 5, recordlen - 5);
	}

	return 1;
}

int tls_recv_server_hello(TLS_CONNECT *conn)
{
	uint8_t *record = conn->record;
	size_t recordlen;

	tls_trace("recv ServerHello\n");
	if (tls_record_recv(record, &recordlen, conn->sock) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	tls12_record_trace(stderr, record, recordlen, 0, 0);
	if (tls_record_protocol(record) != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_protocol_version);
		return -1;
	}

	// 这些值要放在哪儿呢？是否放在CONNECT中
	int protocol;
	int cipher_suite;
	uint8_t server_random[32];
	const uint8_t *random;
	const uint8_t *session_id;
	size_t session_id_len;
	const uint8_t *server_exts;
	size_t server_exts_len;

	// 扩展的协商结果，-1 表示服务器不支持该扩展（未给出响应）
	int ec_point_format = -1;
	int supported_group = -1;
	int signature_algor = -1;

	if (tls_record_get_handshake_server_hello(record,
		&protocol, &random, &session_id, &session_id_len, &cipher_suite,
		&server_exts, &server_exts_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	if (protocol != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_protocol_version);
		return -1;
	}
	// tls12_ciphers 应该改为conn的内部变量
	if (tls_cipher_suite_in_list(cipher_suite, tls12_ciphers, sizeof(tls12_ciphers)/sizeof(tls12_ciphers[0])) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_handshake_failure);
		return -1;
	}
	if (!server_exts) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	if (tls_process_server_hello_exts(server_exts, server_exts_len, &ec_point_format, &supported_group, &signature_algor) != 1
		|| ec_point_format < 0
		|| supported_group < 0
		|| signature_algor < 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	memcpy(server_random, random, 32);
	memcpy(conn->session_id, session_id, session_id_len);
	conn->cipher_suite = cipher_suite;
	sm3_update(&conn->sm3_ctx, record + 5, recordlen - 5);
	if (conn->client_certs_len) {
		sm2_sign_update(&conn->sign_ctx, record + 5, recordlen - 5);
	}

	return 1;
}

int tls_recv_server_certificate(TLS_CONNECT *conn)
{
	const int depth = 5;
	uint8_t *record = conn->record;
	size_t recordlen;
	int verify_result;

	// recv ServerCertificate
	tls_trace("recv ServerCertificate\n");
	if (tls_record_recv(record, &recordlen, conn->sock) != 1
		|| tls_record_protocol(record) != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	tls12_record_trace(stderr, record, recordlen, 0, 0);

	if (tls_record_get_handshake_certificate(record,
		conn->server_certs, &conn->server_certs_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	sm3_update(&conn->sm3_ctx, record + 5, recordlen - 5);
	if (conn->client_certs_len)
		sm2_sign_update(&conn->sign_ctx, record + 5, recordlen - 5);

	// verify ServerCertificate
	if (x509_certs_verify(conn->server_certs, conn->server_certs_len, X509_cert_chain_server,
		conn->ca_certs, conn->ca_certs_len, depth, &verify_result) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}

	return 1;
}

int tls_recv_server_key_exchange(TLS_CONNECT *conn)
{
	return 1;
}

int tls_recv_server_certificate_request(TLS_CONNECT *conn)
{
	return 1;
}

int tls_recv_server_hello_done(TLS_CONNECT *conn)
{
	return 1;
}

int tls_send_client_certificate(TLS_CONNECT *conn)
{
	return 1;
}

int tls_send_client_key_exchange(TLS_CONNECT *conn)
{
	return 1;
}

int tls_send_certificate_verify(TLS_CONNECT *conn)
{
	return 1;
}

int tls_send_client_finished(TLS_CONNECT *conn)
{
	return 1;
}

int tls_recv_server_change_cipher_spec(TLS_CONNECT *conn)
{
	return 1;
}

int tls_recv_server_finished(TLS_CONNECT *conn)
{
	return 1;
}


int tls12_client_handshake(TLS_CONNECT *conn)
{
	int ret;

	switch (conn->state) {
	case TLS_state_client_hello:
		ret = tls_send_client_hello(conn);
		break;
	case TLS_state_server_hello:
		ret = tls_recv_server_hello(conn);
		break;
	case TLS_state_server_certificate:
		ret = tls_recv_server_certificate(conn);
		break;
	case TLS_state_server_key_exchange:
		ret = tls_recv_server_key_exchange(conn);
		break;
	case TLS_state_server_certificate_request:
		ret = tls_recv_server_certificate_request(conn);
		break;
	case TLS_state_server_hello_done:
		ret = tls_recv_server_hello_done(conn);
		break;
	case TLS_state_client_certificate:
		ret = tls_send_client_certificate(conn);
		break;
	case TLS_state_client_key_exchange:
		ret = tls_send_client_key_exchange(conn);
		break;
	case TLS_state_client_certificate_verify:
		ret = tls_send_certificate_verify(conn);
	case TLS_state_client_change_cipher_spec:
		break;
	case TLS_state_client_finished:
		ret = tls_send_client_finished(conn);
		break;
	case TLS_state_server_change_cipher_spec:
		ret = tls_recv_server_change_cipher_spec(conn);
		break;
	case TLS_state_server_finished:
		ret = tls_recv_server_finished(conn);
		break;
	default:
		error_print();
		return -1;
	}
	return 1;
}


