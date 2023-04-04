/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
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



static const int tls12_ciphers[] = {
	TLS_cipher_ecdhe_sm4_cbc_sm3,
};

static const size_t tls12_ciphers_count = sizeof(tls12_ciphers)/sizeof(tls12_ciphers[0]);

static const uint8_t tls12_exts[] = {
	/* supported_groups */ 0x00,0x0A, 0x00,0x04, 0x00,0x02, 0x00,30,//0x29, // curveSM2
	/* ec_point_formats */ 0x00,0x0B, 0x00,0x02, 0x01,      0x00, // uncompressed
	/* signature_algors */ 0x00,0x0D, 0x00,0x04, 0x00,0x02, 0x07,0x07,//0x08, // sm2sig_sm3
};


int tls12_record_print(FILE *fp, const uint8_t *record,  size_t recordlen, int format, int indent)
{
	// 目前只支持TLCP的ECC公钥加密套件，因此不论用哪个套件解析都是一样的
	// 如果未来支持ECDHE套件，可以将函数改为宏，直接传入 (conn->cipher_suite << 8)
	format |= tls12_ciphers[0] << 8;
	return tls_record_print(fp, record, recordlen, format, indent);
}


int tls_record_set_handshake_server_key_exchange_ecdhe(uint8_t *record, size_t *recordlen,
	int curve, const SM2_POINT *point, const uint8_t *sig, size_t siglen)
{
	int type = TLS_handshake_server_key_exchange;
	uint8_t *server_ecdh_params = record + 9;
	uint8_t *p = server_ecdh_params + 69;
	size_t len = 69;

	if (!record || !recordlen || !tls_named_curve_name(curve) || !point
		|| !sig || !siglen || siglen > TLS_MAX_SIGNATURE_SIZE) {
		error_print();
		return -1;
	}
	server_ecdh_params[0] = TLS_curve_type_named_curve;
	server_ecdh_params[1] = curve >> 8;
	server_ecdh_params[2] = curve;
	server_ecdh_params[3] = 65;
	sm2_point_to_uncompressed_octets(point, server_ecdh_params + 4);
	tls_uint16_to_bytes(TLS_sig_sm2sig_sm3, &p, &len);
	tls_uint16array_to_bytes(sig, siglen, &p, &len);
	tls_record_set_handshake(record, recordlen, type, NULL, len);
	return 1;
}

// 这里返回的应该是一个SM2_POINT吗？
int tls_record_get_handshake_server_key_exchange_ecdhe(const uint8_t *record,
	int *curve, SM2_POINT *point, const uint8_t **sig, size_t *siglen)
{
	int type;
	const uint8_t *p;
	size_t len;
	uint8_t curve_type;
	uint16_t named_curve;
	const uint8_t *octets;
	size_t octetslen;
	uint16_t sig_alg;

	if (!record || !curve || !point || !sig || !siglen) {
		error_print();
		return -1;
	}
	if (tls_record_get_handshake(record, &type, &p, &len) != 1
		|| type != TLS_handshake_server_key_exchange) {
		error_print();
		return -1;
	}
	if (tls_uint8_from_bytes(&curve_type, &p, &len) != 1
		|| tls_uint16_from_bytes(&named_curve, &p, &len) != 1
		|| tls_uint8array_from_bytes(&octets, &octetslen, &p, &len) != 1
		|| tls_uint16_from_bytes(&sig_alg, &p, &len) != 1
		|| tls_uint16array_from_bytes(sig, siglen, &p, &len) != 1
		|| tls_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	if (curve_type != TLS_curve_type_named_curve) {
		error_print();
		return -1;
	}
	if (named_curve != TLS_curve_sm2p256v1) {
		error_print();
		return -1;
	}
	*curve = named_curve;
	if (octetslen != 65
		|| sm2_point_from_octets(point, octets, octetslen) != 1) {
		error_print();
		return -1;
	}
	if (sig_alg != TLS_sig_sm2sig_sm3) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_record_set_handshake_client_key_exchange_ecdhe(uint8_t *record, size_t *recordlen,
	const SM2_POINT *point)
{
	int type = TLS_handshake_client_key_exchange;
	record[9] = 65;
	sm2_point_to_uncompressed_octets(point, record + 9 + 1);
	tls_record_set_handshake(record, recordlen, type, NULL, 1 + 65);
	return 1;
}

int tls_record_get_handshake_client_key_exchange_ecdhe(const uint8_t *record, SM2_POINT *point)
{
	int type;
	const uint8_t *p;
	size_t len;
	const uint8_t *octets;
	size_t octetslen;

	if (tls_record_get_handshake(record, &type, &p, &len) != 1
		|| type != TLS_handshake_client_key_exchange) {
		error_print();
		return -1;
	}
	if (tls_uint8array_from_bytes(&octets, &octetslen, &p, &len) != 1
		|| len > 0) {
		error_print();
		return -1;
	}
	if (octetslen != 65
		|| sm2_point_from_octets(point, octets, octetslen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

/*
      Client                                               Server

      ClientHello                  -------->
                                                      ServerHello
                                                      Certificate
                                                ServerKeyExchange
                                              CertificateRequest*
                                   <--------      ServerHelloDone
      Certificate*
      ClientKeyExchange
      CertificateVerify*
      [ChangeCipherSpec]
      Finished                     -------->
                                               [ChangeCipherSpec]
                                   <--------             Finished
      Application Data             <------->     Application Data


*/

int tls12_do_connect(TLS_CONNECT *conn)
{
	int ret = -1;
	uint8_t *record = conn->record;
	uint8_t finished_record[TLS_FINISHED_RECORD_BUF_SIZE];
	size_t recordlen, finished_record_len;

	uint8_t client_random[32];
	uint8_t server_random[32];
	int protocol;
	int cipher_suite;
	const uint8_t *random;
	const uint8_t *session_id;
	size_t session_id_len;

	uint8_t client_exts[TLS_MAX_EXTENSIONS_SIZE];
	size_t client_exts_len = 0;
	const uint8_t *server_exts;
	size_t server_exts_len;

	// 扩展的协商结果，-1 表示服务器不支持该扩展（未给出响应）
	int ec_point_format = -1;
	int supported_group = -1;
	int signature_algor = -1;


	SM2_KEY server_sign_key;
	SM2_SIGN_CTX sign_ctx;
	const uint8_t *sig;
	size_t siglen;
	uint8_t pre_master_secret[48];
	SM3_CTX sm3_ctx;
	SM3_CTX tmp_sm3_ctx;
	uint8_t sm3_hash[32];
	const uint8_t *verify_data;
	size_t verify_data_len;
	uint8_t local_verify_data[12];
	int handshake_type;

	const uint8_t *cp;
	uint8_t *p;
	size_t len;

	int depth = 5;
	int alert = 0;
	int verify_result;


	// 初始化记录缓冲
	tls_record_set_protocol(record, TLS_protocol_tls1); // ClientHello的记录层协议版本是TLSv1.0
	tls_record_set_protocol(finished_record, conn->protocol);

	// 准备Finished Context（和ClientVerify）
	sm3_init(&sm3_ctx);
	if (conn->client_certs_len)
		sm2_sign_init(&sign_ctx, &conn->sign_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH);


	// send ClientHello
	tls_random_generate(client_random);
	int ec_point_formats[] = { TLS_point_uncompressed };
	size_t ec_point_formats_cnt = 1;
	int supported_groups[] = { TLS_curve_sm2p256v1 };
	size_t supported_groups_cnt = 1;
	int signature_algors[] = { TLS_sig_sm2sig_sm3 };
	size_t signature_algors_cnt = 1;


	p = client_exts;
	client_exts_len = 0;

	tls_ec_point_formats_ext_to_bytes(ec_point_formats, ec_point_formats_cnt, &p, &client_exts_len);
	tls_supported_groups_ext_to_bytes(supported_groups, supported_groups_cnt, &p, &client_exts_len);
	tls_signature_algorithms_ext_to_bytes(signature_algors, signature_algors_cnt, &p, &client_exts_len);

	if (tls_record_set_handshake_client_hello(record, &recordlen,
		conn->protocol, client_random, NULL, 0,
		tls12_ciphers, tls12_ciphers_count,
		client_exts, client_exts_len) != 1) {
		error_print();
		goto end;
	}
	tls_trace("send ClientHello\n");
	tls12_record_trace(stderr, record, recordlen, 0, 0);
	if (tls_record_send(record, recordlen, conn->sock) != 1) {
		error_print();
		goto end;
	}
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);
	if (conn->client_certs_len)
		sm2_sign_update(&sign_ctx, record + 5, recordlen - 5);

	// recv ServerHello
	tls_trace("recv ServerHello\n");
	if (tls_record_recv(record, &recordlen, conn->sock) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	tls12_record_trace(stderr, record, recordlen, 0, 0);
	if (tls_record_protocol(record) != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_protocol_version);
		goto end;
	}
	if (tls_record_get_handshake_server_hello(record,
		&protocol, &random, &session_id, &session_id_len, &cipher_suite,
		&server_exts, &server_exts_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	if (protocol != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_protocol_version);
		goto end;
	}
	// tls12_ciphers 应该改为conn的内部变量
	if (tls_cipher_suite_in_list(cipher_suite, tls12_ciphers, tls12_ciphers_count) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_handshake_failure);
		goto end;
	}
	if (!server_exts) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	if (tls_process_server_hello_exts(server_exts, server_exts_len, &ec_point_format, &supported_group, &signature_algor) != 1
		|| ec_point_format < 0
		|| supported_group < 0
		|| signature_algor < 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	memcpy(server_random, random, 32);
	memcpy(conn->session_id, session_id, session_id_len);
	conn->cipher_suite = cipher_suite;
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);
	if (conn->client_certs_len)
		sm2_sign_update(&sign_ctx, record + 5, recordlen - 5);

	// recv ServerCertificate
	tls_trace("recv ServerCertificate\n");
	if (tls_record_recv(record, &recordlen, conn->sock) != 1
		|| tls_record_protocol(record) != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	tls12_record_trace(stderr, record, recordlen, 0, 0);

	if (tls_record_get_handshake_certificate(record,
		conn->server_certs, &conn->server_certs_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);
	if (conn->client_certs_len)
		sm2_sign_update(&sign_ctx, record + 5, recordlen - 5);

	// verify ServerCertificate
	if (x509_certs_verify(conn->server_certs, conn->server_certs_len, X509_cert_chain_server,
		conn->ca_certs, conn->ca_certs_len, depth, &verify_result) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		goto end;
	}

	// recv ServerKeyExchange
	tls_trace("recv ServerKeyExchange\n");
	if (tls_record_recv(record, &recordlen, conn->sock) != 1
		|| tls_record_protocol(record) != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	tls12_record_trace(stderr, record, recordlen, 0, 0);

	int curve;
	SM2_POINT server_ecdhe_public;
	if (tls_record_get_handshake_server_key_exchange_ecdhe(record, &curve, &server_ecdhe_public, &sig, &siglen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	if (curve != TLS_curve_sm2p256v1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);
	if (conn->client_certs_len)
		sm2_sign_update(&sign_ctx, record + 5, recordlen - 5);

	// verify ServerKeyExchange
	if (x509_certs_get_cert_by_index(conn->server_certs, conn->server_certs_len, 0, &cp, &len) != 1
		|| x509_cert_get_subject_public_key(cp, len, &server_sign_key) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		goto end;
	}
	if (tls_verify_server_ecdh_params(&server_sign_key, // 这应该是签名公钥
		client_random, server_random, curve, &server_ecdhe_public, sig, siglen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		goto end;
	}

	// recv CertificateRequest or ServerHelloDone
	if (tls_record_recv(record, &recordlen, conn->sock) != 1
		|| tls_record_protocol(record) != conn->protocol
		|| tls_record_get_handshake(record, &handshake_type, &cp, &len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	if (handshake_type == TLS_handshake_certificate_request) {
		const uint8_t *cert_types;
		size_t cert_types_len;
		const uint8_t *ca_names;
		size_t ca_names_len;

		// recv CertificateRequest
		tls_trace("recv CertificateRequest\n");
		tls12_record_trace(stderr, record, recordlen, 0, 0);
		if (tls_record_get_handshake_certificate_request(record,
			&cert_types, &cert_types_len, &ca_names, &ca_names_len) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_unexpected_message);
			goto end;
		}
		if(!conn->client_certs_len) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			goto end;
		}
		if (tls_cert_types_accepted(cert_types, cert_types_len, conn->client_certs, conn->client_certs_len) != 1
			|| tls_authorities_issued_certificate(ca_names, ca_names_len, conn->client_certs, conn->client_certs_len) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_unsupported_certificate);
			goto end;
		}
		sm3_update(&sm3_ctx, record + 5, recordlen - 5);
		sm2_sign_update(&sign_ctx, record + 5, recordlen - 5);

		// recv ServerHelloDone
		if (tls_record_recv(record, &recordlen, conn->sock) != 1
			|| tls_record_protocol(record) != conn->protocol) {
			error_print();
			tls_send_alert(conn, TLS_alert_unexpected_message);
			goto end;
		}
	} else {
		// 这个得处理一下
		conn->client_certs_len = 0;
		gmssl_secure_clear(&conn->sign_key, sizeof(SM2_KEY));
	}
	tls_trace("recv ServerHelloDone\n");
	tls12_record_trace(stderr, record, recordlen, 0, 0);
	if (tls_record_get_handshake_server_hello_done(record) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);
	if (conn->client_certs_len)
		sm2_sign_update(&sign_ctx, record + 5, recordlen - 5);

	// send ClientCertificate
	if (conn->client_certs_len) {
		tls_trace("send ClientCertificate\n");
		if (tls_record_set_handshake_certificate(record, &recordlen, conn->client_certs, conn->client_certs_len) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			goto end;
		}
		tls12_record_trace(stderr, record, recordlen, 0, 0);
		if (tls_record_send(record, recordlen, conn->sock) != 1) {
			error_print();
			goto end;
		}
		sm3_update(&sm3_ctx, record + 5, recordlen - 5);
		sm2_sign_update(&sign_ctx, record + 5, recordlen - 5);
	}

	// generate MASTER_SECRET
	tls_trace("generate secrets\n");
	SM2_KEY client_ecdh;
	sm2_key_generate(&client_ecdh);
	sm2_do_ecdh(&client_ecdh, &server_ecdhe_public, &server_ecdhe_public);
	memcpy(pre_master_secret, &server_ecdhe_public, 32); // 这个做法很不优雅
	// ECDHE和ECC的PMS结构是不一样的吗？

	if (tls_prf(pre_master_secret, 32, "master secret",
			client_random, 32, server_random, 32,
			48, conn->master_secret) != 1
		|| tls_prf(conn->master_secret, 48, "key expansion",
			server_random, 32, client_random, 32,
			96, conn->key_block) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		goto end;
	}
	sm3_hmac_init(&conn->client_write_mac_ctx, conn->key_block, 32);
	sm3_hmac_init(&conn->server_write_mac_ctx, conn->key_block + 32, 32);
	sm4_set_encrypt_key(&conn->client_write_enc_key, conn->key_block + 64);
	sm4_set_decrypt_key(&conn->server_write_enc_key, conn->key_block + 80);
	/*
	tls_secrets_print(stderr,
		pre_master_secret, 48,
		client_random, server_random,
		conn->master_secret,
		conn->key_block, 96,
		0, 4);
	*/

	// send ClientKeyExchange
	tls_trace("send ClientKeyExchange\n");
	if (tls_record_set_handshake_client_key_exchange_ecdhe(record, &recordlen, &client_ecdh.public_key) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		goto end;
	}
	tls12_record_trace(stderr, record, recordlen, 0, 0);
	if (tls_record_send(record, recordlen, conn->sock) != 1) {
		error_print();
		goto end;
	}
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);
	if (conn->client_certs_len)
		sm2_sign_update(&sign_ctx, record + 5, recordlen - 5);

	// send CertificateVerify
	if (conn->client_certs_len) {
		tls_trace("send CertificateVerify\n");
		uint8_t sigbuf[SM2_MAX_SIGNATURE_SIZE];
		if (sm2_sign_finish(&sign_ctx, sigbuf, &siglen) != 1
			|| tls_record_set_handshake_certificate_verify(record, &recordlen, sigbuf, siglen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			goto end;
		}
		tls12_record_trace(stderr, record, recordlen, 0, 0);
		if (tls_record_send(record, recordlen, conn->sock) != 1) {
			error_print();
			goto end;
		}
		sm3_update(&sm3_ctx, record + 5, recordlen - 5);
	}

	// send [ChangeCipherSpec]
	tls_trace("send [ChangeCipherSpec]\n");
	if (tls_record_set_change_cipher_spec(record, &recordlen) !=1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		goto end;
	}
	tls12_record_trace(stderr, record, recordlen, 0, 0);
	if (tls_record_send(record, recordlen, conn->sock) != 1) {
		error_print();
		goto end;
	}

	// send Client Finished
	tls_trace("send Finished\n");
	memcpy(&tmp_sm3_ctx, &sm3_ctx, sizeof(sm3_ctx));
	sm3_finish(&tmp_sm3_ctx, sm3_hash);
	if (tls_prf(conn->master_secret, 48, "client finished",
			sm3_hash, 32, NULL, 0, sizeof(local_verify_data), local_verify_data) != 1
		|| tls_record_set_handshake_finished(finished_record, &finished_record_len,
			local_verify_data, sizeof(local_verify_data)) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		goto end;
	}
	tls12_record_trace(stderr, finished_record, finished_record_len, 0, 0);
	sm3_update(&sm3_ctx, finished_record + 5, finished_record_len - 5);

	// encrypt Client Finished
	tls_trace("encrypt Finished\n");
	if (tls_record_encrypt(&conn->client_write_mac_ctx, &conn->client_write_enc_key,
		conn->client_seq_num, finished_record, finished_record_len, record, &recordlen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		goto end;
	}
	tls12_record_trace(stderr, record, recordlen, (1<<24), 0); // 强制打印密文原数据
	tls_seq_num_incr(conn->client_seq_num);
	if (tls_record_send(record, recordlen, conn->sock) != 1) {
		error_print();
		goto end;
	}

	// [ChangeCipherSpec]
	tls_trace("recv [ChangeCipherSpec]\n");
	if (tls_record_recv(record, &recordlen, conn->sock) != 1
		|| tls_record_protocol(record) != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	tls12_record_trace(stderr, record, recordlen, 0, 0);
	if (tls_record_get_change_cipher_spec(record) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}

	// Finished
	tls_trace("recv Finished\n");
	if (tls_record_recv(record, &recordlen, conn->sock) != 1
		|| tls_record_protocol(record) != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	if (recordlen > sizeof(finished_record)) {
		error_print(); // 解密可能导致 finished_record 溢出
		tls_send_alert(conn, TLS_alert_bad_record_mac);
		goto end;
	}
	tls12_record_trace(stderr, record, recordlen, (1<<24), 0); // 强制打印密文原数据
	tls_trace("decrypt Finished\n");
	if (tls_record_decrypt(&conn->server_write_mac_ctx, &conn->server_write_enc_key,
		conn->server_seq_num, record, recordlen, finished_record, &finished_record_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_record_mac);
		goto end;
	}
	tls12_record_trace(stderr, finished_record, finished_record_len, 0, 0);
	tls_seq_num_incr(conn->server_seq_num);
	if (tls_record_get_handshake_finished(finished_record, &verify_data, &verify_data_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	if (verify_data_len != sizeof(local_verify_data)) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	sm3_finish(&sm3_ctx, sm3_hash);
	if (tls_prf(conn->master_secret, 48, "server finished",
		sm3_hash, 32, NULL, 0, sizeof(local_verify_data), local_verify_data) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		goto end;
	}
	if (memcmp(verify_data, local_verify_data, sizeof(local_verify_data)) != 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_decrypt_error);
		goto end;
	}
	fprintf(stderr, "Connection established!\n");


	conn->protocol = conn->protocol;
	conn->cipher_suite = cipher_suite;

	ret = 1;

end:
	gmssl_secure_clear(&sign_ctx, sizeof(sign_ctx));
	gmssl_secure_clear(pre_master_secret, sizeof(pre_master_secret));
	return ret;
}

int tls12_do_accept(TLS_CONNECT *conn)
{
	int ret = -1;

	int client_verify = 0;

	uint8_t *record = conn->record;
	uint8_t finished_record[TLS_FINISHED_RECORD_BUF_SIZE]; // 解密可能导致前面的record被覆盖
	size_t recordlen, finished_record_len;

	// 这个ciphers不是应该在CTX中设置的吗
	const int server_ciphers[] = { TLS_cipher_ecdhe_sm4_cbc_sm3 }; // 未来应该支持GCM/CBC两个套件

	// ClientHello, ServerHello
	uint8_t client_random[32];
	uint8_t server_random[32];
	int protocol;
	const uint8_t *random;
	const uint8_t *session_id; // TLCP服务器忽略客户端SessionID，也不主动设置SessionID
	size_t session_id_len;
	const uint8_t *client_ciphers;
	size_t client_ciphers_len;
	const uint8_t *client_exts;
	size_t client_exts_len;
	uint8_t server_exts[TLS_MAX_EXTENSIONS_SIZE];
	size_t server_exts_len;
	int curve = TLS_curve_sm2p256v1; // 这个是否应该在conn中设置？		

	// ServerKeyExchange
	SM2_KEY server_ecdhe_key;
	SM2_SIGN_CTX sign_ctx;
	uint8_t sigbuf[SM2_MAX_SIGNATURE_SIZE];
	size_t siglen;

	// ClientCertificate, CertificateVerify
	TLS_CLIENT_VERIFY_CTX client_verify_ctx;
	SM2_KEY client_sign_key;
	const uint8_t *sig;
	const int verify_depth = 5;
	int verify_result;

	// ClientKeyExchange
	SM2_POINT client_ecdhe_point;
	uint8_t pre_master_secret[SM2_MAX_PLAINTEXT_SIZE]; // sm2_decrypt 保证输出不会溢出

	// Finished
	SM3_CTX sm3_ctx;
	SM3_CTX tmp_sm3_ctx;
	uint8_t sm3_hash[32];
	uint8_t local_verify_data[12];
	const uint8_t *verify_data;
	size_t verify_data_len;

	const uint8_t *cp;
	size_t len;


	// 服务器端如果设置了CA
	if (conn->ca_certs_len)
		client_verify = 1;

	// 初始化Finished和客户端验证环境
	sm3_init(&sm3_ctx);
	if (client_verify)
		tls_client_verify_init(&client_verify_ctx);


	// recv ClientHello
	tls_trace("recv ClientHello\n");
	if (tls_record_recv(record, &recordlen, conn->sock) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	tls12_record_trace(stderr, record, recordlen, 0, 0);
	if (tls_record_protocol(record) != conn->protocol
		&& tls_record_protocol(record) != TLS_protocol_tls1) {
		error_print();
		tls_send_alert(conn, TLS_alert_protocol_version);
		goto end;
	}
	if (tls_record_get_handshake_client_hello(record,
		&protocol, &random, &session_id, &session_id_len,
		&client_ciphers, &client_ciphers_len,
		&client_exts, &client_exts_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	if (protocol != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_protocol_version);
		goto end;
	}
	memcpy(client_random, random, 32);
	if (tls_cipher_suites_select(client_ciphers, client_ciphers_len,
		server_ciphers, sizeof(server_ciphers)/sizeof(server_ciphers[0]),
		&conn->cipher_suite) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_insufficient_security);
		goto end;
	}
	if (client_exts) {
		server_exts_len = 0;
		curve = TLS_curve_sm2p256v1;

		tls_process_client_hello_exts(client_exts, client_exts_len, server_exts, &server_exts_len, sizeof(server_exts));



	}
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);
	if (client_verify)
		tls_client_verify_update(&client_verify_ctx, record + 5, recordlen - 5);


	// send ServerHello
	tls_trace("send ServerHello\n");
	tls_random_generate(server_random);
	tls_record_set_protocol(record, conn->protocol);
	if (tls_record_set_handshake_server_hello(record, &recordlen,
		conn->protocol, server_random, NULL, 0,
		conn->cipher_suite, server_exts, server_exts_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		goto end;
	}
	tls12_record_trace(stderr, record, recordlen, 0, 0);
	if (tls_record_send(record, recordlen, conn->sock) != 1) {
		error_print();
		goto end;
	}
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);
	if (client_verify)
		tls_client_verify_update(&client_verify_ctx, record + 5, recordlen - 5);

	// send ServerCertificate
	tls_trace("send ServerCertificate\n");
	if (tls_record_set_handshake_certificate(record, &recordlen,
		conn->server_certs, conn->server_certs_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		goto end;
	}
	tls12_record_trace(stderr, record, recordlen, 0, 0);
	if (tls_record_send(record, recordlen, conn->sock) != 1) {
		error_print();
		goto end;
	}
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);
	if (client_verify)
		tls_client_verify_update(&client_verify_ctx, record + 5, recordlen - 5);

	// send ServerKeyExchange
	tls_trace("send ServerKeyExchange\n");
	sm2_key_generate(&server_ecdhe_key);
	if (tls_sign_server_ecdh_params(&conn->sign_key,
		client_random, server_random, TLS_curve_sm2p256v1, &server_ecdhe_key.public_key,
		sigbuf, &siglen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		return -1;
	}
	if (tls_record_set_handshake_server_key_exchange_ecdhe(record, &recordlen,
		curve, &server_ecdhe_key.public_key, sigbuf, siglen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		goto end;
	}
	tls12_record_trace(stderr, record, recordlen, 0, 0);
	if (tls_record_send(record, recordlen, conn->sock) != 1) {
		error_print();
		goto end;
	}
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);
	if (client_verify)
		tls_client_verify_update(&client_verify_ctx, record + 5, recordlen - 5);

	// send CertificateRequest
	if (client_verify) {
		const uint8_t cert_types[] = { TLS_cert_type_ecdsa_sign };
		uint8_t ca_names[TLS_MAX_CA_NAMES_SIZE] = {0}; // TODO: 根据客户端验证CA证书列计算缓冲大小，或直接输出到record缓冲
		size_t ca_names_len = 0;

		tls_trace("send CertificateRequest\n");
		if (tls_authorities_from_certs(ca_names, &ca_names_len, sizeof(ca_names),
			conn->ca_certs, conn->ca_certs_len) != 1) {
			error_print();
			goto end;
		}
		if (tls_record_set_handshake_certificate_request(record, &recordlen,
			cert_types, sizeof(cert_types),
			ca_names, ca_names_len) != 1) {
			error_print();
			goto end;
		}
		tls12_record_trace(stderr, record, recordlen, 0, 0);
		if (tls_record_send(record, recordlen, conn->sock) != 1) {
			error_print();
			goto end;
		}
		sm3_update(&sm3_ctx, record + 5, recordlen - 5);
		tls_client_verify_update(&client_verify_ctx, record + 5, recordlen - 5);
	}

	// send ServerHelloDone
	tls_trace("send ServerHelloDone\n");
	tls_record_set_handshake_server_hello_done(record, &recordlen);
	tls12_record_trace(stderr, record, recordlen, 0, 0);
	if (tls_record_send(record, recordlen, conn->sock) != 1) {
		error_print();
		goto end;
	}
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);
	if (client_verify)
		tls_client_verify_update(&client_verify_ctx, record + 5, recordlen - 5);

	// recv ClientCertificate
	if (conn->ca_certs_len) {
		tls_trace("recv ClientCertificate\n");
		if (tls_record_recv(record, &recordlen, conn->sock) != 1
			|| tls_record_protocol(record) != conn->protocol) { // protocol检查应该在trace之后
			error_print();
			tls_send_alert(conn, TLS_alert_unexpected_message);
			goto end;
		}
		tls12_record_trace(stderr, record, recordlen, 0, 0);
		if (tls_record_get_handshake_certificate(record, conn->client_certs, &conn->client_certs_len) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_unexpected_message);
			goto end;
		}
		if (x509_certs_verify(conn->client_certs, conn->client_certs_len, X509_cert_chain_client,
			conn->ca_certs, conn->ca_certs_len, verify_depth, &verify_result) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_bad_certificate);
			goto end;
		}
		sm3_update(&sm3_ctx, record + 5, recordlen - 5);
		tls_client_verify_update(&client_verify_ctx, record + 5, recordlen - 5);
	}

	// recv ClientKeyExchange
	tls_trace("recv ClientKeyExchange\n");
	if (tls_record_recv(record, &recordlen, conn->sock) != 1
		|| tls_record_protocol(record) != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	tls12_record_trace(stderr, record, recordlen, 0, 0); // 应该给tls12一个独立的trace
	if (tls_record_get_handshake_client_key_exchange_ecdhe(record, &client_ecdhe_point) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}

	sm3_update(&sm3_ctx, record + 5, recordlen - 5);
	if (client_verify)
		tls_client_verify_update(&client_verify_ctx, record + 5, recordlen - 5);

	// recv CertificateVerify
	if (client_verify) {
		tls_trace("recv CertificateVerify\n");
		if (tls_record_recv(record, &recordlen, conn->sock) != 1
			|| tls_record_protocol(record) != conn->protocol) {
			tls_send_alert(conn, TLS_alert_unexpected_message);
			error_print();
			goto end;
		}
		tls12_record_trace(stderr, record, recordlen, 0, 0);
		if (tls_record_get_handshake_certificate_verify(record, &sig, &siglen) != 1) {
			tls_send_alert(conn, TLS_alert_unexpected_message);
			error_print();
			goto end;
		}
		if (x509_certs_get_cert_by_index(conn->client_certs, conn->client_certs_len, 0, &cp, &len) != 1
			|| x509_cert_get_subject_public_key(cp, len, &client_sign_key) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_bad_certificate);
			goto end;
		}
		if (tls_client_verify_finish(&client_verify_ctx, sig, siglen, &client_sign_key) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_decrypt_error);
			goto end;
		}
		sm3_update(&sm3_ctx, record + 5, recordlen - 5);
	}

	// generate secrets
	tls_trace("generate secrets\n");
	sm2_do_ecdh(&server_ecdhe_key, &client_ecdhe_point, &client_ecdhe_point);
	memcpy(pre_master_secret, (uint8_t *)&client_ecdhe_point, 32); // 这里应该修改一下表示方式，比如get_xy()
	tls_prf(pre_master_secret, 32, "master secret",
		client_random, 32, server_random, 32,
		48, conn->master_secret);
	tls_prf(conn->master_secret, 48, "key expansion",
		server_random, 32, client_random, 32,
		96, conn->key_block);
	sm3_hmac_init(&conn->client_write_mac_ctx, conn->key_block, 32);
	sm3_hmac_init(&conn->server_write_mac_ctx, conn->key_block + 32, 32);
	sm4_set_decrypt_key(&conn->client_write_enc_key, conn->key_block + 64);
	sm4_set_encrypt_key(&conn->server_write_enc_key, conn->key_block + 80);
	/*
	tls_secrets_print(stderr, pre_master_secret, 32, client_random, server_random,
		conn->master_secret, conn->key_block, 96, 0, 4);
	*/

	// recv [ChangeCipherSpec]
	tls_trace("recv [ChangeCipherSpec]\n");
	if (tls_record_recv(record, &recordlen, conn->sock) != 1
		|| tls_record_protocol(record) != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	tls12_record_trace(stderr, record, recordlen, 0, 0);
	if (tls_record_get_change_cipher_spec(record) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}

	// recv ClientFinished
	tls_trace("recv Finished\n");
	if (tls_record_recv(record, &recordlen, conn->sock) != 1
		|| tls_record_protocol(record) != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	if (recordlen > sizeof(finished_record)) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	tls12_record_trace(stderr, record, recordlen, (1<<24), 0); // 强制打印密文原数据

	// decrypt ClientFinished
	tls_trace("decrypt Finished\n");
	if (tls_record_decrypt(&conn->client_write_mac_ctx, &conn->client_write_enc_key,
		conn->client_seq_num, record, recordlen, finished_record, &finished_record_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_record_mac);
		goto end;
	}
	tls12_record_trace(stderr, finished_record, finished_record_len, 0, 0);
	tls_seq_num_incr(conn->client_seq_num);
	if (tls_record_get_handshake_finished(finished_record, &verify_data, &verify_data_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_record_mac);
		goto end;
	}
	if (verify_data_len != sizeof(local_verify_data)) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_record_mac);
		goto end;
	}

	// verify ClientFinished
	memcpy(&tmp_sm3_ctx, &sm3_ctx, sizeof(SM3_CTX));
	sm3_update(&sm3_ctx, finished_record + 5, finished_record_len - 5);
	sm3_finish(&tmp_sm3_ctx, sm3_hash);
	if (tls_prf(conn->master_secret, 48, "client finished", sm3_hash, 32, NULL, 0,
		sizeof(local_verify_data), local_verify_data) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		goto end;
	}
	if (memcmp(verify_data, local_verify_data, sizeof(local_verify_data)) != 0) {
		error_puts("client_finished.verify_data verification failure");
		tls_send_alert(conn, TLS_alert_decrypt_error);
		goto end;
	}

	// send [ChangeCipherSpec]
	tls_trace("send [ChangeCipherSpec]\n");
	if (tls_record_set_change_cipher_spec(record, &recordlen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		goto end;
	}
	tls12_record_trace(stderr, record, recordlen, 0, 0);
	if (tls_record_send(record, recordlen, conn->sock) != 1) {
		error_print();
		goto end;
	}

	// send ServerFinished
	tls_trace("send Finished\n");
	sm3_finish(&sm3_ctx, sm3_hash);
	if (tls_prf(conn->master_secret, 48, "server finished", sm3_hash, 32, NULL, 0,
			sizeof(local_verify_data), local_verify_data) != 1
		|| tls_record_set_handshake_finished(finished_record, &finished_record_len,
			local_verify_data, sizeof(local_verify_data)) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		goto end;
	}
	tls12_record_trace(stderr, finished_record, finished_record_len, 0, 0);
	if (tls_record_encrypt(&conn->server_write_mac_ctx, &conn->server_write_enc_key,
		conn->server_seq_num, finished_record, finished_record_len, record, &recordlen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		goto end;
	}
	tls_trace("encrypt Finished\n");
	tls12_record_trace(stderr, record, recordlen, (1<<24), 0); // 强制打印密文原数据
	tls_seq_num_incr(conn->server_seq_num);
	if (tls_record_send(record, recordlen, conn->sock) != 1) {
		error_print();
		goto end;
	}

	conn->protocol = conn->protocol;

	fprintf(stderr, "Connection Established!\n\n");
	ret = 1;

end:
	gmssl_secure_clear(&sign_ctx, sizeof(sign_ctx));
	gmssl_secure_clear(pre_master_secret, sizeof(pre_master_secret));
	if (client_verify) tls_client_verify_cleanup(&client_verify_ctx);
	return ret;
}
