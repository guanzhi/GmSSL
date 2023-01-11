/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmssl/rand.h>
#include <gmssl/x509.h>
#include <gmssl/error.h>
#include <gmssl/mem.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/pem.h>
#include <gmssl/tls.h>


static const int tlcp_ciphers[] = { TLS_cipher_ecc_sm4_cbc_sm3 };
static const size_t tlcp_ciphers_count = sizeof(tlcp_ciphers)/sizeof(tlcp_ciphers[0]);

void printbyte(uint8_t *ptr, int len, char *name) {
  fprintf(stderr, "%s", name);
  for (int i = 0; i < len; i++) {
    if (i % 16 == 0)
      fprintf(stderr, "\n");
    fprintf(stderr, "0x%02X ", ptr[i]);
  }
  fprintf(stderr, "\n");
}

int tlcp_record_print(FILE *fp, const uint8_t *record,  size_t recordlen, int format, int indent)
{
	// 目前只支持TLCP的ECC公钥加密套件，因此不论用哪个套件解析都是一样的
	// 如果未来支持ECDHE套件，可以将函数改为宏，直接传入 (conn->cipher_suite << 8)
	format |= tlcp_ciphers[0] << 8;
	return tls_record_print(fp, record, recordlen, format, indent);
}

int tlcp_record_set_handshake_server_key_exchange_pke(uint8_t *record, size_t *recordlen,
	const uint8_t *sig, size_t siglen)
{
	int type = TLS_handshake_server_key_exchange;
	uint8_t *p;
	size_t len = 0;

	if (!record || !recordlen || !sig || !siglen) {
		error_print();
		return -1;
	}
	if (siglen > SM2_MAX_SIGNATURE_SIZE) {
		error_print();
		return -1;
	}
	if (tls_record_protocol(record) != TLS_protocol_tlcp) {
		error_print();
		return -1;
	}
	p = tls_handshake_data(tls_record_data(record));
	// 注意TLCP的ServerKeyExchange中的签名值需要封装在uint16array中
	// 但是CertificateVerify中直接装载签名值DER
	tls_uint16array_to_bytes(sig, siglen, &p, &len);
	tls_record_set_handshake(record, recordlen, type, NULL, len);
	return 1;
}

int tlcp_record_get_handshake_server_key_exchange_pke(const uint8_t *record,
	const uint8_t **sig, size_t *siglen)
{
	int type;
	const uint8_t *p;
	size_t len;

	if (!record || !sig || !siglen) {
		error_print();
		return -1;
	}
	if (tls_record_get_handshake(record, &type, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (type != TLS_handshake_server_key_exchange) {
		error_print();
		return -1;
	}
	if (tls_record_protocol(record) != TLS_protocol_tlcp) {
		error_print();
		return -1;
	}
	if (tls_uint16array_from_bytes(sig, siglen, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (len) {
		error_print();
		return -1;
	}
	return 1;
}

int tlcp_server_key_exchange_pke_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent)
{
	const uint8_t *sig;
	size_t siglen;

	format_print(fp, format, indent, "ServerKeyExchange\n");
	indent += 4;
	if (tls_uint16array_from_bytes(&sig, &siglen, &data, &datalen) != 1) {
		error_print();
		return -1;
	}
	format_bytes(fp, format, indent, "signature", sig, siglen);
	if (datalen) {
		error_print();
		return -1;
	}
	return 1;
}

int tlcp_do_connect(TLS_CONNECT *conn)
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
	const uint8_t *exts;
	size_t exts_len;

	SM2_KEY server_sign_key;
	SM2_KEY server_enc_key;
	SM2_SIGN_CTX verify_ctx;
	SM2_SIGN_CTX sign_ctx;
	const uint8_t *sig;
	size_t siglen;
	uint8_t pre_master_secret[48];
	uint8_t enced_pre_master_secret[SM2_MAX_CIPHERTEXT_SIZE];
	size_t enced_pre_master_secret_len;
	SM3_CTX sm3_ctx;
	SM3_CTX tmp_sm3_ctx;
	uint8_t sm3_hash[32];
	const uint8_t *verify_data;
	size_t verify_data_len;
	uint8_t local_verify_data[12];

	int handshake_type;
	const uint8_t *server_enc_cert;
	size_t server_enc_cert_len;
	uint8_t server_enc_cert_lenbuf[3];
	const uint8_t *cp;
	uint8_t *p;
	size_t len;

	int depth = 5;
	int alert = 0;
	int verify_result;


	// 初始化记录缓冲
	tls_record_set_protocol(record, TLS_protocol_tlcp);
	tls_record_set_protocol(finished_record, TLS_protocol_tlcp);

	// 准备Finished Context（和ClientVerify）
	sm3_init(&sm3_ctx);

	// send ClientHello
	tls_random_generate(client_random);
	if (tls_record_set_handshake_client_hello(record, &recordlen,
		TLS_protocol_tlcp, client_random, NULL, 0,
		tlcp_ciphers, tlcp_ciphers_count, NULL, 0) != 1) {
		error_print();
		goto end;
	}
	tls_trace("send ClientHello\n");
	tlcp_record_trace(stderr, record, recordlen, 0, 0);
	if (tls_record_send(record, recordlen, conn->sock) != 1) {
		error_print();
		goto end;
	}
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);

	// recv ServerHello
	tls_trace("recv ServerHello\n");
	if (tls_record_recv(record, &recordlen, conn->sock) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	tlcp_record_trace(stderr, record, recordlen, 0, 0);
	if (tls_record_protocol(record) != TLS_protocol_tlcp) {
		error_print();
		tls_send_alert(conn, TLS_alert_protocol_version);
		goto end;
	}
	if (tls_record_get_handshake_server_hello(record,
		&protocol, &random, &session_id, &session_id_len, &cipher_suite,
		&exts, &exts_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	if (protocol != TLS_protocol_tlcp) {
		tls_send_alert(conn, TLS_alert_protocol_version);
		error_print();
		goto end;
	}
	if (tls_cipher_suite_in_list(cipher_suite, tlcp_ciphers, tlcp_ciphers_count) != 1) {
		tls_send_alert(conn, TLS_alert_handshake_failure);
		error_print();
		goto end;
	}
	if (exts) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	memcpy(server_random, random, 32);
	memcpy(conn->session_id, session_id, session_id_len);
	conn->cipher_suite = cipher_suite;
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);

	// recv ServerCertificate
	tls_trace("recv ServerCertificate\n");
	if (tls_record_recv(record, &recordlen, conn->sock) != 1
		|| tls_record_protocol(record) != TLS_protocol_tlcp) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	tlcp_record_trace(stderr, record, recordlen, 0, 0);

	if (tls_record_get_handshake_certificate(record,
		conn->server_certs, &conn->server_certs_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);

	// verify ServerCertificate
	if (conn->ca_certs_len) {
		// 只有提供了CA证书才验证服务器证书链
		// FIXME: 逻辑需要再检查
		if (x509_certs_verify_tlcp(conn->server_certs, conn->server_certs_len, X509_cert_chain_server,
			conn->ca_certs, conn->ca_certs_len, depth, &verify_result) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_bad_certificate);
			goto end;
		}
	}

	// recv ServerKeyExchange
	tls_trace("recv ServerKeyExchange\n");
	if (tls_record_recv(record, &recordlen, conn->sock) != 1
		|| tls_record_protocol(record) != TLS_protocol_tlcp) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	tlcp_record_trace(stderr, record, recordlen, 0, 0);
	if (tlcp_record_get_handshake_server_key_exchange_pke(record, &sig, &siglen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);

	// verify ServerKeyExchange
	if (x509_certs_get_cert_by_index(conn->server_certs, conn->server_certs_len, 0, &cp, &len) != 1
		|| x509_cert_get_subject_public_key(cp, len, &server_sign_key) != 1
		|| x509_certs_get_cert_by_index(conn->server_certs, conn->server_certs_len, 1, &server_enc_cert, &server_enc_cert_len) != 1
		|| x509_cert_get_subject_public_key(server_enc_cert, server_enc_cert_len, &server_enc_key) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		goto end;
	}
	p = server_enc_cert_lenbuf; len = 0;
	tls_uint24_to_bytes((uint24_t)server_enc_cert_len, &p, &len);
	if (sm2_verify_init(&verify_ctx, &server_sign_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1
		|| sm2_verify_update(&verify_ctx, client_random, 32) != 1
		|| sm2_verify_update(&verify_ctx, server_random, 32) != 1
		|| sm2_verify_update(&verify_ctx, server_enc_cert_lenbuf, 3) != 1
		|| sm2_verify_update(&verify_ctx, server_enc_cert, server_enc_cert_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		goto end;
	}
	if (sm2_verify_finish(&verify_ctx, sig, siglen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_decrypt_error);
		goto end;
	}

	// recv CertificateRequest or ServerHelloDone
	if (tls_record_recv(record, &recordlen, conn->sock) != 1
		|| tls_record_protocol(record) != TLS_protocol_tlcp
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
		tlcp_record_trace(stderr, record, recordlen, 0, 0);
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

		// recv ServerHelloDone
		if (tls_record_recv(record, &recordlen, conn->sock) != 1
			|| tls_record_protocol(record) != TLS_protocol_tlcp) {
			error_print();
			tls_send_alert(conn, TLS_alert_unexpected_message);
			goto end;
		}
	} else {
		// 这个得处理一下
		conn->client_certs_len = 0;
		gmssl_secure_clear(&conn->sign_key, sizeof(SM2_KEY));
		//client_sign_key = NULL;
	}
	tls_trace("recv ServerHelloDone\n");
	tlcp_record_trace(stderr, record, recordlen, 0, 0);
	if (tls_record_get_handshake_server_hello_done(record) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);

	// send ClientCertificate
	if (conn->client_certs_len) {
		tls_trace("send ClientCertificate\n");
		if (tls_record_set_handshake_certificate(record, &recordlen, conn->client_certs, conn->client_certs_len) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			goto end;
		}
		tlcp_record_trace(stderr, record, recordlen, 0, 0);
		if (tls_record_send(record, recordlen, conn->sock) != 1) {
			error_print();
			goto end;
		}
		sm3_update(&sm3_ctx, record + 5, recordlen - 5);
	}

	// generate MASTER_SECRET
	tls_trace("generate secrets\n");
	if (tls_pre_master_secret_generate(pre_master_secret, TLS_protocol_tlcp) != 1
		|| tls_prf(pre_master_secret, 48, "master secret",
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
	if (sm2_encrypt(&server_enc_key, pre_master_secret, 48,
			enced_pre_master_secret, &enced_pre_master_secret_len) != 1
		|| tls_record_set_handshake_client_key_exchange_pke(record, &recordlen,
			enced_pre_master_secret, enced_pre_master_secret_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		goto end;
	}
	tlcp_record_trace(stderr, record, recordlen, 0, 0);
	if (tls_record_send(record, recordlen, conn->sock) != 1) {
		error_print();
		goto end;
	}
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);

	// send CertificateVerify
	if (conn->client_certs_len) {
		tls_trace("send CertificateVerify\n");

		SM3_CTX cert_verify_sm3_ctx = sm3_ctx;
		uint8_t cert_verify_hash[SM3_DIGEST_SIZE];
		uint8_t sigbuf[SM2_MAX_SIGNATURE_SIZE];

		sm3_finish(&cert_verify_sm3_ctx, cert_verify_hash);
		if (sm2_sign_init(&sign_ctx, &conn->sign_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1
			|| sm2_sign_update(&sign_ctx, cert_verify_hash, SM3_DIGEST_SIZE) != 1
			|| sm2_sign_finish(&sign_ctx, sigbuf, &siglen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			goto end;
		}
		if (tls_record_set_handshake_certificate_verify(record, &recordlen, sigbuf, siglen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			goto end;
		}
		tlcp_record_trace(stderr, record, recordlen, 0, 0);
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
	tlcp_record_trace(stderr, record, recordlen, 0, 0);
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
	tlcp_record_trace(stderr, finished_record, finished_record_len, 0, 0);
	sm3_update(&sm3_ctx, finished_record + 5, finished_record_len - 5);

	// encrypt Client Finished
	tls_trace("encrypt Finished\n");
	if (tls_record_encrypt(&conn->client_write_mac_ctx, &conn->client_write_enc_key,
		conn->client_seq_num, finished_record, finished_record_len, record, &recordlen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		goto end;
	}
	tlcp_record_trace(stderr, record, recordlen, (1<<24), 0); // 强制打印密文原数据
	tls_seq_num_incr(conn->client_seq_num);
	if (tls_record_send(record, recordlen, conn->sock) != 1) {
		error_print();
		goto end;
	}

	// [ChangeCipherSpec]
	tls_trace("recv [ChangeCipherSpec]\n");
	if (tls_record_recv(record, &recordlen, conn->sock) != 1
		|| tls_record_protocol(record) != TLS_protocol_tlcp) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	tlcp_record_trace(stderr, record, recordlen, 0, 0);
	if (tls_record_get_change_cipher_spec(record) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}

	// Finished
	tls_trace("recv Finished\n");
	if (tls_record_recv(record, &recordlen, conn->sock) != 1
		|| tls_record_protocol(record) != TLS_protocol_tlcp) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	if (recordlen > sizeof(finished_record)) {
		error_print(); // 解密可能导致 finished_record 溢出
		tls_send_alert(conn, TLS_alert_bad_record_mac);
		goto end;
	}
	tlcp_record_trace(stderr, record, recordlen, (1<<24), 0); // 强制打印密文原数据
	tls_trace("decrypt Finished\n");
	if (tls_record_decrypt(&conn->server_write_mac_ctx, &conn->server_write_enc_key,
		conn->server_seq_num, record, recordlen, finished_record, &finished_record_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_record_mac);
		goto end;
	}
	tlcp_record_trace(stderr, finished_record, finished_record_len, 0, 0);
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


	conn->protocol = TLS_protocol_tlcp;
	conn->cipher_suite = cipher_suite;

	ret = 1;

end:
	gmssl_secure_clear(&sign_ctx, sizeof(sign_ctx));
	gmssl_secure_clear(pre_master_secret, sizeof(pre_master_secret));
	return ret;
}

int tlcp_do_accept(TLS_CONNECT *conn)
{
	int ret = -1;

	int client_verify = 0;

	uint8_t *record = conn->record;
	uint8_t finished_record[TLS_FINISHED_RECORD_BUF_SIZE]; // 解密可能导致前面的record被覆盖
	size_t recordlen, finished_record_len;
	const int server_ciphers[] = { TLS_cipher_ecc_sm4_cbc_sm3 }; // 未来应该支持GCM/CBC两个套件

	// ClientHello, ServerHello
	uint8_t client_random[32];
	uint8_t server_random[32];
	int protocol;
	const uint8_t *random;
	const uint8_t *session_id; // TLCP服务器忽略客户端SessionID，也不主动设置SessionID
	size_t session_id_len;
	const uint8_t *client_ciphers;
	size_t client_ciphers_len;
	const uint8_t *exts;
	size_t exts_len;

	// ServerKeyExchange
	const uint8_t *server_enc_cert;
	size_t server_enc_cert_len;
	uint8_t server_enc_cert_lenbuf[3];
	SM2_SIGN_CTX sign_ctx;
	uint8_t sigbuf[SM2_MAX_SIGNATURE_SIZE];
	size_t siglen;

	// ClientCertificate, CertificateVerify
	SM2_KEY client_sign_key;
	SM2_SIGN_CTX verify_ctx;
	const uint8_t *sig;
	const int verify_depth = 5;
	int verify_result;

	// ClientKeyExchange
	const uint8_t *enced_pms;
	size_t enced_pms_len;
	uint8_t pre_master_secret[SM2_MAX_PLAINTEXT_SIZE]; // sm2_decrypt 保证输出不会溢出
	size_t pre_master_secret_len;

	// Finished
	SM3_CTX sm3_ctx;
	SM3_CTX tmp_sm3_ctx;
	uint8_t sm3_hash[32];
	uint8_t local_verify_data[12];
	const uint8_t *verify_data;
	size_t verify_data_len;

	uint8_t *p;
	const uint8_t *cp;
	size_t len;


	// 服务器端如果设置了CA
	if (conn->ca_certs_len)
		client_verify = 1;

	// 初始化Finished和客户端验证环境
	sm3_init(&sm3_ctx);


	// recv ClientHello
	tls_trace("recv ClientHello\n");
	if (tls_record_recv(record, &recordlen, conn->sock) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	tlcp_record_trace(stderr, record, recordlen, 0, 0);
	if (tls_record_protocol(record) != TLS_protocol_tlcp) {
		error_print();
		tls_send_alert(conn, TLS_alert_protocol_version);
		goto end;
	}
	if (tls_record_get_handshake_client_hello(record,
		&protocol, &random, &session_id, &session_id_len,
		&client_ciphers, &client_ciphers_len,
		&exts, &exts_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	if (protocol != TLS_protocol_tlcp) {
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
	if (exts) {
		// 忽略客户端扩展错误可以兼容错误的TLCP客户端实现
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);

	// send ServerHello
	tls_trace("send ServerHello\n");
	tls_random_generate(server_random);
	if (tls_record_set_handshake_server_hello(record, &recordlen,
		TLS_protocol_tlcp, server_random, NULL, 0,
		conn->cipher_suite, NULL, 0) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		goto end;
	}
	tlcp_record_trace(stderr, record, recordlen, 0, 0);
	if (tls_record_send(record, recordlen, conn->sock) != 1) {
		error_print();
		goto end;
	}
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);

	// send ServerCertificate
	tls_trace("send ServerCertificate\n");
	if (tls_record_set_handshake_certificate(record, &recordlen,
		conn->server_certs, conn->server_certs_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		goto end;
	}
	tlcp_record_trace(stderr, record, recordlen, 0, 0);
	if (tls_record_send(record, recordlen, conn->sock) != 1) {
		error_print();
		goto end;
	}
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);

	// send ServerKeyExchange
	tls_trace("send ServerKeyExchange\n");
	if (x509_certs_get_cert_by_index(conn->server_certs, conn->server_certs_len, 1,
		&server_enc_cert, &server_enc_cert_len) != 1) {
		error_print();
		goto end;
	}
	p = server_enc_cert_lenbuf; len = 0;
	tls_uint24_to_bytes((uint24_t)server_enc_cert_len, &p, &len);
	if (sm2_sign_init(&sign_ctx, &conn->sign_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1
		|| sm2_sign_update(&sign_ctx, client_random, 32) != 1
		|| sm2_sign_update(&sign_ctx, server_random, 32) != 1
		|| sm2_sign_update(&sign_ctx, server_enc_cert_lenbuf, 3) != 1
		|| sm2_sign_update(&sign_ctx, server_enc_cert, server_enc_cert_len) != 1
		|| sm2_sign_finish(&sign_ctx, sigbuf, &siglen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		goto end;
	}
	if (tlcp_record_set_handshake_server_key_exchange_pke(record, &recordlen, sigbuf, siglen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		goto end;
	}
	tlcp_record_trace(stderr, record, recordlen, 0, 0);
	if (tls_record_send(record, recordlen, conn->sock) != 1) {
		error_print();
		goto end;
	}
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);

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
		tlcp_record_trace(stderr, record, recordlen, 0, 0);
		if (tls_record_send(record, recordlen, conn->sock) != 1) {
			error_print();
			goto end;
		}
		sm3_update(&sm3_ctx, record + 5, recordlen - 5);
	}

	// send ServerHelloDone
	tls_trace("send ServerHelloDone\n");
	tls_record_set_handshake_server_hello_done(record, &recordlen);
	tlcp_record_trace(stderr, record, recordlen, 0, 0);
	if (tls_record_send(record, recordlen, conn->sock) != 1) {
		error_print();
		goto end;
	}
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);

	// recv ClientCertificate
	if (conn->ca_certs_len) {
		tls_trace("recv ClientCertificate\n");
		if (tls_record_recv(record, &recordlen, conn->sock) != 1
			|| tls_record_protocol(record) != TLS_protocol_tlcp) {
			error_print();
			tls_send_alert(conn, TLS_alert_unexpected_message);
			goto end;
		}
		tlcp_record_trace(stderr, record, recordlen, 0, 0);
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
	}

	// ClientKeyExchange
	tls_trace("recv ClientKeyExchange\n");
	if (tls_record_recv(record, &recordlen, conn->sock) != 1
		|| tls_record_protocol(record) != TLS_protocol_tlcp) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	tlcp_record_trace(stderr, record, recordlen, 0, 0);
	if (tls_record_get_handshake_client_key_exchange_pke(record, &enced_pms, &enced_pms_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	if (sm2_decrypt(&conn->kenc_key, enced_pms, enced_pms_len,
		pre_master_secret, &pre_master_secret_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_decrypt_error);
		goto end;
	}
	if (pre_master_secret_len != 48) {
		error_print();
		tls_send_alert(conn, TLS_alert_decrypt_error);
		goto end;
	}
	sm3_update(&sm3_ctx, record + 5, recordlen - 5);

	// recv CertificateVerify
	if (client_verify) {
		tls_trace("recv CertificateVerify\n");
		SM3_CTX cert_verify_sm3_ctx = sm3_ctx;
		uint8_t cert_verify_hash[SM3_DIGEST_SIZE];

		if (tls_record_recv(record, &recordlen, conn->sock) != 1
			|| tls_record_protocol(record) != TLS_protocol_tlcp) {
			tls_send_alert(conn, TLS_alert_unexpected_message);
			error_print();
			goto end;
		}
		tlcp_record_trace(stderr, record, recordlen, 0, 0);
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

		sm3_finish(&cert_verify_sm3_ctx, cert_verify_hash);
		if (sm2_verify_init(&verify_ctx, &client_sign_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1
			|| sm2_verify_update(&verify_ctx, cert_verify_hash, SM3_DIGEST_SIZE) != 1
			|| sm2_verify_finish(&verify_ctx, sig, siglen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_decrypt_error);
			goto end;
		}
		sm3_update(&sm3_ctx, record + 5, recordlen - 5);
	}

	// generate secrets
	tls_trace("generate secrets\n");
	if (tls_prf(pre_master_secret, 48, "master secret",
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
	sm4_set_decrypt_key(&conn->client_write_enc_key, conn->key_block + 64);
	sm4_set_encrypt_key(&conn->server_write_enc_key, conn->key_block + 80);
	/*
	tls_secrets_print(stderr,
		pre_master_secret, 48,
		client_random, server_random,
		conn->master_secret,
		conn->key_block, 96,
		0, 4);
	*/

	// recv [ChangeCipherSpec]
	tls_trace("recv [ChangeCipherSpec]\n");
	if (tls_record_recv(record, &recordlen, conn->sock) != 1
		|| tls_record_protocol(record) != TLS_protocol_tlcp) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	tlcp_record_trace(stderr, record, recordlen, 0, 0);
	if (tls_record_get_change_cipher_spec(record) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}

	// recv ClientFinished
	tls_trace("recv Finished\n");
	if (tls_record_recv(record, &recordlen, conn->sock) != 1
		|| tls_record_protocol(record) != TLS_protocol_tlcp) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	if (recordlen > sizeof(finished_record)) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		goto end;
	}
	tlcp_record_trace(stderr, record, recordlen, (1<<24), 0); // 强制打印密文原数据

	// decrypt ClientFinished
	tls_trace("decrypt Finished\n");
	if (tls_record_decrypt(&conn->client_write_mac_ctx, &conn->client_write_enc_key,
		conn->client_seq_num, record, recordlen, finished_record, &finished_record_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_record_mac);
		goto end;
	}
	tlcp_record_trace(stderr, finished_record, finished_record_len, 0, 0);
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
	tlcp_record_trace(stderr, record, recordlen, 0, 0);
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
	tlcp_record_trace(stderr, finished_record, finished_record_len, 0, 0);
	if (tls_record_encrypt(&conn->server_write_mac_ctx, &conn->server_write_enc_key,
		conn->server_seq_num, finished_record, finished_record_len, record, &recordlen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		goto end;
	}
	tls_trace("encrypt Finished\n");
	tlcp_record_trace(stderr, record, recordlen, (1<<24), 0); // 强制打印密文原数据
	tls_seq_num_incr(conn->server_seq_num);
	if (tls_record_send(record, recordlen, conn->sock) != 1) {
		error_print();
		goto end;
	}

	conn->protocol = TLS_protocol_tlcp;

	fprintf(stderr, "Connection Established!\n\n");
	ret = 1;

end:
	gmssl_secure_clear(&sign_ctx, sizeof(sign_ctx));
	gmssl_secure_clear(pre_master_secret, sizeof(pre_master_secret));
	return ret;
}
