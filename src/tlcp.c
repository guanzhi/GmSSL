/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
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


// sign_master_public_key, enc_master_public_key, sign_key, enc_key
int tls_ctx_set_sm9_keys(TLS_CTX *ctx, const char *masterfile,
	const char *keyfile, const char *keypass)
{
	// 从masterfile中读取两个


	// 从keyfile中读取两个密钥


	return -1;
}


// TLCP的套件和TLS12不一样，我们现在只支持一种									
static const int tlcp_ciphers[] = { TLS_cipher_ecc_sm4_cbc_sm3 };
static const size_t tlcp_ciphers_count = sizeof(tlcp_ciphers)/sizeof(tlcp_ciphers[0]);


int tlcp_record_print(FILE *fp, int format, int indent, const uint8_t *record, size_t recordlen)
{
	// 目前只支持TLCP的ECC公钥加密套件，因此不论用哪个套件解析都是一样的
	// 如果未来支持ECDHE套件，可以将函数改为宏，直接传入 (conn->cipher_suite << 8)
	format |= tlcp_ciphers[0] << 8;
	return tls_record_print(fp, record, recordlen, format, indent);
}



/*
select (KeyExchangeAlgorithm) {
	case ECC:
		digitall-signed struct {
			opaque client_random[32];
			opaque server_random[32];
			opaque ASN1.Cert<1..2^24-1>;
		} signed_params;
	}
} ServerKeyExchange;

-- in TLCP 1.1, the `signed_params` is DER signature encoded in uint16array


在TLS12中，ServerKeyExchange中是有ECDH公钥的，但是在TLCP中

*/
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

int tlcp_send_client_hello(TLS_CONNECT *conn)
{
	int ret;
	uint8_t *record = conn->record;

	if (!conn->recordlen) {
		tls_record_set_protocol(record, TLS_protocol_tlcp);

		if (tls_random_generate(conn->client_random) != 1) {
			error_print();
			return -1;
		}

		if (tls_record_set_handshake_client_hello(conn->record, &conn->recordlen,
			conn->protocol, conn->client_random, NULL, 0,
			conn->ctx->cipher_suites, conn->ctx->cipher_suites_cnt,
			NULL, 0) != 1) {
			error_print();
			return -1;
		}

		tls_trace("send ClientHello\n");
		tlcp_record_print(stderr, 0, 0, conn->record, conn->recordlen);
		sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
	}

	if (conn->client_certificate_verify) {
		sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);
	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	tls_clean_record(conn);
	return 1;
}

int tlcp_recv_client_hello(TLS_CONNECT *conn)
{
	int ret;
	uint8_t *record = conn->record;

	int client_verify = 0;

	int protocol;
	const uint8_t *client_random;
	const uint8_t *session_id;
	size_t session_id_len;
	const uint8_t *client_ciphers;
	size_t client_ciphers_len;
	const uint8_t *client_exts;
	size_t client_exts_len;

	//sm3_init(&conn->sm3_ctx);


	// 服务器端如果设置了CA
	if (conn->ctx->cacertslen)
		client_verify = 1;

	// 这个判断应该改为一个函数
	if (client_verify)
		tls_client_verify_init(&conn->client_verify_ctx);


	tls_trace("recv ClientHello\n");

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	tlcp_record_print(stderr, 0, 0, conn->record, conn->recordlen);


	// 这里TLCP和TLS12是不一样的
	if (tls_record_protocol(record) != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_protocol_version);
		return -1;
	}

	if (tls_record_get_handshake_client_hello(record,
		&protocol, &client_random, &session_id, &session_id_len,
		&client_ciphers, &client_ciphers_len,
		&client_exts, &client_exts_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	if (protocol != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_protocol_version);
		return -1;
	}
	memcpy(conn->client_random, client_random, 32);

	if (tls_cipher_suites_select(client_ciphers, client_ciphers_len,
		conn->ctx->cipher_suites, conn->ctx->cipher_suites_cnt,
		&conn->cipher_suite) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_insufficient_security);
		return -1;
	}

	switch (conn->cipher_suite) {
	case TLS_cipher_ecc_sm4_cbc_sm3:
		conn->signature_algorithms[0] = TLS_sig_sm2sig_sm3;
		conn->ecdh_named_curve = 0;
		break;
	case TLS_cipher_ecdhe_sm4_cbc_sm3:
	case TLS_cipher_ecdhe_sm4_gcm_sm3:
	default:
		error_print();
		return -1;
	}

	if (client_exts) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
	if (client_verify)
		tls_client_verify_update(&conn->client_verify_ctx, conn->record + 5, conn->recordlen - 5);


	fprintf(stderr, "end of recv_client_hello\n");
	tls_clean_record(conn);

	return 1;
}

int tlcp_send_server_key_exchange(TLS_CONNECT *conn)
{
	SM2_SIGN_CTX sign_ctx;
	uint8_t sigbuf[SM2_MAX_SIGNATURE_SIZE];
	size_t siglen;
	const uint8_t *server_enc_cert;
	size_t server_enc_cert_len;
	uint8_t server_enc_cert_lenbuf[3];
	uint8_t *p;
	size_t len;
	int ret;

	tls_trace("send ServerKeyExchange\n");

	if (conn->recordlen == 0) {

		if (x509_certs_get_cert_by_index(conn->server_certs, conn->server_certs_len, 1,
			&server_enc_cert, &server_enc_cert_len) != 1) {
			error_print();
			return -1;
		}

		p = server_enc_cert_lenbuf;
		len = 0;
		tls_uint24_to_bytes((uint24_t)server_enc_cert_len, &p, &len);

		if (sm2_sign_init(&sign_ctx, &conn->sign_key.u.sm2_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1
			|| sm2_sign_update(&sign_ctx, conn->client_random, 32) != 1
			|| sm2_sign_update(&sign_ctx, conn->server_random, 32) != 1
			|| sm2_sign_update(&sign_ctx, server_enc_cert_lenbuf, 3) != 1
			|| sm2_sign_update(&sign_ctx, server_enc_cert, server_enc_cert_len) != 1
			|| sm2_sign_finish(&sign_ctx, sigbuf, &siglen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}

		if (tlcp_record_set_handshake_server_key_exchange_pke(conn->record, &conn->recordlen, sigbuf, siglen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		tlcp_record_print(stderr, 0, 0, conn->record, conn->recordlen);
	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
	if (conn->client_certificate_verify) {
		tls_client_verify_update(&conn->client_verify_ctx, conn->record + 5, conn->recordlen - 5);
	}

	return 1;
}


int tlcp_recv_server_key_exchange(TLS_CONNECT *conn)
{
	const uint8_t *sig;
	size_t siglen;
	const uint8_t *cp;
	size_t len;
	X509_KEY server_sign_key;

	const uint8_t *server_enc_cert;
	size_t server_enc_cert_len;

	uint8_t server_enc_cert_lenbuf[3];
	uint8_t *p;

	SM2_VERIFY_CTX verify_ctx;


	tls_trace("recv ServerKeyExchange\n");

	if (tls_record_recv(conn->record, &conn->recordlen, conn->sock) != 1
		|| tls_record_protocol(conn->record) != TLS_protocol_tlcp) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	tlcp_record_print(stderr, 0, 0, conn->record, conn->recordlen);

	if (tlcp_record_get_handshake_server_key_exchange_pke(conn->record, &sig, &siglen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);


	// verify ServerKeyExchange
	if (x509_certs_get_cert_by_index(conn->server_certs, conn->server_certs_len, 0, &cp, &len) != 1
		|| x509_cert_get_subject_public_key(cp, len, &server_sign_key) != 1
		|| x509_certs_get_cert_by_index(conn->server_certs, conn->server_certs_len, 1, &server_enc_cert, &server_enc_cert_len) != 1
		|| x509_cert_get_subject_public_key(server_enc_cert, server_enc_cert_len, &conn->server_enc_key) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}
	if (server_sign_key.algor != OID_ec_public_key
		|| server_sign_key.algor_param != OID_sm2
		|| conn->server_enc_key.algor != OID_ec_public_key
		|| conn->server_enc_key.algor_param != OID_sm2) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}
	p = server_enc_cert_lenbuf;
	len = 0;
	tls_uint24_to_bytes((uint24_t)server_enc_cert_len, &p, &len);
	if (sm2_verify_init(&verify_ctx, &server_sign_key.u.sm2_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1
		|| sm2_verify_update(&verify_ctx, conn->client_random, 32) != 1
		|| sm2_verify_update(&verify_ctx, conn->server_random, 32) != 1
		|| sm2_verify_update(&verify_ctx, server_enc_cert_lenbuf, 3) != 1
		|| sm2_verify_update(&verify_ctx, server_enc_cert, server_enc_cert_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		return -1;
	}
	if (sm2_verify_finish(&verify_ctx, sig, siglen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_decrypt_error);
		return -1;
	}

	return 1;
}

// 对于客户端，是先发送client_key_exchange在generate_keys
int tlcp_generate_keys(TLS_CONNECT *conn)
{
	tls_trace("generate secrets\n");



	if (tls_prf(conn->pre_master_secret, 48, "master secret",
			conn->client_random, 32,
			conn->server_random, 32,
			48, conn->master_secret) != 1
		|| tls_prf(conn->master_secret, 48, "key expansion",
			conn->server_random, 32, // 这里顺序为什么是反的				
			conn->client_random, 32,
			96, conn->key_block) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		return -1;
	}

	// 主力这里是不对的，需要为client, server设定不同的加密密钥			
	sm3_hmac_init(&conn->client_write_mac_ctx, conn->key_block, 32);
	sm3_hmac_init(&conn->server_write_mac_ctx, conn->key_block + 32, 32);

	if (conn->is_client) {
		sm4_set_encrypt_key(&conn->client_write_enc_key, conn->key_block + 64);
		sm4_set_decrypt_key(&conn->server_write_enc_key, conn->key_block + 80);
	} else {
		sm4_set_decrypt_key(&conn->client_write_enc_key, conn->key_block + 64);
		sm4_set_encrypt_key(&conn->server_write_enc_key, conn->key_block + 80);
	}

	tls_secrets_print(stderr,
		conn->pre_master_secret, 48,
		conn->client_random, conn->server_random,
		conn->master_secret,
		conn->key_block, 96,
		0, 4);

	return 1;
}

// 对于TLCP是否应该先执行send_client_key_exchange再生成密钥呢？
int tlcp_send_client_key_exchange(TLS_CONNECT *conn)
{
	uint8_t enced_pre_master_secret[SM2_MAX_CIPHERTEXT_SIZE];
	size_t enced_pre_master_secret_len;

	tls_trace("send ClientKeyExchange\n");

	if (tls_pre_master_secret_generate(conn->pre_master_secret, TLS_protocol_tlcp) != 1) {
		error_print();
		return -1;
	}

	if (sm2_encrypt(&conn->server_enc_key.u.sm2_key, conn->pre_master_secret, 48,
			enced_pre_master_secret, &enced_pre_master_secret_len) != 1
		|| tls_record_set_handshake_client_key_exchange_pke(conn->record, &conn->recordlen,
			enced_pre_master_secret, enced_pre_master_secret_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		return -1;
	}
	tlcp_record_print(stderr, 0, 0, conn->record, conn->recordlen);
	if (tls_record_send(conn->record, conn->recordlen, conn->sock) != 1) {
		error_print();
		return -1;
	}
	sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);

	return 1;
}


int tlcp_recv_client_key_exchange(TLS_CONNECT *conn)
{
	const uint8_t *enced_pms;
	size_t enced_pms_len;
	size_t pre_master_secret_len;

	tls_trace("recv ClientKeyExchange\n");

	if (tls_record_recv(conn->record, &conn->recordlen, conn->sock) != 1
		|| tls_record_protocol(conn->record) != TLS_protocol_tlcp) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	tlcp_record_print(stderr, 0, 0, conn->record, conn->recordlen);

	if (tls_record_get_handshake_client_key_exchange_pke(conn->record, &enced_pms, &enced_pms_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	// FIXME:
	// 这里需要检查一下密钥的长度，因为输入的长度是确定的，因此输出的密文长度应该也是确定的

	if (sm2_decrypt(&conn->kenc_key.u.sm2_key, enced_pms, enced_pms_len,
		conn->pre_master_secret, &pre_master_secret_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_decrypt_error);
		return -1;
	}
	if (pre_master_secret_len != 48) {
		error_print();
		tls_send_alert(conn, TLS_alert_decrypt_error);
		return -1;
	}
	sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);



	return 1;
}





int tlcp_recv_server_hello(TLS_CONNECT *conn)
{
	int ret;

	if ((ret = tls_recv_server_hello(conn)) != 1) {
		error_print();
		return ret;
	}
	return 1;
}

int tlcp_recv_server_certificate(TLS_CONNECT *conn)
{
	int ret;

	if ((ret = tls_recv_server_certificate(conn)) != 1) {
		error_print();
		return ret;
	}
	return 1;
}

int tlcp_recv_certificate_request(TLS_CONNECT *conn)
{
	int ret;

	if ((ret = tls_recv_certificate_request(conn)) != 1) {
		if (ret == 0) {
			return 0;
		}
		error_print();
		return ret;
	}
	return 1;
}

int tlcp_recv_server_hello_done(TLS_CONNECT *conn)
{
	int ret;

	if ((ret = tls_recv_server_hello_done(conn)) != 1) {
		error_print();
		return ret;
	}
	return 1;
}

int tlcp_send_client_certificate(TLS_CONNECT *conn)
{
	int ret;

	if ((ret = tls_send_client_certificate(conn)) != 1) {
		error_print();
		return ret;
	}
	return 1;
}

int tlcp_send_certificate_verify(TLS_CONNECT *conn)
{
	int ret;

	if ((ret = tls_send_certificate_verify(conn)) != 1) {
		error_print();
		return ret;
	}
	return 1;
}

int tlcp_send_change_cipher_spec(TLS_CONNECT *conn)
{
	int ret;

	if ((ret = tls_send_change_cipher_spec(conn)) != 1) {
		error_print();
		return ret;
	}
	return 1;
}

int tlcp_send_client_finished(TLS_CONNECT *conn)
{
	int ret;

	if ((ret = tls_send_client_finished(conn)) != 1) {
		error_print();
		return ret;
	}
	return 1;
}

int tlcp_recv_change_cipher_spec(TLS_CONNECT *conn)
{
	int ret;

	if ((ret = tls_recv_change_cipher_spec(conn)) != 1) {
		error_print();
		return ret;
	}
	return 1;
}

int tlcp_recv_server_finished(TLS_CONNECT *conn)
{
	int ret;

	if ((ret = tls_recv_server_finished(conn)) != 1) {
		error_print();
		return ret;
	}
	return 1;
}

int tlcp_send_server_hello(TLS_CONNECT *conn)
{
	int ret;

	if ((ret = tls_send_server_hello(conn)) != 1) {
		error_print();
		return ret;
	}
	return 1;
}

int tlcp_send_server_certificate(TLS_CONNECT *conn)
{
	int ret;

	if ((ret = tls_send_server_certificate(conn)) != 1) {
		error_print();
		return ret;
	}
	return 1;
}

int tlcp_send_certificate_request(TLS_CONNECT *conn)
{
	int ret;

	if ((ret = tls_send_certificate_request(conn)) != 1) {
		error_print();
		return ret;
	}
	return 1;
}

int tlcp_send_server_hello_done(TLS_CONNECT *conn)
{
	int ret;

	if ((ret = tls_send_server_hello_done(conn)) != 1) {
		error_print();
		return ret;
	}
	return 1;
}

int tlcp_recv_client_certificate(TLS_CONNECT *conn)
{
	int ret;

	if ((ret = tls_recv_client_certificate(conn)) != 1) {
		error_print();
		return ret;
	}
	return 1;
}

int tlcp_recv_certificate_verify(TLS_CONNECT *conn)
{
	int ret;

	if ((ret = tls_recv_certificate_verify(conn)) != 1) {
		error_print();
		return ret;
	}
	return 1;
}

int tlcp_recv_client_finished(TLS_CONNECT *conn)
{
	int ret;

	if ((ret = tls_recv_client_finished(conn)) != 1) {
		error_print();
		return ret;
	}
	return 1;
}

int tlcp_send_server_finished(TLS_CONNECT *conn)
{
	int ret;

	if ((ret = tls_send_server_finished(conn)) != 1) {
		error_print();
		return ret;
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

int tlcp_do_client_handshake(TLS_CONNECT *conn)
{
	int ret;
	int next_state;

	switch (conn->state) {
	case TLS_state_client_hello:
		ret = tlcp_send_client_hello(conn);
		next_state = TLS_state_server_hello;
		break;

	case TLS_state_server_hello:
		ret = tlcp_recv_server_hello(conn);
		next_state = TLS_state_server_certificate;
		break;

	case TLS_state_server_certificate:
		ret = tlcp_recv_server_certificate(conn);
		next_state = TLS_state_server_key_exchange;
		break;

	case TLS_state_server_key_exchange:
		ret = tlcp_recv_server_key_exchange(conn);
		next_state = TLS_state_certificate_request;
		break;

	case TLS_state_certificate_request:
		ret = tlcp_recv_certificate_request(conn);
		if (ret == 1) conn->client_certificate_verify = 1;
		next_state = TLS_state_server_hello_done;
		break;

	case TLS_state_server_hello_done:
		ret = tlcp_recv_server_hello_done(conn);
		if (conn->client_certificate_verify)
			next_state = TLS_state_client_certificate;
		else	next_state = TLS_state_client_key_exchange;
		break;

	case TLS_state_client_certificate:
		ret = tlcp_send_client_certificate(conn);
		next_state = TLS_state_client_key_exchange;
		break;

	case TLS_state_client_key_exchange:
		ret = tlcp_send_client_key_exchange(conn);
		next_state = TLS_state_generate_keys;
		break;

	case TLS_state_generate_keys:
		ret = tlcp_generate_keys(conn);
		if (conn->client_certificate_verify)
			next_state = TLS_state_certificate_verify;
		else	next_state = TLS_state_client_change_cipher_spec;
		break;

	case TLS_state_certificate_verify:
		ret = tlcp_send_certificate_verify(conn);
		next_state = TLS_state_client_change_cipher_spec;

	case TLS_state_client_change_cipher_spec:
		ret = tlcp_send_change_cipher_spec(conn);
		next_state = TLS_state_client_finished;
		break;

	case TLS_state_client_finished:
		ret = tlcp_send_client_finished(conn);
		next_state = TLS_state_server_change_cipher_spec;
		break;

	case TLS_state_server_change_cipher_spec:
		ret = tlcp_recv_change_cipher_spec(conn);
		next_state = TLS_state_server_finished;
		break;

	case TLS_state_server_finished:
		ret = tlcp_recv_server_finished(conn);
		next_state = TLS_state_handshake_over;
		break;

	default:
		error_print();
		return -1;
	}

	if (ret < 0) {
		if (ret == TLS_ERROR_RECV_AGAIN || ret == TLS_ERROR_SEND_AGAIN) {
			return ret;
		} else {
			error_print();
			return ret;
		}
	}

	conn->state = next_state;

	// ret == 0 means this step is bypassed
	if (ret == 1) {
		tls_clean_record(conn);
	}

	return 1;
}

int tlcp_do_server_handshake(TLS_CONNECT *conn)
{
	int ret;
	int next_state;

	switch (conn->state) {
	case TLS_state_client_hello:
		ret = tlcp_recv_client_hello(conn);
		next_state = TLS_state_server_hello;
		break;

	case TLS_state_server_hello:
		ret = tlcp_send_server_hello(conn);
		next_state = TLS_state_server_certificate;
		break;

	case TLS_state_server_certificate:
		ret = tlcp_send_server_certificate(conn);
		next_state = TLS_state_server_key_exchange;
		break;

	case TLS_state_server_key_exchange:
		ret = tlcp_send_server_key_exchange(conn);
		if (conn->client_certificate_verify)
			next_state = TLS_state_certificate_request;
		else	next_state = TLS_state_server_hello_done;
		break;

	case TLS_state_certificate_request:
		ret = tlcp_send_certificate_request(conn);
		next_state = TLS_state_server_hello_done;
		break;

	case TLS_state_server_hello_done:
		ret = tlcp_send_server_hello_done(conn);
		if (conn->client_certificate_verify)
			next_state = TLS_state_client_certificate;
		else	next_state = TLS_state_client_key_exchange;
		break;

	case TLS_state_client_certificate:
		ret = tlcp_recv_client_certificate(conn);
		next_state = TLS_state_client_key_exchange;
		break;

	case TLS_state_client_key_exchange:
		ret = tlcp_recv_client_key_exchange(conn);
		if (conn->client_certificate_verify)
			next_state = TLS_state_certificate_verify;
		else	next_state = TLS_state_generate_keys;
		break;

	case TLS_state_certificate_verify:
		ret = tlcp_recv_certificate_verify(conn);
		next_state = TLS_state_generate_keys;
		break;

	case TLS_state_generate_keys:
		ret = tlcp_generate_keys(conn);
		next_state = TLS_state_client_change_cipher_spec;
		break;

	case TLS_state_client_change_cipher_spec:
		ret = tlcp_recv_change_cipher_spec(conn);
		next_state = TLS_state_client_finished;
		break;

	case TLS_state_client_finished:
		ret = tlcp_recv_client_finished(conn);
		next_state = TLS_state_server_change_cipher_spec;
		break;

	case TLS_state_server_change_cipher_spec:
		ret = tlcp_send_change_cipher_spec(conn);
		next_state = TLS_state_server_finished;
		break;

	case TLS_state_server_finished:
		ret = tlcp_send_server_finished(conn);
		next_state = TLS_state_handshake_over;
		break;

	default:
		error_print();
		return -1;
	}

	if (ret != 1) {
		if (ret == TLS_ERROR_RECV_AGAIN || ret == TLS_ERROR_SEND_AGAIN) {
			return ret;
		} else {
			error_print();
			return ret;
		}

	}

	conn->state = next_state;

	tls_clean_record(conn);

	return 1;
}

int tlcp_client_handshake(TLS_CONNECT *conn)
{
	int ret;

	while (conn->state != TLS_state_handshake_over) {

		ret = tlcp_do_client_handshake(conn);

		if (ret != 1) {
			if (ret != TLS_ERROR_RECV_AGAIN && ret != TLS_ERROR_SEND_AGAIN) {
				error_print();
			}
			return ret;
		}
	}

	// TODO: cleanup conn?

	return 1;
}

int tlcp_server_handshake(TLS_CONNECT *conn)
{
	int ret;


	while (conn->state != TLS_state_handshake_over) {

		ret = tlcp_do_server_handshake(conn);

		if (ret != 1) {
			if (ret != TLS_ERROR_RECV_AGAIN && ret != TLS_ERROR_SEND_AGAIN) {
				error_print();
			}
			return ret;
		}
	}

	// TODO: cleanup conn?

	return 1;
}

int tlcp_do_connect(TLS_CONNECT *conn)
{
	int ret;
	fd_set rfds;
	fd_set wfds;

	// 应该把protocol_version的初始化放在这里

	conn->state = TLS_state_client_hello;
	sm3_init(&conn->sm3_ctx);

	while (1) {

		ret = tlcp_client_handshake(conn);
		if (ret == 1) {
			break;

		} else if (ret == TLS_ERROR_SEND_AGAIN) {
			FD_ZERO(&rfds);
			FD_ZERO(&wfds);
			FD_SET(conn->sock, &rfds);
			select(conn->sock + 1, &rfds, &wfds, NULL, NULL);

		} else if (ret == TLS_ERROR_RECV_AGAIN) {
			FD_ZERO(&rfds);
			FD_ZERO(&wfds);
			FD_SET(conn->sock, &wfds);
			select(conn->sock + 1, &rfds, &wfds, NULL, NULL);

		} else {
			error_print();
			return -1;
		}
	}

	return 1;
}

int tlcp_do_accept(TLS_CONNECT *conn)
{
	int ret;
	fd_set rfds;
	fd_set wfds;

	conn->state = TLS_state_client_hello;

	sm3_init(&conn->sm3_ctx);

	while (1) {

		ret = tlcp_server_handshake(conn);

		if (ret == 1) {
			break;

		} else if (ret == TLS_ERROR_SEND_AGAIN) {
			FD_ZERO(&rfds);
			FD_ZERO(&wfds);
			FD_SET(conn->sock, &rfds);
			select(conn->sock + 1, &rfds, &wfds, NULL, NULL);

		} else if (ret == TLS_ERROR_RECV_AGAIN) {
			FD_ZERO(&rfds);
			FD_ZERO(&wfds);
			FD_SET(conn->sock, &wfds);
			select(conn->sock + 1, &rfds, &wfds, NULL, NULL);

		} else {
			error_print();
			return -1;
		}
	}

	return 1;
}
