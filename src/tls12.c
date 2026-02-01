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
#include <assert.h>
#include <gmssl/rand.h>
#include <gmssl/x509.h>
#include <gmssl/error.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/pem.h>
#include <gmssl/mem.h>
#include <gmssl/tls.h>

#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>



static const int tls12_ciphers[] = {
	TLS_cipher_ecdhe_sm4_cbc_sm3,
	TLS_cipher_ecdhe_sm4_gcm_sm3,
	TLS_cipher_ecdhe_ecdsa_with_aes_128_cbc_sha256,
};

// 现在client_certificate_verify做的是不好的
/*
	是否要求客户端提供证书是服务器决定的，服务器方需要提供相应的CA证书
	对于服务器来说，CONN中保存的CA证书是用于验证客户端的
	对于客户端来说，这些证书是用于验证服务器的

	服务器知道是否验证客户端证书是通过是否有CA证书判断的

	客户端是通过什么判断的？
	实际上客户端可以提供备选的证书，因此应该有一个标识符来标记


现在通盘考虑一下ECDHE过程中双方需要准备什么


	Client:  X509_KEY私钥，自己生成
		从服务器那边拿到的对方的X509_KEY公钥

	服务器：自己的私钥，以及对方的公钥

每次如果发现当前的缓冲区是有数据的，record_left > 0，说明已经组装完了还没发送完
然后我们就要调用一个函数来发送数据

*/

// 实际上这个功能本质上是把缓冲区的数据发出去


int tls12_record_print(FILE *fp, const uint8_t *record,  size_t recordlen, int format, int indent)
{
	// 目前只支持TLCP的ECC公钥加密套件，因此不论用哪个套件解析都是一样的
	// 如果未来支持ECDHE套件，可以将函数改为宏，直接传入 (conn->cipher_suite << 8)
	format |= tls12_ciphers[0] << 8;
	return tls_record_print(fp, record, recordlen, format, indent);
}



// modify: conn->record_offset
int tls_send_record(TLS_CONNECT *conn)
{
	size_t left;
	tls_ret_t n;

	left = tls_record_length(conn->record) - conn->record_offset;
	while (left) {
		n = tls_socket_send(conn->sock, conn->record + conn->record_offset, left, 0);
		if (n < 0) {
			if (errno == EAGAIN && errno == EWOULDBLOCK) {
				return TLS_ERROR_SEND_AGAIN;
			} else if (errno == EINTR) {
				continue;
			} else {
				error_print();
				return -1;
			}
		}
		conn->record_offset += n;
		left -= n;
	}
	return 1;
}

int tls_recv_record(TLS_CONNECT *conn)
{
	size_t left;
	tls_ret_t n;

	// 说明报文已经完整的读取到了
	if (conn->recordlen) {
		return 1;
	}

	if (conn->record_offset < 5) {
		left = 5 - conn->record_offset;
		while (left) {
			n = tls_socket_recv(conn->sock, conn->record + conn->record_offset, left, 0);
			if (n < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					return TLS_ERROR_RECV_AGAIN;
				} else if (errno == EINTR) {
					continue;
				} else {
					error_print();
					// TODO: check the usage of OpenSSL SSL_ERR_SYSCALL
					// if applications such as Nginx, HTTPD do not use this error, we just return -1
					return TLS_ERROR_SYSCALL;
				}
			} else if (n == 0) {
				error_print();
				return TLS_ERROR_TCP_CLOSED;
			}
			conn->record_offset += n;
			left -= n;
		}
	}

	if (conn->record_offset == 5) {
		if (!tls_record_type_name(tls_record_type(conn->record))) {
			error_print();
			return -1;
		}
		if (!tls_protocol_name(tls_record_protocol(conn->record))) {
			error_print();
			return -1;
		}
		if (tls_record_length(conn->record) > TLS_MAX_RECORD_SIZE) {
			error_print();
			return -1;
		}
	}

	if (conn->record_offset >= tls_record_length(conn->record)) {
		error_print();
		return -1;
	}
	left = tls_record_length(conn->record) - conn->record_offset;
	while (left) {
		n = tls_socket_recv(conn->sock, conn->record + conn->record_offset, left, 0);
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return TLS_ERROR_RECV_AGAIN;
			} else if (errno == EINTR) {
				continue;
			} else {
				error_print();
				return TLS_ERROR_SYSCALL;
			}
		} else if (n == 0) {
			error_print();
			return TLS_ERROR_TCP_CLOSED;
		}
		conn->record_offset += n;
		left -= n;

	}

	conn->recordlen = conn->record_offset;
	return 1;
}

int tls_named_curve_oid(int named_curve)
{
	switch (named_curve) {
	case TLS_curve_secp256r1: return OID_secp256r1;
	case TLS_curve_sm2p256v1: return OID_sm2;
	}
	return OID_undef;
}

int tls_named_curve_from_oid(int oid)
{
	switch (oid) {
	case OID_secp256r1: return TLS_curve_secp256r1;
	case OID_sm2: return TLS_curve_sm2p256v1;
	}
	return 0;
}

enum {
	TLS_state_handshake_init = 0,
	TLS_state_client_hello,
	TLS_state_server_hello,
	TLS_state_server_certificate,
	TLS_state_server_key_exchange,
	TLS_state_certificate_request,
	TLS_state_server_hello_done,
	TLS_state_client_certificate,
	TLS_state_client_key_exchange,
	TLS_state_certificate_verify,
	TLS_state_generate_keys,
	TLS_state_client_change_cipher_spec,
	TLS_state_client_finished,
	TLS_state_server_change_cipher_spec,
	TLS_state_server_finished,
	TLS_state_handshake_over,
};

// 这个是必选的
const int ec_point_formats[] = { TLS_point_uncompressed };
size_t ec_point_formats_cnt = sizeof(ec_point_formats)/sizeof(ec_point_formats[0]);

// 服务器通常推荐返回这个值
const int supported_groups[] = {
	TLS_curve_sm2p256v1,
	TLS_curve_secp256r1,
};
size_t supported_groups_cnt = sizeof(supported_groups)/sizeof(supported_groups[0]);

// 仍旧是不可设置的
const int signature_algors[] = {
	TLS_sig_sm2sig_sm3,
	TLS_sig_ecdsa_secp256r1_sha256,
};
size_t signature_algors_cnt = sizeof(signature_algors)/sizeof(signature_algors[0]);



int tls_record_set_handshake_server_key_exchange(uint8_t *record, size_t *recordlen,
	const uint8_t *server_ecdh_params, size_t server_ecdh_params_len,
	uint16_t sig_alg, const uint8_t *sig, size_t siglen)
{
	const int type = TLS_handshake_server_key_exchange;
	uint8_t *p = tls_handshake_data(tls_record_data(record));
	size_t len = 0;

	if (server_ecdh_params_len != 69) {
		error_print();
		return -1;
	}
	if (siglen > TLS_MAX_SIGNATURE_SIZE) {
		error_print();
		return -1;
	}
	tls_array_to_bytes(server_ecdh_params, server_ecdh_params_len, &p, &len);
	tls_uint16_to_bytes(sig_alg, &p, &len);
	tls_uint16array_to_bytes(sig, siglen, &p, &len);
	tls_record_set_handshake(record, recordlen, type, NULL, len);
	return 1;
}

int tls_record_get_handshake_server_key_exchange(const uint8_t *record,
	uint8_t *curve_type, uint16_t *named_curve,
	const uint8_t **point_octets, size_t *point_octets_len,
	const uint8_t **server_ecdh_params, size_t *server_ecdh_params_len,
	uint16_t *sig_alg, const uint8_t **sig, size_t *siglen)
{
	int type;
	const uint8_t *p;
	size_t len;

	if (tls_record_get_handshake(record, &type, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (type != TLS_handshake_server_key_exchange) {
		error_print();
		return -1;
	}

	*server_ecdh_params = p;
	if (tls_uint8_from_bytes(curve_type, &p, &len) != 1
		|| tls_uint16_from_bytes(named_curve, &p, &len) != 1
		|| tls_uint8array_from_bytes(point_octets, point_octets_len, &p, &len) != 1) {
		error_print();
		return -1;
	}
	*server_ecdh_params_len = p - *server_ecdh_params;
	if (*server_ecdh_params_len != 69) {
		error_print();
		return -1;
	}
	if (tls_uint16_from_bytes(sig_alg, &p, &len) != 1
		|| tls_uint16array_from_bytes(sig, siglen, &p, &len) != 1
		|| tls_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	if (*curve_type != TLS_curve_type_named_curve) {
		error_print();
		return -1;
	}
	if (!tls_named_curve_name(*named_curve)) {
		error_print();
		return -1;
	}
	if (!tls_signature_scheme_name(*sig_alg)) {
		error_print();
		return -1;
	}
	return 1;
}

int tls_record_set_handshake_client_key_exchange(uint8_t *record, size_t *recordlen,
	const uint8_t *point_octets, size_t point_octets_len)
{
	int type = TLS_handshake_client_key_exchange;
	uint8_t *p = tls_handshake_data(tls_record_data(record));
	size_t len = 0;

	if (point_octets_len != 65) {
		error_print();
		return -1;
	}
	tls_uint8array_to_bytes(point_octets, (uint8_t)point_octets_len, &p, &len);
	tls_record_set_handshake(record, recordlen, type, NULL, len);
	return 1;
}

int tls_record_get_handshake_client_key_exchange(const uint8_t *record,
	const uint8_t **point_octets, size_t *point_octets_len)
{
	int type;
	const uint8_t *p;
	size_t len;

	if (tls_record_get_handshake(record, &type, &p, &len) != 1
		|| type != TLS_handshake_client_key_exchange) {
		error_print();
		return -1;
	}
	if (tls_uint8array_from_bytes(point_octets, point_octets_len, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (*point_octets_len != 65) {
		error_print();
		return -1;
	}
	if (len) {
		error_print();
		return -1;
	}
	return 1;
}

void tls_clean_record(TLS_CONNECT *conn)
{
	conn->record_offset = 0;
	conn->recordlen = 0;
}





int tls_handshake_init(TLS_CONNECT *conn)
{

	sm3_init(&conn->sm3_ctx);

	if (conn->client_certs_len) {
		//sm2_sign_init(&conn->sign_ctx, &conn->sign_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH);
	}

	return 1;
}

int tls_send_client_hello(TLS_CONNECT *conn)
{
	int ret;
	uint8_t *record = conn->record;

	if (!conn->recordlen) {
		uint8_t client_exts[TLS_MAX_EXTENSIONS_SIZE];
		uint8_t *p = client_exts;
		size_t client_exts_len = 0;

		tls_record_set_protocol(record, TLS_protocol_tls1);

		if (tls_random_generate(conn->client_random) != 1) {
			error_print();
			return -1;
		}
		if (tls_ec_point_formats_ext_to_bytes(ec_point_formats, ec_point_formats_cnt, &p, &client_exts_len) != 1
			|| tls_supported_groups_ext_to_bytes(supported_groups, supported_groups_cnt, &p, &client_exts_len) != 1
			|| tls_signature_algorithms_ext_to_bytes(signature_algors, signature_algors_cnt, &p, &client_exts_len) != 1) {
			error_print();
			return -1;
		}
		if (tls_record_set_handshake_client_hello(conn->record, &conn->recordlen,
			conn->protocol, conn->client_random, NULL, 0,
			tls12_ciphers, sizeof(tls12_ciphers)/sizeof(tls12_ciphers[0]),
			client_exts, client_exts_len) != 1) {
			error_print();
			return -1;
		}
		// offset = 0, recordlen > 0

		tls_trace("send ClientHello\n");
		tls12_record_trace(stderr, conn->record, conn->recordlen, 0, 0);
		sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
	}

	// 客户端一开始不知道是否要进行客户端验证
	// 如果用户提供了客户端证书那么就准备，如果没提供就完全不准确
	// 客户端的证书可以通过回调函数来设置
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

const int server_ciphers[] = { TLS_cipher_ecdhe_sm4_cbc_sm3 };
const size_t server_ciphers_cnt = 1;
const int curve = TLS_curve_sm2p256v1;


// 服务器在收到ClientHello之后，
int tls_recv_client_hello(TLS_CONNECT *conn)
{
	int ret;
	uint8_t *record = conn->record;
	size_t recordlen;

	int client_verify = 0;

	int protocol;
	const uint8_t *client_random;
	const uint8_t *session_id;
	size_t session_id_len;
	const uint8_t *client_ciphers;
	size_t client_ciphers_len;
	const uint8_t *client_exts;
	size_t client_exts_len;

	sm3_init(&conn->sm3_ctx);


	// 服务器端如果设置了CA
	if (conn->ca_certs_len)
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
	tls12_record_trace(stderr, conn->record, conn->recordlen, 0, 0);


	if (tls_record_protocol(record) != conn->protocol
		&& tls_record_protocol(record) != TLS_protocol_tls1) {
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

	// 服务器选择的cipher_suites需要和服务器准备的证书和公钥匹配
	if (tls_cipher_suites_select(client_ciphers, client_ciphers_len,
		server_ciphers, server_ciphers_cnt,
		&conn->cipher_suite) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_insufficient_security);
		return -1;
	}

	switch (conn->cipher_suite) {
	case TLS_cipher_ecdhe_sm4_cbc_sm3:
	case TLS_cipher_ecdhe_sm4_gcm_sm3:
		conn->sig_alg = TLS_sig_sm2sig_sm3;
		conn->ecdh_named_curve = TLS_curve_sm2p256v1;
		break;
	case TLS_cipher_ecdhe_ecdsa_with_aes_128_cbc_sha256:
		conn->sig_alg = TLS_sig_ecdsa_secp256r1_sha256;
		conn->ecdh_named_curve = TLS_curve_secp256r1;
		break;
	default:
		error_print();
		return -1;
	}

	if (client_exts) {
		// 这些函数需要能够访问conn的内部变量
		tls_process_client_hello_exts(client_exts, client_exts_len,
			conn->server_exts, &conn->server_exts_len, sizeof(conn->server_exts));
	}

	sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
	if (client_verify)
		tls_client_verify_update(&conn->client_verify_ctx, conn->record + 5, conn->recordlen - 5);


	fprintf(stderr, "end of recv_client_hello\n");
	tls_clean_record(conn);
	return 1;
}

int tls_send_server_hello(TLS_CONNECT *conn)
{
	int ret;
	tls_trace("send ServerHello\n");

	if (conn->recordlen == 0) {
		tls_record_set_protocol(conn->record, conn->protocol);
		if (tls_random_generate(conn->server_random) != 1) {
			error_print();
			return -1;
		}
		if (tls_record_set_handshake_server_hello(conn->record, &conn->recordlen,
			conn->protocol, conn->server_random, NULL, 0,
			conn->cipher_suite, conn->server_exts, conn->server_exts_len) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		tls12_record_trace(stderr, conn->record, conn->recordlen, 0, 0);
	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
	if (conn->ca_certs_len) {
		tls_client_verify_update(&conn->client_verify_ctx, conn->record + 5, conn->recordlen - 5);
	}

	tls_clean_record(conn);
	return 1;
}

int tls_recv_server_hello(TLS_CONNECT *conn)
{
	int ret;
	int protocol;
	int cipher_suite;
	const uint8_t *server_random;
	const uint8_t *session_id;
	size_t session_id_len;
	const uint8_t *server_exts;
	size_t server_exts_len;

	// 扩展的协商结果，-1 表示服务器不支持该扩展（未给出响应）
	int ec_point_format = -1;
	int supported_group = -1;
	int signature_algor = -1;

	// 实际上当前的record已经有完整的数据了，但是我们不知道啊

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}

	tls12_record_trace(stderr, conn->record, conn->recordlen, 0, 0);
	if (tls_record_protocol(conn->record) != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_protocol_version);
		return -1;
	}

	if (tls_record_get_handshake_server_hello(conn->record,
		&protocol, &server_random, &session_id, &session_id_len, &cipher_suite,
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

	memcpy(conn->server_random, server_random, 32);
	memcpy(conn->session_id, session_id, session_id_len);
	conn->cipher_suite = cipher_suite;
	sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
	if (conn->client_certs_len) {
		sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);
	}

	return 1;
}

int tls_send_server_certificate(TLS_CONNECT *conn)
{
	int ret;
	tls_trace("send ServerCertificate\n");

	if (conn->recordlen == 0) {
		if (tls_record_set_handshake_certificate(conn->record, &conn->recordlen,
			conn->server_certs, conn->server_certs_len) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		tls12_record_trace(stderr, conn->record, conn->recordlen, 0, 0);
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

int tls_recv_server_certificate(TLS_CONNECT *conn)
{
	int ret;
	int verify_result;
	const uint8_t *server_cert;
	size_t server_cert_len;
	X509_KEY server_sign_key;


	tls_trace("recv ServerCertificate\n");

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	if (tls_record_protocol(conn->record) != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	tls12_record_trace(stderr, conn->record, conn->recordlen, 0, 0);

	if (tls_record_get_handshake_certificate(conn->record,
		conn->server_certs, &conn->server_certs_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	if (x509_certs_get_cert_by_index(conn->server_certs, conn->server_certs_len, 0,
		&server_cert, &server_cert_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}
	if (x509_cert_get_subject_public_key(server_cert, server_cert_len, &server_sign_key) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}

	// set conn->server_sig_alg (decided by cipher_suite and server_cert.sign_key.algor, algor_param)
	if (server_sign_key.algor != OID_ec_public_key) {
		error_print();
		return -1;
	}
	switch (conn->cipher_suite) {
	case TLS_cipher_ecdhe_sm4_cbc_sm3:
	case TLS_cipher_ecdhe_sm4_gcm_sm3:
	case TLS_cipher_ecc_sm4_cbc_sm3:
	case TLS_cipher_ecc_sm4_gcm_sm3:
		if (server_sign_key.algor_param != OID_sm2) {
			error_print();
			return -1;
		}
		conn->server_sig_alg = TLS_sig_sm2sig_sm3;
		break;

	case TLS_cipher_ecdhe_ecdsa_with_aes_128_cbc_sha256:
		if (server_sign_key.algor_param != OID_secp256r1) {
			error_print();
			return -1;
		}
		conn->server_sig_alg = TLS_sig_ecdsa_secp256r1_sha256;
		break;
	default:
		error_print();
		return -1;
	}

	sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
	if (conn->client_certs_len) {
		sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);
	}

	assert(conn->verify_depth > 0 && conn->verify_depth < 10);

	// verify ServerCertificate
	if (x509_certs_verify(conn->server_certs, conn->server_certs_len, X509_cert_chain_server,
		conn->ca_certs, conn->ca_certs_len, conn->verify_depth, &verify_result) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}

	return 1;
}

int tls_send_server_key_exchange(TLS_CONNECT *conn)
{
	int ret;
	uint8_t server_ecdh_params[69];
	uint8_t *p = server_ecdh_params + 4;
	size_t len = 0;
	X509_SIGN_CTX sign_ctx;
	const void *sign_args = NULL;
	size_t sign_argslen = 0;
	uint8_t sig[X509_SIGNATURE_MAX_SIZE];
	size_t siglen;

	tls_trace("send ServerKeyExchange\n");


	if (conn->recordlen == 0) {
		// generate server ecdh_key
		if (x509_key_generate(&conn->ecdh_key,
			OID_ec_public_key, tls_named_curve_oid(conn->ecdh_named_curve)) != 1) {
			error_print();
			return -1;
		}

		// build server_ecdh_params
		server_ecdh_params[0] = TLS_curve_type_named_curve;
		server_ecdh_params[1] = conn->ecdh_named_curve >> 8;
		server_ecdh_params[2] = conn->ecdh_named_curve;
		server_ecdh_params[3] = 65;
		if (x509_public_key_to_bytes(&conn->ecdh_key, &p, &len) != 1) {
			error_print();
			return -1;
		}
		if (len != 65) {
			error_print();
			return -1;
		}

		// sign server_ecdh_params
		if (conn->sign_key.algor == OID_ec_public_key && conn->sign_key.algor_param == OID_sm2) {
			sign_args = SM2_DEFAULT_ID;
			sign_argslen = SM2_DEFAULT_ID_LENGTH;
		}
		if (x509_sign_init(&sign_ctx, &conn->sign_key, sign_args, sign_argslen) != 1
			|| x509_sign_update(&sign_ctx, conn->client_random, 32) != 1
			|| x509_sign_update(&sign_ctx, conn->server_random, 32) != 1
			|| x509_sign_update(&sign_ctx, server_ecdh_params, 69) != 1
			|| x509_sign_finish(&sign_ctx, sig, &siglen) != 1) {
			x509_sign_ctx_cleanup(&sign_ctx);
			error_print();
			return -1;
		}
		x509_sign_ctx_cleanup(&sign_ctx);

		if (tls_record_set_handshake_server_key_exchange(conn->record, &conn->recordlen,
			server_ecdh_params, sizeof(server_ecdh_params),
			conn->sig_alg, sig, siglen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		tls12_record_trace(stderr, conn->record, conn->recordlen, 0, 0);
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

// match the ecdhe of cipher_suite
int tls_curve_match_cipher_suite(int named_curve, int cipher_suite)
{
	switch (named_curve) {
	case TLS_curve_sm2p256v1:
		switch (cipher_suite) {
		case TLS_cipher_ecdhe_sm4_cbc_sm3:
		case TLS_cipher_ecdhe_sm4_gcm_sm3:
			break;
		default:
			error_print();
			return -1;
		}
		break;
	case TLS_curve_secp256r1:
		if (cipher_suite != TLS_cipher_ecdhe_ecdsa_with_aes_128_cbc_sha256) {
			error_print();
			return -1;
		}
		break;
	default:
		error_print();
		return -1;
	}
	return 1;
}

int tls_signature_scheme_match_cipher_suite(int sig_alg, int cipher_suite)
{
	switch (sig_alg) {
	case TLS_sig_sm2sig_sm3:
		switch (cipher_suite) {
		case TLS_cipher_ecdhe_sm4_cbc_sm3:
		case TLS_cipher_ecdhe_sm4_gcm_sm3:
		case TLS_cipher_ecc_sm4_cbc_sm3:
		case TLS_cipher_ecc_sm4_gcm_sm3:
			break;
		default:
			error_print();
			return -1;
		}
		break;
	case TLS_sig_ecdsa_secp256r1_sha256:
		switch (cipher_suite) {
		case TLS_cipher_ecdhe_ecdsa_with_aes_128_cbc_sha256:
			break;
		default:
			error_print();
			return -1;
		}
		break;
	default:
		error_print();
		return -1;
	}
	return 1;
}

int tls_recv_server_key_exchange(TLS_CONNECT *conn)
{
	int ret;
	uint8_t curve_type;
	uint16_t named_curve;
	const uint8_t *point_octets;
	size_t point_octets_len;
	const uint8_t *server_ecdh_params;
	size_t server_ecdh_params_len;
	uint16_t sig_alg;
	const uint8_t *sig;
	size_t siglen;

	// verify ServerKeyExchange
	X509_KEY server_sign_key;

	int server_cert_index = 0;
	const uint8_t *server_cert;
	size_t server_cert_len;

	uint16_t tls_sig_alg; // 这个值没有初始化				
	// 这属于握手过程中决定的具体算法，因此握手完成之后就应该确定下来了
	// 这应该是由cipher_suite和服务器证书中公钥（named_curve)共同决定的

	X509_SIGN_CTX sign_ctx;
	const void *sign_args = NULL;
	size_t sign_argslen = 0;

	tls_trace("recv ServerKeyExchange\n");


	if (tls_record_recv(conn->record, &conn->recordlen, conn->sock) != 1
		|| tls_record_protocol(conn->record) != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	tls12_record_trace(stderr, conn->record, conn->recordlen, 0, 0);


	if (tls_record_get_handshake_server_key_exchange(conn->record,
		&curve_type, &named_curve, &point_octets, &point_octets_len,
		&server_ecdh_params, &server_ecdh_params_len,
		&sig_alg, &sig, &siglen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	if (curve_type != TLS_curve_type_named_curve) {
		error_print();
		return -1;
	}
	// named_curve应该在supported_groups里面


	conn->ecdh_named_curve = named_curve;

	if (point_octets_len != 65) {
		error_print();
		return -1;
	}
	memcpy(conn->peer_ecdh_point, point_octets, point_octets_len);
	conn->peer_ecdh_point_len = point_octets_len;


	if (tls_curve_match_cipher_suite(named_curve, conn->cipher_suite) != 1) {
		error_print();
		return -1;
	}
	if (point_octets_len != 65) {
		error_print();
		return -1;
	}
	if (tls_signature_scheme_match_cipher_suite(sig_alg, conn->cipher_suite) != 1) {
		error_print();
		return -1;
	}

	// 解析server_key_exchange, curve_type, curve_name, point 这三个信息
	// 判断curve_type == named_curve
	// 判断curve_name在supported_groups中并记录这个信息
	// 验证point确实在curve_name的group中

	sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
	if (conn->client_certs_len)
		sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);



	// get sign_key from first cert of server_certs
	if (x509_certs_get_cert_by_index(conn->server_certs, conn->server_certs_len,
		server_cert_index, &server_cert, &server_cert_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}
	if (x509_cert_get_subject_public_key(server_cert, server_cert_len, &server_sign_key) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}

	// 这个检查是否是多余的？			
	// 这个值是签名算法和椭圆曲线名字的结合
	// cipher_suite只能决定签名算法类型
	// 公钥证书里面的公钥实际上只包含曲线的类型（而不决定签名算法，因为一个椭圆曲线本质上支持多种不同的签名算法）
	switch (sig_alg) {
	case TLS_sig_sm2sig_sm3:
		if (server_sign_key.algor != OID_ec_public_key
			|| server_sign_key.algor_param != OID_sm2) {
			error_print();
			tls_send_alert(conn, TLS_alert_bad_certificate);
			return -1;
		}
		break;
	case TLS_sig_ecdsa_secp256r1_sha256:
		if (server_sign_key.algor != OID_ec_public_key
			|| server_sign_key.algor_param != OID_secp256r1) {
			error_print();
			tls_send_alert(conn, TLS_alert_bad_certificate);
			return -1;
		}
		break;
	default:
		error_print();
		return -1;
	}

	if (server_sign_key.algor == OID_ec_public_key && server_sign_key.algor_param == OID_sm2) {
		sign_args = SM2_DEFAULT_ID;
		sign_argslen = SM2_DEFAULT_ID_LENGTH;
	}
	if (x509_verify_init(&sign_ctx, &server_sign_key, sign_args, sign_argslen, sig, siglen) != 1
		|| x509_verify_update(&sign_ctx, conn->client_random, 32) != 1
		|| x509_verify_update(&sign_ctx, conn->server_random, 32) != 1
		|| x509_verify_update(&sign_ctx, server_ecdh_params, 69) != 1
		|| x509_verify_finish(&sign_ctx) != 1) {
		error_print();
		return -1;
	}

	// xxxx
	// 这里的签名错了，肯定是sign_ctx就是不对的，因此是不可能正确的
	// 现在要做的是，必须确定server_key_exchange中都包括了哪些被签名的消息

	return 1;
}

int tls_send_certificate_request(TLS_CONNECT *conn)
{
	int ret;

	// 如果要进行客户端证书验证，服务器要提供验证的证书，但是所有证书的
	const uint8_t cert_types[] = { TLS_cert_type_ecdsa_sign };
	uint8_t ca_names[TLS_MAX_CA_NAMES_SIZE] = {0}; // TODO: 根据客户端验证CA证书列计算缓冲大小，或直接输出到record缓冲
	size_t ca_names_len = 0;


	if (!conn->client_certificate_verify) {
		error_print();
		return -1;
	}

	if (conn->recordlen == 0) {
		tls_trace("send CertificateRequest\n");
		if (tls_authorities_from_certs(ca_names, &ca_names_len, sizeof(ca_names),
			conn->ca_certs, conn->ca_certs_len) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		if (tls_record_set_handshake_certificate_request(conn->record, &conn->recordlen,
			cert_types, sizeof(cert_types),
			ca_names, ca_names_len) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		tls12_record_trace(stderr, conn->record, conn->recordlen, 0, 0);
	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
	tls_client_verify_update(&conn->client_verify_ctx, conn->record + 5, conn->recordlen - 5);

	return 1;
}

// 如果收到的是预期的报文，就处理，然后将recordlen = 0
// 否则保留recordlen
int tls_recv_certificate_request(TLS_CONNECT *conn)
{
	int ret;
	uint8_t *record = conn->record;
	size_t recordlen;
	const uint8_t *cp;
	size_t len;
	int handshake_type;

	const uint8_t *cert_types;
	size_t cert_types_len;
	const uint8_t *ca_names;
	size_t ca_names_len;


	// recv CertificateRequest or ServerHelloDone
	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	if (tls_record_protocol(conn->record) != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	if (tls_record_get_handshake(record, &handshake_type, &cp, &len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	if (handshake_type != TLS_handshake_certificate_request) {
		conn->client_certs_len = 0;

		fprintf(stderr, "%s %d: no certificate_request\n", __FILE__, __LINE__);
		fprintf(stderr, "recordlen = %zu\n", conn->recordlen);

		return 0; // 表明对方没有发送预期的报文
	}

	tls_trace("recv CertificateRequest\n");
	tls12_record_trace(stderr, conn->record, conn->recordlen, 0, 0);
	if (tls_record_get_handshake_certificate_request(conn->record,
		&cert_types, &cert_types_len, &ca_names, &ca_names_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	if(!conn->client_certs_len) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		return -1;
	}
	if (tls_cert_types_accepted(cert_types, cert_types_len, conn->client_certs, conn->client_certs_len) != 1
		|| tls_authorities_issued_certificate(ca_names, ca_names_len, conn->client_certs, conn->client_certs_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unsupported_certificate);
		return -1;
	}
	sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
	sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);

	conn->recordlen = 0;
	return 1;
}

int tls_send_server_hello_done(TLS_CONNECT *conn)
{
	int ret;
	tls_trace("send ServerHelloDone\n");


	if (conn->recordlen == 0) {
		tls_record_set_handshake_server_hello_done(conn->record, &conn->recordlen);
		tls12_record_trace(stderr, conn->record, conn->recordlen, 0, 0);
	}


	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}
	sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);

	if (conn->client_certs_len) {
		tls_client_verify_update(&conn->client_verify_ctx, conn->record + 5, conn->recordlen - 5);
	}
	return 1;
}


// 这是一个非常特殊的状态，其他的所有recv状态都是要读取的
// 但是这个状态在大多数情况下，之前已经读取完了，但是我们无法判断这个信息
int tls_recv_server_hello_done(TLS_CONNECT *conn)
{
	int ret;
	tls_trace("recv ServerHelloDone\n");

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	if (tls_record_protocol(conn->record) != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	tls12_record_trace(stderr, conn->record, conn->recordlen, 0, 0);

	if (tls_record_get_handshake_server_hello_done(conn->record) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
	if (conn->client_certs_len)
		sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);


	return 1;
}

int tls_send_client_certificate(TLS_CONNECT *conn)
{
	int ret;
	tls_trace("send ClientCertificate\n");

	if (conn->client_certs_len == 0) {
		error_print();
		return -1;
	}

	if (conn->recordlen == 0) {
		if (tls_record_set_handshake_certificate(conn->record, &conn->recordlen,
			conn->client_certs, conn->client_certs_len) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		tls12_record_trace(stderr, conn->record, conn->recordlen, 0, 0);
	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}


	sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
	sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);

	return 1;
}

// 只有在需要验证客户端证书的时候这个函数才执行，是否内部要判断一下
int tls_recv_client_certificate(TLS_CONNECT *conn)
{
	int ret;
	const int verify_depth = 5;
	int verify_result;

	tls_trace("recv ClientCertificate\n");

	if (conn->ca_certs_len == 0) {
		error_print();
		return -1;
	}

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	if (tls_record_protocol(conn->record) != conn->protocol) { // protocol检查应该在trace之后
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	tls12_record_trace(stderr, conn->record, conn->recordlen, 0, 0);
	if (tls_record_get_handshake_certificate(conn->record, conn->client_certs, &conn->client_certs_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	if (x509_certs_verify(conn->client_certs, conn->client_certs_len, X509_cert_chain_client,
		conn->ca_certs, conn->ca_certs_len, verify_depth, &verify_result) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}
	sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
	tls_client_verify_update(&conn->client_verify_ctx, conn->record + 5, conn->recordlen - 5);

	return 1;
}

int tls_generate_keys(TLS_CONNECT *conn)
{
	uint8_t pre_master_secret[32];
	size_t pre_master_secret_len;
	uint8_t key_block[96];


	if (x509_key_exchange(&conn->ecdh_key,
		conn->peer_ecdh_point, conn->peer_ecdh_point_len,
		pre_master_secret, &pre_master_secret_len) != 1) {
		error_print();
		return -1;
	}
	if (pre_master_secret_len != sizeof(pre_master_secret)) {
		error_print();
		return -1;
	}

	if (tls_prf(pre_master_secret, 32, "master secret",
			conn->client_random, 32,
			conn->server_random, 32,
			48, conn->master_secret) != 1) {
		error_print();
		return -1;
	}

	if (tls_prf(conn->master_secret, 48, "key expansion",
			conn->server_random, 32,
			conn->client_random, 32,
			96, conn->key_block) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		return -1;
	}

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
		pre_master_secret, 48,
		conn->client_random, conn->server_random,
		conn->master_secret,
		conn->key_block, 96,
		0, 4);

	return 1;
}

int tls_send_client_key_exchange(TLS_CONNECT *conn)
{
	int ret;
	uint8_t point_octets[65];
	uint8_t *p = point_octets;
	size_t len = 0;

	// 客户端的ECDHE的公钥肯定和服务器是保持一致的
	// 因此在接收到服务器的公钥之后，应该保存这个信息

	if (conn->recordlen == 0) {
		if (x509_key_generate(&conn->ecdh_key,
			OID_ec_public_key, tls_named_curve_oid(conn->ecdh_named_curve)) != 1) {
			error_print();
			return -1;
		}
		if (x509_public_key_to_bytes(&conn->ecdh_key, &p, &len) != 1) {
			error_print();
			return -1;
		}
		if (len != sizeof(point_octets)) {
			error_print();
			return -1;
		}

		tls_trace("send ClientKeyExchange\n");
		if (tls_record_set_handshake_client_key_exchange(conn->record, &conn->recordlen,
			point_octets, len) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		tls12_record_trace(stderr, conn->record, conn->recordlen, 0, 0);
	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
	if (conn->client_certs_len)
		sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);

	return 1;
}

int tls_recv_client_key_exchange(TLS_CONNECT *conn)
{
	int ret;
	const uint8_t *point_octets;
	size_t point_octets_len;

	tls_trace("recv ClientKeyExchange\n");
	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	if (tls_record_protocol(conn->record) != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	tls12_record_trace(stderr, conn->record, conn->recordlen, 0, 0);

	if (tls_record_get_handshake_client_key_exchange(conn->record,
		&point_octets, &point_octets_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	if (point_octets_len != 65) {
		error_print();
		return -1;
	}

	memcpy(conn->peer_ecdh_point, point_octets, point_octets_len);
	conn->peer_ecdh_point_len = point_octets_len;

	sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
	if (conn->ca_certs_len)
		tls_client_verify_update(&conn->client_verify_ctx, conn->record + 5, conn->recordlen - 5);

	return 1;
}

int tls_send_certificate_verify(TLS_CONNECT *conn)
{
	int ret;
	uint8_t sig[SM2_MAX_SIGNATURE_SIZE];
	size_t siglen;

	tls_trace("send CertificateVerify\n");

	if (!conn->client_certificate_verify) {
		error_print();
		return -1;
	}

	if (conn->recordlen == 0) {
		if (sm2_sign_finish(&conn->sign_ctx, sig, &siglen) != 1) {
			error_print();
			return -1;
		}
		if (tls_record_set_handshake_certificate_verify(conn->record, &conn->recordlen, sig, siglen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		tls12_record_trace(stderr, conn->record, conn->recordlen, 0, 0);
	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
	return 1;
}

int tls_recv_certificate_verify(TLS_CONNECT *conn)
{
	int ret;
	X509_KEY client_sign_key;

	const uint8_t *sig;
	size_t siglen;

	const uint8_t *client_cert;
	size_t client_cert_len;

	if (!conn->client_certificate_verify) {
		error_print();
		return -1;
	}

	tls_trace("recv CertificateVerify\n");
	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	if (tls_record_protocol(conn->record) != conn->protocol) {
		tls_send_alert(conn, TLS_alert_unexpected_message);
		error_print();
		return -1;
	}
	tls12_record_trace(stderr, conn->record, conn->recordlen, 0, 0);

	// get signature from certificate_verify
	if (tls_record_get_handshake_certificate_verify(conn->record, &sig, &siglen) != 1) {
		tls_send_alert(conn, TLS_alert_unexpected_message);
		error_print();
		return -1;
	}

	// get sign_key from client certificate
	if (x509_certs_get_cert_by_index(conn->client_certs, conn->client_certs_len, 0,
		&client_cert, &client_cert_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}
	if (x509_cert_get_subject_public_key(client_cert, client_cert_len, &client_sign_key) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}
	// 这里是否要验证证书的类型呢？我们现在还不支持其他签名算法
	if (client_sign_key.algor != OID_ec_public_key
		|| client_sign_key.algor_param != OID_sm2) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}

	if (tls_client_verify_finish(&conn->client_verify_ctx, sig, siglen, &client_sign_key.u.sm2_key) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_decrypt_error);
		return -1;
	}
	sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);

	return 1;
}

int tls_send_change_cipher_spec(TLS_CONNECT *conn)
{
	int ret;
	if (conn->recordlen == 0) {
		tls_trace("send [ChangeCipherSpec]\n");
		if (tls_record_set_change_cipher_spec(conn->record, &conn->recordlen) !=1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		tls12_record_trace(stderr, conn->record, conn->recordlen, 0, 0);
	}
	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}
	return 1;
}

int tls_recv_change_cipher_spec(TLS_CONNECT *conn)
{
	int ret;

	tls_trace("recv [ChangeCipherSpec]\n");
	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}

	if (tls_record_protocol(conn->record) != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	tls12_record_trace(stderr, conn->record, conn->recordlen, 0, 0);
	if (tls_record_get_change_cipher_spec(conn->record) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	return 1;
}

int tls_send_client_finished(TLS_CONNECT *conn)
{
	int ret;

	SM3_CTX tmp_sm3_ctx;
	uint8_t sm3_hash[32];
	uint8_t finished_record[TLS_FINISHED_RECORD_BUF_SIZE];
	size_t finished_record_len;
	uint8_t local_verify_data[12];


	tls_record_set_protocol(finished_record, conn->protocol);

	if (conn->recordlen == 0) {
		tls_trace("send Finished\n");

		// 到目前为止所有消息的哈希
		memcpy(&tmp_sm3_ctx, &conn->sm3_ctx, sizeof(SM3_CTX));
		sm3_finish(&tmp_sm3_ctx, sm3_hash);


		if (tls_prf(conn->master_secret, 48,
			"client finished", sm3_hash, 32, NULL, 0,
			sizeof(local_verify_data), local_verify_data) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}

		// finished_record是没有问题的
		if (tls_record_set_handshake_finished(finished_record, &finished_record_len,
			local_verify_data, sizeof(local_verify_data)) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}

		// 此时finished_record中的头部应该是完整的
		tls12_record_trace(stderr, finished_record, finished_record_len, 0, 0);

		sm3_update(&conn->sm3_ctx, finished_record + 5, finished_record_len - 5);

		// encrypt Client Finished

		// 此时finished_record中的头部应该是完整的


		// encrypt Client Finished

		// 但是conn->record并没有设置

		// 但是conn->record并没有设置

		// 这个会把finished的头部copy过来, 但是握手的头部并没有copy



		if (tls_record_encrypt(&conn->client_write_mac_ctx, &conn->client_write_enc_key,
			conn->client_seq_num, finished_record, finished_record_len,
			conn->record, &conn->recordlen) != 1) {

			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}

		// 最后输出的负载数据是80-bytes，而实际上应该是64字节，多了16字节，这显然是不对的
		// 为什么会有这样的结果呢？

		tls_encrypted_record_trace(stderr, conn->record, conn->recordlen, (1<<24), 0); // 强制打印密文原数据

		// 这里直接就出错了
		/*
		if (tls_record_decrypt(&conn->client_write_mac_ctx, &conn->client_write_enc_key,
			conn->client_seq_num, conn->record, conn->recordlen, finished_record, &finished_record_len) != 1) {
			error_print();
			return -1;
		}

		*/

		tls_trace("encrypted ClientFinished\n");
		tls_encrypted_record_trace(stderr, conn->record, conn->recordlen, (1<<24), 0); // 强制打印密文原数据
		tls_seq_num_incr(conn->client_seq_num);

	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	return 1;
}

int tls_recv_client_finished(TLS_CONNECT *conn)
{
	int ret;

	uint8_t finished_record[TLS_FINISHED_RECORD_BUF_SIZE];
	size_t finished_record_len;
	const uint8_t *verify_data;
	size_t verify_data_len;

	uint8_t local_verify_data[12];

	SM3_CTX tmp_sm3_ctx;
	uint8_t sm3_hash[32];

	// recv ClientFinished
	tls_trace("recv Finished\n");
	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	if (tls_record_protocol(conn->record) != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	if (conn->recordlen > sizeof(finished_record)) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	tls_encrypted_record_trace(stderr, conn->record, conn->recordlen, (1<<24), 0); // 强制打印密文原数据

	// decrypt ClientFinished
	tls_trace("decrypt Finished\n");


	if (tls_record_decrypt(&conn->client_write_mac_ctx, &conn->client_write_enc_key,
		conn->client_seq_num, conn->record, conn->recordlen,
		finished_record, &finished_record_len) != 1) {


		error_print();
		tls_send_alert(conn, TLS_alert_bad_record_mac);
		return -1;
	}
	tls12_record_trace(stderr, finished_record, finished_record_len, 0, 0);
	tls_seq_num_incr(conn->client_seq_num);
	if (tls_record_get_handshake_finished(finished_record, &verify_data, &verify_data_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_record_mac);
		return -1;
	}
	if (verify_data_len != sizeof(local_verify_data)) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_record_mac);
		return -1;
	}

	// verify ClientFinished
	memcpy(&tmp_sm3_ctx, &conn->sm3_ctx, sizeof(SM3_CTX));
	sm3_update(&conn->sm3_ctx, finished_record + 5, finished_record_len - 5);
	sm3_finish(&tmp_sm3_ctx, sm3_hash);
	if (tls_prf(conn->master_secret, 48, "client finished", sm3_hash, 32, NULL, 0,
		sizeof(local_verify_data), local_verify_data) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		return -1;
	}
	if (memcmp(verify_data, local_verify_data, sizeof(local_verify_data)) != 0) {
		error_puts("client_finished.verify_data verification failure");
		tls_send_alert(conn, TLS_alert_decrypt_error);
		return -1;
	}

	return 1;
}

int tls_send_server_finished(TLS_CONNECT *conn)
{
	int ret;
	uint8_t *record = conn->record;
	size_t recordlen;
	uint8_t sm3_hash[32];
	uint8_t local_verify_data[12];

	uint8_t finished_record[TLS_FINISHED_RECORD_BUF_SIZE];
	size_t finished_record_len;

	tls_record_set_protocol(finished_record, conn->protocol);

	if (conn->recordlen == 0) {
		tls_trace("send Finished\n");
		sm3_finish(&conn->sm3_ctx, sm3_hash);
		if (tls_prf(conn->master_secret, 48, "server finished", sm3_hash, 32, NULL, 0,
				sizeof(local_verify_data), local_verify_data) != 1
			|| tls_record_set_handshake_finished(finished_record, &finished_record_len,
				local_verify_data, sizeof(local_verify_data)) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		tls12_record_trace(stderr, finished_record, finished_record_len, 0, 0);
		if (tls_record_encrypt(&conn->server_write_mac_ctx, &conn->server_write_enc_key,
			conn->server_seq_num, finished_record, finished_record_len, record, &recordlen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		tls_trace("encrypt Finished\n");
		tls_encrypted_record_trace(stderr, record, recordlen, (1<<24), 0); // 强制打印密文原数据
		tls_seq_num_incr(conn->server_seq_num);
	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}


	return 1;
}

int tls_recv_server_finished(TLS_CONNECT *conn)
{
	int ret;
	uint8_t finished_record[TLS_FINISHED_RECORD_BUF_SIZE];
	size_t finished_record_len;

	uint8_t sm3_hash[32];

	const uint8_t *verify_data;
	size_t verify_data_len;
	uint8_t local_verify_data[12];


	// Finished
	tls_trace("recv Finished\n");
	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	if (tls_record_protocol(conn->record) != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	if (conn->recordlen > sizeof(finished_record)) {
		error_print(); // 解密可能导致 finished_record 溢出
		tls_send_alert(conn, TLS_alert_bad_record_mac);
		return -1;
	}
	tls_encrypted_record_trace(stderr, conn->record, conn->recordlen, (1<<24), 0); // 强制打印密文原数据


	tls_trace("decrypt Finished\n");
	if (tls_record_decrypt(&conn->server_write_mac_ctx, &conn->server_write_enc_key,
		conn->server_seq_num, conn->record, conn->recordlen, finished_record, &finished_record_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_record_mac);
		return -1;
	}
	tls12_record_trace(stderr, finished_record, finished_record_len, 0, 0);
	tls_seq_num_incr(conn->server_seq_num);
	if (tls_record_get_handshake_finished(finished_record, &verify_data, &verify_data_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	if (verify_data_len != sizeof(local_verify_data)) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	sm3_finish(&conn->sm3_ctx, sm3_hash);
	if (tls_prf(conn->master_secret, 48, "server finished",
		sm3_hash, 32, NULL, 0, sizeof(local_verify_data), local_verify_data) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		return -1;
	}
	if (memcmp(verify_data, local_verify_data, sizeof(local_verify_data)) != 0) {
		error_puts("server_finished.verify_data verification failure");
		tls_send_alert(conn, TLS_alert_decrypt_error);
		return -1;
	}

	if (!conn->quiet)
		fprintf(stderr, "Connection established!\n");

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

int tls12_do_client_handshake(TLS_CONNECT *conn)
{
	int ret;
	int next_state;

	switch (conn->state) {
	case TLS_state_client_hello:
		ret = tls_send_client_hello(conn);
		next_state = TLS_state_server_hello;
		break;

	case TLS_state_server_hello:
		ret = tls_recv_server_hello(conn);
		next_state = TLS_state_server_certificate;
		break;

	case TLS_state_server_certificate:
		ret = tls_recv_server_certificate(conn);
		next_state = TLS_state_server_key_exchange;
		break;

	case TLS_state_server_key_exchange:
		ret = tls_recv_server_key_exchange(conn);
		next_state = TLS_state_certificate_request;
		break;

	// the only optional state
	case TLS_state_certificate_request:
		fprintf(stderr, "TLS_state_certificate_request\n");
		ret = tls_recv_certificate_request(conn);
		fprintf(stderr, "    ret = %d\n", ret);

		if (ret == 1) conn->client_certificate_verify = 1;
		next_state = TLS_state_server_hello_done;
		break;

	case TLS_state_server_hello_done:
		fprintf(stderr, "TLS_state_server_hello_done\n");
		ret = tls_recv_server_hello_done(conn);
		if (conn->client_certificate_verify)
			next_state = TLS_state_client_certificate;
		else	next_state = TLS_state_client_key_exchange;
		break;

	case TLS_state_client_certificate:
		ret = tls_send_client_certificate(conn);
		next_state = TLS_state_client_key_exchange;
		break;

	case TLS_state_client_key_exchange:
		ret = tls_send_client_key_exchange(conn);
		next_state = TLS_state_generate_keys;
		break;

	case TLS_state_generate_keys:
		ret = tls_generate_keys(conn);
		if (conn->client_certificate_verify)
			next_state = TLS_state_certificate_verify;
		else	next_state = TLS_state_client_change_cipher_spec;
		break;

	case TLS_state_certificate_verify:
		ret = tls_send_certificate_verify(conn);
		next_state = TLS_state_client_change_cipher_spec;

	case TLS_state_client_change_cipher_spec:
		ret = tls_send_change_cipher_spec(conn);
		next_state = TLS_state_client_finished;
		break;

	case TLS_state_client_finished:
		ret = tls_send_client_finished(conn);
		next_state = TLS_state_server_change_cipher_spec;
		break;

	case TLS_state_server_change_cipher_spec:
		ret = tls_recv_change_cipher_spec(conn);
		next_state = TLS_state_server_finished;
		break;

	case TLS_state_server_finished:
		ret = tls_recv_server_finished(conn);
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

int tls12_do_server_handshake(TLS_CONNECT *conn)
{
	int ret;
	int next_state;

	switch (conn->state) {
	case TLS_state_client_hello:
		ret = tls_recv_client_hello(conn);
		next_state = TLS_state_server_hello;
		break;

	case TLS_state_server_hello:
		ret = tls_send_server_hello(conn);
		next_state = TLS_state_server_certificate;
		break;

	case TLS_state_server_certificate:
		ret = tls_send_server_certificate(conn);
		next_state = TLS_state_server_key_exchange;
		break;

	case TLS_state_server_key_exchange:
		ret = tls_send_server_key_exchange(conn);
		if (conn->client_certificate_verify)
			next_state = TLS_state_certificate_request;
		else	next_state = TLS_state_server_hello_done;
		break;

	case TLS_state_certificate_request:
		ret = tls_send_certificate_request(conn);
		next_state = TLS_state_server_hello_done;
		break;

	case TLS_state_server_hello_done:
		ret = tls_send_server_hello_done(conn);
		if (conn->client_certificate_verify)
			next_state = TLS_state_client_certificate;
		else	next_state = TLS_state_client_key_exchange;
		break;

	case TLS_state_client_certificate:
		ret = tls_recv_client_certificate(conn);
		next_state = TLS_state_client_key_exchange;
		break;

	case TLS_state_client_key_exchange:
		ret = tls_recv_client_key_exchange(conn);
		if (conn->client_certificate_verify)
			next_state = TLS_state_certificate_verify;
		else	next_state = TLS_state_generate_keys;
		break;

	case TLS_state_certificate_verify:
		ret = tls_recv_certificate_verify(conn);
		next_state = TLS_state_generate_keys;
		break;

	case TLS_state_generate_keys:
		ret = tls_generate_keys(conn);
		next_state = TLS_state_client_change_cipher_spec;
		break;

	case TLS_state_client_change_cipher_spec:
		ret = tls_recv_change_cipher_spec(conn);
		next_state = TLS_state_client_finished;
		break;

	case TLS_state_client_finished:
		ret = tls_recv_client_finished(conn);
		next_state = TLS_state_server_change_cipher_spec;
		break;

	case TLS_state_server_change_cipher_spec:
		ret = tls_send_change_cipher_spec(conn);
		next_state = TLS_state_server_finished;
		break;

	case TLS_state_server_finished:
		ret = tls_send_server_finished(conn);
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


// 这个函数显然是不对的，因为这个函数就是一个重入的函数，重入函数不应该自己设置状态啊
int tls12_client_handshake(TLS_CONNECT *conn)
{
	int ret;

	while (conn->state != TLS_state_handshake_over) {

		ret = tls12_do_client_handshake(conn);

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

int tls12_server_handshake(TLS_CONNECT *conn)
{
	int ret;


	while (conn->state != TLS_state_handshake_over) {

		ret = tls12_do_server_handshake(conn);

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

int tls12_do_connect(TLS_CONNECT *conn)
{
	int ret;
	fd_set rfds;
	fd_set wfds;

	conn->state = TLS_state_client_hello;
	sm3_init(&conn->sm3_ctx);

	while (1) {

		ret = tls12_client_handshake(conn);
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

int tls12_do_accept(TLS_CONNECT *conn)
{
	int ret;
	fd_set rfds;
	fd_set wfds;

	conn->state = TLS_state_client_hello;

	sm3_init(&conn->sm3_ctx);

	while (1) {

		ret = tls12_server_handshake(conn);

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

