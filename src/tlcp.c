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



static const int tlcp_ciphers[] = {
	TLS_cipher_ecc_sm4_cbc_sm3,
	TLS_cipher_ecc_sm4_gcm_sm3,
};
static const size_t tlcp_ciphers_count = sizeof(tlcp_ciphers)/sizeof(tlcp_ciphers[0]);


int tlcp_record_print(FILE *fp, int format, int indent, const uint8_t *record, size_t recordlen)
{
	// 目前只支持TLCP的ECC公钥加密套件，因此不论用CBC/GCM哪个套件解析都是一样的
	// 如果未来支持ECDHE套件，可以将函数改为宏，直接传入 (conn->cipher_suite << 8)
	format |= tlcp_ciphers[0] << 8;
	return tls_record_print(fp, record, recordlen, format, indent);
}

static int tlcp_cipher_suite_get(int cipher_suite, const BLOCK_CIPHER **cipher, const DIGEST **digest)
{
	switch (cipher_suite) {
	case TLS_cipher_ecc_sm4_cbc_sm3:
	case TLS_cipher_ecc_sm4_gcm_sm3:
		*cipher = BLOCK_CIPHER_sm4();
		*digest = DIGEST_sm3();
		break;
	default:
		error_print();
		return -1;
	}
	return 1;
}

int tlcp_record_encrypt(int cipher_suite,
	const HMAC_CTX *hmac_ctx, const BLOCK_CIPHER_KEY *key, const uint8_t fixed_iv[4],
	const uint8_t seq_num[8], const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen)
{
	switch (cipher_suite) {
	case TLS_cipher_ecc_sm4_cbc_sm3:
		if (tls_record_cbc_encrypt(hmac_ctx, key, seq_num, in, inlen, out, outlen) != 1) {
			error_print();
			return -1;
		}
		break;
	case TLS_cipher_ecc_sm4_gcm_sm3:
		if (tls12_record_gcm_encrypt(key, fixed_iv, seq_num, in, inlen, out, outlen) != 1) {
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

int tlcp_record_decrypt(int cipher_suite,
	const HMAC_CTX *hmac_ctx, const BLOCK_CIPHER_KEY *key, const uint8_t fixed_iv[4],
	const uint8_t seq_num[8], const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen)
{
	switch (cipher_suite) {
	case TLS_cipher_ecc_sm4_cbc_sm3:
		if (tls_record_cbc_decrypt(hmac_ctx, key, seq_num, in, inlen, out, outlen) != 1) {
			error_print();
			return -1;
		}
		break;
	case TLS_cipher_ecc_sm4_gcm_sm3:
		if (tls12_record_gcm_decrypt(key, fixed_iv, seq_num, in, inlen, out, outlen) != 1) {
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


/*
ServerKeyExchange

select (KeyExchangeAlgorithm) {
	case ECC:
		digitall-signed struct {
			opaque client_random[32];
			opaque server_random[32];
			opaque ASN1.Cert<1..2^24-1>;
		} signed_params;

	case ECDHE:
		ServerECDHEParams params;
		digitally-signed struct {
			opaque client_random[32];
			opaque server_random[32];
			ServerECDHEParams params;
		} signed_params;

	case IBSDH:
		ServerIBSDHParams params;
		digitally-signed struct {
			opaque client_random[32];
			opaque server_random[32];
			ServerIBSDHParams params;
		} signed_params;

	case IBC:
		digitally-signed struct {
			opaque client_random[32];
			opaque server_random[32];
			opaque ibc_id(1..2-16-1);
		} signed_params;
	}
} ServerKeyExchange;

`signed_params` is DER signature encoded in uint16array
sm3_ctx*/
static int tlcp_server_ecc_params_to_bytes(const uint8_t *server_enc_cert,
	size_t server_enc_cert_len, uint8_t **out, size_t *outlen)
{
	if (!server_enc_cert || !server_enc_cert_len || !outlen) {
		error_print();
		return -1;
	}
	tls_uint24array_to_bytes(server_enc_cert, server_enc_cert_len, out, outlen);
	return 1;
}

static int tlcp_server_ecc_params_from_bytes(const uint8_t **server_enc_cert,
	size_t *server_enc_cert_len, const uint8_t **in, size_t *inlen)
{
	if (!server_enc_cert || !server_enc_cert_len || !in || !*in || !inlen) {
		error_print();
		return -1;
	}
	if (tls_uint24array_from_bytes(server_enc_cert, server_enc_cert_len, in, inlen) != 1) {
		error_print();
		return -1;
	}
	if (!*server_enc_cert || !*server_enc_cert_len) {
		error_print();
		return -1;
	}
	return 1;
}

int tlcp_record_set_handshake_server_key_exchange_ecc(uint8_t *record, size_t *recordlen,
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

int tlcp_record_get_handshake_server_key_exchange_ecc(const uint8_t *record,
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

int tlcp_server_key_exchange_ecc_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent)
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


/*
ClientKeyExchange

struct {
	select (KeyExchangeAlgorithm) {
	case ECC:
		opaque ECCEncryptedPreMasterSecret<0..2^16-1>;
	case ECDHE:
		Opaque ClientECDHEParams<1..2^16-1>;
	case IBSDH:
		Opaque ClientIBSDHParams<1..2^16-1>;
	case IBC:
		opaque IBCEncryptedPreMasterSecret<0..2^16-1>;
	case RSA:
		opaque RSAEncryptedPreMasterSecret<0..2^16-1>;
	} exchange_keys;
} ClientKeyExchange;

这里比较特殊的是需要打印一个SM2Ciphertext，也许直接打印二进制就可以了
*/


// Handshakes

// 一般来说digest_init是在cipher_suite定下来之后才能设置
// 但是TLCP中的SM3是确定的，因此可以在ClientHello, ServerHello中设置


// 这个一定是要不同的
int tlcp_send_client_hello(TLS_CONNECT *conn)
{
	int ret;

	if (!conn->recordlen) {

		uint8_t exts[TLS_MAX_EXTENSIONS_SIZE];
		uint8_t *pexts = exts;
		size_t extslen = 0;

		if (!conn->ctx->cipher_suites_cnt) {
			error_print();
			return -1;
		}
		if (tlcp_cipher_suite_get(conn->ctx->cipher_suites[0], &conn->cipher, &conn->digest) != 1
			|| digest_init(&conn->dgst_ctx, conn->digest) != 1) {
			error_print();
			return -1;
		}


		tls_record_set_protocol(conn->record, TLS_protocol_tlcp);

		if (tls_random_generate(conn->client_random) != 1) {
			error_print();
			return -1;
		}

		// extensions in GM/T 0024-2023
		//  * server_name (0)
		//  * trusted_ca_keys (3)
		//  * status_request (5)
		//  * supported_groups (10)
		//  * signature_algorithms (13)
		//  * application_layer_protocol_negotiation (16)
		//  * client_id (66)

		// server_name
		if (conn->server_name) {
			if (tls_server_name_ext_to_bytes(
				conn->host_name, conn->host_name_len, &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		// trusted_ca_keys
		if (conn->ctx->trusted_ca_keys) {
			if (tls_trusted_ca_keys_ext_to_bytes(conn->ctx->trusted_authorities,
				conn->ctx->trusted_authorities_len, &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		// status_request (hint only)
		if (conn->status_request) {
			if (tls_client_status_request_ext_to_bytes(TLS_certificate_status_type_ocsp,
				conn->status_request_responder_id_list, conn->status_request_responder_id_list_len,
				conn->status_request_exts, conn->status_request_exts_len,
				&pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
			conn->status_request = 0; // to track CertificateRequest.status_request
		}

		// supported_groups
		if (conn->ctx->supported_groups_cnt) {
			if (tls_supported_groups_ext_to_bytes(conn->ctx->supported_groups,
				conn->ctx->supported_groups_cnt, &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		// signature_algorithms
		if (conn->ctx->signature_algorithms_cnt) {
			if (tls_signature_algorithms_ext_to_bytes(conn->ctx->signature_algorithms,
				conn->ctx->signature_algorithms_cnt, &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		// application_layer_protocol_negotiation
		if (conn->ctx->alpn_protocols_cnt) {
			if (tls_application_layer_protocol_negotiation_ext_to_bytes(
				conn->ctx->alpn_protocols, conn->ctx->alpn_protocols_cnt,
				&pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		// client_id
		if (conn->ctx->client_id) {
			error_print();
			return -1;
		}

		if (tls_record_set_handshake_client_hello(conn->record, &conn->recordlen,
			conn->protocol, conn->client_random, NULL, 0,
			conn->ctx->cipher_suites, conn->ctx->cipher_suites_cnt,
			extslen ? exts : NULL, extslen) != 1) {
			error_print();
			return -1;
		}

		tls_trace("send ClientHello\n");
		tlcp_record_print(stderr, 0, 0, conn->record, conn->recordlen);

		if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
			error_print();
			return -1;
		}
		tls_handshake_digest_print(stderr, 0, 0, "ClientHello", &conn->dgst_ctx);
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

int tlcp_recv_server_hello(TLS_CONNECT *conn)
{
	int ret;
	int protocol;
	int cipher_suite;
	const uint8_t *server_random;
	const uint8_t *session_id;
	size_t session_id_len;
	const uint8_t *exts;
	size_t extslen;

	// extensions
	int server_name = 0;
	int trusted_ca_keys = 0;
	int status_request = 0;
	const uint8_t *supported_groups = NULL;
	size_t supported_groups_len;
	const uint8_t *application_layer_protocol_negotiation = NULL;
	size_t application_layer_protocol_negotiation_len;


	tls_trace("recv ServerHello\n");

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	tlcp_record_print(stderr, 0, 0, conn->record, conn->recordlen);

	if (tls_record_protocol(conn->record) != TLS_protocol_tlcp) {
		error_print();
		tls_send_alert(conn, TLS_alert_protocol_version);
		return -1;
	}
	if (tls_record_get_handshake_server_hello(conn->record,
		&protocol, &server_random, &session_id, &session_id_len, &cipher_suite,
		&exts, &extslen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	if (protocol != TLS_protocol_tlcp) {
		error_print();
		tls_send_alert(conn, TLS_alert_protocol_version);
		return -1;
	}
	memcpy(conn->server_random, server_random, 32);
	memcpy(conn->session_id, session_id, session_id_len);
	if (tls_type_is_in_list(cipher_suite,
		conn->ctx->cipher_suites, conn->ctx->cipher_suites_cnt) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_handshake_failure);
		return -1;
	}
	conn->cipher_suite = cipher_suite;
	if (tlcp_cipher_suite_get(conn->cipher_suite, &conn->cipher, &conn->digest) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		return -1;
	}

	while (extslen) {
		int ext_type;
		const uint8_t *ext_data;
		size_t ext_datalen;

		if (tls_ext_from_bytes(&ext_type, &ext_data, &ext_datalen, &exts, &extslen) != 1) {
			error_print();
			tls13_send_alert(conn, TLS_alert_decode_error);
			return -1;
		}

		switch (ext_type) {
		case TLS_extension_server_name:
		case TLS_extension_trusted_ca_keys:
		case TLS_extension_status_request:
			if (ext_data) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			break;
		case TLS_extension_supported_groups:
		case TLS_extension_application_layer_protocol_negotiation:
			if (!ext_data) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			break;
		default:
			error_print();
			tls_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}

		switch (ext_type) {
		case TLS_extension_server_name:
			if (!conn->server_name) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			if (server_name) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			server_name = 1;
			break;

		case TLS_extension_trusted_ca_keys:
			if (!conn->ctx->trusted_ca_keys) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			if (trusted_ca_keys) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			trusted_ca_keys = 1;
			break;

		case TLS_extension_status_request:
			if (!conn->ctx->status_request) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			if (status_request) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			status_request = 1;
			break;

		case TLS_extension_supported_groups:
			if (supported_groups) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			supported_groups = ext_data;
			supported_groups_len = ext_datalen;
			break;

		case TLS_extension_application_layer_protocol_negotiation:
			if (!conn->ctx->alpn_protocols_cnt) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			if (application_layer_protocol_negotiation) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			application_layer_protocol_negotiation = ext_data;
			application_layer_protocol_negotiation_len = ext_datalen;
			break;
		}
	}

	// supported_groups
	if (supported_groups) {
		// 检查cipher_suite依赖的SM2/SM9曲线是否在其中，否则报错
	}

	// application_layer_protocol_negotiation
	if (application_layer_protocol_negotiation) {
		if ((ret = tls_application_layer_protocol_negotiation_selected_from_bytes(
			&conn->alpn_selected,
			application_layer_protocol_negotiation, application_layer_protocol_negotiation_len,
			conn->ctx->alpn_protocols, conn->ctx->alpn_protocols_cnt)) < 0) {
			error_print();
			tls_send_alert(conn, TLS_alert_decode_error);
			return -1;
		} else if (ret == 0) {
			error_print();
			tls_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}
		conn->application_layer_protocol_negotiation = 1;
	}


	if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
		error_print();
		return -1;
	}
	tls_handshake_digest_print(stderr, 0, 0, "ServerHello", &conn->dgst_ctx);

	if (conn->client_certs_len) {
		sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);
	}

	return 1;
}

int tlcp_recv_server_certificate(TLS_CONNECT *conn)
{
	int ret;
	int verify_result;
	const uint8_t *server_cert;
	size_t server_cert_len;

	tls_trace("recv server Certificate\n");

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	tlcp_record_print(stderr, 0, 0, conn->record, conn->recordlen);

	if (tls_record_protocol(conn->record) != TLS_protocol_tlcp) {
		error_print();
		tls_send_alert(conn, TLS_alert_protocol_version);
		return -1;
	}

	if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
		error_print();
		return -1;
	}
	tls_handshake_digest_print(stderr, 0, 0, "Certificate", &conn->dgst_ctx);


	if (conn->client_certs_len) {
		sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);
	}

	if (tls_record_protocol(conn->record) != TLS_protocol_tlcp) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	if (tls_record_get_handshake_certificate(conn->record,
		conn->peer_cert_chain, &conn->peer_cert_chain_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	if (x509_certs_get_cert_by_index(conn->peer_cert_chain, conn->peer_cert_chain_len,
		0, &server_cert, &server_cert_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}
	if (conn->server_name) {
		if ((ret = tls_cert_match_server_name(server_cert, server_cert_len,
			conn->host_name, conn->host_name_len)) < 0) {
			error_print();
			tls_send_alert(conn, TLS_alert_bad_certificate);
			return -1;
		} else if (ret == 0) {
			error_print();
			tls_send_alert(conn, TLS_alert_bad_certificate);
			return -1;
		}
	}

	if (conn->ctx->cacertslen) {
		if (x509_certs_verify_tlcp(conn->peer_cert_chain, conn->peer_cert_chain_len, X509_cert_chain_server,
			conn->ctx->cacerts, conn->ctx->cacertslen, conn->ctx->verify_depth, &verify_result) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_bad_certificate);
			return -1;
		}
	}

	return 1;
}

// 存疑
int tlcp_recv_server_key_exchange(TLS_CONNECT *conn)
{
	int ret;
	const uint8_t *sig;
	size_t siglen;
	const uint8_t *cp;
	size_t len;
	X509_KEY server_sign_key;

	const uint8_t *server_enc_cert;
	size_t server_enc_cert_len;

	uint8_t server_ecc_params[TLS_MAX_CERTIFICATES_SIZE + 3];
	uint8_t *p;
	size_t server_ecc_params_len;
	const uint8_t *q;
	size_t qlen;
	const uint8_t *server_ecc_params_cert;
	size_t server_ecc_params_cert_len;

	SM2_VERIFY_CTX verify_ctx;


	tls_trace("recv ServerKeyExchange\n");

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	tlcp_record_print(stderr, 0, 0, conn->record, conn->recordlen);

	if (tls_record_protocol(conn->record) != TLS_protocol_tlcp) {
		error_print();
		tls_send_alert(conn, TLS_alert_protocol_version);
		return -1;
	}

	if (tlcp_record_get_handshake_server_key_exchange_ecc(conn->record, &sig, &siglen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
		error_print();
		return -1;
	}

	tls_handshake_digest_print(stderr, 0, 0, "ServerKeyExchange", &conn->dgst_ctx);

	// verify ServerKeyExchange
	if (x509_certs_get_cert_by_index(conn->peer_cert_chain, conn->peer_cert_chain_len, 0, &cp, &len) != 1
		|| x509_cert_get_subject_public_key(cp, len, &server_sign_key) != 1
		|| x509_certs_get_cert_by_index(conn->peer_cert_chain, conn->peer_cert_chain_len, 1, &server_enc_cert, &server_enc_cert_len) != 1
		|| x509_cert_get_subject_public_key(server_enc_cert, server_enc_cert_len, &conn->server_enc_key) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}

	// 取得加密证书和加密公钥应该是没有用的，TLCP中的ServerKeyExchange是怎么计算的？

	if (server_sign_key.algor != OID_ec_public_key
		|| server_sign_key.algor_param != OID_sm2
		|| conn->server_enc_key.algor != OID_ec_public_key
		|| conn->server_enc_key.algor_param != OID_sm2) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_certificate);
		return -1;
	}
	p = server_ecc_params;
	server_ecc_params_len = 0;
	if (tlcp_server_ecc_params_to_bytes(server_enc_cert, server_enc_cert_len,
		&p, &server_ecc_params_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		return -1;
	}
	q = server_ecc_params;
	qlen = server_ecc_params_len;
	if (tlcp_server_ecc_params_from_bytes(&server_ecc_params_cert, &server_ecc_params_cert_len,
		&q, &qlen) != 1
		|| qlen
		|| server_ecc_params_cert_len != server_enc_cert_len
		|| memcmp(server_ecc_params_cert, server_enc_cert, server_enc_cert_len) != 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		return -1;
	}
	if (sm2_verify_init(&verify_ctx, &server_sign_key.u.sm2_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1
		|| sm2_verify_update(&verify_ctx, conn->client_random, 32) != 1
		|| sm2_verify_update(&verify_ctx, conn->server_random, 32) != 1
		|| sm2_verify_update(&verify_ctx, server_ecc_params, server_ecc_params_len) != 1) {
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

int tlcp_recv_certificate_request(TLS_CONNECT *conn)
{
	int ret;
	uint8_t *record = conn->record;
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
	tlcp_record_print(stderr, 0, 0, conn->record, conn->recordlen);

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

	// 这里根据cipher_suite判断请求的类型是否合适
	if (tls_cert_types_accepted(cert_types, cert_types_len, conn->client_certs, conn->client_certs_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unsupported_certificate);
		return -1;
	}

	// 当采用SM9时有什么特别处理？
	if (tls_authorities_issued_certificate(ca_names, ca_names_len, conn->client_certs, conn->client_certs_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unsupported_certificate);
		return -1;
	}

	if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
		error_print();
		return -1;
	}

	tls_handshake_digest_print(stderr, 0, 0, "CertificateRequest", &conn->dgst_ctx);

	sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);

	conn->recordlen = 0;

	return 1;
}

int tlcp_recv_server_hello_done(TLS_CONNECT *conn)
{
	int ret;
	tls_trace("recv ServerHelloDone\n");

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	if (tls_record_protocol(conn->record) != TLS_protocol_tlcp) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	tlcp_record_print(stderr, 0, 0, conn->record, conn->recordlen);

	if (tls_record_get_handshake_server_hello_done(conn->record) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
		error_print();
		return -1;
	}
	tls_handshake_digest_print(stderr, 0, 0, "ServerHelloDone", &conn->dgst_ctx);



	if (conn->client_certs_len) {
		sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);
	}

	return 1;
}




int tlcp_send_client_certificate(TLS_CONNECT *conn)
{
	int ret;
	tls_trace("send client Certificate\n");


	// 如果我们没有证书，并且也没有设置optional，那么就得返回错误了
	// 可能还需要返回一个alert

	if (conn->client_certs_len == 0) {
		error_print();
		return -1;
	}

	if (conn->recordlen == 0) {
		// 这里的证书应该是
		if (tls_record_set_handshake_certificate(conn->record, &conn->recordlen,
			conn->cert_chain, conn->cert_chain_len) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		tlcp_record_print(stderr, 0, 0, conn->record, conn->recordlen);



		if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
			error_print();
			return -1;
		}
		tls_handshake_digest_print(stderr, 0, 0, "client Certificate", &conn->dgst_ctx);

		sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);

	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}


	return 1;
}


int tlcp_send_client_key_exchange(TLS_CONNECT *conn)
{
	uint8_t enced_pre_master_secret[SM2_MAX_CIPHERTEXT_SIZE];
	size_t enced_pre_master_secret_len;
	int ret;

	tls_trace("send ClientKeyExchange\n");

	if (!conn->recordlen) {
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

		if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
			error_print();
			return -1;
		}
		tls_handshake_digest_print(stderr, 0, 0, "ClientKeyExchange", &conn->dgst_ctx);
	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	tls_clean_record(conn);

	if (tlcp_generate_keys(conn) != 1) {
		error_print();
		return -1;
	}

	return 1;
}










int tlcp_send_certificate_verify(TLS_CONNECT *conn)
{
	int ret;
	uint8_t sig[SM2_MAX_SIGNATURE_SIZE];
	size_t siglen;

	tls_trace("send CertificateVerify\n");

	// 这句应该是没用的			
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
		tlcp_record_print(stderr, 0, 0, conn->record, conn->recordlen);
	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	//sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
	//tlcp_handshake_digest_print(stderr, 0, 0, "CertificateVerify", &conn->sm3_ctx);

	return 1;
}

int tlcp_send_client_finished(TLS_CONNECT *conn)
{
	int ret;

	if (conn->recordlen == 0) {
		uint8_t verify_data[12];

		tls_trace("send client {Finished}\n");


		if (tls_compute_verify_data(conn->master_secret, "client finished", &conn->dgst_ctx, verify_data) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}

		tls_record_set_protocol(conn->plain_record, conn->protocol);

		if (tls_record_set_handshake_finished(conn->plain_record, &conn->plain_recordlen,
			verify_data, sizeof(verify_data)) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}

		tlcp_record_print(stderr, 0, 0, conn->plain_record, conn->plain_recordlen);

		if (digest_update(&conn->dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5) != 1) {
			error_print();
			return -1;
		}
		tls_handshake_digest_print(stderr, 0, 0, "client Finished", &conn->dgst_ctx);


		if (tlcp_record_encrypt(conn->cipher_suite,
			&conn->client_write_mac_ctx, &conn->client_write_key, conn->client_write_iv,
			conn->client_seq_num, conn->plain_record, conn->plain_recordlen,
			conn->record, &conn->recordlen) != 1) {

			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}

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

int tlcp_recv_server_finished(TLS_CONNECT *conn)
{
	int ret;

	uint8_t sm3_hash[32];

	const uint8_t *verify_data;
	size_t verify_data_len;
	uint8_t local_verify_data[12];


	tls_trace("recv server {Finished}\n");

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	tlcp_record_print(stderr, 0, 0, conn->record, conn->recordlen);


	if (tls_record_protocol(conn->record) != TLS_protocol_tlcp) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	if (tlcp_record_decrypt(conn->cipher_suite,
		&conn->server_write_mac_ctx, &conn->server_write_key, conn->server_write_iv,
		conn->server_seq_num, conn->record, conn->recordlen,
		conn->plain_record, &conn->plain_recordlen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_record_mac);
		return -1;
	}
	tls_seq_num_incr(conn->server_seq_num);

	tlcp_record_print(stderr, 0, 0, conn->plain_record, conn->plain_recordlen);

	// 最后没有必要再计算handshke_digest了

	if (tls_record_get_handshake_finished(conn->plain_record, &verify_data, &verify_data_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	if (verify_data_len != sizeof(local_verify_data)) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	if (tls_compute_verify_data(conn->master_secret, "server finished", &conn->dgst_ctx, local_verify_data) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		return -1;
	}

	if (memcmp(verify_data, local_verify_data, sizeof(local_verify_data)) != 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_decrypt_error);
		return -1;
	}

	if (!conn->ctx->quiet)
		fprintf(stderr, "Connection established!\n");



	return 1;
}




























// Server

static int tlcp_cert_chains_select(TLS_CONNECT *conn,
	const uint8_t *host_name, size_t host_name_len)
{
	const uint8_t *cert_chains;
	size_t cert_chains_len;
	size_t cert_chain_idx;

	if (!conn || !conn->ctx || !conn->ctx->cert_chains_len) {
		error_print();
		return -1;
	}

	cert_chains = conn->ctx->cert_chains;
	cert_chains_len = conn->ctx->cert_chains_len;

	for (cert_chain_idx = 1; cert_chains_len; cert_chain_idx++) {
		const uint8_t *cert_chain;
		size_t cert_chain_len;
		const uint8_t *sign_cert;
		size_t sign_cert_len;
		const uint8_t *enc_cert;
		size_t enc_cert_len;
		int ret;

		if (tls_uint24array_from_bytes(&cert_chain, &cert_chain_len,
			&cert_chains, &cert_chains_len) != 1) {
			error_print();
			return -1;
		}
		if (x509_certs_get_cert_by_index(cert_chain, cert_chain_len, 0, &sign_cert, &sign_cert_len) != 1
			|| x509_certs_get_cert_by_index(cert_chain, cert_chain_len, 1, &enc_cert, &enc_cert_len) != 1) {
			error_print();
			return -1;
		}

		if (host_name && host_name_len) {
			if ((ret = tls_cert_match_server_name(sign_cert, sign_cert_len, host_name, host_name_len)) < 0) {
				error_print();
				return -1;
			} else if (ret == 0) {
				continue;
			}
		}

		conn->cert_chain = cert_chain;
		conn->cert_chain_len = cert_chain_len;
		conn->cert_chain_idx = cert_chain_idx;
		conn->signature_algorithms[0] = TLS_sig_sm2sig_sm3;
		conn->signature_algorithms_cnt = 1;
		return 1;
	}

	conn->cert_chain = NULL;
	conn->cert_chain_len = 0;
	conn->cert_chain_idx = 0;
	warning_print();
	return 0;
}

int tlcp_recv_client_hello(TLS_CONNECT *conn)
{
	int ret;
	int protocol;
	const uint8_t *client_random;
	const uint8_t *session_id;
	size_t session_id_len;
	const uint8_t *cipher_suites;
	size_t cipher_suites_len;
	const uint8_t *exts;
	size_t extslen;

	// extensions
	const uint8_t *server_name = NULL;
	size_t server_name_len = 0;
	int trusted_ca_keys = 0;
	const uint8_t *trusted_authorities = NULL;
	size_t trusted_authorities_len = 0;
	const uint8_t *status_request = NULL;
	size_t status_request_len = 0;
	const uint8_t *supported_groups = NULL;
	size_t supported_groups_len = 0;
	const uint8_t *signature_algorithms = NULL;
	size_t signature_algorithms_len = 0;
	const uint8_t *application_layer_protocol_negotiation = NULL;
	size_t application_layer_protocol_negotiation_len = 0;
	const uint8_t *client_id = NULL;
	size_t client_id_len = 0;
	const uint8_t *host_name = NULL;
	size_t host_name_len = 0;





	// 这个判断应该改为一个函数
	/*
	if (client_verify)
		tls_client_verify_init(&conn->client_verify_ctx);
	*/

	tls_trace("recv ClientHello\n");

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	tlcp_record_print(stderr, 0, 0, conn->record, conn->recordlen);


	if (tls_record_protocol(conn->record) != conn->protocol) {
		error_print();
		tls_send_alert(conn, TLS_alert_protocol_version);
		return -1;
	}

	if (tls_record_get_handshake_client_hello(conn->record,
		&protocol, &client_random, &session_id, &session_id_len,
		&cipher_suites, &cipher_suites_len,
		&exts, &extslen) != 1) {
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

	if (tls_cipher_suites_select(cipher_suites, cipher_suites_len,
		conn->ctx->cipher_suites, conn->ctx->cipher_suites_cnt,
		&conn->cipher_suite) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_insufficient_security);
		return -1;
	}


	// 在TLS 1.3中，公钥密码算法是用扩展完成的，而在TLS1.2中，算法完全是由cipher_sutie决定的

	switch (conn->cipher_suite) {
	case TLS_cipher_ecc_sm4_cbc_sm3:
	case TLS_cipher_ecc_sm4_gcm_sm3:
		conn->signature_algorithms[0] = TLS_sig_sm2sig_sm3;
		break;
	case TLS_cipher_ecdhe_sm4_cbc_sm3:
	case TLS_cipher_ecdhe_sm4_gcm_sm3:
	default:
		error_print();
		return -1;
	}

	while (extslen) {
		int ext_type;
		const uint8_t *ext_data;
		size_t ext_datalen;

		if (tls_ext_from_bytes(&ext_type, &ext_data, &ext_datalen, &exts, &extslen) != 1) {
			error_print();
			tls13_send_alert(conn, TLS_alert_decode_error);
			return -1;
		}

		// extensions in GM/T 0024-2023
		//  * server_name (0)
		//  * trusted_ca_keys (3)
		//  * status_request (5)
		//  * supported_groups (10)
		//  * signature_algorithms (13)
		//  * application_layer_protocol_negotiation (16)
		//  * client_id (66)

		switch (ext_type) {
		case TLS_extension_server_name:
			if (server_name) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			server_name = ext_data;
			server_name_len = ext_datalen;
			break;

		case TLS_extension_trusted_ca_keys:
			if (trusted_ca_keys) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			if (tls_trusted_authorities_from_bytes(&trusted_authorities,
				&trusted_authorities_len, ext_data, ext_datalen) != 1) {
				error_print();
				tls13_send_alert(conn, TLS_alert_decode_error);
				return -1;
			}
			trusted_ca_keys = 1;
			break;

		case TLS_extension_status_request:
			if (status_request) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			status_request = ext_data;
			status_request_len = ext_datalen;
			break;

		case TLS_extension_supported_groups:
			if (supported_groups) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			supported_groups = ext_data;
			supported_groups_len = ext_datalen;
			break;

		case TLS_extension_signature_algorithms:
			if (signature_algorithms) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			signature_algorithms = ext_data;
			signature_algorithms_len = ext_datalen;
			break;

		case TLS_extension_application_layer_protocol_negotiation:
			if (application_layer_protocol_negotiation) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			application_layer_protocol_negotiation = ext_data;
			application_layer_protocol_negotiation_len = ext_datalen;
			break;

		case TLS_extension_client_id:
			if (client_id) {
				error_print();
				tls13_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			client_id = ext_data;
			client_id_len = ext_datalen;
			break;

		default:
			error_print();
			return -1;
		}
	}

	if (tlcp_cipher_suite_get(conn->cipher_suite, &conn->cipher, &conn->digest) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		return -1;
	}

	if (trusted_ca_keys) {
		conn->trusted_ca_keys = 1;
		if (trusted_authorities_len > sizeof(conn->trusted_authorities)) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		if (trusted_authorities_len) {
			memcpy(conn->trusted_authorities, trusted_authorities, trusted_authorities_len);
		}
		conn->trusted_authorities_len = trusted_authorities_len;
	}

	if (application_layer_protocol_negotiation) {
		if (!conn->ctx->alpn_protocols_cnt) {
			error_print();
			tls_send_alert(conn, TLS_alert_no_application_protocol);
			return -1;
		}
		if ((ret = tls_application_layer_protocol_negotiation_select(
			application_layer_protocol_negotiation, application_layer_protocol_negotiation_len,
			conn->ctx->alpn_protocols, conn->ctx->alpn_protocols_cnt,
			&conn->alpn_selected)) < 0) {
			error_print();
			tls_send_alert(conn, TLS_alert_decode_error);
			return -1;
		} else if (ret == 0) {
			error_print();
			tls_send_alert(conn, TLS_alert_no_application_protocol);
			return -1;
		}
		conn->application_layer_protocol_negotiation = 1;
	}

	if (server_name) {
		if (tls_server_name_from_bytes(&host_name, &host_name_len, server_name, server_name_len) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_decode_error);
			return -1;
		}
		if (host_name_len > sizeof(conn->host_name)) {
			error_print();
			tls_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}
		memcpy(conn->host_name, host_name, host_name_len);
		conn->host_name_len = host_name_len;
		conn->server_name = 1;
	}

	if ((ret = tlcp_cert_chains_select(conn, host_name, host_name_len)) < 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_handshake_failure);
		return -1;
	}

	if (digest_init(&conn->dgst_ctx, conn->digest) != 1
		|| digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
		error_print();
		return -1;
	}
	tls_handshake_digest_print(stderr, 0, 0, "ClientHello", &conn->dgst_ctx);

	//sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
	//tlcp_handshake_digest_print(stderr, 0, 0, "ClientHello", &conn->sm3_ctx);

	/*
	if (client_verify)
		tls_client_verify_update(&conn->client_verify_ctx, conn->record + 5, conn->recordlen - 5);
	*/


	fprintf(stderr, "end of recv_client_hello\n");
	tls_clean_record(conn);

	return 1;
}

int tlcp_send_server_hello(TLS_CONNECT *conn)
{
	int ret;

	tls_trace("send ServerHello\n");

	if (conn->recordlen == 0) {
		uint8_t exts[TLS_MAX_EXTENSIONS_SIZE];
		uint8_t *pexts = exts;
		size_t extslen = 0;


		tls_record_set_protocol(conn->record, conn->protocol);

		if (tls_random_generate(conn->server_random) != 1) {
			error_print();
			return -1;
		}

		// 服务器需要判断客户端的版本，看看是早期的版本还是后期的版本

		// extensions in GM/T 0024-2023
		//  * server_name (0)
		//  * trusted_ca_keys (3)
		//  * status_request (5)
		//  * supported_groups (10)
		//  * signature_algorithms (13)
		//  * application_layer_protocol_negotiation (16)
		//  * client_id (66)

		// server_name
		if (conn->server_name) {
			if (tls_ext_to_bytes(TLS_extension_server_name, NULL, 0, &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		// trusted_ca_keys
		if (conn->trusted_ca_keys) {
			if (tls_ext_to_bytes(TLS_extension_trusted_ca_keys, NULL, 0, &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		// status_request
		if (conn->status_request) {
			if (tls_ext_to_bytes(TLS_extension_status_request, NULL, 0, &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		// supported_groups
		// 通常ServerHello不提供

		// signature_algorithms (client only)

		// application_layer_protocol_negotiation
		if (conn->alpn_selected) {
			if (tls_application_layer_protocol_negotiation_selected_ext_to_bytes(
				conn->alpn_selected, &pexts, &extslen) != 1) {
				error_print();
				return -1;
			}
		}

		// client_id (client only)


		if (tls_record_set_handshake_server_hello(conn->record, &conn->recordlen,
			conn->protocol, conn->server_random, NULL, 0,
			conn->cipher_suite,
			extslen ? exts : NULL, extslen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		tlcp_record_trace(stderr, conn->record, conn->recordlen, 0, 0);

		if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
			error_print();
			return -1;
		}
		tls_handshake_digest_print(stderr, 0, 0, "ServerHello", &conn->dgst_ctx);
	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	//sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
	//tlcp_handshake_digest_print(stderr, 0, 0, "ServerHello", &conn->sm3_ctx);

	if (conn->ctx->cacertslen) {
		tls_client_verify_update(&conn->client_verify_ctx, conn->record + 5, conn->recordlen - 5);
	}

	tls_clean_record(conn);


	return 1;
}


/*
-- IBC_SM4_CBC_SM3 和 IBC_SM4_GCM_SM3 套件的服务器Certificate消息格式

opaque ASN.1IBCParam<1..2^24-1>

struct {
	opaque ibc_id<1..2^16-1>;
	ASN.1IBCParam ibc_parameter;
} Certificate;

其中ibc_id是服务器的SM9的ID，这个ID暂时是一个没有内部结构的字节串，后续有可能是一个DER结构的字节串
ibc_parameter 是SM9 sm9_enc_master_key_to_der 输出的DER数据


*/
int tlcp_send_server_certificate(TLS_CONNECT *conn)
{
	int ret;

	tls_trace("send ServerCertificate\n");

	if (conn->recordlen == 0) {
		if (!conn->cert_chain || !conn->cert_chain_len) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		if (tls_record_set_handshake_certificate(conn->record, &conn->recordlen,
			conn->cert_chain, conn->cert_chain_len) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		tlcp_record_print(stderr, 0, 0, conn->record, conn->recordlen);

		if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
			error_print();
			return -1;
		}
		tls_handshake_digest_print(stderr, 0, 0, "Certificate", &conn->dgst_ctx);
	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	if (conn->client_certificate_verify) {
		tls_client_verify_update(&conn->client_verify_ctx, conn->record + 5, conn->recordlen - 5);
	}
	return 1;
}



// 这个也有这个问题，要考虑兼容SM9
int tlcp_send_server_key_exchange(TLS_CONNECT *conn)
{
	SM2_SIGN_CTX sign_ctx;
	uint8_t sigbuf[SM2_MAX_SIGNATURE_SIZE];
	size_t siglen;
	const uint8_t *server_enc_cert;
	size_t server_enc_cert_len;
	uint8_t server_ecc_params[TLS_MAX_CERTIFICATES_SIZE + 3];
	uint8_t *p;
	size_t server_ecc_params_len;
	int ret;

	tls_trace("send ServerKeyExchange\n");

	if (conn->recordlen == 0) {
		X509_KEY *sign_key;

		if (!conn->cert_chain || !conn->cert_chain_len || !conn->cert_chain_idx) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}

		if (x509_certs_get_cert_by_index(conn->cert_chain, conn->cert_chain_len, 1,
			&server_enc_cert, &server_enc_cert_len) != 1) {
			error_print();
			return -1;
		}

		p = server_ecc_params;
		server_ecc_params_len = 0;
		if (tlcp_server_ecc_params_to_bytes(server_enc_cert, server_enc_cert_len,
			&p, &server_ecc_params_len) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}

		sign_key = &conn->ctx->x509_keys[conn->cert_chain_idx - 1];
		if (sign_key->algor != OID_ec_public_key || sign_key->algor_param != OID_sm2) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		if (sm2_sign_init(&sign_ctx, &sign_key->u.sm2_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1
			|| sm2_sign_update(&sign_ctx, conn->client_random, 32) != 1
			|| sm2_sign_update(&sign_ctx, conn->server_random, 32) != 1
			|| sm2_sign_update(&sign_ctx, server_ecc_params, server_ecc_params_len) != 1
			|| sm2_sign_finish(&sign_ctx, sigbuf, &siglen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}

		if (tlcp_record_set_handshake_server_key_exchange_ecc(conn->record, &conn->recordlen, sigbuf, siglen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		tlcp_record_print(stderr, 0, 0, conn->record, conn->recordlen);

		if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
			error_print();
			return -1;
		}
		tls_handshake_digest_print(stderr, 0, 0, "ServerKeyExchange", &conn->dgst_ctx);
	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	if (conn->client_certificate_verify) {
		tls_client_verify_update(&conn->client_verify_ctx, conn->record + 5, conn->recordlen - 5);
	}

	return 1;
}

















static int tlcp_generate_master_secret(TLS_CONNECT *conn)
{
	if (!conn) {
		error_print();
		return -1;
	}
	if (tls_prf(conn->pre_master_secret, 48, "master secret",
			conn->client_random, 32,
			conn->server_random, 32,
			48, conn->master_secret) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		return -1;
	}
	return 1;
}

static int tlcp_generate_key_block(TLS_CONNECT *conn)
{
	size_t key_block_len;

	if (!conn) {
		error_print();
		return -1;
	}
	switch (conn->cipher_suite) {
	case TLS_cipher_ecc_sm4_gcm_sm3:
		if (!conn->cipher) {
			error_print();
			return -1;
		}
		key_block_len = conn->cipher->key_size * 2 + 8;
		break;
	case TLS_cipher_ecc_sm4_cbc_sm3:
		key_block_len = 96;
		break;
	default:
		error_print();
		return -1;
	}
	if (tls_prf(conn->master_secret, 48, "key expansion",
			conn->server_random, 32,
			conn->client_random, 32,
			key_block_len, conn->key_block) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		return -1;
	}
	return 1;
}

static int tlcp_generate_record_keys(TLS_CONNECT *conn)
{
	if (!conn) {
		error_print();
		return -1;
	}
	switch (conn->cipher_suite) {
	case TLS_cipher_ecc_sm4_gcm_sm3:
	{
		size_t keylen;

		if (!conn->cipher) {
			error_print();
			return -1;
		}
		keylen = conn->cipher->key_size;

		memset(conn->client_write_iv, 0, sizeof(conn->client_write_iv));
		memset(conn->server_write_iv, 0, sizeof(conn->server_write_iv));
		memcpy(conn->client_write_iv, conn->key_block + keylen * 2, 4);
		memcpy(conn->server_write_iv, conn->key_block + keylen * 2 + 4, 4);

		if (block_cipher_set_encrypt_key(&conn->client_write_key, conn->cipher, conn->key_block) != 1
			|| block_cipher_set_encrypt_key(&conn->server_write_key, conn->cipher, conn->key_block + keylen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		break;
	}
	case TLS_cipher_ecc_sm4_cbc_sm3:
		if (hmac_init(&conn->client_write_mac_ctx, conn->digest, conn->key_block, 32) != 1
			|| hmac_init(&conn->server_write_mac_ctx, conn->digest, conn->key_block + 32, 32) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}

		if (conn->is_client) {
			if (block_cipher_set_encrypt_key(&conn->client_write_key, conn->cipher, conn->key_block + 64) != 1
				|| block_cipher_set_decrypt_key(&conn->server_write_key, conn->cipher, conn->key_block + 80) != 1) {
				error_print();
				tls_send_alert(conn, TLS_alert_internal_error);
				return -1;
			}
		} else {
			if (block_cipher_set_decrypt_key(&conn->client_write_key, conn->cipher, conn->key_block + 64) != 1
				|| block_cipher_set_encrypt_key(&conn->server_write_key, conn->cipher, conn->key_block + 80) != 1) {
				error_print();
				tls_send_alert(conn, TLS_alert_internal_error);
				return -1;
			}
		}
		break;
	default:
		error_print();
		return -1;
	}
	return 1;
}

static void tlcp_secrets_print(TLS_CONNECT *conn)
{
	if (conn->cipher_suite == TLS_cipher_ecc_sm4_gcm_sm3) {
		size_t keylen = conn->cipher->key_size;

		format_bytes(stderr, 0, 4, "pre_master_secret", conn->pre_master_secret, 48);
		format_bytes(stderr, 0, 4, "client_random", conn->client_random, 32);
		format_bytes(stderr, 0, 4, "server_random", conn->server_random, 32);
		format_bytes(stderr, 0, 4, "master_secret", conn->master_secret, 48);
		format_bytes(stderr, 0, 4, "client_write_key", conn->key_block, keylen);
		format_bytes(stderr, 0, 4, "server_write_key", conn->key_block + keylen, keylen);
		format_bytes(stderr, 0, 4, "client_write_iv", conn->client_write_iv, 4);
		format_bytes(stderr, 0, 4, "server_write_iv", conn->server_write_iv, 4);
	} else {
		tls_secrets_print(stderr,
			conn->pre_master_secret, 48,
			conn->client_random, conn->server_random,
			conn->master_secret,
			conn->key_block, 96,
			0, 4);
	}
}

int tlcp_generate_keys(TLS_CONNECT *conn)
{
	tls_trace("generate secrets\n");

	if (tlcp_generate_master_secret(conn) != 1
		|| tlcp_generate_key_block(conn) != 1
		|| tlcp_generate_record_keys(conn) != 1) {
		error_print();
		return -1;
	}
	tls_seq_num_reset(conn->client_seq_num);
	tls_seq_num_reset(conn->server_seq_num);

	tlcp_secrets_print(conn);

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


					
	return 1;
}


int tlcp_recv_client_key_exchange(TLS_CONNECT *conn)
{
	const uint8_t *enced_pms;
	size_t enced_pms_len;
	size_t pre_master_secret_len;
	X509_KEY *enc_key;
	int ret;

	tls_trace("recv ClientKeyExchange\n");

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}

	if (tls_record_protocol(conn->record) != TLS_protocol_tlcp) {
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
	if (!conn->cert_chain_idx) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		return -1;
	}
	enc_key = &conn->ctx->enc_keys[conn->cert_chain_idx - 1];
	if (enc_key->algor != OID_ec_public_key || enc_key->algor_param != OID_sm2) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		return -1;
	}

	// FIXME:
	// 这里需要检查一下密钥的长度，因为输入的长度是确定的，因此输出的密文长度应该也是确定的

	if (sm2_decrypt(&enc_key->u.sm2_key, enced_pms, enced_pms_len,
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
	if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
		error_print();
		return -1;
	}
	tls_handshake_digest_print(stderr, 0, 0, "ClientKeyExchange", &conn->dgst_ctx);

	if (tlcp_generate_keys(conn) != 1) {
		error_print();
		return -1;
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
	const uint8_t *verify_data;
	size_t verify_data_len;
	uint8_t local_verify_data[12];

	if (tls_compute_verify_data(conn->master_secret, "client finished",
		&conn->dgst_ctx, local_verify_data) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_internal_error);
		return -1;
	}

	tls_trace("recv client {Finished}\n");

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
	if (tlcp_record_decrypt(conn->cipher_suite,
		&conn->client_write_mac_ctx, &conn->client_write_key, conn->client_write_iv,
		conn->client_seq_num, conn->record, conn->recordlen,
		conn->plain_record, &conn->plain_recordlen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_bad_record_mac);
		return -1;
	}
	tls_seq_num_incr(conn->client_seq_num);

	tlcp_record_print(stderr, 0, 0, conn->plain_record, conn->plain_recordlen);

	if (tls_record_get_handshake_finished(conn->plain_record, &verify_data, &verify_data_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	if (verify_data_len != sizeof(local_verify_data)
		|| memcmp(verify_data, local_verify_data, sizeof(local_verify_data)) != 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_decrypt_error);
		return -1;
	}

	if (digest_update(&conn->dgst_ctx, conn->plain_record + 5, conn->plain_recordlen - 5) != 1) {
		error_print();
		return -1;
	}
	tls_handshake_digest_print(stderr, 0, 0, "client Finished", &conn->dgst_ctx);

	return 1;
}

int tlcp_send_server_finished(TLS_CONNECT *conn)
{
	int ret;
	uint8_t verify_data[12];

	if (conn->recordlen == 0) {
		tls_trace("send server {Finished}\n");

		if (tls_compute_verify_data(conn->master_secret, "server finished",
			&conn->dgst_ctx, verify_data) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}

		tls_record_set_protocol(conn->plain_record, conn->protocol);

		if (tls_record_set_handshake_finished(conn->plain_record, &conn->plain_recordlen,
			verify_data, sizeof(verify_data)) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		tlcp_record_print(stderr, 0, 0, conn->plain_record, conn->plain_recordlen);

		if (tlcp_record_encrypt(conn->cipher_suite,
			&conn->server_write_mac_ctx, &conn->server_write_key, conn->server_write_iv,
			conn->server_seq_num, conn->plain_record, conn->plain_recordlen,
			conn->record, &conn->recordlen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
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

	switch (conn->handshake_state) {
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
		if (conn->client_certificate_verify)
			next_state = TLS_state_certificate_verify;
		else	next_state = TLS_state_client_change_cipher_spec;
		break;

	case TLS_state_certificate_verify:
		ret = tlcp_send_certificate_verify(conn);
		next_state = TLS_state_client_change_cipher_spec;
		break;

	case TLS_state_client_change_cipher_spec:
		ret = tls_send_change_cipher_spec(conn);
		next_state = TLS_state_client_finished;
		break;

	case TLS_state_client_finished:
		ret = tlcp_send_client_finished(conn);
		next_state = TLS_state_server_change_cipher_spec;
		break;

	case TLS_state_server_change_cipher_spec:
		ret = tls_recv_change_cipher_spec(conn);
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

	conn->handshake_state = next_state;

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

	switch (conn->handshake_state) {
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
		else	next_state = TLS_state_client_change_cipher_spec;
		break;

	case TLS_state_certificate_verify:
		ret = tlcp_recv_certificate_verify(conn);
		next_state = TLS_state_client_change_cipher_spec;
		break;

	case TLS_state_client_change_cipher_spec:
		ret = tls_recv_change_cipher_spec(conn);
		next_state = TLS_state_client_finished;
		break;

	case TLS_state_client_finished:
		ret = tlcp_recv_client_finished(conn);
		next_state = TLS_state_server_change_cipher_spec;
		break;

	case TLS_state_server_change_cipher_spec:
		ret = tls_send_change_cipher_spec(conn);
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

	conn->handshake_state = next_state;

	tls_clean_record(conn);

	return 1;
}

int tlcp_client_handshake(TLS_CONNECT *conn)
{
	int ret;

	while (conn->handshake_state != TLS_state_handshake_over) {

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


	while (conn->handshake_state != TLS_state_handshake_over) {

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

	// 应该把protocol_version的初始化放在这里

	if (conn->handshake_state == TLS_state_handshake_over) {
		return 1;
	}

	if (conn->handshake_state == TLS_state_handshake_init) {
		conn->handshake_state = TLS_state_client_hello;
	}

	ret = tlcp_client_handshake(conn);
	if (ret == 1
		|| ret == TLS_ERROR_RECV_AGAIN
		|| ret == TLS_ERROR_SEND_AGAIN) {
		return ret;
	}
	error_print();
	return -1;
}

int tlcp_do_accept(TLS_CONNECT *conn)
{
	int ret;

	if (conn->handshake_state == TLS_state_handshake_over) {
		return 1;
	}

	if (conn->handshake_state == TLS_state_handshake_init) {
		conn->handshake_state = TLS_state_client_hello;
	}

	ret = tlcp_server_handshake(conn);
	if (ret == 1
		|| ret == TLS_ERROR_RECV_AGAIN
		|| ret == TLS_ERROR_SEND_AGAIN) {
		return ret;
	}
	error_print();
	return -1;
}
