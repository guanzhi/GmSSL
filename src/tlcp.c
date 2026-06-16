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


const int tlcp_supported_groups[] = {
	TLS_curve_sm2p256v1,
};
const size_t tlcp_supported_groups_cnt =
	sizeof(tlcp_supported_groups)/sizeof(tlcp_supported_groups[0]);

const int tlcp_signature_algorithms[] = {
	TLS_sig_sm2sig_sm3,
};
const size_t tlcp_signature_algorithms_cnt =
	sizeof(tlcp_signature_algorithms)/sizeof(tlcp_signature_algorithms[0]);

const int tlcp_cipher_suites[] = {
	TLS_cipher_ecc_sm4_cbc_sm3,
	TLS_cipher_ecc_sm4_gcm_sm3,
};
const size_t tlcp_cipher_suites_cnt =
	sizeof(tlcp_cipher_suites)/sizeof(tlcp_cipher_suites[0]);



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
*/

int tlcp_server_key_exchange_ecc_print(FILE *fp, const uint8_t *data, size_t datalen, int fmt, int ind)
{
	const uint8_t *sig;
	size_t siglen;

	format_print(fp, fmt, ind, "ServerKeyExchange.ECC\n");
	ind += 4;
	if (tls_uint16array_from_bytes(&sig, &siglen, &data, &datalen) != 1) {
		error_print();
		return -1;
	}
	format_bytes(fp, fmt, ind, "signature", sig, siglen);
	if (datalen) {
		error_print();
		return -1;
	}
	return 1;
}

int tlcp_record_set_handshake_server_key_exchange(uint8_t *record, size_t *recordlen,
	int server_key_exchange_alg, const uint8_t *server_ecdh_params, size_t server_ecdh_params_len,
	const uint8_t *sig, size_t siglen)
{
	const int type = TLS_handshake_server_key_exchange;
	uint8_t *p = tls_handshake_data(tls_record_data(record));
	size_t len = 0;

	if (!record || !recordlen || !sig || !siglen) {
		error_print();
		return -1;
	}
	if (siglen > TLS_MAX_SIGNATURE_SIZE) {
		error_print();
		return -1;
	}

	switch (server_key_exchange_alg) {
	case TLS_server_key_exchange_ecdhe:
		if (!server_ecdh_params || !server_ecdh_params_len) {
			error_print();
			return -1;
		}
		tls_array_to_bytes(server_ecdh_params, server_ecdh_params_len, &p, &len);
		break;
	case TLS_server_key_exchange_ecc:
		if (server_ecdh_params || server_ecdh_params_len) {
			error_print();
			return -1;
		}
		break;
	default:
		error_print();
		return -1;
	}

	// TLCP use TLS 1.1 ServerKeyExchange, no signature_algorithm
	tls_uint16array_to_bytes(sig, siglen, &p, &len);

	tls_record_set_handshake(record, recordlen, type, NULL, len);
	return 1;
}

int tlcp_record_get_handshake_server_key_exchange(const uint8_t *record,
	int server_key_exchange_alg, const uint8_t **server_ecdh_params, size_t *server_ecdh_params_len,
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
		return 0;
	}

	switch (server_key_exchange_alg) {
	case TLS_server_key_exchange_ecdhe:
		if (!server_ecdh_params || !server_ecdh_params_len) {
			error_print();
			return -1;
		}
		*server_ecdh_params = p;
		*server_ecdh_params_len = len;
		{
			int key_exchange_group;
			const uint8_t *key_exchange;
			size_t key_exchange_len;

			if (tls_server_ecdh_params_from_bytes(&key_exchange_group,
				&key_exchange, &key_exchange_len, &p, &len) != 1) {
				error_print();
				return -1;
			}
		}
		*server_ecdh_params_len -= len;
		break;

	case TLS_server_key_exchange_ecc:
		if (server_ecdh_params || server_ecdh_params_len) {
			error_print();
			return -1;
		}
		break;

	default:
		error_print();
		return -1;
	}

	if (tls_uint16array_from_bytes(sig, siglen, &p, &len) != 1
		|| tls_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	if (!siglen) {
		error_print();
		return -1;
	}
	return 1;
}


/*
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
*/

int tlcp_record_set_handshake_client_key_exchange(uint8_t *record, size_t *recordlen,
	const uint8_t *enced_pms, size_t enced_pms_len)
{
	int type = TLS_handshake_client_key_exchange;
	uint8_t *p;
	size_t len = 0;

	if (!record || !recordlen || !enced_pms || !enced_pms_len) {
		error_print();
		return -1;
	}
	if (enced_pms_len > TLS_MAX_HANDSHAKE_DATA_SIZE - tls_uint16_size()) {
		error_print();
		return -1;
	}
	p = tls_handshake_data(tls_record_data(record));
	tls_uint16array_to_bytes(enced_pms, enced_pms_len, &p, &len);
	tls_record_set_handshake(record, recordlen, type, NULL, len);
	return 1;
}

int tlcp_record_get_handshake_client_key_exchange(const uint8_t *record,
	const uint8_t **enced_pms, size_t *enced_pms_len)
{
	int type;
	const uint8_t *cp;
	size_t len;

	if (!record || !enced_pms || !enced_pms_len) {
		error_print();
		return -1;
	}
	if (tls_record_get_handshake(record, &type, &cp, &len) != 1) {
		error_print();
		return -1;
	}
	if (type != TLS_handshake_client_key_exchange) {
		error_print();
		return -1;
	}
	if (tls_uint16array_from_bytes(enced_pms, enced_pms_len, &cp, &len) != 1
		|| tls_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	if (!enced_pms_len) {
		error_print();
		return -1;
	}
	return 1;
}

/*
struct {
	ClientCertificateType certificate_types<1..2^8-1>;
	DistinguishedName certificate_authorities<0..2^16-1>;
} CertificateRequest;
*/
int tlcp_record_set_handshake_certificate_request(uint8_t *record, size_t *recordlen,
	const uint8_t *cert_types, size_t cert_types_len,
	const uint8_t *ca_names, size_t ca_names_len)
{
	int type = TLS_handshake_certificate_request;
	uint8_t *p;
	size_t len =0;
	size_t datalen = 0;

	if (!record || !recordlen) {
		error_print();
		return -1;
	}
	if (cert_types) {
		if (cert_types_len == 0 || cert_types_len > TLS_MAX_CERTIFICATE_TYPES) {
			error_print();
			return -1;
		}
	}
	if (ca_names) {
		if (ca_names_len == 0 || ca_names_len > TLS_MAX_CA_NAMES_SIZE) {
			error_print();
			return -1;
		}
	}
	tls_uint8array_to_bytes(cert_types, cert_types_len, NULL, &datalen);
	tls_uint16array_to_bytes(ca_names, ca_names_len, NULL, &datalen);
	if (datalen > TLS_MAX_HANDSHAKE_DATA_SIZE) {
		error_print();
		return -1;
	}
	p = tls_handshake_data(tls_record_data(record));
	tls_uint8array_to_bytes(cert_types, cert_types_len, &p, &len);
	tls_uint16array_to_bytes(ca_names, ca_names_len, &p, &len);
	tls_record_set_handshake(record, recordlen, type, NULL, datalen);
	return 1;
}

int tlcp_record_get_handshake_certificate_request(const uint8_t *record,
	const uint8_t **cert_types, size_t *cert_types_len,
	const uint8_t **ca_names, size_t *ca_names_len)
{
	int type;
	const uint8_t *cp;
	size_t len;
	size_t i;

	if (!record || !cert_types || !cert_types_len || !ca_names || !ca_names_len) {
		error_print();
		return -1;
	}
	if (tls_record_get_handshake(record, &type, &cp, &len) != 1) {
		error_print();
		return -1;
	}
	if (type != TLS_handshake_certificate_request) {
		error_print();
		return -1;
	}
	if (tls_uint8array_from_bytes(cert_types, cert_types_len, &cp, &len) != 1
		|| tls_uint16array_from_bytes(ca_names, ca_names_len, &cp, &len) != 1
		|| tls_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}

	if (*cert_types == NULL) {
		error_print();
		return -1;
	}
	for (i = 0; i < *cert_types_len; i++) {
		if (!tls_cert_type_name((*cert_types)[i])) {
			error_print();
			return -1;
		}
	}
	if (*ca_names) {
		const uint8_t *names = *ca_names;
		size_t nameslen = *ca_names_len;
		while (nameslen) {
			if (tls_uint16array_from_bytes(&cp, &len, &names, &nameslen) != 1) {
				error_print();
				return -1;
			}
		}
	}
	return 1;
}


// Handshakes

int tlcp_send_client_hello(TLS_CONNECT *conn)
{
	int ret;

	if (!conn->recordlen) {
		uint8_t exts[TLS_MAX_EXTENSIONS_SIZE];
		uint8_t *pexts = exts;
		size_t extslen = 0;

		conn->sig_alg = TLS_sig_sm2sig_sm3;
		conn->cipher = BLOCK_CIPHER_sm4();
		conn->digest = DIGEST_sm3();

		if (digest_init(&conn->dgst_ctx, conn->digest) != 1) {
			error_print();
			return -1;
		}

		if (conn->verbose)
			tls_trace("send ClientHello\n");

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
		if (conn->verbose)
			tls_record_print(stderr, 0, 0, conn->cipher_suite, conn->record, conn->recordlen);

		if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
			error_print();
			return -1;
		}
		if(conn->verbose)
			tls_handshake_digest_print(stderr, 0, 0, "ClientHello", &conn->dgst_ctx);

		if (tls_update_transcript(conn, conn->record) != 1) {
			error_print();
			return -1;
		}

		if (conn->client_certificate_verify) {
			sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);
		}
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


	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	if (conn->verbose)
		tls_trace("recv ServerHello\n");
	if (conn->verbose)
		tls_record_print(stderr, 0, 0, conn->cipher_suite, conn->record, conn->recordlen);

	if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
		error_print();
		return -1;
	}
	if (conn->verbose)
		tls_handshake_digest_print(stderr, 0, 0, "ServerHello", &conn->dgst_ctx);

	if (tls_update_transcript(conn, conn->record) != 1) {
		error_print();
		return -1;
	}

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
	conn->session_id_len = session_id_len;

	if (tls_type_is_in_list(cipher_suite,
		conn->ctx->cipher_suites, conn->ctx->cipher_suites_cnt) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_handshake_failure);
		return -1;
	}
	conn->cipher_suite = cipher_suite;

	while (extslen) {
		int ext_type;
		const uint8_t *ext_data;
		size_t ext_datalen;

		if (tls_ext_from_bytes(&ext_type, &ext_data, &ext_datalen, &exts, &extslen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_decode_error);
			return -1;
		}

		switch (ext_type) {
		case TLS_extension_server_name:
		case TLS_extension_trusted_ca_keys:
		case TLS_extension_status_request:
			if (ext_data) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			break;
		case TLS_extension_supported_groups:
		case TLS_extension_application_layer_protocol_negotiation:
			if (!ext_data) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
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
				tls_send_alert(conn, TLS_alert_illegal_parameter);
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
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			application_layer_protocol_negotiation = ext_data;
			application_layer_protocol_negotiation_len = ext_datalen;
			break;
		}
	}

	// supported_groups
	if (supported_groups) {
		int common_group;
		size_t common_groups_cnt = 0;

		if ((ret = tls_process_supported_groups(supported_groups, supported_groups_len,
			tlcp_supported_groups, tlcp_supported_groups_cnt,
			&common_group, &common_groups_cnt, 1)) < 0) {
			error_print();
			tls_send_alert(conn, TLS_alert_decode_error);
			return -1;
		} else if (ret == 0) {
			error_print();
			tls_send_alert(conn, TLS_alert_handshake_failure);
			return -1;
		}
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

	if (conn->client_certs_len) {
		sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);
	}

	return 1;
}


// 这个必须要独立的，因为TLCP的是双证书，这个双证书是从对方读取的
int tlcp_recv_server_certificate(TLS_CONNECT *conn)
{
	int ret;
	const uint8_t *server_cert;
	size_t server_cert_len;
	int verify_result;

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	if (conn->verbose)
		tls_trace("recv server Certificate\n");
	if (conn->verbose)
		tls_record_print(stderr, 0, 0, conn->cipher_suite, conn->record, conn->recordlen);

	if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
		error_print();
		return -1;
	}
	if (conn->verbose)
		tls_handshake_digest_print(stderr, 0, 0, "Certificate", &conn->dgst_ctx);

	if (tls_update_transcript(conn, conn->record) != 1) {
		error_print();
		return -1;
	}

	if (tls_record_protocol(conn->record) != TLS_protocol_tlcp) {
		error_print();
		tls_send_alert(conn, TLS_alert_protocol_version);
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
	// FIXME: 需要根据密码套件、ClientHello扩展等对证书做进一步的验证
	// x509_certs_verify_tlcp 只是验证证书链有效，不能完全判定服务器证书有效

	if (conn->ctx->cacertslen) {
		if (x509_certs_verify_tlcp(conn->peer_cert_chain, conn->peer_cert_chain_len, X509_cert_chain_server,
			conn->ctx->cacerts, conn->ctx->cacertslen, conn->ctx->verify_depth, &verify_result) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_bad_certificate);
			return -1;
		}
	}

	if (conn->client_certs_len) {
		sm2_sign_update(&conn->sign_ctx, conn->record + 5, conn->recordlen - 5);
	}

	return 1;
}

int tlcp_recv_server_key_exchange(TLS_CONNECT *conn)
{
	int ret;
	const uint8_t *sig;
	size_t siglen;
	const uint8_t *sign_cert;
	size_t sign_cert_len;
	X509_KEY sign_key;
	const uint8_t *enc_cert;
	size_t enc_cert_len;
	uint8_t enc_cert_header[3];
	uint8_t *enc_cert_header_ptr = enc_cert_header;
	size_t enc_cert_header_len = 0;
	SM2_VERIFY_CTX verify_ctx;

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	if(conn->verbose)
		tls_trace("recv ServerKeyExchange\n");
	if (conn->verbose)
		tls_record_print(stderr, 0, 0, conn->cipher_suite, conn->record, conn->recordlen);

	if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
		error_print();
		return -1;
	}
	if(conn->verbose)
		tls_handshake_digest_print(stderr, 0, 0, "ServerKeyExchange", &conn->dgst_ctx);

	if (tls_update_transcript(conn, conn->record) != 1) {
		error_print();
		return -1;
	}

	if (tls_record_protocol(conn->record) != TLS_protocol_tlcp) {
		error_print();
		tls_send_alert(conn, TLS_alert_protocol_version);
		return -1;
	}
	if (tlcp_record_get_handshake_server_key_exchange(conn->record,
		TLS_server_key_exchange_ecc, NULL, 0, &sig, &siglen) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	// verify ServerKeyExchange
	if (x509_certs_get_cert_by_index(conn->peer_cert_chain, conn->peer_cert_chain_len, 0, &sign_cert, &sign_cert_len) != 1
		|| x509_cert_get_subject_public_key(sign_cert, sign_cert_len, &sign_key) != 1
		|| x509_certs_get_cert_by_index(conn->peer_cert_chain, conn->peer_cert_chain_len, 1, &enc_cert, &enc_cert_len) != 1) {
		error_print();
		return -1;
	}
	tls_uint24_to_bytes(enc_cert_len, &enc_cert_header_ptr, &enc_cert_header_len);

	if (sm2_verify_init(&verify_ctx, &sign_key.u.sm2_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1
		|| sm2_verify_update(&verify_ctx, conn->client_random, 32) != 1
		|| sm2_verify_update(&verify_ctx, conn->server_random, 32) != 1
		|| sm2_verify_update(&verify_ctx, enc_cert_header, enc_cert_header_len) != 1
		|| sm2_verify_update(&verify_ctx, enc_cert, enc_cert_len) != 1) {
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
		return 0;
	}

	if(conn->verbose) tls_trace("recv CertificateRequest\n");
	if (conn->verbose)
		tls_record_print(stderr, 0, 0, conn->cipher_suite, conn->record, conn->recordlen);

	if (tlcp_record_get_handshake_certificate_request(conn->record,
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

	if (tls_cert_types_has_ecdsa_sign(cert_types, cert_types_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unsupported_certificate);
		return -1;
	}

	if (tls_authorities_issued_certificate(ca_names, ca_names_len, conn->client_certs, conn->client_certs_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unsupported_certificate);
		return -1;
	}

	if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
		error_print();
		return -1;
	}
	if (conn->verbose)
		tls_handshake_digest_print(stderr, 0, 0, "CertificateRequest", &conn->dgst_ctx);

	if (tls_update_transcript(conn, conn->record) != 1) {
		error_print();
		return -1;
	}

	conn->recordlen = 0;

	return 1;
}

int tlcp_send_client_key_exchange(TLS_CONNECT *conn)
{
	int ret;

	if (!conn->recordlen) {
		const uint8_t *enc_cert;
		size_t enc_cert_len;
		X509_KEY public_key;
		uint8_t enced_pre_master_secret[SM2_MAX_CIPHERTEXT_SIZE];
		size_t enced_pre_master_secret_len;

		if (conn->verbose)
			tls_trace("send ClientKeyExchange\n");

		if (x509_certs_get_cert_by_index(conn->peer_cert_chain, conn->peer_cert_chain_len, 1,
			&enc_cert, &enc_cert_len) != 1
			|| x509_cert_get_subject_public_key(enc_cert, enc_cert_len, &public_key) != 1) {
			error_print();
			return -1;
		}

		if (tlcp_generate_pre_master_secret(conn) != 1
			|| tls_derive_master_secret(conn) != 1
			|| tls_derive_key_block(conn) != 1
			|| tls_init_application_keys(conn) != 1) {
			error_print();
			return -1;
		}

		if (sm2_encrypt(&public_key.u.sm2_key, conn->pre_master_secret, 48,
			enced_pre_master_secret, &enced_pre_master_secret_len) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		if (tlcp_record_set_handshake_client_key_exchange(conn->record, &conn->recordlen,
			enced_pre_master_secret, enced_pre_master_secret_len) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		if (conn->verbose)
			tls_record_print(stderr, 0, 0, conn->cipher_suite, conn->record, conn->recordlen);

		if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
			error_print();
			return -1;
		}
		if (conn->verbose)
			tls_handshake_digest_print(stderr, 0, 0, "ClientKeyExchange", &conn->dgst_ctx);

		if (tls_update_transcript(conn, conn->record) != 1) {
			error_print();
			return -1;
		}
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

	conn->sig_alg = TLS_sig_sm2sig_sm3;
	conn->cipher = BLOCK_CIPHER_sm4();
	conn->digest = DIGEST_sm3();

	if (digest_init(&conn->dgst_ctx, conn->digest) != 1) {
		error_print();
		return -1;
	}

	// 这个判断应该改为一个函数
	/*
	if (client_verify)
		tls_client_verify_init(&conn->client_verify_ctx);
	*/

	if(conn->verbose) tls_trace("recv ClientHello\n");

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	if (conn->verbose)
		tls_record_print(stderr, 0, 0, conn->cipher_suite, conn->record, conn->recordlen);


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
			tls_send_alert(conn, TLS_alert_decode_error);
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
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			server_name = ext_data;
			server_name_len = ext_datalen;
			break;

		case TLS_extension_trusted_ca_keys:
			if (trusted_ca_keys) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			if (tls_trusted_authorities_from_bytes(&trusted_authorities,
				&trusted_authorities_len, ext_data, ext_datalen) != 1) {
				error_print();
				tls_send_alert(conn, TLS_alert_decode_error);
				return -1;
			}
			trusted_ca_keys = 1;
			break;

		case TLS_extension_status_request:
			if (status_request) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			status_request = ext_data;
			status_request_len = ext_datalen;
			break;

		case TLS_extension_supported_groups:
			if (supported_groups) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			supported_groups = ext_data;
			supported_groups_len = ext_datalen;
			break;

		case TLS_extension_signature_algorithms:
			if (signature_algorithms) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			signature_algorithms = ext_data;
			signature_algorithms_len = ext_datalen;
			break;

		case TLS_extension_application_layer_protocol_negotiation:
			if (application_layer_protocol_negotiation) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
				return -1;
			}
			application_layer_protocol_negotiation = ext_data;
			application_layer_protocol_negotiation_len = ext_datalen;
			break;

		case TLS_extension_client_id:
			if (client_id) {
				error_print();
				tls_send_alert(conn, TLS_alert_illegal_parameter);
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

	if (supported_groups) {
		int common_group;
		size_t common_groups_cnt = 0;

		if ((ret = tls_process_supported_groups(supported_groups, supported_groups_len,
			tlcp_supported_groups, tlcp_supported_groups_cnt,
			&common_group, &common_groups_cnt, 1)) < 0) {
			error_print();
			tls_send_alert(conn, TLS_alert_decode_error);
			return -1;
		} else if (ret == 0) {
			error_print();
			tls_send_alert(conn, TLS_alert_handshake_failure);
			return -1;
		}
	}

	if (signature_algorithms) {
		int common_sig_alg;
		size_t common_sig_algs_cnt = 0;

		if ((ret = tls_process_signature_algorithms(signature_algorithms, signature_algorithms_len,
			tlcp_signature_algorithms, tlcp_signature_algorithms_cnt,
			&common_sig_alg, &common_sig_algs_cnt, 1)) < 0) {
			error_print();
			tls_send_alert(conn, TLS_alert_decode_error);
			return -1;
		} else if (ret == 0) {
			error_print();
			tls_send_alert(conn, TLS_alert_handshake_failure);
			return -1;
		}
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

	if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
		error_print();
		return -1;
	}
	if(conn->verbose) tls_handshake_digest_print(stderr, 0, 0, "ClientHello", &conn->dgst_ctx);

	if (tls_update_transcript(conn, conn->record) != 1) {
		error_print();
		return -1;
	}

	//sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
	//tlcp_handshake_digest_print(stderr, 0, 0, "ClientHello", &conn->sm3_ctx);

	/*
	if (client_verify)
		tls_client_verify_update(&conn->client_verify_ctx, conn->record + 5, conn->recordlen - 5);
	*/

	if(conn->verbose) {
		fprintf(stderr, "end of recv_client_hello\n");
	}
	tls_clean_record(conn);

	return 1;
}

int tlcp_send_server_hello(TLS_CONNECT *conn)
{
	int ret;

	if(conn->verbose) tls_trace("send ServerHello\n");

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
		if(conn->verbose) tlcp_record_trace(stderr, conn->record, conn->recordlen, 0, 0);

		if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
			error_print();
			return -1;
		}
		if(conn->verbose) tls_handshake_digest_print(stderr, 0, 0, "ServerHello", &conn->dgst_ctx);

		if (tls_update_transcript(conn, conn->record) != 1) {
			error_print();
			return -1;
		}

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


// TLCP的ServerKeyExchange 需要对服务器的证书签名
// 这是一个明显的不同，因此还是独立比较好

int tlcp_send_server_key_exchange(TLS_CONNECT *conn)
{
	int ret;

	if (conn->recordlen == 0) {
		const uint8_t *enc_cert;
		size_t enc_cert_len;
		uint8_t enc_cert_header[3];
		uint8_t *enc_cert_header_ptr = enc_cert_header;
		size_t enc_cert_header_len = 0;
		X509_KEY *sign_key;
		SM2_SIGN_CTX sign_ctx;
		uint8_t sigbuf[SM2_MAX_SIGNATURE_SIZE];
		size_t siglen;

		if (conn->verbose)
			tls_trace("send ServerKeyExchange\n");

		if (!conn->cert_chain || !conn->cert_chain_len || !conn->cert_chain_idx) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}

		if (x509_certs_get_cert_by_index(conn->cert_chain, conn->cert_chain_len, 1,
			&enc_cert, &enc_cert_len) != 1) {
			error_print();
			return -1;
		}
		tls_uint24_to_bytes(enc_cert_len, &enc_cert_header_ptr, &enc_cert_header_len);

		sign_key = &conn->ctx->x509_keys[conn->cert_chain_idx - 1];
		if (sign_key->algor != OID_ec_public_key
			|| sign_key->algor_param != OID_sm2) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		if (sm2_sign_init(&sign_ctx, &sign_key->u.sm2_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1
			|| sm2_sign_update(&sign_ctx, conn->client_random, 32) != 1
			|| sm2_sign_update(&sign_ctx, conn->server_random, 32) != 1
			|| sm2_sign_update(&sign_ctx, enc_cert_header, enc_cert_header_len) != 1
			|| sm2_sign_update(&sign_ctx, enc_cert, enc_cert_len) != 1
			|| sm2_sign_finish(&sign_ctx, sigbuf, &siglen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}

		if (tlcp_record_set_handshake_server_key_exchange(conn->record, &conn->recordlen,
			TLS_server_key_exchange_ecc, NULL, 0, sigbuf, siglen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		if (conn->verbose)
			tls_record_print(stderr, 0, 0, conn->cipher_suite, conn->record, conn->recordlen);

		if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
			error_print();
			return -1;
		}
		if (conn->verbose)
			tls_handshake_digest_print(stderr, 0, 0, "ServerKeyExchange", &conn->dgst_ctx);

		if (tls_update_transcript(conn, conn->record) != 1) {
			error_print();
			return -1;
		}
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

static void tlcp_secrets_print(TLS_CONNECT *conn)
{
	if (conn->verbose < 5) {
		return;
	}

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

int tlcp_generate_pre_master_secret(TLS_CONNECT *conn)
{
	uint8_t *pre_master_secret;
	size_t len = 0;

	if (!conn || conn->protocol != TLS_protocol_tlcp) {
		error_print();
		return -1;
	}
	pre_master_secret = conn->pre_master_secret;
	tls_uint16_to_bytes((uint16_t)conn->protocol, &pre_master_secret, &len);
	if (rand_bytes(pre_master_secret, 46) != 1) {
		error_print();
		return -1;
	}
	conn->pre_master_secret_len = 48;
	return 1;
}

int tlcp_check_pre_master_secret(TLS_CONNECT *conn)
{
	const uint8_t *pre_master_secret;
	size_t len = 2;
	uint16_t protocol;

	if (!conn || conn->protocol != TLS_protocol_tlcp
		|| conn->pre_master_secret_len != 48) {
		error_print();
		return -1;
	}
	pre_master_secret = conn->pre_master_secret;
	if (tls_uint16_from_bytes(&protocol, &pre_master_secret, &len) != 1) {
		error_print();
		return -1;
	}
	if (protocol != conn->protocol) {
		error_print();
		return -1;
	}
	return 1;
}



int tlcp_send_certificate_request(TLS_CONNECT *conn)
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

		if(conn->verbose) tls_trace("send CertificateRequest\n");
		if (tls_authorities_from_certs(ca_names, &ca_names_len, sizeof(ca_names),
			conn->ctx->cacerts, conn->ctx->cacertslen) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		if (tlcp_record_set_handshake_certificate_request(conn->record, &conn->recordlen,
			cert_types, sizeof(cert_types),
			ca_names, ca_names_len) != 1) {
			error_print();
			tls_send_alert(conn, TLS_alert_internal_error);
			return -1;
		}
		if(conn->verbose)
			tls_record_print(stderr, 0, 0, conn->cipher_suite, conn->record, conn->recordlen);


		if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
			error_print();
			return -1;
		}

		if (tls_update_transcript(conn, conn->record) != 1) {
			error_print();
			return -1;
		}
	}

	if ((ret = tls_send_record(conn)) != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	//sm3_update(&conn->sm3_ctx, conn->record + 5, conn->recordlen - 5);
	tls_client_verify_update(&conn->client_verify_ctx, conn->record + 5, conn->recordlen - 5);

	return 1;
}

int tlcp_recv_client_key_exchange(TLS_CONNECT *conn)
{
	int ret;
	const uint8_t *enced_pms;
	size_t enced_pms_len;
	X509_KEY *enc_key;

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			error_print();
		}
		return ret;
	}
	if (conn->verbose)
		tls_trace("recv ClientKeyExchange\n");

	if (tls_record_protocol(conn->record) != TLS_protocol_tlcp) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}
	if (conn->verbose)
		tls_record_print(stderr, 0, 0, conn->cipher_suite, conn->record, conn->recordlen);

	if (digest_update(&conn->dgst_ctx, conn->record + 5, conn->recordlen - 5) != 1) {
		error_print();
		return -1;
	}
	if (conn->verbose)
		tls_handshake_digest_print(stderr, 0, 0, "ClientKeyExchange", &conn->dgst_ctx);

	if (tls_update_transcript(conn, conn->record) != 1) {
		error_print();
		return -1;
	}


	if ((ret = tlcp_record_get_handshake_client_key_exchange(conn->record, &enced_pms, &enced_pms_len)) < 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_decode_error);
		return -1;
	} else if (ret == 0) {
		error_print();
		tls_send_alert(conn, TLS_alert_unexpected_message);
		return -1;
	}

	// decrypt enced_pre_master_secret
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
	if (sm2_decrypt(&enc_key->u.sm2_key, enced_pms, enced_pms_len,
		conn->pre_master_secret, &conn->pre_master_secret_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_decrypt_error);
		return -1;
	}
	if (tlcp_check_pre_master_secret(conn) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_illegal_parameter);
		return -1;
	}
	if (tls_derive_master_secret(conn) != 1
		|| tls_derive_key_block(conn) != 1
		|| tls_init_application_keys(conn) != 1) {
		error_print();
		return -1;
	}

	return 1;
}

int tlcp_send(TLS_CONNECT *conn, const uint8_t *in, size_t inlen, size_t *sentlen)
{
	const HMAC_CTX *hmac_ctx;
	const BLOCK_CIPHER_KEY *enc_key;
	const uint8_t *iv;
	uint8_t *seq_num;
	size_t recordlen;
	int ret;

	if (!conn) {
		error_print();
		return -1;
	}
	if (!in || !inlen || !sentlen) {
		error_print();
		return -1;
	}
	if (conn->recv_state) {
		*sentlen = 0;
		return TLS_ERROR_RECV_AGAIN;
	}
	if (conn->send_state && conn->send_state != TLS_state_send_record) {
		error_print();
		return -1;
	}

	*sentlen = 0;

	if (!conn->recordlen) {

		if (inlen > TLS_MAX_PLAINTEXT_SIZE) {
			inlen = TLS_MAX_PLAINTEXT_SIZE;
		}

		if (conn->datalen) {
			error_puts("recv all buffered data before send");
			return -1;
		}

		if (conn->is_client) {
			hmac_ctx = &conn->client_write_mac_ctx;
			enc_key = &conn->client_write_key;
			iv = conn->client_write_iv;
			seq_num = conn->client_seq_num;
		} else {
			hmac_ctx = &conn->server_write_mac_ctx;
			enc_key = &conn->server_write_key;
			iv = conn->server_write_iv;
			seq_num = conn->server_seq_num;
		}

		if (tls_record_set_type(conn->databuf, TLS_record_application_data) != 1
			|| tls_record_set_protocol(conn->databuf, conn->protocol) != 1
			|| tls_record_set_data(conn->databuf, in, inlen) != 1) {
			error_print();
			return -1;
		}
		if(conn->verbose) tls_record_trace(stderr, conn->databuf, tls_record_length(conn->databuf), 0, 0);

		switch (conn->cipher_suite) {
		case TLS_cipher_ecc_sm4_cbc_sm3:
			if (tls_cbc_encrypt(hmac_ctx, enc_key, seq_num, conn->databuf,
				conn->databuf + 5, tls_record_data_length(conn->databuf),
				conn->record + 5, &recordlen) != 1) {
				error_print();
				return -1;
			}
			break;

		case TLS_cipher_ecc_sm4_gcm_sm3:
			if (tls_gcm_encrypt(enc_key, iv, seq_num, conn->databuf,
				conn->databuf + 5, tls_record_data_length(conn->databuf),
				conn->record + 5, &recordlen) != 1) {
				error_print();
				return -1;
			}
			break;

		default:
			error_print();
			return -1;
		}
		tls_seq_num_incr(seq_num);

		conn->record[0] = conn->databuf[0];
		conn->record[1] = conn->databuf[1];
		conn->record[2] = conn->databuf[2];
		conn->record[3] = (uint8_t)(recordlen >> 8);
		conn->record[4] = (uint8_t)(recordlen);
		recordlen += 5;

		conn->recordlen = recordlen;
		conn->record_offset = 0;
		conn->sentlen = inlen;
		conn->send_state = TLS_state_send_record;
		if(conn->verbose) tls_encrypted_record_trace(stderr, conn->record, recordlen, 0, 0);
	}

	ret = tls_send_record(conn);
	if (ret != 1) {
		if (ret != TLS_ERROR_SEND_AGAIN) {
			error_print();
		}
		return ret;
	}

	*sentlen = conn->sentlen;
	conn->send_state = 0;
	tls_clean_record(conn);
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
		ret = tlcp_send_client_key_exchange(conn);
		if (conn->client_certificate_verify)
			next_state = TLS_state_certificate_verify;
		else	next_state = TLS_state_client_change_cipher_spec;
		break;

	case TLS_state_certificate_verify:
		ret = tls_send_certificate_verify(conn);
		next_state = TLS_state_client_change_cipher_spec;
		break;

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
		ret = tls_send_server_certificate(conn);
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
		ret = tlcp_recv_client_key_exchange(conn);
		if (conn->client_certificate_verify)
			next_state = TLS_state_certificate_verify;
		else	next_state = TLS_state_client_change_cipher_spec;
		break;

	case TLS_state_certificate_verify:
		ret = tls_recv_certificate_verify(conn);
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
