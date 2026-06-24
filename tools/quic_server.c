/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/quic.h>
#include <gmssl/tls.h>
#include <gmssl/socket.h>
#include <gmssl/error.h>

int tls13_generate_application_secrets(TLS_CONNECT *conn);
int tls13_generate_client_application_keys(TLS_CONNECT *conn);
int tls13_generate_server_application_keys(TLS_CONNECT *conn);
int tls13_record_set_handshake_encrypted_extensions(uint8_t *record, size_t *recordlen, const uint8_t *exts, size_t extslen);

static const char *options = "[-port num] -cert pem -key pem [-pass str] [-cipher_suite str] [-supported_group str] [-sig_alg str] [-verbose]";

static const char *help =
"Options\n"
"\n"
"    -port num                 Listening UDP port number, default 443\n"
"    -cert pem                 Server's certificate chain in PEM format\n"
"    -key pem                  Server's encrypted private key in PEM format\n"
"    -pass str                 Password to decrypt private key\n"
"    -cipher_suite str         TLS 1.3 cipher suite, default TLS_AES_128_GCM_SHA256 and TLS_AES_128_CCM_SHA256\n"
"    -supported_group str      Supported elliptic curve, default prime256v1\n"
"    -sig_alg str              Supported signature algorithm, default ecdsa_secp256r1_sha256\n"
"    -verbose                  Print QUIC packet, frame and TLS handshake messages\n"
"\n"
#include "quic_help.h"
;

static int quic_tls_record_from_handshake(const uint8_t *handshake, size_t handshake_len, uint8_t *record, size_t *record_len)
{
	if (!handshake || !record || !record_len || handshake_len > TLS_MAX_PLAINTEXT_SIZE) {
		error_print();
		return -1;
	}
	record[0] = TLS_record_handshake;
	record[1] = 0x03;
	record[2] = 0x03;
	record[3] = (uint8_t)(handshake_len >> 8);
	record[4] = (uint8_t)handshake_len;
	memcpy(record + TLS_RECORD_HEADER_SIZE, handshake, handshake_len);
	*record_len = TLS_RECORD_HEADER_SIZE + handshake_len;
	return 1;
}

static int quic_long_packet_connection_ids_get(const uint8_t *packet, size_t packet_len,
	const uint8_t **dcid, size_t *dcid_len, const uint8_t **scid, size_t *scid_len)
{
	const uint8_t *p;
	size_t len;
	uint8_t n;

	if (!packet || packet_len < 7 || !(packet[0] & 0x80) || !dcid || !dcid_len || !scid || !scid_len) {
		error_print();
		return -1;
	}
	p = packet + 5;
	len = packet_len - 5;
	n = *p++;
	len--;
	if (n > len) {
		error_print();
		return -1;
	}
	*dcid = p;
	*dcid_len = n;
	p += n;
	len -= n;
	if (!len) {
		error_print();
		return -1;
	}
	n = *p++;
	len--;
	if (n > len) {
		error_print();
		return -1;
	}
	*scid = p;
	*scid_len = n;
	return 1;
}

static int quic_ack_frame_to_bytes(uint64_t packet_number, uint8_t **out, size_t *outlen)
{
	if (quic_varint_to_bytes(QUIC_frame_ack, out, outlen) != 1
		|| quic_varint_to_bytes(packet_number, out, outlen) != 1
		|| quic_varint_to_bytes(0, out, outlen) != 1
		|| quic_varint_to_bytes(0, out, outlen) != 1
		|| quic_varint_to_bytes(0, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

static int quic_crypto_frame_to_bytes(uint64_t offset, const uint8_t *data, size_t datalen, uint8_t **out, size_t *outlen)
{
	if ((!data && datalen)
		|| quic_varint_to_bytes(QUIC_frame_crypto, out, outlen) != 1
		|| quic_varint_to_bytes(offset, out, outlen) != 1
		|| quic_varint_to_bytes(datalen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	if (out && *out) {
		memcpy(*out, data, datalen);
		*out += datalen;
	}
	*outlen += datalen;
	return 1;
}

static int quic_stream_frame_to_bytes(uint64_t stream_id, uint64_t offset, int fin, const uint8_t *data, size_t datalen, uint8_t **out, size_t *outlen)
{
	uint64_t type = QUIC_frame_stream_base | 0x02 | (offset ? 0x04 : 0) | (fin ? 0x01 : 0);

	if ((!data && datalen)
		|| quic_varint_to_bytes(type, out, outlen) != 1
		|| quic_varint_to_bytes(stream_id, out, outlen) != 1) {
		error_print();
		return -1;
	}
	if (offset && quic_varint_to_bytes(offset, out, outlen) != 1) {
		error_print();
		return -1;
	}
	if (quic_varint_to_bytes(datalen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	if (out && *out) {
		memcpy(*out, data, datalen);
		*out += datalen;
	}
	*outlen += datalen;
	return 1;
}

static int quic_frames_crypto_collect(const uint8_t *frames, size_t frames_len,
	uint8_t *crypto, size_t *crypto_len, size_t crypto_max, uint64_t *largest_ack)
{
	const uint8_t *p = frames;
	size_t len = frames_len;

	if (!frames || !crypto || !crypto_len || !largest_ack) {
		error_print();
		return -1;
	}
	while (len) {
		uint64_t type;
		if (quic_varint_from_bytes(&type, &p, &len) != 1) {
			error_print();
			return -1;
		}
		if (type == QUIC_frame_padding) {
			while (len && *p == 0) {
				p++;
				len--;
			}
		} else if (type == QUIC_frame_ping) {
			continue;
		} else if (type == QUIC_frame_ack || type == QUIC_frame_ack_ecn) {
			uint64_t ack_delay, ack_range_count, first_ack_range, i;
			if (quic_varint_from_bytes(largest_ack, &p, &len) != 1
				|| quic_varint_from_bytes(&ack_delay, &p, &len) != 1
				|| quic_varint_from_bytes(&ack_range_count, &p, &len) != 1
				|| quic_varint_from_bytes(&first_ack_range, &p, &len) != 1) {
				error_print();
				return -1;
			}
			for (i = 0; i < ack_range_count; i++) {
				uint64_t gap, ack_range;
				if (quic_varint_from_bytes(&gap, &p, &len) != 1 || quic_varint_from_bytes(&ack_range, &p, &len) != 1) {
					error_print();
					return -1;
				}
			}
			if (type == QUIC_frame_ack_ecn) {
				uint64_t ect0, ect1, ce;
				if (quic_varint_from_bytes(&ect0, &p, &len) != 1
					|| quic_varint_from_bytes(&ect1, &p, &len) != 1
					|| quic_varint_from_bytes(&ce, &p, &len) != 1) {
					error_print();
					return -1;
				}
			}
		} else if (type == QUIC_frame_crypto) {
			uint64_t off, data_len;
			if (quic_varint_from_bytes(&off, &p, &len) != 1
				|| quic_varint_from_bytes(&data_len, &p, &len) != 1
				|| data_len > len || off + data_len > crypto_max) {
				error_print();
				return -1;
			}
			memcpy(crypto + off, p, (size_t)data_len);
			if (*crypto_len < off + data_len) {
				*crypto_len = (size_t)(off + data_len);
			}
			p += data_len;
			len -= data_len;
		} else {
			error_print();
			return -1;
		}
	}
	return 1;
}

static int quic_tls_handshake_is_complete(const uint8_t *handshake, size_t handshake_len)
{
	size_t len;

	if (!handshake || handshake_len < TLS_HANDSHAKE_HEADER_SIZE) {
		return 0;
	}
	len = ((size_t)handshake[1] << 16) | ((size_t)handshake[2] << 8) | handshake[3];
	return handshake_len >= TLS_HANDSHAKE_HEADER_SIZE + len;
}

static int quic_server_client_hello_process(TLS_CONNECT *conn, const uint8_t *client_hello, size_t client_hello_len)
{
	uint8_t record[TLS_MAX_RECORD_SIZE];
	size_t record_len;
	int legacy_version;
	const uint8_t *random;
	const uint8_t *legacy_session_id;
	size_t legacy_session_id_len;
	const uint8_t *cipher_suites;
	size_t cipher_suites_len;
	const uint8_t *exts;
	size_t extslen;
	const uint8_t *supported_versions = NULL;
	size_t supported_versions_len = 0;
	const uint8_t *supported_groups = NULL;
	size_t supported_groups_len = 0;
	const uint8_t *signature_algorithms = NULL;
	size_t signature_algorithms_len = 0;
	const uint8_t *key_share = NULL;
	size_t key_share_len = 0;
	const uint8_t *server_name = NULL;
	size_t server_name_len = 0;
	const uint8_t *alpn = NULL;
	size_t alpn_len = 0;
	int common_versions[4];
	size_t common_versions_cnt = 0;
	int common_groups[4];
	size_t common_groups_cnt = 0;
	int common_sig_algs[8];
	size_t common_sig_algs_cnt = 0;
	const uint8_t *host_name = NULL;
	size_t host_name_len = 0;
	int group = 0;
	const uint8_t *key_exchange = NULL;
	size_t key_exchange_len = 0;
	int ret;

	if (!conn || !client_hello || !client_hello_len) {
		error_print();
		return -1;
	}
	if (quic_tls_record_from_handshake(client_hello, client_hello_len, record, &record_len) != 1
		|| tls_record_get_handshake_client_hello(record, &legacy_version, &random, &legacy_session_id,
			&legacy_session_id_len, &cipher_suites, &cipher_suites_len, &exts, &extslen) != 1) {
		error_print();
		return -1;
	}
	if (legacy_version != TLS_protocol_tls12) {
		error_print();
		return -1;
	}
	memcpy(conn->client_random, random, 32);
	if (legacy_session_id_len > sizeof(conn->session_id)) {
		error_print();
		return -1;
	}
	memcpy(conn->session_id, legacy_session_id, legacy_session_id_len);
	conn->session_id_len = legacy_session_id_len;

	while (extslen) {
		int ext_type;
		const uint8_t *ext_data;
		size_t ext_datalen;

		if (tls_ext_from_bytes(&ext_type, &ext_data, &ext_datalen, &exts, &extslen) != 1) {
			error_print();
			return -1;
		}
		switch (ext_type) {
		case TLS_extension_supported_versions:
			supported_versions = ext_data;
			supported_versions_len = ext_datalen;
			break;
		case TLS_extension_supported_groups:
			supported_groups = ext_data;
			supported_groups_len = ext_datalen;
			break;
		case TLS_extension_signature_algorithms:
			signature_algorithms = ext_data;
			signature_algorithms_len = ext_datalen;
			break;
		case TLS_extension_key_share:
			key_share = ext_data;
			key_share_len = ext_datalen;
			break;
		case TLS_extension_server_name:
			server_name = ext_data;
			server_name_len = ext_datalen;
			break;
		case TLS_extension_application_layer_protocol_negotiation:
			alpn = ext_data;
			alpn_len = ext_datalen;
			break;
		default:
			break;
		}
	}
	if (!supported_versions || !supported_groups || !signature_algorithms || !key_share || !alpn) {
		error_print();
		return -1;
	}
	if ((ret = tls13_process_client_supported_versions(supported_versions, supported_versions_len,
		conn->ctx->supported_versions, conn->ctx->supported_versions_cnt,
		common_versions, &common_versions_cnt, sizeof(common_versions)/sizeof(common_versions[0]))) != 1
		|| common_versions[0] != TLS_protocol_tls13) {
		error_print();
		return -1;
	}
	conn->protocol = TLS_protocol_tls13;
	if ((ret = tls_process_supported_groups(supported_groups, supported_groups_len,
		conn->ctx->supported_groups, conn->ctx->supported_groups_cnt,
		common_groups, &common_groups_cnt, sizeof(common_groups)/sizeof(common_groups[0]))) != 1) {
		error_print();
		return -1;
	}
	if ((ret = tls_process_signature_algorithms(signature_algorithms, signature_algorithms_len,
		conn->ctx->signature_algorithms, conn->ctx->signature_algorithms_cnt,
		common_sig_algs, &common_sig_algs_cnt, sizeof(common_sig_algs)/sizeof(common_sig_algs[0]))) != 1) {
		error_print();
		return -1;
	}
	if (server_name
		&& tls_server_name_from_bytes(&host_name, &host_name_len, server_name, server_name_len) != 1) {
		error_print();
		return -1;
	}
	if ((ret = tls_application_layer_protocol_negotiation_select(alpn, alpn_len,
		conn->ctx->alpn_protocols, conn->ctx->alpn_protocols_cnt, &conn->alpn_selected)) != 1) {
		error_print();
		return -1;
	}
	if ((ret = tls13_cert_chains_select(conn->ctx->cert_chains, conn->ctx->cert_chains_len,
		common_sig_algs, common_sig_algs_cnt, NULL, 0, NULL, 0, NULL, 0, host_name, host_name_len,
		&conn->cert_chain, &conn->cert_chain_len, &conn->cert_chain_idx, &conn->sig_alg)) != 1) {
		error_print();
		return -1;
	}
	if (tls_cipher_suites_select(cipher_suites, cipher_suites_len,
		conn->ctx->cipher_suites, conn->ctx->cipher_suites_cnt, &conn->cipher_suite) != 1
		|| tls_cipher_suite_get(conn->cipher_suite, &conn->cipher, &conn->digest) != 1) {
		error_print();
		return -1;
	}
	if (tls13_process_key_share_client_hello(key_share, key_share_len, common_groups, common_groups_cnt,
		&group, &key_exchange, &key_exchange_len) != 1 || key_exchange_len != 65) {
		error_print();
		return -1;
	}
	conn->key_exchange_group = group;
	memcpy(conn->peer_key_exchange, key_exchange, key_exchange_len);
	conn->peer_key_exchange_len = key_exchange_len;
	conn->key_exchange_modes = TLS_KE_CERT_DHE;
	if (digest_init(&conn->dgst_ctx, conn->digest) != 1
		|| digest_update(&conn->dgst_ctx, client_hello, client_hello_len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

static int quic_record_handshake_append(TLS_CONNECT *conn, const uint8_t *record, size_t record_len, uint8_t **out, size_t *outlen)
{
	const uint8_t *handshake;
	size_t handshake_len;

	if (!conn || !record || record_len < TLS_RECORD_HEADER_SIZE || !outlen
		|| tls_record_type(record) != TLS_record_handshake || tls_record_length(record) != record_len) {
		error_print();
		return -1;
	}
	handshake = record + TLS_RECORD_HEADER_SIZE;
	handshake_len = record_len - TLS_RECORD_HEADER_SIZE;
	if (out && *out) {
		memcpy(*out, handshake, handshake_len);
		*out += handshake_len;
	}
	*outlen += handshake_len;
	if (digest_update(&conn->dgst_ctx, handshake, handshake_len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

static void quic_tls_record_header_init(uint8_t *record)
{
	record[0] = TLS_record_handshake;
	record[1] = 0x03;
	record[2] = 0x03;
}

static int quic_server_encrypted_extensions_to_bytes(TLS_CONNECT *conn, const QUIC_TRANSPORT_PARAMS *params, uint8_t **out, size_t *outlen)
{
	uint8_t exts[512];
	uint8_t *pexts = exts;
	size_t extslen = 0;
	uint8_t transport_params[QUIC_TRANSPORT_PARAM_MAX_SIZE];
	uint8_t *ptransport_params = transport_params;
	size_t transport_params_len = 0;
	uint8_t record[TLS_MAX_RECORD_SIZE];
	size_t record_len = 0;

	if (!conn || !params || !outlen) {
		error_print();
		return -1;
	}
	quic_tls_record_header_init(record);
	if (tls_application_layer_protocol_negotiation_selected_ext_to_bytes(conn->alpn_selected, &pexts, &extslen) != 1
		|| quic_transport_params_to_bytes(params, &ptransport_params, &transport_params_len) != 1
		|| tls_ext_to_bytes(TLS_extension_quic_transport_parameters, transport_params, transport_params_len, &pexts, &extslen) != 1
		|| tls13_record_set_handshake_encrypted_extensions(record, &record_len, exts, extslen) != 1
		|| quic_record_handshake_append(conn, record, record_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

static int quic_server_certificate_to_bytes(TLS_CONNECT *conn, uint8_t **out, size_t *outlen)
{
	uint8_t record[TLS_MAX_RECORD_SIZE];
	size_t record_len = 0;

	if (!conn || !outlen) {
		error_print();
		return -1;
	}
	quic_tls_record_header_init(record);
	if (tls13_record_set_handshake_certificate(record, &record_len, NULL, 0,
		conn->cert_chain, conn->cert_chain_len, NULL, 0, NULL, 0) != 1
		|| quic_record_handshake_append(conn, record, record_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

static int quic_server_certificate_verify_to_bytes(TLS_CONNECT *conn, uint8_t **out, size_t *outlen)
{
	X509_KEY *sign_key;
	uint8_t sig[SM2_MAX_SIGNATURE_SIZE];
	size_t siglen;
	uint8_t record[TLS_MAX_RECORD_SIZE];
	size_t record_len = 0;

	if (!conn || !outlen || !conn->cert_chain_idx) {
		error_print();
		return -1;
	}
	quic_tls_record_header_init(record);
	sign_key = &conn->ctx->x509_keys[conn->cert_chain_idx - 1];
	if (tls13_sign_certificate_verify(TLS_server_mode, conn->sig_alg, sign_key, &conn->dgst_ctx, sig, &siglen) != 1
		|| tls13_record_set_handshake_certificate_verify(record, &record_len, conn->sig_alg, sig, siglen) != 1
		|| quic_record_handshake_append(conn, record, record_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

static int quic_server_finished_to_bytes(TLS_CONNECT *conn, uint8_t **out, size_t *outlen)
{
	uint8_t verify_data[64];
	size_t verify_data_len;
	uint8_t record[TLS_MAX_RECORD_SIZE];
	size_t record_len = 0;
	const uint8_t *handshake;
	size_t handshake_len;

	if (!conn || !outlen) {
		error_print();
		return -1;
	}
	quic_tls_record_header_init(record);
	if (tls13_compute_verify_data(conn->server_handshake_traffic_secret, &conn->dgst_ctx, verify_data, &verify_data_len) != 1
		|| tls13_record_set_handshake_finished(record, &record_len, verify_data, verify_data_len) != 1) {
		error_print();
		return -1;
	}
	handshake = record + TLS_RECORD_HEADER_SIZE;
	handshake_len = record_len - TLS_RECORD_HEADER_SIZE;
	if (out && *out) {
		memcpy(*out, handshake, handshake_len);
		*out += handshake_len;
	}
	*outlen += handshake_len;
	if (digest_update(&conn->dgst_ctx, handshake, handshake_len) != 1
		|| tls13_generate_application_secrets(conn) != 1
		|| tls13_generate_server_application_keys(conn) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

static int quic_server_client_finished_process(TLS_CONNECT *conn, const uint8_t *handshake, size_t handshake_len)
{
	uint8_t record[TLS_MAX_RECORD_SIZE];
	size_t record_len;
	const uint8_t *client_verify_data;
	size_t client_verify_data_len;
	uint8_t verify_data[64];
	size_t verify_data_len;

	if (!conn || !handshake || !handshake_len) {
		error_print();
		return -1;
	}
	if (quic_tls_record_from_handshake(handshake, handshake_len, record, &record_len) != 1
		|| tls13_compute_verify_data(conn->client_handshake_traffic_secret, &conn->dgst_ctx, verify_data, &verify_data_len) != 1
		|| tls13_record_get_handshake_finished(record, &client_verify_data, &client_verify_data_len) != 1
		|| client_verify_data_len != verify_data_len
		|| memcmp(client_verify_data, verify_data, verify_data_len) != 0
		|| digest_update(&conn->dgst_ctx, handshake, handshake_len) != 1
		|| tls13_generate_client_application_keys(conn) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

static int quic_http3_response_to_frames(uint64_t request_stream_id, const uint8_t *body, size_t body_len, uint64_t ack_pn, uint8_t *frames, size_t *frames_len)
{
	uint8_t control_stream[] = { 0x00, 0x04, 0x00 };
	uint8_t qpack_encoder_stream[] = { 0x02 };
	uint8_t qpack_decoder_stream[] = { 0x03 };
	uint8_t headers[] = { 0x01, 0x03, 0x00, 0x00, 0xd9 };
	uint8_t data[512];
	uint8_t *p = frames;
	uint8_t *q = data;
	size_t data_len = 0;

	if (!body || !frames || !frames_len || body_len > 255) {
		error_print();
		return -1;
	}
	*frames_len = 0;
	if (quic_varint_to_bytes(0x00, &q, &data_len) != 1
		|| quic_varint_to_bytes(body_len, &q, &data_len) != 1) {
		error_print();
		return -1;
	}
	memcpy(q, body, body_len);
	data_len += body_len;
	if (quic_ack_frame_to_bytes(ack_pn, &p, frames_len) != 1
		|| quic_varint_to_bytes(QUIC_frame_handshake_done, &p, frames_len) != 1
		|| quic_stream_frame_to_bytes(3, 0, 0, control_stream, sizeof(control_stream), &p, frames_len) != 1
		|| quic_stream_frame_to_bytes(7, 0, 0, qpack_encoder_stream, sizeof(qpack_encoder_stream), &p, frames_len) != 1
		|| quic_stream_frame_to_bytes(11, 0, 0, qpack_decoder_stream, sizeof(qpack_decoder_stream), &p, frames_len) != 1
		|| quic_stream_frame_to_bytes(request_stream_id, 0, 0, headers, sizeof(headers), &p, frames_len) != 1
		|| quic_stream_frame_to_bytes(request_stream_id, sizeof(headers), 1, data, data_len, &p, frames_len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

static int quic_application_request_stream_id(const uint8_t *frames, size_t frames_len, uint64_t *packet_number, uint64_t *stream_id)
{
	const uint8_t *p = frames;
	size_t len = frames_len;

	if (!frames || !stream_id) {
		error_print();
		return -1;
	}
	*stream_id = 0;
	while (len) {
		uint64_t type;
		if (quic_varint_from_bytes(&type, &p, &len) != 1) return -1;
		if (type == QUIC_frame_padding) {
			while (len && *p == 0) { p++; len--; }
		} else if (type == QUIC_frame_ack || type == QUIC_frame_ack_ecn) {
			uint64_t val, range_count, i;
			if (quic_varint_from_bytes(&val, &p, &len) != 1
				|| quic_varint_from_bytes(&val, &p, &len) != 1
				|| quic_varint_from_bytes(&range_count, &p, &len) != 1
				|| quic_varint_from_bytes(&val, &p, &len) != 1) return -1;
			for (i = 0; i < range_count; i++) {
				if (quic_varint_from_bytes(&val, &p, &len) != 1 || quic_varint_from_bytes(&val, &p, &len) != 1) return -1;
			}
			if (type == QUIC_frame_ack_ecn) {
				if (quic_varint_from_bytes(&val, &p, &len) != 1
					|| quic_varint_from_bytes(&val, &p, &len) != 1
					|| quic_varint_from_bytes(&val, &p, &len) != 1) return -1;
			}
		} else if ((type & 0xf8) == QUIC_frame_stream_base) {
			uint64_t off = 0, data_len;
			if (quic_varint_from_bytes(stream_id, &p, &len) != 1) return -1;
			if (type & 0x04) {
				if (quic_varint_from_bytes(&off, &p, &len) != 1) return -1;
			}
			if (type & 0x02) {
				if (quic_varint_from_bytes(&data_len, &p, &len) != 1 || data_len > len) return -1;
			} else {
				data_len = len;
			}
			(void)off;
			p += data_len;
			len -= data_len;
			if ((*stream_id & 0x03) == 0) {
				if (packet_number) *packet_number = 0;
				return 1;
			}
		} else if (type == QUIC_frame_new_connection_id) {
			uint64_t seq, retire, cid_len;
			if (quic_varint_from_bytes(&seq, &p, &len) != 1
				|| quic_varint_from_bytes(&retire, &p, &len) != 1
				|| quic_varint_from_bytes(&cid_len, &p, &len) != 1
				|| cid_len > 20 || cid_len + 16 > len) return -1;
			p += cid_len + 16;
			len -= cid_len + 16;
		} else {
			return 0;
		}
	}
	return 0;
}

int quic_server_main(int argc, char **argv)
{
	char *prog = argv[0];
	int ret = 1;
	int port = 443;
	char *certfile = NULL;
	char *keyfile = NULL;
	char *pass = NULL;
	int verbose = 0;
	TLS_CTX ctx;
	TLS_CONNECT conn;
	int cipher_suites[TLS_MAX_CIPHER_SUITES] = { TLS_cipher_aes_128_gcm_sha256, TLS_cipher_aes_128_ccm_sha256 };
	size_t cipher_suites_cnt = 2;
	int supported_group = TLS_curve_secp256r1;
	int sig_alg = TLS_sig_ecdsa_secp256r1_sha256;
	char *alpn = "h3";
	tls_socket_t sock = tls_socket_invalid();
	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;
	tls_socklen_t client_addr_len;
	uint8_t buf[4096];
	uint8_t sendbuf[4096];
	uint8_t initial_crypto[TLS_MAX_RECORD_SIZE];
	size_t initial_crypto_len = 0;
	uint8_t handshake_crypto[TLS_MAX_RECORD_SIZE];
	size_t handshake_crypto_len = 0;
	uint8_t server_initial_crypto[TLS_MAX_RECORD_SIZE];
	uint8_t server_handshake_crypto[TLS_MAX_RECORD_SIZE];
	uint8_t frames[TLS_MAX_RECORD_SIZE];
	uint8_t packet[1500];
	uint8_t server_dcid[20];
	size_t server_dcid_len = 0;
	uint8_t server_scid[20] = {
		0x51, 0x72, 0x9a, 0x41, 0x3e, 0x55, 0x12, 0x3f,
		0x7b, 0x20, 0x65, 0x94, 0xac, 0x37, 0xd1, 0xe8,
	};
	size_t server_scid_len = 16;
	size_t server_initial_crypto_len = 0;
	size_t server_handshake_crypto_len = 0;
	size_t frames_len = 0;
	size_t packet_len = 0;
	uint8_t *p;
	QUIC_INITIAL_SECRETS initial_secrets;
	QUIC_INITIAL_KEYS initial_client_keys0;
	QUIC_INITIAL_KEYS initial_server_keys0;
	QUIC_PACKET_KEYS initial_client_keys;
	QUIC_PACKET_KEYS initial_server_keys;
	QUIC_PACKET_KEYS client_handshake_keys;
	QUIC_PACKET_KEYS server_handshake_keys;
	QUIC_PACKET_KEYS client_application_keys;
	QUIC_PACKET_KEYS server_application_keys;
	QUIC_DECRYPTED_PACKET decrypted;
	QUIC_TRANSPORT_PARAMS params;
	uint64_t largest_ack = 0;
	uint64_t request_stream_id = 0;
	tls_ret_t n;

	argc--;
	argv++;
	if (argc < 1) {
		fprintf(stderr, "usage: %s %s\n", prog, options);
		return 1;
	}
	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: %s %s\n", prog, options);
			printf("%s\n", help);
			return 0;
		} else if (!strcmp(*argv, "-port")) {
			if (--argc < 1) goto bad;
			port = atoi(*(++argv));
		} else if (!strcmp(*argv, "-cert")) {
			if (--argc < 1) goto bad;
			certfile = *(++argv);
		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			keyfile = *(++argv);
		} else if (!strcmp(*argv, "-pass")) {
			if (--argc < 1) goto bad;
			pass = *(++argv);
		} else if (!strcmp(*argv, "-cipher_suite")) {
			int cipher_suite;
			if (--argc < 1) goto bad;
			if ((cipher_suite = tls_cipher_suite_from_name(*(++argv))) == 0) {
				fprintf(stderr, "%s: invalid cipher suite '%s'\n", prog, *argv);
				return 1;
			}
			if (cipher_suites_cnt == 2 && cipher_suites[0] == TLS_cipher_aes_128_gcm_sha256 && cipher_suites[1] == TLS_cipher_aes_128_ccm_sha256) {
				cipher_suites_cnt = 0;
			}
			if (cipher_suites_cnt >= sizeof(cipher_suites)/sizeof(cipher_suites[0])) {
				fprintf(stderr, "%s: too many -cipher_suite options\n", prog);
				return 1;
			}
			cipher_suites[cipher_suites_cnt++] = cipher_suite;
		} else if (!strcmp(*argv, "-supported_group")) {
			if (--argc < 1) goto bad;
			if ((supported_group = tls_named_curve_from_name(*(++argv))) == 0) {
				fprintf(stderr, "%s: invalid supported group '%s'\n", prog, *argv);
				return 1;
			}
		} else if (!strcmp(*argv, "-sig_alg")) {
			if (--argc < 1) goto bad;
			if ((sig_alg = tls_signature_scheme_from_name(*(++argv))) == 0) {
				fprintf(stderr, "%s: invalid signature algorithm '%s'\n", prog, *argv);
				return 1;
			}
		} else if (!strcmp(*argv, "-verbose")) {
			verbose = 1;
		} else {
			fprintf(stderr, "%s: invalid option '%s'\n", prog, *argv);
			return 1;
bad:
			fprintf(stderr, "%s: option '%s' argument required\n", prog, *argv);
			return 1;
		}
		argc--;
		argv++;
	}
	if (!certfile || !keyfile) {
		fprintf(stderr, "%s: -cert and -key required\n", prog);
		return 1;
	}

	memset(&ctx, 0, sizeof(ctx));
	memset(&conn, 0, sizeof(conn));
	if (tls_socket_lib_init() != 1
		|| tls_ctx_init(&ctx, TLS_protocol_tls13, TLS_server_mode) != 1
		|| tls_ctx_set_cipher_suites(&ctx, cipher_suites, cipher_suites_cnt) != 1
		|| tls_ctx_set_supported_groups(&ctx, &supported_group, 1) != 1
		|| tls_ctx_set_signature_algorithms(&ctx, &sig_alg, 1) != 1
		|| tls_ctx_set_application_layer_protocol_negotiation(&ctx, &alpn, 1) != 1
		|| tls_ctx_add_certificate_chain_and_key(&ctx, certfile, keyfile, pass ? pass : "") != 1
		|| tls_init(&conn, &ctx) != 1) {
		error_print();
		goto end;
	}
	conn.verbose = verbose ? TLS_verbose : 0;

	if (tls_socket_create(&sock, AF_INET, SOCK_DGRAM, 0) != 1) {
		error_print();
		goto end;
	}
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;
	server_addr.sin_port = htons(port);
	if (tls_socket_bind(sock, &server_addr) != 1) {
		fprintf(stderr, "%s: socket bind error\n", prog);
		goto end;
	}

	client_addr_len = sizeof(client_addr);
	n = recvfrom(sock, (char *)buf, sizeof(buf), 0, (struct sockaddr *)&client_addr, &client_addr_len);
	if (n <= 0) {
		fprintf(stderr, "%s: recvfrom error\n", prog);
		goto end;
	}
	if (verbose) {
		fprintf(stderr, "recv UDP datagram: %ld bytes\n", (long)n);
		quic_packet_print(stderr, 0, 0, buf, (size_t)n);
	}

	{
		const uint8_t *odcid;
		const uint8_t *client_scid;
		size_t odcid_len;
		size_t client_scid_len;
		if (quic_long_packet_connection_ids_get(buf, (size_t)n, &odcid, &odcid_len, &client_scid, &client_scid_len) != 1
			|| odcid_len > sizeof(server_dcid) || client_scid_len > sizeof(server_dcid)) {
			error_print();
			goto end;
		}
		memcpy(server_dcid, client_scid, client_scid_len);
		server_dcid_len = client_scid_len;
		if (quic_derive_initial_secrets(odcid, odcid_len, &initial_secrets) != 1
			|| quic_derive_initial_client_keys(&initial_secrets, &initial_client_keys0) != 1
			|| quic_derive_initial_server_keys(&initial_secrets, &initial_server_keys0) != 1
			|| quic_packet_keys_from_initial(&initial_client_keys0, &initial_client_keys) != 1
			|| quic_packet_keys_from_initial(&initial_server_keys0, &initial_server_keys) != 1
			|| quic_long_packet_decrypt(&initial_client_keys, buf, (size_t)n, QUIC_packet_initial, &decrypted) != 1) {
			error_print();
			goto end;
		}
	}
	if (verbose) {
		format_print(stderr, 0, 0, "Decrypted Client Initial Packet\n");
		format_print(stderr, 0, 4, "Packet Number: %llu\n", (unsigned long long)decrypted.packet_number);
		quic_frames_print(stderr, 0, 4, QUIC_encryption_initial, decrypted.plaintext, decrypted.plaintext_len);
	}
	if (quic_frames_crypto_collect(decrypted.plaintext, decrypted.plaintext_len,
		initial_crypto, &initial_crypto_len, sizeof(initial_crypto), &largest_ack) != 1) {
		error_print();
		goto end;
	}
	while (!quic_tls_handshake_is_complete(initial_crypto, initial_crypto_len)) {
		n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&client_addr, &client_addr_len);
		if (n <= 0) {
			error_print();
			goto end;
		}
		if (verbose) {
			fprintf(stderr, "recv UDP datagram: %ld bytes\n", (long)n);
			quic_packet_print(stderr, 0, 0, buf, (size_t)n);
		}
		if (quic_long_packet_decrypt(&initial_client_keys, buf, (size_t)n, QUIC_packet_initial, &decrypted) != 1) {
			error_print();
			goto end;
		}
		if (verbose) {
			format_print(stderr, 0, 0, "Decrypted Client Initial Packet\n");
			format_print(stderr, 0, 4, "Packet Number: %llu\n", (unsigned long long)decrypted.packet_number);
			quic_frames_print(stderr, 0, 4, QUIC_encryption_initial, decrypted.plaintext, decrypted.plaintext_len);
		}
		if (quic_frames_crypto_collect(decrypted.plaintext, decrypted.plaintext_len,
			initial_crypto, &initial_crypto_len, sizeof(initial_crypto), &largest_ack) != 1) {
			error_print();
			goto end;
		}
	}
	if (quic_server_client_hello_process(&conn, initial_crypto, initial_crypto_len) != 1) {
		error_print();
		goto end;
	}

	quic_transport_params_init(&params);
	if (quic_transport_params_add(&params, QUIC_transport_param_original_destination_connection_id, decrypted.dcid, decrypted.dcid_len) != 1
		|| quic_transport_params_add(&params, QUIC_transport_param_initial_source_connection_id, server_scid, server_scid_len) != 1
		|| quic_transport_params_add_varint(&params, QUIC_transport_param_max_udp_payload_size, 1200) != 1
		|| quic_transport_params_add_varint(&params, QUIC_transport_param_initial_max_data, 1048576) != 1
		|| quic_transport_params_add_varint(&params, QUIC_transport_param_initial_max_stream_data_bidi_remote, 262144) != 1
		|| quic_transport_params_add_varint(&params, QUIC_transport_param_initial_max_stream_data_uni, 262144) != 1
		|| quic_transport_params_add_varint(&params, QUIC_transport_param_initial_max_streams_bidi, 100) != 1
		|| quic_transport_params_add_varint(&params, QUIC_transport_param_initial_max_streams_uni, 3) != 1
		|| quic_transport_params_add_varint(&params, QUIC_transport_param_active_connection_id_limit, 2) != 1) {
		error_print();
		goto end;
	}

	p = server_initial_crypto;
	if (quic_server_hello_to_bytes(&conn, &p, &server_initial_crypto_len) != 1
		|| quic_packet_keys_derive(conn.digest, conn.client_handshake_traffic_secret, conn.cipher_suite, &client_handshake_keys) != 1
		|| quic_packet_keys_derive(conn.digest, conn.server_handshake_traffic_secret, conn.cipher_suite, &server_handshake_keys) != 1) {
		error_print();
		goto end;
	}
	p = server_handshake_crypto;
	if (quic_server_encrypted_extensions_to_bytes(&conn, &params, &p, &server_handshake_crypto_len) != 1
		|| quic_server_certificate_to_bytes(&conn, &p, &server_handshake_crypto_len) != 1
		|| quic_server_certificate_verify_to_bytes(&conn, &p, &server_handshake_crypto_len) != 1
		|| quic_server_finished_to_bytes(&conn, &p, &server_handshake_crypto_len) != 1
		|| quic_packet_keys_derive(conn.digest, conn.server_application_traffic_secret, conn.cipher_suite, &server_application_keys) != 1) {
		error_print();
		goto end;
	}

	p = frames;
	frames_len = 0;
	if (quic_ack_frame_to_bytes(decrypted.packet_number, &p, &frames_len) != 1
		|| quic_crypto_frame_to_bytes(0, server_initial_crypto, server_initial_crypto_len, &p, &frames_len) != 1
		|| quic_long_packet_encrypt(&initial_server_keys, QUIC_packet_initial, server_dcid, server_dcid_len,
			server_scid, server_scid_len, 0, frames, frames_len, packet, &packet_len) != 1) {
		error_print();
		goto end;
	}
	memcpy(sendbuf, packet, packet_len);
	{
		size_t sendbuf_len = packet_len;
		p = frames;
		frames_len = 0;
		if (quic_crypto_frame_to_bytes(0, server_handshake_crypto, server_handshake_crypto_len, &p, &frames_len) != 1
			|| quic_long_packet_encrypt(&server_handshake_keys, QUIC_packet_handshake, server_dcid, server_dcid_len,
				server_scid, server_scid_len, 0, frames, frames_len, packet, &packet_len) != 1) {
			error_print();
			goto end;
		}
		memcpy(sendbuf + sendbuf_len, packet, packet_len);
		sendbuf_len += packet_len;
		if (verbose) {
			fprintf(stderr, "send QUIC Initial+Handshake flight: %zu bytes\n", sendbuf_len);
		}
		if (sendto(sock, (const char *)sendbuf, sendbuf_len, 0, (struct sockaddr *)&client_addr, client_addr_len) != (tls_ret_t)sendbuf_len) {
			fprintf(stderr, "%s: sendto handshake flight error\n", prog);
			goto end;
		}
	}

	for (;;) {
		size_t off = 0;
		client_addr_len = sizeof(client_addr);
		n = recvfrom(sock, (char *)buf, sizeof(buf), 0, (struct sockaddr *)&client_addr, &client_addr_len);
		if (n <= 0) {
			fprintf(stderr, "%s: recvfrom error\n", prog);
			goto end;
		}
		if (verbose) {
			fprintf(stderr, "recv UDP datagram: %ld bytes\n", (long)n);
			quic_packet_print(stderr, 0, 0, buf, (size_t)n);
		}
		while (off < (size_t)n) {
			size_t current_len;
			if (quic_packet_total_length(buf + off, (size_t)n - off, &current_len) != 1 || !current_len) {
				break;
			}
			if ((buf[off] & 0x80) && ((buf[off] >> 4) & 0x03) == QUIC_packet_handshake) {
				if (quic_long_packet_decrypt(&client_handshake_keys, buf + off, current_len, QUIC_packet_handshake, &decrypted) == 1) {
					handshake_crypto_len = 0;
					largest_ack = 0;
					if (quic_frames_crypto_collect(decrypted.plaintext, decrypted.plaintext_len,
						handshake_crypto, &handshake_crypto_len, sizeof(handshake_crypto), &largest_ack) != 1
						|| quic_server_client_finished_process(&conn, handshake_crypto, handshake_crypto_len) != 1
						|| quic_packet_keys_derive(conn.digest, conn.client_application_traffic_secret, conn.cipher_suite, &client_application_keys) != 1) {
						error_print();
						goto end;
					}
					if (verbose) {
						fprintf(stderr, "QUIC TLS handshake completed\n");
					}
				}
			} else if (!(buf[off] & 0x80)) {
				if (quic_short_packet_decrypt(&client_application_keys, buf + off, current_len,
					server_scid, server_scid_len, &decrypted) == 1) {
					if (verbose) {
						format_print(stderr, 0, 0, "Decrypted 1-RTT Packet\n");
						format_print(stderr, 0, 4, "Packet Number: %llu\n", (unsigned long long)decrypted.packet_number);
						quic_frames_print(stderr, 0, 4, QUIC_encryption_application, decrypted.plaintext, decrypted.plaintext_len);
					}
					if (quic_application_request_stream_id(decrypted.plaintext, decrypted.plaintext_len, NULL, &request_stream_id) == 1) {
						const uint8_t body[] = "hello from gmssl quic server\n";
						if (quic_http3_response_to_frames(request_stream_id, body, sizeof(body) - 1,
							decrypted.packet_number, frames, &frames_len) != 1
							|| quic_short_packet_encrypt(&server_application_keys, server_dcid, server_dcid_len,
								0, frames, frames_len, packet, &packet_len) != 1) {
							error_print();
							goto end;
						}
						if (verbose) {
							fprintf(stderr, "send QUIC 1-RTT HTTP/3 response: %zu bytes\n", packet_len);
							quic_frames_print(stderr, 0, 4, QUIC_encryption_application, frames, frames_len);
						}
						if (sendto(sock, (const char *)packet, packet_len, 0, (struct sockaddr *)&client_addr, client_addr_len) != (tls_ret_t)packet_len) {
							fprintf(stderr, "%s: sendto response error\n", prog);
							goto end;
						}
						ret = 0;
						goto end;
					}
				}
			}
			off += current_len;
		}
	}

end:
	if (tls_socket_is_valid(sock)) {
		tls_socket_close(sock);
	}
	tls_ctx_cleanup(&ctx);
	tls_socket_lib_cleanup();
	return ret;
}
