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
#include <gmssl/aes.h>
#include <gmssl/digest.h>
#include <gmssl/x509_cer.h>
#include <gmssl/quic.h>
#include <gmssl/tls.h>
#include <gmssl/socket.h>
#include <gmssl/error.h>

int tls13_generate_handshake_secrets(TLS_CONNECT *conn);
int tls13_generate_master_secret(TLS_CONNECT *conn);
int tls13_generate_client_handshake_keys(TLS_CONNECT *conn);
int tls13_generate_server_handshake_keys(TLS_CONNECT *conn);
int tls13_generate_application_secrets(TLS_CONNECT *conn);
int tls13_generate_client_application_keys(TLS_CONNECT *conn);
int tls13_generate_server_application_keys(TLS_CONNECT *conn);
int tls13_record_get_handshake_encrypted_extensions(const uint8_t *record, const uint8_t **exts, size_t *extslen);

static const char *options = "-host str [-port num] [-server_name str] [-cipher_suite str] [-supported_group str] [-sig_alg str] [-get path] [-verbose]";

static const char *help =
"Options\n"
"\n"
"    -host str                 Server's hostname\n"
"    -port num                 Server's UDP port number, default 443\n"
"    -server_name str          Send server_name (SNI) request\n"
"    -cipher_suite str         TLS 1.3 cipher suite, default TLS_AES_128_GCM_SHA256\n"
"    -supported_group str      Supported elliptic curve, default prime256v1\n"
"    -sig_alg str              Supported signature algorithm, default ecdsa_secp256r1_sha256\n"
"    -get path                 HTTP/3 request path kept for future use\n"
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

static int quic_handshake_header_get(int *type, const uint8_t **data, size_t *datalen, const uint8_t *handshake, size_t handshake_len)
{
	if (!type || !data || !datalen || !handshake || handshake_len < TLS_HANDSHAKE_HEADER_SIZE) {
		error_print();
		return -1;
	}
	*type = handshake[0];
	*datalen = ((size_t)handshake[1] << 16) | ((size_t)handshake[2] << 8) | handshake[3];
	if (*datalen + TLS_HANDSHAKE_HEADER_SIZE > handshake_len) {
		error_print();
		return -1;
	}
	*data = handshake + TLS_HANDSHAKE_HEADER_SIZE;
	return 1;
}

static int quic_client_server_hello_process(TLS_CONNECT *conn, const uint8_t *client_hello, size_t client_hello_len, const uint8_t *server_hello, size_t server_hello_len)
{
	uint8_t record[TLS_MAX_RECORD_SIZE];
	size_t record_len;
	int legacy_version;
	const uint8_t *random;
	const uint8_t *legacy_session_id_echo;
	size_t legacy_session_id_echo_len;
	int cipher_suite;
	const uint8_t *exts;
	size_t extslen;
	const uint8_t *supported_versions = NULL;
	size_t supported_versions_len = 0;
	const uint8_t *key_share = NULL;
	size_t key_share_len = 0;
	int selected_version;
	int key_exchange_group;
	const uint8_t *key_exchange;
	size_t key_exchange_len;

	if (!conn || !client_hello || !client_hello_len || !server_hello || !server_hello_len) {
		error_print();
		return -1;
	}
	if (quic_tls_record_from_handshake(server_hello, server_hello_len, record, &record_len) != 1
		|| tls_record_get_handshake_server_hello(record, &legacy_version, &random,
			&legacy_session_id_echo, &legacy_session_id_echo_len, &cipher_suite, &exts, &extslen) != 1) {
		error_print();
		return -1;
	}
	if (legacy_version != TLS_protocol_tls12
		|| legacy_session_id_echo_len != conn->session_id_len
		|| memcmp(legacy_session_id_echo, conn->session_id, conn->session_id_len) != 0
		|| tls_type_is_in_list(cipher_suite, conn->ctx->cipher_suites, conn->ctx->cipher_suites_cnt) != 1) {
		error_print();
		return -1;
	}
	memcpy(conn->server_random, random, 32);
	conn->cipher_suite = cipher_suite;
	if (tls_cipher_suite_get(cipher_suite, &conn->cipher, &conn->digest) != 1) {
		error_print();
		return -1;
	}
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
		case TLS_extension_key_share:
			key_share = ext_data;
			key_share_len = ext_datalen;
			break;
		default:
			error_print();
			return -1;
		}
	}
	if (!supported_versions || !key_share
		|| tls13_server_supported_versions_from_bytes(&selected_version, supported_versions, supported_versions_len) != 1
		|| selected_version != TLS_protocol_tls13
		|| tls13_key_share_server_hello_from_bytes(&key_exchange_group, &key_exchange, &key_exchange_len, key_share, key_share_len) != 1
		|| key_exchange_len != 65) {
		error_print();
		return -1;
	}
	conn->protocol = selected_version;
	conn->key_exchange_group = key_exchange_group;
	memcpy(conn->peer_key_exchange, key_exchange, key_exchange_len);
	conn->peer_key_exchange_len = key_exchange_len;
	conn->key_exchange_modes &= TLS_KE_CERT_DHE;
	if (!conn->key_exchange_modes
		|| digest_init(&conn->dgst_ctx, conn->digest) != 1
		|| digest_update(&conn->dgst_ctx, client_hello, client_hello_len) != 1
		|| digest_update(&conn->dgst_ctx, server_hello, server_hello_len) != 1
		|| tls13_generate_handshake_secrets(conn) != 1) {
		error_print();
		return -1;
	}
	tls13_generate_master_secret(conn);
	if (tls13_generate_server_handshake_keys(conn) != 1
		|| tls13_generate_client_handshake_keys(conn) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

static int quic_client_handshake_flight_process(TLS_CONNECT *conn, const uint8_t *handshake, size_t handshake_len, int verbose)
{
	const uint8_t *p = handshake;
	size_t len = handshake_len;
	uint8_t record[TLS_MAX_RECORD_SIZE];
	size_t record_len;
	int got_finished = 0;

	if (!conn || !handshake) {
		error_print();
		return -1;
	}
	while (len) {
		int type;
		const uint8_t *data;
		size_t datalen;
		const uint8_t *msg = p;
		size_t msglen;

		if (quic_handshake_header_get(&type, &data, &datalen, p, len) != 1) {
			error_print();
			return -1;
		}
		msglen = TLS_HANDSHAKE_HEADER_SIZE + datalen;
		if (verbose) {
			quic_crypto_data_print(stderr, 0, 4, QUIC_encryption_handshake, msg, msglen);
		}
		if (quic_tls_record_from_handshake(msg, msglen, record, &record_len) != 1) {
			error_print();
			return -1;
		}
		switch (type) {
		case TLS_handshake_encrypted_extensions:
			if (tls13_record_get_handshake_encrypted_extensions(record, &data, &datalen) != 1) {
				error_print();
				return -1;
			}
			if (digest_update(&conn->dgst_ctx, msg, msglen) != 1) {
				error_print();
				return -1;
			}
			break;
		case TLS_handshake_certificate: {
			const uint8_t *request_context;
			size_t request_context_len;
			const uint8_t *ocsp;
			size_t ocsp_len;
			const uint8_t *sct;
			size_t sct_len;
			if (tls13_record_get_handshake_certificate(record, &request_context, &request_context_len,
				conn->peer_cert_chain, &conn->peer_cert_chain_len, sizeof(conn->peer_cert_chain), &ocsp, &ocsp_len, &sct, &sct_len) != 1) {
				error_print();
				return -1;
			}
			if (digest_update(&conn->dgst_ctx, msg, msglen) != 1) {
				error_print();
				return -1;
			}
			break;
		}
		case TLS_handshake_certificate_verify: {
			int sig_alg;
			const uint8_t *sig;
			size_t siglen;
			const uint8_t *cert;
			size_t certlen;
			X509_KEY public_key;
			if (tls13_record_get_handshake_certificate_verify(record, &sig_alg, &sig, &siglen) != 1
				|| x509_certs_get_cert_by_index(conn->peer_cert_chain, conn->peer_cert_chain_len, 0, &cert, &certlen) != 1
				|| x509_cert_get_subject_public_key(cert, certlen, &public_key) != 1
				|| tls13_verify_certificate_verify(TLS_server_mode, sig_alg, &public_key, &conn->dgst_ctx, sig, siglen) != 1
				|| digest_update(&conn->dgst_ctx, msg, msglen) != 1) {
				error_print();
				return -1;
			}
			break;
		}
		case TLS_handshake_finished: {
			const uint8_t *server_verify_data;
			size_t server_verify_data_len;
			uint8_t verify_data[64];
			size_t verify_data_len;
			if (tls13_compute_verify_data(conn->server_handshake_traffic_secret, &conn->dgst_ctx, verify_data, &verify_data_len) != 1
				|| tls13_record_get_handshake_finished(record, &server_verify_data, &server_verify_data_len) != 1
				|| server_verify_data_len != verify_data_len
				|| memcmp(server_verify_data, verify_data, verify_data_len) != 0
				|| digest_update(&conn->dgst_ctx, msg, msglen) != 1
				|| tls13_generate_application_secrets(conn) != 1
				|| tls13_generate_server_application_keys(conn) != 1) {
				error_print();
				return -1;
			}
			got_finished = 1;
			break;
		}
		default:
			error_print();
			return -1;
		}
		p += msglen;
		len -= msglen;
	}
	return got_finished ? 1 : 0;
}

static int quic_client_finished_to_bytes(TLS_CONNECT *conn, uint8_t *out, size_t *outlen)
{
	uint8_t record[TLS_MAX_RECORD_SIZE];
	size_t record_len = 0;
	uint8_t verify_data[64];
	size_t verify_data_len;
	const uint8_t *handshake;
	size_t handshake_len;

	if (!conn || !out || !outlen) {
		error_print();
		return -1;
	}
	memset(record, 0, sizeof(record));
	record[1] = 0x03;
	record[2] = 0x03;
	if (tls13_compute_verify_data(conn->client_handshake_traffic_secret, &conn->dgst_ctx, verify_data, &verify_data_len) != 1
		|| tls13_record_set_handshake_finished(record, &record_len, verify_data, verify_data_len) != 1) {
		error_print();
		return -1;
	}
	handshake = record + TLS_RECORD_HEADER_SIZE;
	handshake_len = record_len - TLS_RECORD_HEADER_SIZE;
	memcpy(out, handshake, handshake_len);
	*outlen = handshake_len;
	if (digest_update(&conn->dgst_ctx, handshake, handshake_len) != 1
		|| tls13_generate_client_application_keys(conn) != 1) {
		error_print();
		return -1;
	}
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
	if (!data && datalen) {
		error_print();
		return -1;
	}
	if (quic_varint_to_bytes(QUIC_frame_crypto, out, outlen) != 1
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

static int quic_client_initial_packet_to_bytes(const uint8_t *dcid, size_t dcid_len,
	const uint8_t *scid, size_t scid_len, const uint8_t *frames, size_t frames_len,
	uint8_t *packet, size_t *packet_len)
{
	uint8_t *p = packet;
	uint8_t *pn;
	uint8_t *payload;
	size_t len = 0;
	size_t plain_payload_len;
	size_t padding_len;
	size_t payload_len;
	QUIC_INITIAL_SECRETS secrets;
	QUIC_INITIAL_KEYS keys;
	AES_KEY aes_key;
	AES_KEY hp_key;
	uint8_t nonce[QUIC_INITIAL_IV_SIZE];
	uint8_t mask[16];
	uint64_t packet_number = 1;
	size_t i;

	if (!dcid || dcid_len > 20 || !scid || scid_len > 20 || !frames || !packet || !packet_len) {
		error_print();
		return -1;
	}

	plain_payload_len = frames_len;
	padding_len = plain_payload_len < 1162 ? 1162 - plain_payload_len : 0;
	payload_len = plain_payload_len + padding_len + 16;

	*p++ = 0xc3; len++;
	*p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x01; len += 4;
	*p++ = (uint8_t)dcid_len; len++;
	memcpy(p, dcid, dcid_len); p += dcid_len; len += dcid_len;
	*p++ = (uint8_t)scid_len; len++;
	memcpy(p, scid, scid_len); p += scid_len; len += scid_len;
	if (quic_varint_to_bytes(0, &p, &len) != 1
		|| quic_varint_to_bytes(4 + payload_len, &p, &len) != 1) {
		error_print();
		return -1;
	}
	pn = p;
	*p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x01; len += 4;
	payload = p;
	memcpy(payload, frames, frames_len);
	memset(payload + frames_len, 0, padding_len);

	if (quic_derive_initial_secrets(dcid, dcid_len, &secrets) != 1
		|| quic_derive_initial_client_keys(&secrets, &keys) != 1
		|| aes_set_encrypt_key(&aes_key, keys.key, sizeof(keys.key)) != 1
		|| aes_set_encrypt_key(&hp_key, keys.hp, sizeof(keys.hp)) != 1) {
		error_print();
		return -1;
	}
	memcpy(nonce, keys.iv, sizeof(nonce));
	for (i = 0; i < 8; i++) {
		nonce[sizeof(nonce) - 1 - i] ^= (uint8_t)(packet_number >> (8 * i));
	}
	if (aes_gcm_encrypt(&aes_key, nonce, sizeof(nonce), packet, len,
		payload, plain_payload_len + padding_len, payload, 16,
		payload + plain_payload_len + padding_len) != 1) {
		error_print();
		return -1;
	}
	aes_encrypt(&hp_key, payload, mask);
	packet[0] ^= mask[0] & 0x0f;
	for (i = 0; i < 4; i++) {
		pn[i] ^= mask[i + 1];
	}
	p += payload_len;
	len += payload_len;

	*packet_len = len;
	return 1;
}

static int quic_stream_frame_to_bytes(uint64_t stream_id, int fin, const uint8_t *data, size_t datalen, uint8_t **out, size_t *outlen)
{
	uint64_t type = QUIC_frame_stream_base | 0x02 | (fin ? 0x01 : 0);

	if ((!data && datalen) || quic_varint_to_bytes(type, out, outlen) != 1
		|| quic_varint_to_bytes(stream_id, out, outlen) != 1
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

static int quic_http3_varint_to_bytes(uint64_t val, uint8_t **out, size_t *outlen)
{
	return quic_varint_to_bytes(val, out, outlen);
}

static int quic_qpack_string_to_bytes(const char *s, uint8_t **out, size_t *outlen)
{
	size_t len;

	if (!s || !outlen) {
		error_print();
		return -1;
	}
	len = strlen(s);
	if (len > 127) {
		error_print();
		return -1;
	}
	if (out && *out) {
		*(*out)++ = (uint8_t)len;
		memcpy(*out, s, len);
		*out += len;
	}
	*outlen += 1 + len;
	return 1;
}

static int quic_http3_request_headers_to_bytes(const char *authority, const char *path, uint8_t *out, size_t *outlen)
{
	uint8_t block[512];
	uint8_t *p = block;
	size_t len = 0;
	uint8_t *q = out;

	if (!authority || !path || !out || !outlen) {
		error_print();
		return -1;
	}
	block[len++] = 0x00;
	block[len++] = 0x00;
	block[len++] = 0xd1; /* QPACK static table: :method: GET */
	block[len++] = 0xd7; /* QPACK static table: :scheme: https */
	if (!strcmp(path, "/")) {
		block[len++] = 0xc1; /* QPACK static table: :path: / */
	} else {
		block[len++] = 0x51; /* literal with static name reference :path */
		p = block + len;
		if (quic_qpack_string_to_bytes(path, &p, &len) != 1) {
			error_print();
			return -1;
		}
	}
	block[len++] = 0x50; /* literal with static name reference :authority */
	p = block + len;
	if (quic_qpack_string_to_bytes(authority, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (quic_http3_varint_to_bytes(0x01, &q, outlen) != 1
		|| quic_http3_varint_to_bytes(len, &q, outlen) != 1) {
		error_print();
		return -1;
	}
	memcpy(q, block, len);
	*outlen += len;
	return 1;
}

static int quic_http3_client_data_to_frames(const char *authority, const char *path, uint8_t *frames, size_t *frames_len)
{
	uint8_t control_stream[] = { 0x00, 0x04, 0x00 };
	uint8_t qpack_encoder_stream[] = { 0x02 };
	uint8_t qpack_decoder_stream[] = { 0x03 };
	uint8_t headers[512];
	uint8_t *p = frames;
	size_t headers_len = 0;

	if (!authority || !path || !frames || !frames_len) {
		error_print();
		return -1;
	}
	*frames_len = 0;
	if (quic_http3_request_headers_to_bytes(authority, path, headers, &headers_len) != 1
		|| quic_stream_frame_to_bytes(2, 0, control_stream, sizeof(control_stream), &p, frames_len) != 1
		|| quic_stream_frame_to_bytes(6, 0, qpack_encoder_stream, sizeof(qpack_encoder_stream), &p, frames_len) != 1
		|| quic_stream_frame_to_bytes(10, 0, qpack_decoder_stream, sizeof(qpack_decoder_stream), &p, frames_len) != 1
		|| quic_stream_frame_to_bytes(0, 1, headers, headers_len, &p, frames_len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

static int quic_http3_stream_data_print(const uint8_t *data, size_t datalen, int *got_data, int verbose)
{
	const uint8_t *p = data;
	size_t len = datalen;

	if (!data || !got_data) {
		error_print();
		return -1;
	}
	while (len) {
		uint64_t frame_type, frame_len;
		const uint8_t *frame_data;
		if (quic_varint_from_bytes(&frame_type, &p, &len) != 1
			|| quic_varint_from_bytes(&frame_len, &p, &len) != 1
			|| frame_len > len) {
			return 0;
		}
		frame_data = p;
		p += frame_len;
		len -= frame_len;
		if (verbose) {
			fprintf(stderr, "HTTP/3 frame type=%llu len=%llu\n",
				(unsigned long long)frame_type, (unsigned long long)frame_len);
		}
		if (frame_type == 0x00 && frame_len) {
			fwrite(frame_data, 1, (size_t)frame_len, stdout);
			*got_data = 1;
		}
	}
	return 1;
}

static int quic_frames_crypto_collect(const uint8_t *frames, size_t frames_len, uint8_t *crypto, size_t *crypto_len, size_t crypto_max, uint64_t *largest_ack)
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
		switch (type) {
		case QUIC_frame_padding:
			while (len && *p == 0) {
				p++;
				len--;
			}
			break;
		case QUIC_frame_ack:
		case QUIC_frame_ack_ecn: {
			uint64_t ack_delay;
			uint64_t ack_range_count;
			uint64_t first_ack_range;
			uint64_t i;
			if (quic_varint_from_bytes(largest_ack, &p, &len) != 1
				|| quic_varint_from_bytes(&ack_delay, &p, &len) != 1
				|| quic_varint_from_bytes(&ack_range_count, &p, &len) != 1
				|| quic_varint_from_bytes(&first_ack_range, &p, &len) != 1) {
				error_print();
				return -1;
			}
			for (i = 0; i < ack_range_count; i++) {
				uint64_t gap;
				uint64_t ack_range;
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
			break;
		}
		case QUIC_frame_crypto: {
			uint64_t off;
			uint64_t data_len;
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
			break;
		}
		default:
			error_print();
			return -1;
		}
	}
	return 1;
}

static int quic_application_frames_process(const uint8_t *frames, size_t frames_len, uint64_t *largest_ack, int *got_stream_data, int verbose)
{
	const uint8_t *p = frames;
	size_t len = frames_len;

	if (!frames || !largest_ack || !got_stream_data) {
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
				if (quic_varint_from_bytes(&ect0, &p, &len) != 1 || quic_varint_from_bytes(&ect1, &p, &len) != 1 || quic_varint_from_bytes(&ce, &p, &len) != 1) {
					error_print();
					return -1;
				}
			}
		} else if (type == QUIC_frame_handshake_done) {
			if (verbose) {
				fprintf(stderr, "recv HANDSHAKE_DONE\n");
			}
		} else if (type == QUIC_frame_new_token) {
			uint64_t token_len;
			if (quic_varint_from_bytes(&token_len, &p, &len) != 1 || token_len > len) {
				error_print();
				return -1;
			}
			p += token_len;
			len -= token_len;
		} else if (type == QUIC_frame_crypto) {
			uint64_t offset, data_len;
			const uint8_t *data;
			if (quic_varint_from_bytes(&offset, &p, &len) != 1
				|| quic_varint_from_bytes(&data_len, &p, &len) != 1
				|| data_len > len) {
				error_print();
				return -1;
			}
			data = p;
			p += data_len;
			len -= data_len;
			if (verbose) {
				fprintf(stderr, "recv application CRYPTO offset=%llu len=%llu\n",
					(unsigned long long)offset, (unsigned long long)data_len);
				quic_crypto_data_print(stderr, 0, 4, QUIC_encryption_application, data, (size_t)data_len);
			}
		} else if (type == QUIC_frame_new_connection_id) {
			uint64_t seq, retire_prior_to, cid_len;
			if (quic_varint_from_bytes(&seq, &p, &len) != 1
				|| quic_varint_from_bytes(&retire_prior_to, &p, &len) != 1
				|| quic_varint_from_bytes(&cid_len, &p, &len) != 1
				|| cid_len > 20 || cid_len + 16 > len) {
				error_print();
				return -1;
			}
			p += cid_len + 16;
			len -= cid_len + 16;
		} else if ((type & 0xf8) == QUIC_frame_stream_base) {
			uint64_t stream_id, offset = 0, data_len;
			const uint8_t *data;
			if (quic_varint_from_bytes(&stream_id, &p, &len) != 1) {
				error_print();
				return -1;
			}
			if (type & 0x04) {
				if (quic_varint_from_bytes(&offset, &p, &len) != 1) {
					error_print();
					return -1;
				}
			}
			if (type & 0x02) {
				if (quic_varint_from_bytes(&data_len, &p, &len) != 1 || data_len > len) {
					error_print();
					return -1;
				}
			} else {
				data_len = len;
			}
			data = p;
			p += data_len;
			len -= data_len;
			if (verbose) {
				fprintf(stderr, "recv STREAM id=%llu offset=%llu len=%llu fin=%d\n",
					(unsigned long long)stream_id, (unsigned long long)offset, (unsigned long long)data_len, (int)(type & 0x01));
				format_bytes(stderr, 0, 4, "stream_data", data, (size_t)data_len);
			}
			if (data_len && stream_id == 0) {
				if (quic_http3_stream_data_print(data, (size_t)data_len, got_stream_data, verbose) != 1) {
					fwrite(data, 1, (size_t)data_len, stdout);
					*got_stream_data = 1;
				}
			}
		} else if (type == QUIC_frame_connection_close || type == QUIC_frame_connection_close_app) {
			uint64_t error_code, frame_type = 0, reason_len;
			if (quic_varint_from_bytes(&error_code, &p, &len) != 1) return -1;
			if (type == QUIC_frame_connection_close && quic_varint_from_bytes(&frame_type, &p, &len) != 1) return -1;
			if (quic_varint_from_bytes(&reason_len, &p, &len) != 1 || reason_len > len) return -1;
			if (verbose) {
				fprintf(stderr, "recv CONNECTION_CLOSE error=%llu frame=%llu\n",
					(unsigned long long)error_code, (unsigned long long)frame_type);
			}
			p += reason_len;
			len -= reason_len;
		} else {
			error_print();
			return -1;
		}
	}
	return 1;
}

static int quic_client_initial_packet_decrypt_and_print(FILE *fp, const uint8_t *original_dcid, size_t original_dcid_len,
	const uint8_t *packet, size_t packet_len)
{
	uint8_t buf[1500];
	uint8_t plaintext[1500];
	const uint8_t *p;
	size_t len;
	uint64_t long_packet_len;
	uint8_t type;
	uint8_t dcid_len;
	uint8_t scid_len;
	size_t pn_offset;
	size_t pn_len;
	uint64_t packet_number = 0;
	QUIC_INITIAL_SECRETS secrets;
	QUIC_INITIAL_KEYS keys;
	AES_KEY aes_key;
	AES_KEY hp_key;
	uint8_t nonce[QUIC_INITIAL_IV_SIZE];
	uint8_t mask[16];
	size_t aad_len;
	size_t ciphertext_len;
	size_t i;

	if (!fp || !original_dcid || !packet || packet_len > sizeof(buf) || packet_len < 7) {
		error_print();
		return -1;
	}
	memcpy(buf, packet, packet_len);

	if (!(buf[0] & 0x80)) {
		return 0;
	}
	type = (buf[0] >> 4) & 0x03;
	if (type != QUIC_packet_initial) {
		return 0;
	}

	p = buf + 5;
	len = packet_len - 5;
	if (!len) return -1;
	dcid_len = *p++;
	len--;
	if (dcid_len > len) return -1;
	p += dcid_len;
	len -= dcid_len;
	if (!len) return -1;
	scid_len = *p++;
	len--;
	if (scid_len > len) return -1;
	p += scid_len;
	len -= scid_len;
	if (quic_varint_from_bytes(&long_packet_len, &p, &len) != 1) return -1; /* token length */
	if (long_packet_len > len) return -1;
	p += long_packet_len;
	len -= long_packet_len;
	if (quic_varint_from_bytes(&long_packet_len, &p, &len) != 1) return -1; /* packet length */
	if (long_packet_len > len) return -1;
	pn_offset = (size_t)(p - buf);
	if (pn_offset + 4 + 16 > packet_len) return -1;

	if (quic_derive_initial_secrets(original_dcid, original_dcid_len, &secrets) != 1
		|| quic_derive_initial_server_keys(&secrets, &keys) != 1
		|| aes_set_encrypt_key(&aes_key, keys.key, sizeof(keys.key)) != 1
		|| aes_set_encrypt_key(&hp_key, keys.hp, sizeof(keys.hp)) != 1) {
		error_print();
		return -1;
	}
	aes_encrypt(&hp_key, buf + pn_offset + 4, mask);
	buf[0] ^= mask[0] & 0x0f;
	pn_len = (buf[0] & 0x03) + 1;
	if (pn_len > long_packet_len) return -1;
	for (i = 0; i < pn_len; i++) {
		buf[pn_offset + i] ^= mask[i + 1];
		packet_number = (packet_number << 8) | buf[pn_offset + i];
	}

	memcpy(nonce, keys.iv, sizeof(nonce));
	for (i = 0; i < 8; i++) {
		nonce[sizeof(nonce) - 1 - i] ^= (uint8_t)(packet_number >> (8 * i));
	}
	aad_len = pn_offset + pn_len;
	ciphertext_len = (size_t)long_packet_len - pn_len;
	if (ciphertext_len < 16
		|| aes_gcm_decrypt(&aes_key, nonce, sizeof(nonce), buf, aad_len,
			buf + aad_len, ciphertext_len - 16, buf + aad_len + ciphertext_len - 16, 16, plaintext) != 1) {
		error_print();
		return -1;
	}

	format_print(fp, 0, 0, "Decrypted Initial Packet\n");
	format_print(fp, 0, 4, "Packet Number: %llu\n", (unsigned long long)packet_number);
	quic_frames_print(fp, 0, 4, QUIC_encryption_initial, plaintext, ciphertext_len - 16);
	return 1;
}

static int quic_client_probe(const char *prog, const char *host, int port,
	const char *server_name, int cipher_suite, int supported_group, int sig_alg, const char *request_path, int verbose)
{
	int ret = -1;
	TLS_CTX ctx;
	TLS_CONNECT conn;
	char *alpn = "h3";
	uint8_t handshake[TLS_MAX_RECORD_SIZE];
	uint8_t frames[TLS_MAX_RECORD_SIZE];
	uint8_t packet[1500];
	uint8_t response[4096];
	uint8_t dcid[8] = { 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
	uint8_t scid[8] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
	QUIC_TRANSPORT_PARAMS params;
	uint8_t *p = handshake;
	uint8_t *q = frames;
	size_t handshake_len = 0;
	size_t frames_len = 0;
	size_t packet_len = 0;
	struct sockaddr_in server;
	tls_socket_t sock = tls_socket_invalid();
	fd_set rfds;
	struct timeval timeout;
	tls_ret_t n;

	memset(&ctx, 0, sizeof(ctx));
	memset(&conn, 0, sizeof(conn));

	if (tls_ctx_init(&ctx, TLS_protocol_tls13, TLS_client_mode) != 1
		|| tls_ctx_set_cipher_suites(&ctx, &cipher_suite, 1) != 1
		|| tls_ctx_set_supported_groups(&ctx, &supported_group, 1) != 1
		|| tls_ctx_set_signature_algorithms(&ctx, &sig_alg, 1) != 1
		|| tls_ctx_set_application_layer_protocol_negotiation(&ctx, &alpn, 1) != 1
		|| tls_init(&conn, &ctx) != 1) {
		error_print();
		goto end;
	}
	if (verbose && tls_ctx_set_verbose(&ctx, TLS_verbose) != 1) {
		error_print();
		goto end;
	}
	if (tls_set_hostname(&conn, server_name ? server_name : host) != 1) {
		error_print();
		goto end;
	}
	if (server_name && tls_set_server_name(&conn) != 1) {
		error_print();
		goto end;
	}
	conn.verbose = verbose ? TLS_verbose : 0;

	quic_transport_params_init(&params);
	if (quic_transport_params_add(&params, QUIC_transport_param_initial_source_connection_id, scid, sizeof(scid)) != 1
		|| quic_transport_params_add_varint(&params, QUIC_transport_param_max_udp_payload_size, 1200) != 1
		|| quic_transport_params_add_varint(&params, QUIC_transport_param_initial_max_data, 1048576) != 1
		|| quic_transport_params_add_varint(&params, QUIC_transport_param_initial_max_stream_data_bidi_local, 65536) != 1
		|| quic_transport_params_add_varint(&params, QUIC_transport_param_initial_max_stream_data_bidi_remote, 65536) != 1
		|| quic_transport_params_add_varint(&params, QUIC_transport_param_initial_max_stream_data_uni, 65536) != 1
		|| quic_transport_params_add_varint(&params, QUIC_transport_param_initial_max_streams_bidi, 16) != 1
		|| quic_transport_params_add_varint(&params, QUIC_transport_param_initial_max_streams_uni, 3) != 1) {
		error_print();
		goto end;
	}
	if (quic_client_hello_to_bytes_ex(&conn, &params, &p, &handshake_len) != 1) {
		error_print();
		goto end;
	}
	if (quic_varint_to_bytes(QUIC_frame_crypto, &q, &frames_len) != 1
		|| quic_varint_to_bytes(0, &q, &frames_len) != 1
		|| quic_varint_to_bytes(handshake_len, &q, &frames_len) != 1) {
		error_print();
		goto end;
	}
	memcpy(q, handshake, handshake_len);
	q += handshake_len;
	frames_len += handshake_len;

	if (verbose) {
		quic_frames_print(stderr, 0, 0, QUIC_encryption_initial, frames, frames_len);
	}
	if (quic_client_initial_packet_to_bytes(dcid, sizeof(dcid), scid, sizeof(scid),
		frames, frames_len, packet, &packet_len) != 1) {
		error_print();
		goto end;
	}
	if (verbose) {
		quic_packet_print(stderr, 0, 0, packet, packet_len);
	}

	if (tls_socket_lib_init() != 1
		|| tls_socket_get_addr(host, port, &server) != 1
		|| tls_socket_create(&sock, AF_INET, SOCK_DGRAM, 0) != 1
		|| tls_socket_connect(sock, &server) != 1) {
		error_print();
		goto end;
	}
	n = tls_socket_send(sock, packet, packet_len, 0);
	if (n != (tls_ret_t)packet_len) {
		fprintf(stderr, "%s: send QUIC Initial probe failed\n", prog);
		goto end;
	}
	if (verbose) {
		fprintf(stderr, "send QUIC Initial probe: %zu bytes\n", packet_len);
	}

	FD_ZERO(&rfds);
	FD_SET(sock, &rfds);
	timeout.tv_sec = 2;
	timeout.tv_usec = 0;
	if (select((int)(sock + 1), &rfds, NULL, NULL, &timeout) > 0) {
		n = tls_socket_recv(sock, response, sizeof(response), 0);
		if (n > 0) {
			QUIC_INITIAL_SECRETS initial_secrets;
			QUIC_INITIAL_KEYS client_initial_keys;
			QUIC_INITIAL_KEYS server_initial_keys;
			QUIC_PACKET_KEYS client_initial_packet_keys;
			QUIC_PACKET_KEYS initial_server_packet_keys;
			QUIC_PACKET_KEYS server_handshake_packet_keys;
			QUIC_PACKET_KEYS client_handshake_packet_keys;
			QUIC_PACKET_KEYS server_application_packet_keys;
			QUIC_PACKET_KEYS client_application_packet_keys;
			QUIC_DECRYPTED_PACKET initial_packet;
			QUIC_DECRYPTED_PACKET handshake_packet;
			QUIC_DECRYPTED_PACKET application_packet;
			uint8_t initial_crypto[TLS_MAX_RECORD_SIZE];
			uint8_t handshake_crypto[TLS_MAX_RECORD_SIZE];
			uint8_t client_finished[TLS_MAX_RECORD_SIZE];
			uint8_t request_frames[TLS_MAX_RECORD_SIZE];
			uint8_t send_frames[TLS_MAX_RECORD_SIZE];
			uint8_t send_packet[1500];
			uint8_t *r = send_frames;
			size_t initial_crypto_len = 0;
			size_t handshake_crypto_len = 0;
			size_t client_finished_len = 0;
			size_t request_frames_len = 0;
			size_t send_frames_len = 0;
			size_t send_packet_len = 0;
			size_t response_len = (size_t)n;
			size_t off = 0;
			uint64_t largest_ack = 0;
			uint64_t server_initial_packet_number = 0;
			uint64_t server_handshake_packet_number = 0;
			uint64_t client_application_packet_number = 0;
			int got_stream_data = 0;
			int loop_count;
			if (verbose) {
				fprintf(stderr, "recv UDP datagram: %ld bytes\n", (long)n);
				quic_packet_print(stderr, 0, 0, response, (size_t)n);
			}
			if (quic_derive_initial_secrets(dcid, sizeof(dcid), &initial_secrets) != 1
				|| quic_derive_initial_client_keys(&initial_secrets, &client_initial_keys) != 1
				|| quic_derive_initial_server_keys(&initial_secrets, &server_initial_keys) != 1
				|| quic_packet_keys_from_initial(&client_initial_keys, &client_initial_packet_keys) != 1
				|| quic_packet_keys_from_initial(&server_initial_keys, &initial_server_packet_keys) != 1
				|| quic_long_packet_decrypt(&initial_server_packet_keys, response, response_len, QUIC_packet_initial, &initial_packet) != 1) {
				error_print();
				goto end;
			}
			if (verbose) {
				format_print(stderr, 0, 0, "Decrypted Initial Packet\n");
				format_print(stderr, 0, 4, "Packet Number: %llu\n", (unsigned long long)initial_packet.packet_number);
				quic_frames_print(stderr, 0, 4, QUIC_encryption_initial, initial_packet.plaintext, initial_packet.plaintext_len);
			}
			server_initial_packet_number = initial_packet.packet_number;
			if (quic_frames_crypto_collect(initial_packet.plaintext, initial_packet.plaintext_len,
				initial_crypto, &initial_crypto_len, sizeof(initial_crypto), &largest_ack) != 1
				|| quic_client_server_hello_process(&conn, handshake, handshake_len, initial_crypto, initial_crypto_len) != 1
				|| quic_packet_keys_derive(conn.digest, conn.server_handshake_traffic_secret, conn.cipher_suite, &server_handshake_packet_keys) != 1
				|| quic_packet_keys_derive(conn.digest, conn.client_handshake_traffic_secret, conn.cipher_suite, &client_handshake_packet_keys) != 1) {
				error_print();
				goto end;
			}
			off = initial_packet.packet_len;
			if (off >= response_len
				|| quic_long_packet_decrypt(&server_handshake_packet_keys, response + off, response_len - off, QUIC_packet_handshake, &handshake_packet) != 1) {
				error_print();
				goto end;
			}
			if (verbose) {
				format_print(stderr, 0, 0, "Decrypted Handshake Packet\n");
				format_print(stderr, 0, 4, "Packet Number: %llu\n", (unsigned long long)handshake_packet.packet_number);
				quic_frames_print(stderr, 0, 4, QUIC_encryption_handshake, handshake_packet.plaintext, handshake_packet.plaintext_len);
			}
			server_handshake_packet_number = handshake_packet.packet_number;
			largest_ack = 0;
			if (quic_frames_crypto_collect(handshake_packet.plaintext, handshake_packet.plaintext_len,
				handshake_crypto, &handshake_crypto_len, sizeof(handshake_crypto), &largest_ack) != 1
				|| quic_client_handshake_flight_process(&conn, handshake_crypto, handshake_crypto_len, verbose) != 1
				|| quic_client_finished_to_bytes(&conn, client_finished, &client_finished_len) != 1) {
				error_print();
				goto end;
			}
			if (quic_ack_frame_to_bytes(server_handshake_packet_number, &r, &send_frames_len) != 1
				|| quic_crypto_frame_to_bytes(0, client_finished, client_finished_len, &r, &send_frames_len) != 1
				|| quic_long_packet_encrypt(&client_handshake_packet_keys, QUIC_packet_handshake,
					initial_packet.scid, initial_packet.scid_len, scid, sizeof(scid), 1,
					send_frames, send_frames_len, send_packet, &send_packet_len) != 1) {
				error_print();
				goto end;
			}
			if (verbose) {
				format_print(stderr, 0, 0, "send QUIC Handshake Packet\n");
				quic_frames_print(stderr, 0, 4, QUIC_encryption_handshake, send_frames, send_frames_len);
				quic_packet_print(stderr, 0, 4, send_packet, send_packet_len);
			}
			n = tls_socket_send(sock, send_packet, send_packet_len, 0);
			if (n != (tls_ret_t)send_packet_len) {
				fprintf(stderr, "%s: send QUIC Handshake Finished failed\n", prog);
				goto end;
			}
			r = send_frames;
			send_frames_len = 0;
			if (quic_ack_frame_to_bytes(server_initial_packet_number, &r, &send_frames_len) != 1
				|| quic_long_packet_encrypt(&client_initial_packet_keys, QUIC_packet_initial,
					initial_packet.scid, initial_packet.scid_len, scid, sizeof(scid), 2,
					send_frames, send_frames_len, send_packet, &send_packet_len) != 1) {
				error_print();
				goto end;
			}
			n = tls_socket_send(sock, send_packet, send_packet_len, 0);
			if (n != (tls_ret_t)send_packet_len) {
				fprintf(stderr, "%s: send QUIC Initial ACK failed\n", prog);
				goto end;
			}
			if (quic_packet_keys_derive(conn.digest, conn.server_application_traffic_secret, conn.cipher_suite, &server_application_packet_keys) != 1
				|| quic_packet_keys_derive(conn.digest, conn.client_application_traffic_secret, conn.cipher_suite, &client_application_packet_keys) != 1
				|| quic_http3_client_data_to_frames(server_name ? server_name : host, request_path ? request_path : "/", request_frames, &request_frames_len) != 1
				|| quic_short_packet_encrypt(&client_application_packet_keys, initial_packet.scid, initial_packet.scid_len,
					client_application_packet_number++, request_frames, request_frames_len, send_packet, &send_packet_len) != 1) {
				error_print();
				goto end;
			}
			if (verbose) {
				format_print(stderr, 0, 0, "send QUIC 1-RTT HTTP/3 Request\n");
				quic_frames_print(stderr, 0, 4, QUIC_encryption_application, request_frames, request_frames_len);
				quic_packet_print(stderr, 0, 4, send_packet, send_packet_len);
			}
			n = tls_socket_send(sock, send_packet, send_packet_len, 0);
			if (n != (tls_ret_t)send_packet_len) {
				fprintf(stderr, "%s: send QUIC 1-RTT request failed\n", prog);
				goto end;
			}
			off += handshake_packet.packet_len;
			if (off < response_len
				&& quic_short_packet_decrypt(&server_application_packet_keys, response + off, response_len - off, scid, sizeof(scid), &application_packet) == 1) {
				if (verbose) {
					format_print(stderr, 0, 0, "Decrypted 1-RTT Packet\n");
					format_print(stderr, 0, 4, "Packet Number: %llu\n", (unsigned long long)application_packet.packet_number);
					quic_frames_print(stderr, 0, 4, QUIC_encryption_application, application_packet.plaintext, application_packet.plaintext_len);
				}
				if (quic_application_frames_process(application_packet.plaintext, application_packet.plaintext_len, &largest_ack, &got_stream_data, verbose) != 1) {
					error_print();
					goto end;
				}
			}
			for (loop_count = 0; loop_count < 8 && !got_stream_data; loop_count++) {
				size_t datagram_off;
				FD_ZERO(&rfds);
				FD_SET(sock, &rfds);
				timeout.tv_sec = 2;
				timeout.tv_usec = 0;
				if (select((int)(sock + 1), &rfds, NULL, NULL, &timeout) <= 0) {
					break;
				}
				n = tls_socket_recv(sock, response, sizeof(response), 0);
				if (n <= 0) {
					break;
				}
				if (verbose) {
					fprintf(stderr, "recv UDP datagram: %ld bytes\n", (long)n);
					quic_packet_print(stderr, 0, 0, response, (size_t)n);
				}
				for (datagram_off = 0; datagram_off < (size_t)n && !got_stream_data; ) {
					size_t current_packet_len;
					if (quic_packet_total_length(response + datagram_off, (size_t)n - datagram_off, &current_packet_len) != 1 || !current_packet_len) {
						break;
					}
					if (response[datagram_off] & 0x80) {
						datagram_off += current_packet_len;
						continue;
					}
					if (quic_short_packet_decrypt(&server_application_packet_keys, response + datagram_off, current_packet_len, scid, sizeof(scid), &application_packet) != 1) {
						break;
					}
					if (verbose) {
						format_print(stderr, 0, 0, "Decrypted 1-RTT Packet\n");
						format_print(stderr, 0, 4, "Packet Number: %llu\n", (unsigned long long)application_packet.packet_number);
						quic_frames_print(stderr, 0, 4, QUIC_encryption_application, application_packet.plaintext, application_packet.plaintext_len);
					}
					largest_ack = 0;
					if (quic_application_frames_process(application_packet.plaintext, application_packet.plaintext_len, &largest_ack, &got_stream_data, verbose) != 1) {
						error_print();
						goto end;
					}
					r = send_frames;
					send_frames_len = 0;
					if (quic_ack_frame_to_bytes(application_packet.packet_number, &r, &send_frames_len) == 1
						&& quic_short_packet_encrypt(&client_application_packet_keys, initial_packet.scid, initial_packet.scid_len,
							client_application_packet_number++, send_frames, send_frames_len, send_packet, &send_packet_len) == 1) {
						tls_socket_send(sock, send_packet, send_packet_len, 0);
					}
					break;
				}
			}
			if (verbose) {
				fprintf(stderr, "QUIC TLS handshake completed\n");
			}
			ret = got_stream_data ? 1 : 0;
		}
	} else {
		fprintf(stderr, "%s: no response from server\n", prog);
		ret = 0;
	}

end:
	if (tls_socket_is_valid(sock)) tls_socket_close(sock);
	tls_socket_lib_cleanup();
	tls_ctx_cleanup(&ctx);
	return ret;
}

int quic_client_main(int argc, char **argv)
{
	char *prog = argv[0];
	char *host = NULL;
	char *server_name = NULL;
	char *get = NULL;
	int cipher_suite = TLS_cipher_aes_128_gcm_sha256;
	int supported_group = TLS_curve_secp256r1;
	int sig_alg = TLS_sig_ecdsa_secp256r1_sha256;
	int port = 443;
	int verbose = 0;
	int ret;

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
		} else if (!strcmp(*argv, "-host")) {
			if (--argc < 1) goto bad;
			host = *(++argv);
		} else if (!strcmp(*argv, "-port")) {
			if (--argc < 1) goto bad;
			port = atoi(*(++argv));
		} else if (!strcmp(*argv, "-server_name")) {
			if (--argc < 1) goto bad;
			server_name = *(++argv);
		} else if (!strcmp(*argv, "-cipher_suite")) {
			if (--argc < 1) goto bad;
			if ((cipher_suite = tls_cipher_suite_from_name(*(++argv))) == 0) {
				fprintf(stderr, "%s: invalid cipher suite '%s'\n", prog, *argv);
				return 1;
			}
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
		} else if (!strcmp(*argv, "-get")) {
			if (--argc < 1) goto bad;
			get = *(++argv);
			(void)get;
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
	if (!host) {
		fprintf(stderr, "%s: '-host' option required\n", prog);
		return 1;
	}

	ret = quic_client_probe(prog, host, port, server_name, cipher_suite, supported_group, sig_alg, get, verbose);
	return ret == 1 ? 0 : 1;
}
