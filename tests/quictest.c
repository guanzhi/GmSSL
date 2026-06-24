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
#include <gmssl/quic.h>
#include <gmssl/error.h>


static int quic_test_varint(void)
{
	static const struct {
		uint64_t val;
		size_t len;
	} tests[] = {
		{ 0, 1 },
		{ 63, 1 },
		{ 64, 2 },
		{ 16383, 2 },
		{ 16384, 4 },
		{ 1073741823, 4 },
		{ 1073741824, 8 },
		{ 4611686018427387903ULL, 8 },
	};
	size_t i;

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		uint8_t buf[8];
		uint8_t *p = buf;
		const uint8_t *cp = buf;
		size_t len = 0;
		size_t inlen;
		uint64_t val;

		if (quic_varint_size(tests[i].val) != tests[i].len) {
			error_print();
			return -1;
		}
		if (quic_varint_to_bytes(tests[i].val, &p, &len) != 1) {
			error_print();
			return -1;
		}
		if (len != tests[i].len || p != buf + tests[i].len) {
			error_print();
			return -1;
		}

		inlen = len;
		if (quic_varint_from_bytes(&val, &cp, &inlen) != 1) {
			error_print();
			return -1;
		}
		if (val != tests[i].val || inlen != 0 || cp != buf + len) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int quic_test_transport_params(void)
{
	const uint8_t odcid[] = {
		0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08,
	};
	QUIC_TRANSPORT_PARAMS params;
	QUIC_TRANSPORT_PARAMS decoded;
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	size_t inlen;
	const uint8_t *data;
	size_t datalen;
	uint64_t val;

	quic_transport_params_init(&params);

	if (quic_transport_params_add(&params,
		QUIC_transport_param_original_destination_connection_id,
		odcid, sizeof(odcid)) != 1
		|| quic_transport_params_add_varint(&params,
			QUIC_transport_param_max_idle_timeout, 30) != 1
		|| quic_transport_params_add_varint(&params,
			QUIC_transport_param_initial_max_data, 4096) != 1
		|| quic_transport_params_add(&params,
			QUIC_transport_param_disable_active_migration, NULL, 0) != 1) {
		error_print();
		return -1;
	}

	if (quic_transport_params_to_bytes(&params, &p, &len) != 1) {
		error_print();
		return -1;
	}

	inlen = len;
	if (quic_transport_params_from_bytes(&decoded, &cp, &inlen) != 1) {
		error_print();
		return -1;
	}
	if (inlen != 0 || cp != buf + len) {
		error_print();
		return -1;
	}

	if (quic_transport_params_get(&decoded,
		QUIC_transport_param_original_destination_connection_id,
		&data, &datalen) != 1) {
		error_print();
		return -1;
	}
	if (datalen != sizeof(odcid) || memcmp(data, odcid, sizeof(odcid)) != 0) {
		error_print();
		return -1;
	}

	if (quic_transport_params_get_varint(&decoded,
		QUIC_transport_param_max_idle_timeout, &val) != 1 || val != 30) {
		error_print();
		return -1;
	}
	if (quic_transport_params_get_varint(&decoded,
		QUIC_transport_param_initial_max_data, &val) != 1 || val != 4096) {
		error_print();
		return -1;
	}
	if (quic_transport_params_get(&decoded,
		QUIC_transport_param_disable_active_migration,
		&data, &datalen) != 1 || data != NULL || datalen != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int quic_test_initial_keys(void)
{
#ifdef ENABLE_SHA2
	const uint8_t dcid[] = {
		0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08,
	};
	QUIC_INITIAL_SECRETS secrets;
	QUIC_INITIAL_KEYS client_keys;
	QUIC_INITIAL_KEYS server_keys;

	memset(&secrets, 0, sizeof(secrets));
	memset(&client_keys, 0, sizeof(client_keys));
	memset(&server_keys, 0, sizeof(server_keys));

	if (quic_derive_initial_secrets(dcid, sizeof(dcid), &secrets) != 1
		|| quic_derive_initial_client_keys(&secrets, &client_keys) != 1
		|| quic_derive_initial_server_keys(&secrets, &server_keys) != 1) {
		error_print();
		return -1;
	}
	if (memcmp(secrets.client_secret, secrets.server_secret,
		QUIC_INITIAL_SECRET_SIZE) == 0) {
		error_print();
		return -1;
	}
	if (memcmp(client_keys.key, server_keys.key, QUIC_INITIAL_KEY_SIZE) == 0
		|| memcmp(client_keys.iv, server_keys.iv, QUIC_INITIAL_IV_SIZE) == 0
		|| memcmp(client_keys.hp, server_keys.hp, QUIC_INITIAL_HP_KEY_SIZE) == 0) {
		error_print();
		return -1;
	}
#endif

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int quic_test_aes_128_gcm_sha256_packet_protection(void)
{
#ifdef ENABLE_SHA2
	const uint8_t secret[32] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	};
	const uint8_t dcid[] = { 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
	const uint8_t scid[] = { 0x08, 0x75, 0x6d, 0x35, 0x14, 0xf0, 0x9a, 0x1b };
	const uint8_t frames[] = { QUIC_frame_ping, QUIC_frame_padding, QUIC_frame_padding };
	QUIC_PACKET_KEYS keys;
	QUIC_DECRYPTED_PACKET decrypted;
	uint8_t packet[256];
	size_t packet_len = 0;

	memset(&keys, 0, sizeof(keys));
	memset(&decrypted, 0, sizeof(decrypted));

	if (quic_packet_keys_derive(DIGEST_sha256(), secret, TLS_cipher_aes_128_gcm_sha256, &keys) != 1
		|| quic_long_packet_encrypt(&keys, QUIC_packet_initial, dcid, sizeof(dcid), scid, sizeof(scid),
			1, frames, sizeof(frames), packet, &packet_len) != 1
		|| quic_long_packet_decrypt(&keys, packet, packet_len, QUIC_packet_initial, &decrypted) != 1) {
		error_print();
		return -1;
	}
	if (decrypted.packet_number != 1
		|| decrypted.plaintext_len != sizeof(frames)
		|| memcmp(decrypted.plaintext, frames, sizeof(frames)) != 0) {
		error_print();
		return -1;
	}

	memset(packet, 0, sizeof(packet));
	memset(&decrypted, 0, sizeof(decrypted));
	if (quic_short_packet_encrypt(&keys, dcid, sizeof(dcid), 2, frames, sizeof(frames), packet, &packet_len) != 1
		|| quic_short_packet_decrypt(&keys, packet, packet_len, dcid, sizeof(dcid), &decrypted) != 1) {
		error_print();
		return -1;
	}
	if (decrypted.packet_number != 2
		|| decrypted.plaintext_len != sizeof(frames)
		|| memcmp(decrypted.plaintext, frames, sizeof(frames)) != 0) {
		error_print();
		return -1;
	}
#endif

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int quic_test_sm4_gcm_sm3_packet_protection(void)
{
	const uint8_t secret[32] = {
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
	};
	const uint8_t dcid[] = { 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
	const uint8_t scid[] = { 0x08, 0x75, 0x6d, 0x35, 0x14, 0xf0, 0x9a, 0x1b };
	const uint8_t frames[] = { QUIC_frame_ping, QUIC_frame_padding, QUIC_frame_padding };
	QUIC_PACKET_KEYS keys;
	QUIC_DECRYPTED_PACKET decrypted;
	uint8_t packet[256];
	size_t packet_len = 0;

	memset(&keys, 0, sizeof(keys));
	memset(&decrypted, 0, sizeof(decrypted));

	if (quic_packet_keys_derive(DIGEST_sm3(), secret, TLS_cipher_sm4_gcm_sm3, &keys) != 1
		|| quic_long_packet_encrypt(&keys, QUIC_packet_handshake, dcid, sizeof(dcid), scid, sizeof(scid),
			3, frames, sizeof(frames), packet, &packet_len) != 1
		|| quic_long_packet_decrypt(&keys, packet, packet_len, QUIC_packet_handshake, &decrypted) != 1) {
		error_print();
		return -1;
	}
	if (decrypted.packet_number != 3
		|| decrypted.plaintext_len != sizeof(frames)
		|| memcmp(decrypted.plaintext, frames, sizeof(frames)) != 0) {
		error_print();
		return -1;
	}

	memset(packet, 0, sizeof(packet));
	memset(&decrypted, 0, sizeof(decrypted));
	if (quic_short_packet_encrypt(&keys, dcid, sizeof(dcid), 4, frames, sizeof(frames), packet, &packet_len) != 1
		|| quic_short_packet_decrypt(&keys, packet, packet_len, dcid, sizeof(dcid), &decrypted) != 1) {
		error_print();
		return -1;
	}
	if (decrypted.packet_number != 4
		|| decrypted.plaintext_len != sizeof(frames)
		|| memcmp(decrypted.plaintext, frames, sizeof(frames)) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int quic_test_sm4_ccm_sm3_packet_protection(void)
{
#ifdef ENABLE_SM4_CCM
	const uint8_t secret[32] = {
		0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
		0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
		0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
		0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
	};
	const uint8_t dcid[] = { 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
	const uint8_t scid[] = { 0x08, 0x75, 0x6d, 0x35, 0x14, 0xf0, 0x9a, 0x1b };
	const uint8_t frames[] = { QUIC_frame_ping, QUIC_frame_padding, QUIC_frame_padding };
	QUIC_PACKET_KEYS keys;
	QUIC_DECRYPTED_PACKET decrypted;
	uint8_t packet[256];
	size_t packet_len = 0;

	memset(&keys, 0, sizeof(keys));
	memset(&decrypted, 0, sizeof(decrypted));

	if (quic_packet_keys_derive(DIGEST_sm3(), secret, TLS_cipher_sm4_ccm_sm3, &keys) != 1
		|| quic_long_packet_encrypt(&keys, QUIC_packet_handshake, dcid, sizeof(dcid), scid, sizeof(scid),
			5, frames, sizeof(frames), packet, &packet_len) != 1
		|| quic_long_packet_decrypt(&keys, packet, packet_len, QUIC_packet_handshake, &decrypted) != 1) {
		error_print();
		return -1;
	}
	if (decrypted.packet_number != 5
		|| decrypted.plaintext_len != sizeof(frames)
		|| memcmp(decrypted.plaintext, frames, sizeof(frames)) != 0) {
		error_print();
		return -1;
	}

	memset(packet, 0, sizeof(packet));
	memset(&decrypted, 0, sizeof(decrypted));
	if (quic_short_packet_encrypt(&keys, dcid, sizeof(dcid), 6, frames, sizeof(frames), packet, &packet_len) != 1
		|| quic_short_packet_decrypt(&keys, packet, packet_len, dcid, sizeof(dcid), &decrypted) != 1) {
		error_print();
		return -1;
	}
	if (decrypted.packet_number != 6
		|| decrypted.plaintext_len != sizeof(frames)
		|| memcmp(decrypted.plaintext, frames, sizeof(frames)) != 0) {
		error_print();
		return -1;
	}
#endif

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int quic_test_client_hello_to_bytes(void)
{
	TLS_CTX ctx;
	TLS_CONNECT conn;
	int cipher_suites[] = { TLS_cipher_sm4_gcm_sm3 };
	int supported_groups[] = { TLS_curve_sm2p256v1 };
	int signature_algorithms[] = { TLS_sig_sm2sig_sm3 };
	uint8_t buf[TLS_MAX_RECORD_SIZE];
	uint8_t *p = buf;
	size_t len = 0;
	size_t handshake_len;

	if (tls_ctx_init(&ctx, TLS_protocol_tls13, TLS_client_mode) != 1
		|| tls_ctx_set_cipher_suites(&ctx, cipher_suites, sizeof(cipher_suites)/sizeof(cipher_suites[0])) != 1
		|| tls_ctx_set_supported_groups(&ctx, supported_groups, sizeof(supported_groups)/sizeof(supported_groups[0])) != 1
		|| tls_ctx_set_signature_algorithms(&ctx, signature_algorithms, sizeof(signature_algorithms)/sizeof(signature_algorithms[0])) != 1
		|| tls_init(&conn, &ctx) != 1) {
		error_print();
		return -1;
	}

	if (quic_client_hello_to_bytes(&conn, &p, &len) != 1) {
		error_print();
		tls_ctx_cleanup(&ctx);
		return -1;
	}
	if (len < TLS_HANDSHAKE_HEADER_SIZE || p != buf + len) {
		error_print();
		tls_ctx_cleanup(&ctx);
		return -1;
	}
	if (buf[0] != TLS_handshake_client_hello || buf[0] == TLS_record_handshake) {
		error_print();
		tls_ctx_cleanup(&ctx);
		return -1;
	}
	handshake_len = ((size_t)buf[1] << 16) | ((size_t)buf[2] << 8) | buf[3];
	if (handshake_len + TLS_HANDSHAKE_HEADER_SIZE != len) {
		error_print();
		tls_ctx_cleanup(&ctx);
		return -1;
	}
	if (conn.plain_recordlen != len || memcmp(conn.plain_record, buf, len) != 0) {
		error_print();
		tls_ctx_cleanup(&ctx);
		return -1;
	}

	tls_ctx_cleanup(&ctx);
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int quic_test_verbose_print(void)
{
	TLS_CTX ctx;
	TLS_CONNECT conn;
	int cipher_suites[] = { TLS_cipher_sm4_gcm_sm3 };
	int supported_groups[] = { TLS_curve_sm2p256v1 };
	int signature_algorithms[] = { TLS_sig_sm2sig_sm3 };
	uint8_t handshake[TLS_MAX_RECORD_SIZE];
	uint8_t frames[TLS_MAX_RECORD_SIZE];
	uint8_t packet[64];
	uint8_t *p = handshake;
	uint8_t *q = frames;
	uint8_t *r = packet;
	size_t handshake_len = 0;
	size_t frames_len = 0;
	size_t packet_len = 0;
	FILE *fp;

	fp = tmpfile();
	if (!fp) {
		error_print();
		return -1;
	}

	if (tls_ctx_init(&ctx, TLS_protocol_tls13, TLS_client_mode) != 1
		|| tls_ctx_set_cipher_suites(&ctx, cipher_suites, sizeof(cipher_suites)/sizeof(cipher_suites[0])) != 1
		|| tls_ctx_set_supported_groups(&ctx, supported_groups, sizeof(supported_groups)/sizeof(supported_groups[0])) != 1
		|| tls_ctx_set_signature_algorithms(&ctx, signature_algorithms, sizeof(signature_algorithms)/sizeof(signature_algorithms[0])) != 1
		|| tls_init(&conn, &ctx) != 1) {
		error_print();
		fclose(fp);
		return -1;
	}

	if (quic_client_hello_to_bytes(&conn, &p, &handshake_len) != 1
		|| quic_crypto_data_print(fp, 0, 0, QUIC_encryption_initial, handshake, handshake_len) != 1) {
		error_print();
		tls_ctx_cleanup(&ctx);
		fclose(fp);
		return -1;
	}

	if (quic_varint_to_bytes(QUIC_frame_ping, &q, &frames_len) != 1
		|| quic_varint_to_bytes(QUIC_frame_crypto, &q, &frames_len) != 1
		|| quic_varint_to_bytes(0, &q, &frames_len) != 1
		|| quic_varint_to_bytes(handshake_len, &q, &frames_len) != 1) {
		error_print();
		tls_ctx_cleanup(&ctx);
		fclose(fp);
		return -1;
	}
	memcpy(q, handshake, handshake_len);
	q += handshake_len;
	frames_len += handshake_len;
	if (quic_frames_print(fp, 0, 0, QUIC_encryption_initial, frames, frames_len) != 1) {
		error_print();
		tls_ctx_cleanup(&ctx);
		fclose(fp);
		return -1;
	}

	*r++ = 0xc0;
	*r++ = 0x00; *r++ = 0x00; *r++ = 0x00; *r++ = 0x01;
	*r++ = 0x08;
	memcpy(r, "12345678", 8); r += 8;
	*r++ = 0x08;
	memcpy(r, "87654321", 8); r += 8;
	*r++ = 0x00;
	*r++ = 0x01;
	*r++ = 0x00;
	packet_len = (size_t)(r - packet);
	if (quic_packet_print(fp, 0, 0, packet, packet_len) != 1) {
		error_print();
		tls_ctx_cleanup(&ctx);
		fclose(fp);
		return -1;
	}

	tls_ctx_cleanup(&ctx);
	fclose(fp);
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (quic_test_varint() != 1
		|| quic_test_transport_params() != 1
		|| quic_test_initial_keys() != 1
		|| quic_test_aes_128_gcm_sha256_packet_protection() != 1
		|| quic_test_sm4_gcm_sm3_packet_protection() != 1
		|| quic_test_sm4_ccm_sm3_packet_protection() != 1
		|| quic_test_client_hello_to_bytes() != 1
		|| quic_test_verbose_print() != 1) {
		error_print();
		return 1;
	}

	return 0;
}
