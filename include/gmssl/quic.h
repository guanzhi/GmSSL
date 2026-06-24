/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GMSSL_QUIC_H
#define GMSSL_QUIC_H


#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <gmssl/digest.h>
#include <gmssl/tls.h>


#ifdef __cplusplus
extern "C" {
#endif


#define QUIC_VERSION_V1			0x00000001

#define QUIC_INITIAL_SECRET_SIZE	32
#define QUIC_INITIAL_KEY_SIZE		16
#define QUIC_INITIAL_IV_SIZE		12
#define QUIC_INITIAL_HP_KEY_SIZE	16

#define QUIC_TRANSPORT_PARAM_MAX_COUNT	32
#define QUIC_TRANSPORT_PARAM_MAX_SIZE	512


typedef enum {
	QUIC_packet_initial		= 0,
	QUIC_packet_0_rtt		= 1,
	QUIC_packet_handshake		= 2,
	QUIC_packet_retry		= 3,
} QUIC_PACKET_TYPE;

typedef enum {
	QUIC_frame_padding		= 0x00,
	QUIC_frame_ping			= 0x01,
	QUIC_frame_ack			= 0x02,
	QUIC_frame_ack_ecn		= 0x03,
	QUIC_frame_reset_stream		= 0x04,
	QUIC_frame_stop_sending		= 0x05,
	QUIC_frame_crypto		= 0x06,
	QUIC_frame_new_token		= 0x07,
	QUIC_frame_stream_base		= 0x08,
	QUIC_frame_max_data		= 0x10,
	QUIC_frame_max_stream_data	= 0x11,
	QUIC_frame_max_streams_bidi	= 0x12,
	QUIC_frame_max_streams_uni	= 0x13,
	QUIC_frame_data_blocked		= 0x14,
	QUIC_frame_stream_data_blocked	= 0x15,
	QUIC_frame_streams_blocked_bidi	= 0x16,
	QUIC_frame_streams_blocked_uni	= 0x17,
	QUIC_frame_new_connection_id	= 0x18,
	QUIC_frame_retire_connection_id	= 0x19,
	QUIC_frame_path_challenge	= 0x1a,
	QUIC_frame_path_response		= 0x1b,
	QUIC_frame_connection_close	= 0x1c,
	QUIC_frame_connection_close_app	= 0x1d,
	QUIC_frame_handshake_done	= 0x1e,
} QUIC_FRAME_TYPE;

typedef enum {
	QUIC_transport_param_original_destination_connection_id		= 0x00,
	QUIC_transport_param_max_idle_timeout				= 0x01,
	QUIC_transport_param_stateless_reset_token			= 0x02,
	QUIC_transport_param_max_udp_payload_size			= 0x03,
	QUIC_transport_param_initial_max_data				= 0x04,
	QUIC_transport_param_initial_max_stream_data_bidi_local		= 0x05,
	QUIC_transport_param_initial_max_stream_data_bidi_remote	= 0x06,
	QUIC_transport_param_initial_max_stream_data_uni		= 0x07,
	QUIC_transport_param_initial_max_streams_bidi			= 0x08,
	QUIC_transport_param_initial_max_streams_uni			= 0x09,
	QUIC_transport_param_ack_delay_exponent				= 0x0a,
	QUIC_transport_param_max_ack_delay				= 0x0b,
	QUIC_transport_param_disable_active_migration			= 0x0c,
	QUIC_transport_param_preferred_address				= 0x0d,
	QUIC_transport_param_active_connection_id_limit			= 0x0e,
	QUIC_transport_param_initial_source_connection_id		= 0x0f,
	QUIC_transport_param_retry_source_connection_id			= 0x10,
} QUIC_TRANSPORT_PARAM_ID;

typedef enum {
	QUIC_encryption_initial		= 0,
	QUIC_encryption_early_data	= 1,
	QUIC_encryption_handshake	= 2,
	QUIC_encryption_application	= 3,
} QUIC_ENCRYPTION_LEVEL;


typedef struct {
	uint8_t client_secret[QUIC_INITIAL_SECRET_SIZE];
	uint8_t server_secret[QUIC_INITIAL_SECRET_SIZE];
} QUIC_INITIAL_SECRETS;

typedef struct {
	uint8_t key[QUIC_INITIAL_KEY_SIZE];
	uint8_t iv[QUIC_INITIAL_IV_SIZE];
	uint8_t hp[QUIC_INITIAL_HP_KEY_SIZE]; // hp = header protection key
} QUIC_INITIAL_KEYS;

typedef struct {
	int cipher_suite;
	uint8_t key[QUIC_INITIAL_KEY_SIZE];
	uint8_t iv[QUIC_INITIAL_IV_SIZE];
	uint8_t hp[QUIC_INITIAL_HP_KEY_SIZE]; /* hp is Header Protection. QUIC protects packet number bytes and selected header bits separately from payload AEAD. */
} QUIC_PACKET_KEYS;

typedef struct {
	int type;
	uint64_t packet_number;
	size_t packet_len;
	uint8_t dcid[20];
	size_t dcid_len;
	uint8_t scid[20];
	size_t scid_len;
	uint8_t plaintext[4096];
	size_t plaintext_len;
} QUIC_DECRYPTED_PACKET;

typedef struct {
	uint64_t id;
	uint8_t data[QUIC_TRANSPORT_PARAM_MAX_SIZE];
	size_t datalen;
} QUIC_TRANSPORT_PARAM;

typedef struct {
	QUIC_TRANSPORT_PARAM params[QUIC_TRANSPORT_PARAM_MAX_COUNT];
	size_t params_count;
} QUIC_TRANSPORT_PARAMS;


size_t quic_varint_size(uint64_t val);
int quic_varint_to_bytes(uint64_t val, uint8_t **out, size_t *outlen);
int quic_varint_from_bytes(uint64_t *val, const uint8_t **in, size_t *inlen);

void quic_transport_params_init(QUIC_TRANSPORT_PARAMS *params);
int quic_transport_params_add(QUIC_TRANSPORT_PARAMS *params,
	uint64_t id, const uint8_t *data, size_t datalen);
int quic_transport_params_add_varint(QUIC_TRANSPORT_PARAMS *params,
	uint64_t id, uint64_t val);
int quic_transport_params_get(const QUIC_TRANSPORT_PARAMS *params,
	uint64_t id, const uint8_t **data, size_t *datalen);
int quic_transport_params_get_varint(const QUIC_TRANSPORT_PARAMS *params,
	uint64_t id, uint64_t *val);
int quic_transport_params_to_bytes(const QUIC_TRANSPORT_PARAMS *params,
	uint8_t **out, size_t *outlen);
int quic_transport_params_from_bytes(QUIC_TRANSPORT_PARAMS *params,
	const uint8_t **in, size_t *inlen);

int quic_derive_initial_secrets(const uint8_t *dcid, size_t dcid_len, QUIC_INITIAL_SECRETS *secrets);
int quic_derive_initial_client_keys(const QUIC_INITIAL_SECRETS *secrets, QUIC_INITIAL_KEYS *keys);
int quic_derive_initial_server_keys(const QUIC_INITIAL_SECRETS *secrets, QUIC_INITIAL_KEYS *keys);
int quic_derive_initial_keys(const uint8_t secret[QUIC_INITIAL_SECRET_SIZE], QUIC_INITIAL_KEYS *keys);
int quic_packet_keys_derive(const DIGEST *digest, const uint8_t secret[32], int cipher_suite, QUIC_PACKET_KEYS *keys);
int quic_packet_keys_from_initial(const QUIC_INITIAL_KEYS *initial_keys, QUIC_PACKET_KEYS *keys);

int quic_packet_total_length(const uint8_t *packet, size_t packet_len, size_t *total_len);
int quic_long_packet_decrypt(const QUIC_PACKET_KEYS *keys, const uint8_t *packet, size_t packet_len, int expected_type, QUIC_DECRYPTED_PACKET *out);
int quic_long_packet_encrypt(const QUIC_PACKET_KEYS *keys, int type, const uint8_t *dcid, size_t dcid_len,
	const uint8_t *scid, size_t scid_len, uint64_t packet_number, const uint8_t *frames, size_t frames_len,
	uint8_t *packet, size_t *packet_len);
int quic_short_packet_decrypt(const QUIC_PACKET_KEYS *keys, const uint8_t *packet, size_t packet_len,
	const uint8_t *dcid, size_t dcid_len, QUIC_DECRYPTED_PACKET *out);
int quic_short_packet_encrypt(const QUIC_PACKET_KEYS *keys, const uint8_t *dcid, size_t dcid_len,
	uint64_t packet_number, const uint8_t *frames, size_t frames_len, uint8_t *packet, size_t *packet_len);

int quic_client_hello_to_bytes_ex(TLS_CONNECT *conn, const QUIC_TRANSPORT_PARAMS *params, uint8_t **out, size_t *outlen);
int quic_client_hello_to_bytes(TLS_CONNECT *conn, uint8_t **out, size_t *outlen);
int quic_server_hello_to_bytes(TLS_CONNECT *conn, uint8_t **out, size_t *outlen);

const char *quic_packet_type_name(int type);
const char *quic_frame_type_name(uint64_t type);
const char *quic_encryption_level_name(int level);
int quic_packet_print(FILE *fp, int fmt, int ind, const uint8_t *packet, size_t packetlen);
int quic_frames_print(FILE *fp, int fmt, int ind, int level, const uint8_t *frames, size_t frameslen);
int quic_frame_print(FILE *fp, int fmt, int ind, int level, const uint8_t **in, size_t *inlen);
int quic_crypto_data_print(FILE *fp, int fmt, int ind, int level, const uint8_t *data, size_t datalen);


#ifdef __cplusplus
}
#endif
#endif
