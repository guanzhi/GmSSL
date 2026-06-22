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


#ifdef __cplusplus
}
#endif
#endif
