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

int main(void)
{
	if (quic_test_varint() != 1
		|| quic_test_transport_params() != 1
		|| quic_test_initial_keys() != 1) {
		error_print();
		return 1;
	}

	return 0;
}
