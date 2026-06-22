/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#include <string.h>
#include <gmssl/quic.h>
#include <gmssl/tls.h>
#include <gmssl/hkdf.h>
#include <gmssl/digest.h>
#include <gmssl/mem.h>
#include <gmssl/error.h>


static const uint8_t quic_v1_initial_salt[20] = {
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
	0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
	0xcc, 0xbb, 0x7f, 0x0a,
};


size_t quic_varint_size(uint64_t val)
{
	if (val <= 63) {
		return 1;
	} else if (val <= 16383) {
		return 2;
	} else if (val <= 1073741823) {
		return 4;
	} else if (val <= 4611686018427387903ULL) {
		return 8;
	}
	return 0;
}

int quic_varint_to_bytes(uint64_t val, uint8_t **out, size_t *outlen)
{
	size_t len;

	if (!outlen) {
		error_print();
		return -1;
	}

	len = quic_varint_size(val);
	if (!len) {
		error_print();
		return -1;
	}

	if (out && *out) {
		switch (len) {
		case 1:
			*(*out)++ = (uint8_t)val;
			break;
		case 2:
			*(*out)++ = (uint8_t)(0x40 | (val >> 8));
			*(*out)++ = (uint8_t)val;
			break;
		case 4:
			*(*out)++ = (uint8_t)(0x80 | (val >> 24));
			*(*out)++ = (uint8_t)(val >> 16);
			*(*out)++ = (uint8_t)(val >> 8);
			*(*out)++ = (uint8_t)val;
			break;
		case 8:
			*(*out)++ = (uint8_t)(0xc0 | (val >> 56));
			*(*out)++ = (uint8_t)(val >> 48);
			*(*out)++ = (uint8_t)(val >> 40);
			*(*out)++ = (uint8_t)(val >> 32);
			*(*out)++ = (uint8_t)(val >> 24);
			*(*out)++ = (uint8_t)(val >> 16);
			*(*out)++ = (uint8_t)(val >> 8);
			*(*out)++ = (uint8_t)val;
			break;
		default:
			error_print();
			return -1;
		}
	}

	*outlen += len;
	return 1;
}

int quic_varint_from_bytes(uint64_t *val, const uint8_t **in, size_t *inlen)
{
	uint8_t first;
	size_t len;
	uint64_t ret;
	size_t i;

	if (!val || !in || !*in || !inlen || !*inlen) {
		error_print();
		return -1;
	}

	first = **in;
	len = (size_t)1 << (first >> 6);
	if (*inlen < len) {
		error_print();
		return -1;
	}

	ret = first & 0x3f;
	for (i = 1; i < len; i++) {
		ret <<= 8;
		ret |= (*in)[i];
	}

	*val = ret;
	*in += len;
	*inlen -= len;
	return 1;
}

void quic_transport_params_init(QUIC_TRANSPORT_PARAMS *params)
{
	if (params) {
		memset(params, 0, sizeof(*params));
	}
}

int quic_transport_params_add(QUIC_TRANSPORT_PARAMS *params,
	uint64_t id, const uint8_t *data, size_t datalen)
{
	QUIC_TRANSPORT_PARAM *param;
	size_t i;

	if (!params || (!data && datalen)) {
		error_print();
		return -1;
	}
	if (!quic_varint_size(id) || datalen > QUIC_TRANSPORT_PARAM_MAX_SIZE) {
		error_print();
		return -1;
	}
	if (params->params_count >= QUIC_TRANSPORT_PARAM_MAX_COUNT) {
		error_print();
		return -1;
	}
	for (i = 0; i < params->params_count; i++) {
		if (params->params[i].id == id) {
			error_print();
			return -1;
		}
	}

	param = &params->params[params->params_count++];
	param->id = id;
	param->datalen = datalen;
	if (datalen) {
		memcpy(param->data, data, datalen);
	}
	return 1;
}

int quic_transport_params_add_varint(QUIC_TRANSPORT_PARAMS *params,
	uint64_t id, uint64_t val)
{
	uint8_t buf[8];
	uint8_t *p = buf;
	size_t len = 0;

	if (quic_varint_to_bytes(val, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (quic_transport_params_add(params, id, buf, len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int quic_transport_params_get(const QUIC_TRANSPORT_PARAMS *params,
	uint64_t id, const uint8_t **data, size_t *datalen)
{
	size_t i;

	if (!params || !data || !datalen) {
		error_print();
		return -1;
	}

	for (i = 0; i < params->params_count; i++) {
		if (params->params[i].id == id) {
			*data = params->params[i].datalen ? params->params[i].data : NULL;
			*datalen = params->params[i].datalen;
			return 1;
		}
	}

	return 0;
}

int quic_transport_params_get_varint(const QUIC_TRANSPORT_PARAMS *params,
	uint64_t id, uint64_t *val)
{
	const uint8_t *data;
	size_t datalen;
	int ret;

	if (!val) {
		error_print();
		return -1;
	}
	if ((ret = quic_transport_params_get(params, id, &data, &datalen)) != 1) {
		return ret;
	}
	if (quic_varint_from_bytes(val, &data, &datalen) != 1 || datalen != 0) {
		error_print();
		return -1;
	}
	return 1;
}

int quic_transport_params_to_bytes(const QUIC_TRANSPORT_PARAMS *params,
	uint8_t **out, size_t *outlen)
{
	size_t i;

	if (!params || !outlen) {
		error_print();
		return -1;
	}

	for (i = 0; i < params->params_count; i++) {
		if (quic_varint_to_bytes(params->params[i].id, out, outlen) != 1
			|| quic_varint_to_bytes(params->params[i].datalen, out, outlen) != 1) {
			error_print();
			return -1;
		}
		if (out && *out) {
			memcpy(*out, params->params[i].data, params->params[i].datalen);
			*out += params->params[i].datalen;
		}
		*outlen += params->params[i].datalen;
	}

	return 1;
}

int quic_transport_params_from_bytes(QUIC_TRANSPORT_PARAMS *params,
	const uint8_t **in, size_t *inlen)
{
	uint64_t id;
	uint64_t len;

	if (!params || !in || !inlen || (!*in && *inlen)) {
		error_print();
		return -1;
	}

	quic_transport_params_init(params);

	while (*inlen) {
		if (quic_varint_from_bytes(&id, in, inlen) != 1
			|| quic_varint_from_bytes(&len, in, inlen) != 1) {
			error_print();
			return -1;
		}
		if (len > *inlen || len > QUIC_TRANSPORT_PARAM_MAX_SIZE) {
			error_print();
			return -1;
		}
		if (quic_transport_params_add(params, id, *in, (size_t)len) != 1) {
			error_print();
			return -1;
		}
		*in += len;
		*inlen -= len;
	}

	return 1;
}

int quic_derive_initial_secrets(const uint8_t *dcid, size_t dcid_len, QUIC_INITIAL_SECRETS *secrets)
{
#if defined(ENABLE_SHA2)
	/* QUIC v1 Initial secrets always use SHA-256, independent of the TLS cipher suite. */
	const DIGEST *digest = DIGEST_sha256();
	uint8_t initial_secret[QUIC_INITIAL_SECRET_SIZE];
	size_t initial_secret_len;
	int ret = -1;

	if ((!dcid && dcid_len) || !secrets) {
		error_print();
		return -1;
	}

	if (hkdf_extract(digest, quic_v1_initial_salt, sizeof(quic_v1_initial_salt),
		dcid, dcid_len, initial_secret, &initial_secret_len) != 1
		|| initial_secret_len != QUIC_INITIAL_SECRET_SIZE
		|| tls13_hkdf_expand_label(digest, initial_secret, "client in", NULL, 0,
			QUIC_INITIAL_SECRET_SIZE, secrets->client_secret) != 1
		|| tls13_hkdf_expand_label(digest, initial_secret, "server in", NULL, 0,
			QUIC_INITIAL_SECRET_SIZE, secrets->server_secret) != 1) {
		error_print();
		goto end;
	}

	ret = 1;

end:
	gmssl_secure_clear(initial_secret, sizeof(initial_secret));
	return ret;
#else
	error_print();
	return -1;
#endif
}

int quic_derive_initial_client_keys(const QUIC_INITIAL_SECRETS *secrets, QUIC_INITIAL_KEYS *keys)
{
	if (!secrets) {
		error_print();
		return -1;
	}
	if (quic_derive_initial_keys(secrets->client_secret, keys) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int quic_derive_initial_server_keys(const QUIC_INITIAL_SECRETS *secrets, QUIC_INITIAL_KEYS *keys)
{
	if (!secrets) {
		error_print();
		return -1;
	}
	if (quic_derive_initial_keys(secrets->server_secret, keys) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int quic_derive_initial_keys(const uint8_t secret[QUIC_INITIAL_SECRET_SIZE], QUIC_INITIAL_KEYS *keys)
{
#if defined(ENABLE_SHA2)
	const DIGEST *digest = DIGEST_sha256();

	if (!secret || !keys) {
		error_print();
		return -1;
	}

	if (tls13_hkdf_expand_label(digest, secret, "quic key", NULL, 0,
		QUIC_INITIAL_KEY_SIZE, keys->key) != 1
		|| tls13_hkdf_expand_label(digest, secret, "quic iv", NULL, 0,
			QUIC_INITIAL_IV_SIZE, keys->iv) != 1
		|| tls13_hkdf_expand_label(digest, secret, "quic hp", NULL, 0,
			QUIC_INITIAL_HP_KEY_SIZE, keys->hp) != 1) {
		error_print();
		return -1;
	}

	return 1;
#else
	error_print();
	return -1;
#endif
}
