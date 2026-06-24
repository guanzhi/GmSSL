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
#include <gmssl/mem.h>
#include <gmssl/error.h>
#include <gmssl/sm2.h>


int sm2_do_ecdh(const SM2_KEY *key, const SM2_KEY *peer_key, uint8_t out[32])
{
	SM2_Z256_POINT point;
	sm2_z256_t x;

	if (!key || !peer_key || !out) {
		error_print();
		return -1;
	}
	sm2_z256_point_mul(&point, key->private_key, &peer_key->public_key);
	sm2_z256_point_get_xy(&point, x, NULL);
	sm2_z256_to_bytes(x, out);

	gmssl_secure_clear(&point, sizeof(SM2_Z256_POINT));
	gmssl_secure_clear(x, sizeof(sm2_z256_t));
	return 1;
}

int sm2_ecdh(const SM2_KEY *key, const uint8_t uncompressed_point[65], uint8_t out[32])
{
	SM2_Z256_POINT point;
	sm2_z256_t x;

	if (!key || !uncompressed_point || !out) {
		error_print();
		return -1;
	}
	if (sm2_z256_point_from_octets(&point, uncompressed_point, 65) != 1) {
		error_print();
		return -1;
	}
	sm2_z256_point_mul(&point, key->private_key, &point);
	sm2_z256_point_get_xy(&point, x, NULL);
	sm2_z256_to_bytes(x, out);

	gmssl_secure_clear(&point, sizeof(SM2_Z256_POINT));
	gmssl_secure_clear(x, sizeof(sm2_z256_t));
	return 1;
}

static int sm2_z256_point_get_x_hat(const SM2_Z256_POINT *P, sm2_z256_t x_hat)
{
	sm2_z256_t x;

	if (sm2_z256_point_get_xy(P, x, NULL) != 1) {
		error_print();
		return -1;
	}

	// x' = 2^127 + (x mod 2^127)
	x_hat[0] = x[0];
	x_hat[1] = (x[1] & 0x7fffffffffffffff) | 0x8000000000000000;
	x_hat[2] = 0;
	x_hat[3] = 0;

	gmssl_secure_clear(x, sizeof(x));
	return 1;
}

int sm2_key_exchange(int is_initiator,
	const SM2_KEY *key, const char *id, size_t idlen,
	const SM2_KEY *peer_public_key, const char *peer_id, size_t peer_idlen,
	const SM2_KEY *key_exchange, const uint8_t peer_key_exchange[65],
	uint8_t optional_shared_point[65], size_t shared_key_len, uint8_t *shared_key)
{
	SM2_Z256_POINT peer_point;
	SM2_Z256_POINT point;
	sm2_z256_t local_x_hat;
	sm2_z256_t peer_x_hat;
	sm2_z256_t t;
	uint8_t za[32];
	uint8_t zb[32];
	uint8_t kdf_input[128];
	int ret = -1;

	if (!key || !id || !peer_public_key || !peer_id || !key_exchange
		|| !peer_key_exchange || !shared_key_len || !shared_key) {
		error_print();
		return -1;
	}
	if (idlen > SM2_MAX_ID_LENGTH || peer_idlen > SM2_MAX_ID_LENGTH) {
		error_print();
		return -1;
	}
	if (sm2_z256_point_from_octets(&peer_point, peer_key_exchange, 65) != 1) {
		error_print();
		goto end;
	}
	if (is_initiator) {
		if (sm2_compute_z(za, &key->public_key, id, idlen) != 1
			|| sm2_compute_z(zb, &peer_public_key->public_key, peer_id, peer_idlen) != 1) {
			error_print();
			goto end;
		}
	} else {
		if (sm2_compute_z(za, &peer_public_key->public_key, peer_id, peer_idlen) != 1
			|| sm2_compute_z(zb, &key->public_key, id, idlen) != 1) {
			error_print();
			goto end;
		}
	}

	if (sm2_z256_point_get_x_hat(&key_exchange->public_key, local_x_hat) != 1
		|| sm2_z256_point_get_x_hat(&peer_point, peer_x_hat) != 1) {
		error_print();
		goto end;
	}

	sm2_z256_modn_mul(t, local_x_hat, key_exchange->private_key);
	sm2_z256_modn_add(t, t, key->private_key);

	sm2_z256_point_mul(&point, peer_x_hat, &peer_point);
	sm2_z256_point_add(&point, &peer_public_key->public_key, &point);
	if (sm2_z256_point_is_at_infinity(&point)) {
		error_print();
		goto end;
	}

	sm2_z256_point_mul(&point, t, &point);
	if (sm2_z256_point_is_at_infinity(&point)) {
		error_print();
		goto end;
	}
	if (optional_shared_point
		&& sm2_z256_point_to_uncompressed_octets(&point, optional_shared_point) != 1) {
		error_print();
		goto end;
	}

	sm2_z256_point_to_bytes(&point, kdf_input);
	memcpy(kdf_input + 64, za, 32);
	memcpy(kdf_input + 96, zb, 32);
	if (sm2_kdf(kdf_input, sizeof(kdf_input), shared_key_len, shared_key) != 1) {
		error_print();
		goto end;
	}
	if (mem_is_zero(shared_key, shared_key_len)) {
		error_print();
		goto end;
	}

	ret = 1;

end:
	gmssl_secure_clear(&peer_point, sizeof(peer_point));
	gmssl_secure_clear(&point, sizeof(point));
	gmssl_secure_clear(local_x_hat, sizeof(local_x_hat));
	gmssl_secure_clear(peer_x_hat, sizeof(peer_x_hat));
	gmssl_secure_clear(t, sizeof(t));
	gmssl_secure_clear(za, sizeof(za));
	gmssl_secure_clear(zb, sizeof(zb));
	gmssl_secure_clear(kdf_input, sizeof(kdf_input));
	return ret;
}

static int sm2_key_exchange_compute_confirm_ex(int is_initiator,
	const SM2_KEY *key, const char *id, size_t idlen,
	const SM2_KEY *peer_public_key, const char *peer_id, size_t peer_idlen,
	const SM2_KEY *key_exchange, const uint8_t peer_key_exchange[65],
	const uint8_t shared_point[65], int is_initiator_confirm, uint8_t confirm[32])
{
	SM2_Z256_POINT uv;
	SM2_Z256_POINT peer_point;
	SM2_Z256_POINT ra;
	SM2_Z256_POINT rb;
	uint8_t za[32];
	uint8_t zb[32];
	uint8_t xy[64];
	uint8_t ra_bytes[64];
	uint8_t rb_bytes[64];
	uint8_t hash[32];
	uint8_t prefix = is_initiator_confirm ? 0x03 : 0x02;
	SM3_CTX ctx;
	int ret = -1;

	if (!key || !id || !peer_public_key || !peer_id || !key_exchange
		|| !peer_key_exchange || !shared_point || !confirm) {
		error_print();
		return -1;
	}
	if (idlen > SM2_MAX_ID_LENGTH || peer_idlen > SM2_MAX_ID_LENGTH) {
		error_print();
		return -1;
	}
	if (sm2_z256_point_from_octets(&uv, shared_point, 65) != 1
		|| sm2_z256_point_from_octets(&peer_point, peer_key_exchange, 65) != 1) {
		error_print();
		goto end;
	}
	if (is_initiator) {
		ra = key_exchange->public_key;
		rb = peer_point;
		if (sm2_compute_z(za, &key->public_key, id, idlen) != 1
			|| sm2_compute_z(zb, &peer_public_key->public_key, peer_id, peer_idlen) != 1) {
			error_print();
			goto end;
		}
	} else {
		ra = peer_point;
		rb = key_exchange->public_key;
		if (sm2_compute_z(za, &peer_public_key->public_key, peer_id, peer_idlen) != 1
			|| sm2_compute_z(zb, &key->public_key, id, idlen) != 1) {
			error_print();
			goto end;
		}
	}

	sm2_z256_point_to_bytes(&uv, xy);
	sm2_z256_point_to_bytes(&ra, ra_bytes);
	sm2_z256_point_to_bytes(&rb, rb_bytes);

	sm3_init(&ctx);
	sm3_update(&ctx, xy, 32);
	sm3_update(&ctx, za, sizeof(za));
	sm3_update(&ctx, zb, sizeof(zb));
	sm3_update(&ctx, ra_bytes, sizeof(ra_bytes));
	sm3_update(&ctx, rb_bytes, sizeof(rb_bytes));
	sm3_finish(&ctx, hash);

	sm3_init(&ctx);
	sm3_update(&ctx, &prefix, sizeof(prefix));
	sm3_update(&ctx, xy + 32, 32);
	sm3_update(&ctx, hash, sizeof(hash));
	sm3_finish(&ctx, confirm);

	ret = 1;

end:
	gmssl_secure_clear(&uv, sizeof(uv));
	gmssl_secure_clear(&peer_point, sizeof(peer_point));
	gmssl_secure_clear(&ra, sizeof(ra));
	gmssl_secure_clear(&rb, sizeof(rb));
	gmssl_secure_clear(za, sizeof(za));
	gmssl_secure_clear(zb, sizeof(zb));
	gmssl_secure_clear(xy, sizeof(xy));
	gmssl_secure_clear(ra_bytes, sizeof(ra_bytes));
	gmssl_secure_clear(rb_bytes, sizeof(rb_bytes));
	gmssl_secure_clear(hash, sizeof(hash));
	gmssl_secure_clear(&ctx, sizeof(ctx));
	return ret;
}

int sm2_key_exchange_compute_confirm(int is_initiator,
	const SM2_KEY *key, const char *id, size_t idlen,
	const SM2_KEY *peer_public_key, const char *peer_id, size_t peer_idlen,
	const SM2_KEY *key_exchange, const uint8_t peer_key_exchange[65],
	const uint8_t shared_point[65], uint8_t confirm[32])
{
	if (sm2_key_exchange_compute_confirm_ex(is_initiator,
		key, id, idlen, peer_public_key, peer_id, peer_idlen,
		key_exchange, peer_key_exchange, shared_point, is_initiator, confirm) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_key_exchange_verify_confirm(int is_initiator,
	const SM2_KEY *key, const char *id, size_t idlen,
	const SM2_KEY *peer_public_key, const char *peer_id, size_t peer_idlen,
	const SM2_KEY *key_exchange, const uint8_t peer_key_exchange[65],
	const uint8_t shared_point[65], const uint8_t confirm[32])
{
	uint8_t expected[32];
	int ret;

	if (!confirm) {
		error_print();
		return -1;
	}
	if (sm2_key_exchange_compute_confirm_ex(is_initiator,
		key, id, idlen, peer_public_key, peer_id, peer_idlen,
		key_exchange, peer_key_exchange, shared_point, !is_initiator, expected) != 1) {
		error_print();
		return -1;
	}

	ret = gmssl_secure_memcmp(expected, confirm, sizeof(expected)) == 0 ? 1 : 0;
	gmssl_secure_clear(expected, sizeof(expected));
	return ret;
}
