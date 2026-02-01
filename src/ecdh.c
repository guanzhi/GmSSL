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
#include <gmssl/secp256r1_key.h>


int secp256r1_do_ecdh(const SECP256R1_KEY *key, const SECP256R1_KEY *peer_key, uint8_t out[32])
{
	SECP256R1_POINT point;
	secp256r1_t x;
	secp256r1_t y;

	if (!key || !peer_key || !out) {
		error_print();
		return -1;
	}
	secp256r1_point_mul(&point, key->private_key, &peer_key->public_key);
	secp256r1_point_get_xy(&point, x, y);
	secp256r1_to_32bytes(x, out);

	gmssl_secure_clear(&point, sizeof(SECP256R1_POINT));
	gmssl_secure_clear(x, sizeof(secp256r1_t));
	gmssl_secure_clear(y, sizeof(secp256r1_t));
	return 1;
}

int secp256r1_ecdh(const SECP256R1_KEY *key, const uint8_t uncompressed_point[65], uint8_t out[32])
{
	SECP256R1_POINT point;
	secp256r1_t x;
	secp256r1_t y;

	if (!key || !uncompressed_point || !out) {
		error_print();
		return -1;
	}
	if (secp256r1_point_from_uncompressed_octets(&point, uncompressed_point) != 1) {
		error_print();
		return -1;
	}
	secp256r1_point_mul(&point, key->private_key, &point);
	secp256r1_point_get_xy(&point, x,y);
	secp256r1_to_32bytes(x, out);

	gmssl_secure_clear(&point, sizeof(SECP256R1_POINT));
	gmssl_secure_clear(x, sizeof(secp256r1_t));
	gmssl_secure_clear(y, sizeof(secp256r1_t));
	return 1;
}
