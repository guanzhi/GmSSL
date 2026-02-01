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
