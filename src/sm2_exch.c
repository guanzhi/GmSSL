/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
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
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/asn1.h>
#include <gmssl/error.h>
#include <gmssl/endian.h>


int sm2_do_ecdh(const SM2_KEY *key, const SM2_Z256_POINT *peer_public, SM2_Z256_POINT *out)
{
	sm2_z256_point_mul(out, key->private_key, peer_public);
	return 1;
}

// FIXME: 输入(octets)和输出(bytes)格式不一致		
int sm2_ecdh(const SM2_KEY *key, const uint8_t *peer_public, size_t peer_public_len, uint8_t out[64])
{
	SM2_Z256_POINT point;

	if (!key || !peer_public || !peer_public_len || !out) {
		error_print();
		return -1;
	}
	if (sm2_z256_point_from_octets(&point, peer_public, peer_public_len) != 1) {
		error_print();
		return -1;
	}
	if (sm2_do_ecdh(key, &point, &point) != 1) {
		error_print();
		return -1;
	}

	sm2_z256_point_to_bytes(&point, out);
	return 1;
}
