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


int sm2_do_ecdh(const SM2_KEY *key, const SM2_POINT *peer_public, SM2_POINT *out)
{
	/*
	if (sm2_point_is_on_curve(peer_public) != 1) {
		error_print();
		return -1;
	}
	*/
	if (sm2_point_mul(out, key->private_key, peer_public) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_ecdh(const SM2_KEY *key, const uint8_t *peer_public, size_t peer_public_len, SM2_POINT *out)
{
	SM2_POINT point;

	if (!key || !peer_public || !peer_public_len || !out) {
		error_print();
		return -1;
	}
	if (sm2_point_from_octets(&point, peer_public, peer_public_len) != 1) {
		error_print();
		return -1;
	}
	if (sm2_do_ecdh(key, &point, out) != 1) {
		error_print();
		return -1;
	}
	return 1;
}
