/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <stdint.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/asn1.h>
#include <gmssl/error.h>


#define SM2_H_TEXT "GmSSL SM2 Pederson Commitment Generator H"


static int sm2_bn_rshift(SM2_BN ret, const SM2_BN a, unsigned int nbits)
{
	SM2_BN r;
	int i;
	for (i = 0; i < 7; i++) {
		r[i] = a[i] >> nbits;
		r[i] |= (a[i+1] << (32 - nbits)) & 0xffffffff;
	}
	r[i] = a[i] >> nbits;
	sm2_bn_copy(ret, r);
	return 1;
}

int sm2_point_from_hash(SM2_POINT *R, const uint8_t *data, size_t datalen)
{
	SM2_BN u;
	SM2_Fp x;
	SM2_Fp y;
	SM2_Fp s;
	SM2_Fp s_;
	uint8_t dgst[32];

	// u = (p-1)/4
	sm2_bn_sub(u, SM2_P, SM2_ONE);
	sm2_bn_rshift(u, u, 2);

	do {
		sm3_digest(data, datalen, dgst);

		sm2_bn_from_bytes(x, dgst);
		if (sm2_bn_cmp(x, SM2_P) >= 0) {
			sm2_bn_sub(x, x, SM2_P);
		}

		// s = x^3 + a*x + b
		sm2_fp_sqr(s, x);
		sm2_fp_sub(s, s, SM2_THREE);
		sm2_fp_mul(s, s, x);
		sm2_fp_add(s, s, SM2_B);

		// y = s^((p-1)/4) = (sqrt(s) (mod p))
		sm2_fp_exp(y, s, u);
		sm2_fp_sqr(s_, y);

		data = dgst;
		datalen = sizeof(dgst);

	} while (sm2_bn_cmp(s, s_) != 0);

	sm2_bn_to_bytes(x, R->x);
	sm2_bn_to_bytes(y, R->y);
	return 1;
}

int sm2_pederson_do_commit(const SM2_POINT *H, const uint8_t a[32], uint8_t r[32], SM2_POINT *C)
{
	SM2_BN r_;
	SM2_BN a_;

	sm2_bn_from_bytes(a_, a);
	if (sm2_bn_cmp(a_, SM2_N) >= 0) {
		error_print();
		memset(a_, 0, sizeof(a_));
		return -1;
	}

	do {
		sm2_fn_rand(r_);
	} while (sm2_bn_is_zero(r_));

	sm2_bn_to_bytes(r_, r);

	// C= r*H + a*G
	sm2_point_mul_sum(C, r, H, a);

	memset(a_, 0, sizeof(a_));
	memset(r_, 0, sizeof(r_));
	return 1;
}

int sm2_pederson_do_open(const SM2_POINT *H, const SM2_POINT *C, const uint8_t a[32], const uint8_t r[32])
{
	SM2_BN a_;
	SM2_POINT C_;

	sm2_bn_from_bytes(a_, a);
	if (sm2_bn_cmp(a_, SM2_N) >= 0) {
		error_print();
		memset(a_, 0, sizeof(a_));
		return -1;
	}

	sm2_point_mul_sum(&C_, r, H, a);
	if (memcmp(&C, C, sizeof(SM2_POINT)) != 0) {
		error_print();
		memset(a_, 0, sizeof(a_));
		return 0;
	}

	memset(a_, 0, sizeof(a_));
	return 1;
}

