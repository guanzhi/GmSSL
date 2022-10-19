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
#include <assert.h>
#include <gmssl/sm2.h>
#include <gmssl/error.h>
#include "sm2_recover.h"


static int sm2_bn_rshift(SM2_BN ret, const SM2_BN a, unsigned int nbits)
{
	SM2_BN r;
	int i;
	assert(nbits < 32);
	for (i = 0; i < 7; i++) {
		r[i] = a[i] >> nbits;
		r[i] |= (a[i+1] << (32 - nbits)) & 0xffffffff;
	}
	r[i] = a[i] >> nbits;
	sm2_bn_copy(ret, r);
	return 1;
}

static int test_sm2_bn_rshift(void)
{
	SM2_BN a;
	int i;

	sm2_bn_from_hex(a, "ad23f3bff55b45c7192e25efcefa5fcecab1f072cd04a88e6cf64bfd3f531966");
	sm2_bn_print(stderr, 0, 0, "a", a);

	for (i = 0; i < 64; i++) {
		sm2_bn_rshift(a, a, 31);
		sm2_bn_print(stderr, 0, 0, "a", a);
	}

	return 0;
}

static int sm2_fp_sqrt(SM2_Fp r, const SM2_Fp a)
{
	SM2_BN u;
	SM2_BN y; // temp result, prevent call sm2_fp_sqrt(a, a)

	// r = a^((p - 1)/4) when p = 3 (mod 4)
	sm2_bn_add(u, SM2_P, SM2_ONE);
	sm2_bn_rshift(u, u, 2);
	sm2_fp_exp(y, a, u);

	// check r^2 == a
	sm2_fp_sqr(u, y);
	if (sm2_bn_cmp(u, a) != 0) {
		error_print();
		return -1;
	}

	sm2_bn_copy(r, y);
	return 1;
}

static int test_sm2_fp_sqrt(void)
{
	// a = 0x998eb0e4b8399fb359268966270049a6a4a317f9417c572c910d80c09969dc3
	// a^2 = 0x1b20ef7d2082f66c7561cdd4cdb0a8d58fa753e3e0d2e0560c80c849568f3fdb
	return 1;
}

// r = H(Z||M) + x1 (mod n)
// x1 = r - H(Z||M) (mod n) or (r - H(Z||M) (mod n)) + n
// y1 = sqrt(x1^3 + a*x1 + b)
// R = (x1, y1) or (x1, -y1)
// P = (r + s)^-1 * R - (r + s)^-1 * s * G
int sm2_signature_to_public_key_points(const SM2_SIGNATURE *sig, const uint8_t dgst[32],
	SM2_POINT points[4], size_t *points_cnt)
{
	SM2_BN SM2_P_SUB_N;
	SM2_JACOBIAN_POINT P;
	SM2_JACOBIAN_POINT R;

	SM2_Fp r;
	SM2_Fp s;
	SM2_Fp e;
	SM2_Fn u;
	SM2_Fn v;
	SM2_Fp x1;
	SM2_Fp y1;

	sm2_bn_from_bytes(r, sig->r);
	sm2_bn_from_bytes(s, sig->s);

	// u = (r + s)^-1, v = -(r + s)^-1 * s
	sm2_fn_add(u, r, s);
	sm2_fn_inv(u, u);
	sm2_fn_mul(v, u, s);
	sm2_fn_neg(v, v);

	// e = H(Z||M) (mod n)
	sm2_bn_from_bytes(e, dgst);
	if (sm2_bn_cmp(e, SM2_N) >= 0) {
		sm2_bn_sub(e, e, SM2_N);
	}

	// x1 = r - e (mod n)
	sm2_fn_sub(x1, r, e);

	// y1 = sqrt(x1^3 + a*x + b) = sqrt((x1^2 + a)*x1 + b)
	sm2_fp_sqr(y1, x1);
	sm2_fp_sub(y1, y1, SM2_THREE);
	sm2_fp_mul(y1, y1, x1);
	sm2_fp_add(y1, y1, SM2_B);

	if (sm2_fp_sqrt(y1, y1) != 1) {
		error_print();
		return -1;
	}
	sm2_jacobian_point_set_xy(&R, x1, y1);

	// P = u * R + v * G
	sm2_jacobian_point_mul_sum(&P, u, &R, v);
	sm2_jacobian_point_to_bytes(&P, (uint8_t *)&points[0]);

	// P' = u * (-R) + v * G
	sm2_jacobian_point_neg(&R, &R);
	sm2_jacobian_point_mul_sum(&P, u, &R, v);
	sm2_jacobian_point_to_bytes(&P, (uint8_t *)&points[1]);
	*points_cnt = 2;

	// if x1 in [n, p-1], x1 (mod n) in [0, p-n-1]
	// ==> if x1 (mod n) in [0, p-n-1], x1 == (x1 (mod n) + n) (mod p)
	sm2_bn_sub(SM2_P_SUB_N, SM2_P, SM2_N);

	if (sm2_bn_cmp(x1, SM2_P_SUB_N) < 0) {

		// x1' = x1 (mod n) + n
		sm2_bn_add(x1, x1, SM2_N);

		// y1' = sqrt(x1'^3 + a*x' + b)
		sm2_fp_sqr(y1, x1);
		sm2_fp_sub(y1, y1, SM2_THREE);
		sm2_fp_mul(y1, y1, x1);
		sm2_fp_add(y1, y1, SM2_B);
		if (sm2_fp_sqrt(y1, y1) != 1) {
			error_print();
			return -1;
		}
		sm2_jacobian_point_set_xy(&R, x1, y1);

		// P = u * R + v * G
		sm2_jacobian_point_mul_sum(&P, u, &R, v);
		sm2_jacobian_point_to_bytes(&P, (uint8_t *)&points[2]);
		// P' = u * (-R) + v * G
		sm2_jacobian_point_neg(&R, &R);
		sm2_jacobian_point_mul_sum(&P, u, &R, v);
		sm2_jacobian_point_to_bytes(&P, (uint8_t *)&points[3]);
		*points_cnt = 4;
	}

	return 1;
}

static int test_sm2_signature_to_public_key_points(void)
{
	SM2_KEY key;
	uint8_t dgst[32] = {1,2,3,4};
	SM2_SIGNATURE sig;
	SM2_POINT points[4];
	size_t points_cnt, i;

	sm2_key_generate(&key);
	sm2_do_sign(&key, dgst, &sig);
	sm2_signature_to_public_key_points(&sig, dgst, points, &points_cnt);

	for (i = 0; i < points_cnt; i++) {
		int vr;
		sm2_point_print(stderr, 0, 0, "point", &points[i]);
		vr = sm2_do_verify((SM2_KEY *)&points[1], dgst, &sig);
		printf("verify = %d\n", vr);
	}
	return 1;
}

#if 0
int main(void)
{
	//test_sm2_bn_rshift();
	//test_sm2_fp_sqrt();

	test_sm2_signature_to_public_key_points();
	return 0;
}
#endif
