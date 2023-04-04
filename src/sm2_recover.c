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


extern SM2_BN SM2_P;
extern SM2_BN SM2_B;
extern SM2_BN SM2_N;
extern SM2_BN SM2_THREE;

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

	// FIXME: check r, s
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

// verify the xR of R = s * G + (s + r) * P
// so (-r, -s) is also a valid SM2 signature
int sm2_signature_conjugate(const SM2_SIGNATURE *sig, SM2_SIGNATURE *new_sig)
{
	SM2_Fn r;
	SM2_Fn s;

	// FIXME: check r,s
	sm2_bn_from_bytes(r, sig->r);
	sm2_bn_from_bytes(s, sig->s);
	sm2_fn_neg(r, r);
	sm2_fn_neg(s, s);
	sm2_bn_to_bytes(r, new_sig->r);
	sm2_bn_to_bytes(s, new_sig->s);

	return 1;
}

// TODO: Add API to support sig,siglen



