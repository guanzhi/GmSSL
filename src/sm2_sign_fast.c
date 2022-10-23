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
#include <gmssl/error.h>


// (x1, y1) = k * G
// r = e + x1
// s = (k - r * d)/(1 + d) = (k +r - r * d - r)/(1 + d) = (k + r - r(1 +d))/(1 + d) = (k + r)/(1 + d) - r
//	= -r + (k + r)*(1 + d)^-1
//	= -r + (k + r) * d'

int sm2_do_sign_fast(const SM2_Fn d, const uint8_t dgst[32], SM2_SIGNATURE *sig)
{
	SM2_JACOBIAN_POINT R;
	SM2_BN e;
	SM2_BN k;
	SM2_BN x1;
	SM2_BN r;
	SM2_BN s;

	// e = H(M)
	sm2_bn_from_bytes(e, dgst);
	if (sm2_bn_cmp(e, SM2_N) >= 0) {
		sm2_bn_sub(e, e, SM2_N);
	}

	// rand k in [1, n - 1]
	do {
		sm2_fn_rand(k);
	} while (sm2_bn_is_zero(k));

	// (x1, y1) = kG
	sm2_jacobian_point_mul_generator(&R, k);
	sm2_jacobian_point_get_xy(&R, x1, NULL);

	// r = e + x1 (mod n)
	sm2_fn_add(r, e, x1);

	// s = (k + r) * d' - r
	sm2_bn_add(s, k, r);
	sm2_fn_mul(s, s, d);
	sm2_fn_sub(s, s, r);

	sm2_bn_to_bytes(r, sig->r);
	sm2_bn_to_bytes(s, sig->s);
	return 1;
}

