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



typedef uint8_t sm2_bn_t[32];

int sm2_ring_do_sign(const SM2_KEY *sign_key,
	const SM2_POINT *public_keys, size_t public_keys_cnt,
	const uint8_t dgst[32], uint8_t r0[32], sm2_bn_t *s_vec)
{
	size_t i;
	size_t sign_index = public_keys_cnt;

	SM2_JACOBIAN_POINT R;
	SM2_JACOBIAN_POINT P;
	SM2_Fn e;
	SM2_Fn k;
	SM2_Fp x;
	SM2_Fn r;
	SM2_Fn s;
	SM2_Fn t;
	SM2_Fn d;

	// e = H(M) (mod n)
	sm2_bn_from_bytes(e, dgst);
	if (sm2_bn_cmp(e, SM2_N) >= 0) {
		sm2_bn_sub(e, e, SM2_N);
	}

	// find signer's index
	for (i = 0; i < public_keys_cnt; i++) {
		if (memcmp(&public_keys[i], &(sign_key->public_key), sizeof(SM2_POINT)) == 0) {
			sign_index = i;
			break;
		}
	}
	if (sign_index >= public_keys_cnt) {
		error_print();
		return -1;
	}

	// k[i] = rand(1, n-1), r[i], s[i] will be computed at the last step
	sm2_fn_rand(k);

	// R[i+1] = k[i] * G
	sm2_jacobian_point_mul_generator(&R, k);
	sm2_jacobian_point_get_xy(&R, x, NULL);

	// i = i + 1 (mod N)
	for (i = (i + 1) % public_keys_cnt; i != sign_index; i = (i + 1) % public_keys_cnt) {

		// r[i] = x[i] + e (mod n)
		sm2_fn_add(r, x, e);

		// output r[0]
		if (i == 0) {
			sm2_bn_to_bytes(r, r0);
		}

		// s[i] = rand(1, n-1)
		sm2_fn_rand(s);
		sm2_bn_to_bytes(s, s_vec[i]);

		// R[i+1] = k[i] * G = (s[i] + r[i]) * P[i] + s[i] * G
		sm2_fn_add(t, s, r);
		sm2_jacobian_point_from_bytes(&P, (const uint8_t *)&public_keys[i]);
		sm2_jacobian_point_mul_sum(&R, t, &P, s);
		sm2_jacobian_point_get_xy(&R, x, NULL);
	}

	// r[i] = x[i] + e (mod n)
	sm2_fn_add(r, x, e);

	// s[i] = (k[i] - r[i] * d)/(1 + d)
	sm2_bn_from_bytes(d, sign_key->private_key);
	sm2_fn_mul(r, r, d);
	sm2_fn_sub(s, k, r);
	sm2_fn_add(d, d, SM2_ONE);
	sm2_fn_inv(d, d);
	sm2_fn_mul(s, s, d);
	sm2_bn_to_bytes(s, s_vec[i]);

	// cleanup
	memset(d, 0, sizeof(d));
	memset(k, 0, sizeof(k));
	memset(r, 0, sizeof(r));
	return 1;
}

int sm2_ring_do_verify(const SM2_POINT *public_keys, size_t public_keys_cnt,
	const uint8_t dgst[32], const uint8_t r0[32], const sm2_bn_t *s_vec)
{
	SM2_JACOBIAN_POINT P;
	SM2_JACOBIAN_POINT R;
	SM2_Fn r;
	SM2_Fn r_;
	SM2_Fn s;
	SM2_Fn e;
	SM2_Fn t;
	SM2_Fn x;
	size_t i;

	sm2_bn_from_bytes(e, dgst);
	if (sm2_bn_cmp(e, SM2_N) >= 0) {
		sm2_bn_sub(e, e, SM2_N);
	}

	sm2_bn_from_bytes(r, r0);

	for (i = 0; i < public_keys_cnt; i++) {
		sm2_bn_from_bytes(s, s_vec[i]);

		// R(x, y) = k * G = s * G + (s + r) * P
		sm2_fn_add(t, s, r);
		sm2_jacobian_point_from_bytes(&P, (const uint8_t *)&public_keys[i]);
		sm2_jacobian_point_mul_sum(&R, t, &P, s);
		sm2_jacobian_point_get_xy(&R, x, NULL);

		// r = e + x (mod n)
		sm2_fn_add(r, x, e);
	}

	sm2_bn_from_bytes(r_, r0);
	if (sm2_bn_cmp(r_, r) != 0) {
		//error_print();
		return 0;
	}
	return 1;
}

static int test_sm2_ring_do_sign(void)
{
	SM2_KEY sign_key;
	SM2_KEY key;
	SM2_POINT public_keys[5];
	int sign_index = 2;
	int i;

	uint8_t dgst[32];
	uint8_t r0[32];
	uint8_t s_vec[5][32];

	for (i = 0; i < sizeof(public_keys)/sizeof(public_keys[0]); i++) {
		sm2_key_generate(&key);
		memcpy(&public_keys[i], &(key.public_key), sizeof(SM2_POINT));

		if (i == sign_index) {
			memcpy(&sign_key, &key, sizeof(SM2_KEY));
		}
	}

	sm2_ring_do_sign(&sign_key, public_keys, 5, dgst, r0, &s_vec[0]);

	i = sm2_ring_do_verify(public_keys, 5, dgst, r0, s_vec);

	printf("ret = %d\n", i);

	return 1;
}

