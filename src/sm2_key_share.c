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
#include <stdint.h>
#include <gmssl/sm2.h>
#include <gmssl/error.h>


typedef struct {
	SM2_KEY key;
	unsigned int index;
	unsigned int total_cnt;
} SM2_KEY_SHARE;


static int sm2_fn_mul_word(SM2_Fn r, const SM2_Fn a, uint32_t b)
{
	SM2_Fn t;
	sm2_bn_set_word(t, b);
	sm2_fn_mul(r, a, t);
	return 1;
}

static int eval_univariate_poly(const SM2_Fn *coeffs, size_t coeffs_cnt, unsigned int x, SM2_Fn out)
{
	sm2_bn_set_zero(out);

	while (coeffs_cnt--) {
		sm2_fn_mul_word(out, out, x);
		sm2_fn_add(out, out, coeffs[coeffs_cnt]);
	}
	return 1;
}

int sm2_key_split(const SM2_KEY *key, size_t recover_cnt, size_t total_cnt, SM2_KEY_SHARE *shares)
{
	SM2_Fn *coeffs = NULL;
	size_t coeffs_cnt = recover_cnt;
	size_t x;
	size_t i;

	SM2_Fn y;
	uint8_t y_bytes[32];

	// f(x) = a_0 + a_1 * x + ... + a_(k-1) * x^(k-1)
	// a_0 = private_key, a_i = rand(1, n-1)
	if (!(coeffs = (SM2_Fn *)malloc(sizeof(SM2_Fn) * coeffs_cnt))) {
		error_print();
		return -1;
	}
	sm2_bn_from_bytes(coeffs[0], key->private_key);

	for (i = 1; i < recover_cnt; i++) {
		sm2_fn_rand(coeffs[i]); // FIXME: check return value
	}

	for (x = 1; x <= total_cnt; x++) {
		SM2_KEY *key = &(shares[i].key);
		// y = f(x)
		eval_univariate_poly(coeffs, coeffs_cnt, x, y);

		sm2_bn_to_bytes(y, y_bytes);
		sm2_key_set_private_key(key, y_bytes);

		shares[i].index = x - 1;
		shares[i].total_cnt = total_cnt;
	}

	memset(y, 0, sizeof(SM2_Fn));
	memset(y_bytes, 0, sizeof(y_bytes));
	memset(coeffs, 0, sizeof(SM2_Fn) * coeffs_cnt);
	free(coeffs);
	return 1;
}

// n is total_cnt, out is delta[] array
// for i=1..n, delta[i] = prod(-j/(i - j)) in GF(N), j = 1..n, j != i
int generate_delta_list(size_t total_cnt, SM2_Fn *out)
{
	SM2_Fn a;
	size_t i, j;

	for (i = 0; i < total_cnt; i++) {
		sm2_bn_set_one(out[i]);

		for (j = 0; j < total_cnt; j++) {
			// Here i, j start from 0, so (i+1) and (j+1) is the needed value
			// a = -(j + 1)/((i + 1) - (j + 1)) = -(j + 1)/(i - j), i != j
			if (i < j) {
				sm2_bn_set_word(a, j - i);
			} else if (i > j) {
				sm2_bn_set_word(a, i - j);
				sm2_fn_neg(a, a);
			}
			sm2_fn_inv(a, a);
			sm2_fn_mul_word(a, a, j + 1);
			sm2_fn_mul(out[i], out[i], a);
		}
	}

	return 1;
}

int sm2_key_recover(const SM2_KEY_SHARE *shares, size_t shares_cnt, SM2_KEY *key)
{
	SM2_Fn a;
	SM2_Fn s;
	size_t i;
	size_t total_cnt;
	SM2_Fn *delta = NULL;
	uint8_t a_bytes[32];

	total_cnt = shares[0].total_cnt;
	for (i = 1; i < shares_cnt; i++) {
		if (shares[i].total_cnt != total_cnt
			|| shares[i].index > total_cnt) {
			error_print();
			return -1;
		}
	}

	if (!(delta = (SM2_Fn *)malloc(sizeof(SM2_Fn) * total_cnt))) {
		error_print();
		return -1;
	}
	generate_delta_list(total_cnt, delta);

	sm2_bn_set_zero(a);

	for (i = 0; i < shares_cnt; i++) {
		const SM2_KEY *key = &shares[i].key;

		sm2_bn_from_bytes(s, key->private_key);
		sm2_fn_mul(s, s, delta[shares[i].index]);
		sm2_fn_add(a, a, s);
	}

	sm2_bn_to_bytes(a, a_bytes);
	sm2_key_set_private_key(key, a_bytes);


	memset(a, 0, sizeof(a));
	memset(a_bytes, 0, sizeof(a_bytes));
	return 1;
}

