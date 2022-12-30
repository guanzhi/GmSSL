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
#include <gmssl/sm2_key_share.h>
#include <gmssl/mem.h>
#include <gmssl/error.h>

extern SM2_BN SM2_N;

int sm2_key_share_print(FILE *fp, int fmt, int ind, const char *label, const SM2_KEY_SHARE *share)
{
	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	format_print(fp, fmt, ind, "%zu/%zu\n", share->index, share->total_cnt);
	format_print(fp, fmt, ind, "key", &share->key);
	return 1;
}


// y = f(x)
static void eval_univariate_poly(SM2_Fn y, const SM2_Fn *coeffs, size_t coeffs_cnt, uint32_t x)
{
	sm2_bn_set_zero(y);
	while (coeffs_cnt--) {
		sm2_fn_mul_word(y, y, x);
		sm2_fn_add(y, y, coeffs[coeffs_cnt]);
	}
}

int sm2_key_split(const SM2_KEY *key, size_t recover_cnt, size_t total_cnt, SM2_KEY_SHARE *shares)
{
	SM2_Fn coeffs[SM2_KEY_MAX_SHARES];
	SM2_Fn y;
	uint8_t y_bytes[32];
	size_t i;

	if (!key || !shares) {
		error_print();
		return -1;
	}
	if (!total_cnt || total_cnt > SM2_KEY_MAX_SHARES) {
		error_print();
		return -1;
	}
	if (!recover_cnt || recover_cnt > total_cnt) {
		error_print();
		return -1;
	}
	// try to access mem
	memset(shares, 0, sizeof(SM2_KEY_SHARE) * total_cnt);

	for (i = 1; i < recover_cnt; i++) {
		if (sm2_fn_rand(coeffs[i]) != 1) {
			error_print();
			return -1;
		}
	}
	sm2_bn_from_bytes(coeffs[0], key->private_key);

	for (i = 0; i < total_cnt; i++) {
		uint32_t x = (uint32_t)(i + 1);
		eval_univariate_poly(y, coeffs, recover_cnt, x);
		sm2_bn_to_bytes(y, y_bytes);
		sm2_key_set_private_key(&(shares[i].key), y_bytes);
		shares[i].index = i;
		shares[i].total_cnt = total_cnt;
	}

	gmssl_secure_clear(coeffs, sizeof(coeffs));
	gmssl_secure_clear(y, sizeof(y));
	gmssl_secure_clear(y_bytes, sizeof(y_bytes));
	return 1;
}

int sm2_key_recover(SM2_KEY *key, const SM2_KEY_SHARE *shares, size_t shares_cnt)
{
	SM2_Fn s;
	uint8_t s_bytes[32];
	int x_i;
	SM2_Fn y_i;
	size_t i, j, k, n;

	if (!shares || !shares_cnt || !key) {
		error_print();
		return -1;
	}

	k = shares_cnt;
	n = shares[0].total_cnt;

	if (n > SM2_KEY_MAX_SHARES) {
		error_print();
		return -1;
	}
	for (i = 0; i < k; i++) {
		if (shares[i].total_cnt != n
			|| shares[i].index >= n) {
			error_print();
			return -1;
		}
	}

	sm2_bn_set_zero(s);

	for (i = 0; i < k; i++) {
		// delta_i
		SM2_Fn d;
		int num = 1;
		int den = 1;
		int sign = 1;

		x_i = (int)(shares[i].index + 1);

		for (j = 0; j < k; j++) {
			if (i != j) {
				int x_j = (int)(shares[j].index + 1);
				num *= -x_j;
				den *= x_i - x_j;
			}
		}
		if (num < 0) {
			num = -num;
			sign = -sign;
		}
		if (den < 0) {
			den = -den;
			sign = -sign;
		}

		// delta_i = Fn( num / den )
		sm2_bn_set_word(d, den);
		sm2_fn_inv(d, d);
		sm2_fn_mul_word(d, d, num);
		if (sign < 0) {
			sm2_fn_neg(d, d);
		}

		// s += delta_i * y_i
		sm2_bn_from_bytes(y_i, shares[i].key.private_key);
		if (sm2_bn_cmp(y_i, SM2_N) >= 0) {
			gmssl_secure_clear(y_i, sizeof(y_i));
			gmssl_secure_clear(s, sizeof(s));
			error_print();
			return -1;
		}
		sm2_fn_mul(y_i, y_i, d);
		sm2_fn_add(s, s, y_i);
	}

	sm2_bn_to_bytes(s, s_bytes);
	sm2_key_set_private_key(key, s_bytes);

	gmssl_secure_clear(y_i, sizeof(y_i));
	gmssl_secure_clear(s, sizeof(s));
	gmssl_secure_clear(s_bytes, sizeof(s_bytes));
	return 1;
}

int sm2_key_share_encrypt_to_file(const SM2_KEY_SHARE *share, const char *pass, const char *path_prefix)
{
	int ret;
	char *path = NULL;
	FILE *fp = NULL;
	int len;

	if (!share || !pass || !path_prefix) {
		error_print();
		return -1;
	}
	if (!share->total_cnt || share->total_cnt > 12 || share->index >= share->total_cnt) {
		sm2_key_share_print(stderr, 0, 0, "share", share);
		error_print();
		return -1;
	}
	if ((len = snprintf(NULL, 0, "%s-%zu-of-%zu.pem", path_prefix, share->index + 1, share->total_cnt)) <= 0) {
		error_print();
		return -1;
	}
	if (!(path = malloc(len + 1))) {
		error_print();
		return -1;
	}
	snprintf(path, len+1, "%s-%zu-of-%zu.pem", path_prefix, share->index + 1, share->total_cnt);


	if (!(fp = fopen(path, "wb"))) {
		error_print();
		goto end;
	}
	if (sm2_private_key_info_encrypt_to_pem(&share->key, pass, fp) != 1) {
		error_print();
		goto end;
	}
	ret = 1;
end:
	if (path) free(path);
	if (fp) fclose(fp);
	return ret;
}

int sm2_key_share_decrypt_from_file(SM2_KEY_SHARE *share, const char *pass, const char *file)
{
	error_print();
	return -1;
}
