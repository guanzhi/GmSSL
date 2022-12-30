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
#include <gmssl/sm2_key_share.h>
#include <gmssl/mem.h>
#include <gmssl/error.h>


static int test_sm2_key_share_args(size_t k, size_t n)
{
	SM2_KEY key;
	SM2_KEY key_;
	SM2_KEY_SHARE shares[SM2_KEY_MAX_SHARES];

	if (sm2_key_generate(&key) != 1) {
		error_print();
		return -1;
	}
	if (sm2_key_split(&key, k, n, shares) != 1) {
		error_print();
		return -1;
	}

	// recover from 0 .. k
	if (sm2_key_recover(&key_, shares, k) != 1) {
		error_print();
		return -1;
	}
	if (memcmp(&key_, &key, sizeof(SM2_KEY)) != 0) {
		error_print();
		return -1;
	}

	// recover from n-k .. n
	memset(&key_, 0, sizeof(key_));
	if (sm2_key_recover(&key_, shares + n - k, k) != 1) {
		error_print();
		return -1;
	}
	if (memcmp(&key_, &key, sizeof(SM2_KEY)) != 0) {
		error_print();
		return -1;
	}
	return 1;
}

static int test_sm2_key_share(void)
{
	if (test_sm2_key_share_args(1, 1) != 1) { error_print(); return -1; }
	if (test_sm2_key_share_args(1, 3) != 1) { error_print(); return -1; }
	if (test_sm2_key_share_args(2, 3) != 1) { error_print(); return -1; }
	if (test_sm2_key_share_args(3, 5) != 1) { error_print(); return -1; }
	if (test_sm2_key_share_args(4, 5) != 1) { error_print(); return -1; }
	if (test_sm2_key_share_args(5, 5) != 1) { error_print(); return -1; }
	if (test_sm2_key_share_args(11, 12) != 1) { error_print(); return -1; }
	if (test_sm2_key_share_args(12, 12) != 1) { error_print(); return -1; }
	return 1;
}

static int test_sm2_key_share_file(void)
{
	SM2_KEY key;
	SM2_KEY_SHARE shares[SM2_KEY_MAX_SHARES];

	if (sm2_key_generate(&key) != 1) {
		error_print();
		return -1;
	}
	if (sm2_key_split(&key, 2, 3, shares) != 1) {
		error_print();
		return -1;
	}
	if (sm2_key_share_encrypt_to_file(&shares[0], "123456", "sm2key") != 1
		|| sm2_key_share_encrypt_to_file(&shares[1], "123456", "sm2key") != 1
		|| sm2_key_share_encrypt_to_file(&shares[2], "123456", "sm2key") != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int main(void)
{
	return 0;
}
