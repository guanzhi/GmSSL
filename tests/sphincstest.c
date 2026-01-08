/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/hex.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include <gmssl/endian.h>
#include <gmssl/sphincs.h>


// 这个应该是用值去验证的
static int test_sphincs_wots_derive_sk(void)
{
	sphincs_secret_t secret;
	sphincs_secret_t seed;
	sphincs_adrs_t adrs;
	sphincs_wots_key_t wots_sk;

	sphincs_wots_derive_sk(secret, seed, adrs, wots_sk);

	sphincs_wots_key_print(stderr, 0, 4, "wots_sk", wots_sk);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sphincs_wots_chain(void)
{
	sphincs_secret_t x;
	sphincs_secret_t seed;
	sphincs_adrs_t adrs;
	sphincs_secret_t y;
	int start = 0;
	int steps = 15;

	sphincs_wots_chain(x, seed, adrs, start, steps, y);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sphincs_wots_sk_to_pk(void)
{
	sphincs_wots_key_t wots_sk;
	sphincs_secret_t seed;
	sphincs_adrs_t adrs;
	sphincs_wots_key_t wots_pk;

	sphincs_wots_sk_to_pk(wots_sk, seed, adrs, wots_pk);

	sphincs_wots_key_print(stderr, 0, 4, "wots_pk", wots_pk);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sphincs_wots_pk_to_root(void)
{
	sphincs_wots_key_t wots_pk;
	sphincs_secret_t seed;
	sphincs_adrs_t adrs;
	sphincs_secret_t wots_root;

	sphincs_wots_pk_to_root(wots_pk, seed, adrs, wots_root);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sphincs_wots_sign(void)
{
	sphincs_wots_key_t wots_sk;
	sphincs_secret_t seed;
	sphincs_adrs_t adrs;
	sphincs_secret_t dgst;
	sphincs_wots_sig_t wots_sig;

	sphincs_wots_sign(wots_sk, seed, adrs, dgst, wots_sig);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sphincs_wots_sig_to_pk(void)
{
	sphincs_wots_sig_t wots_sig;
	sphincs_secret_t seed;
	sphincs_adrs_t adrs;
	sphincs_secret_t dgst;
	sphincs_wots_key_t wots_pk;

	sphincs_wots_sig_to_pk(wots_sig, seed, adrs, dgst, wots_pk);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}


static int test_sphincs_wots_sign_verify(void)
{
	sphincs_wots_key_t wots_sk;
	sphincs_wots_key_t wots_pk;
	sphincs_secret_t seed;
	sphincs_adrs_t adrs;
	sphincs_secret_t dgst;
	sphincs_wots_sig_t wots_sig;
	sphincs_wots_key_t wots_pk2;

	sphincs_wots_sk_to_pk(wots_sk, seed, adrs, wots_pk);

	sphincs_wots_sign(wots_sk, seed, adrs, dgst, wots_sig);

	sphincs_wots_sig_to_pk(wots_sig, seed, adrs, dgst, wots_pk2);

	if (memcmp(wots_pk2, wots_pk, sizeof(sphincs_wots_key_t)) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (test_sphincs_wots_derive_sk() != 1) goto err;
	if (test_sphincs_wots_chain() != 1) goto err;
	if (test_sphincs_wots_sk_to_pk() != 1) goto err;
	if (test_sphincs_wots_pk_to_root() != 1) goto err;
	if (test_sphincs_wots_sign() != 1) goto err;
	if (test_sphincs_wots_sig_to_pk() != 1) goto err;
	if (test_sphincs_wots_sign_verify() != 1) goto err;

	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return -1;
}
