/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmssl/sm3.h>
#include <gmssl/hmac.h>
#include <gmssl/error.h>

/*

HKDF-Extract(salt, IKM) -> PRK

	salt optional, len(salt) == hash_len is recommended
	IKM input key material
	PRK output pseudorandom key, len(PRK) = hashLen

	PRK = HMAC_hash(salt, IKM)
	salt as key?


HKDF-Expand(PRK, info, L) -> OKM
	info optional
	L output length, L <= 255 * hashLen
	OKM output key


	N = (L + hashLen - 1)//hashLen
	T = T(1) || T(2) || ... | T(N)
	OKM = T[0..L-1]

	T(0) = empty string (len = 0)
	T(1) = HMAC_hash(PRK, T(0) | info | 0x01)
	T(2) = HMAC_hash(PRK, T(1) | info | 0x02)
	T(3) = HMAC_hash(PRK, T(2) | info | 0x03)
	...


*/

int hkdf_extract(const DIGEST *digest, const uint8_t *salt, size_t saltlen,
	const uint8_t *ikm, size_t ikmlen,
	uint8_t *prk, size_t *prklen)
{
	HMAC_CTX hmac_ctx;

	if (!salt || saltlen == 0) {
		uint8_t zeros[DIGEST_MAX_SIZE] = {0};
		if (hmac_init(&hmac_ctx, digest, zeros, digest->digest_size) != 1) {
			error_print();
			return -1;
		}
	} else {
		if (hmac_init(&hmac_ctx, digest, salt, saltlen) != 1) {
			error_print();
			return -1;
		}
	}

	if (hmac_update(&hmac_ctx, ikm, ikmlen) != 1
		|| hmac_finish(&hmac_ctx, prk, prklen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int hkdf_expand(const DIGEST *digest, const uint8_t *prk, size_t prklen,
	const uint8_t *opt_info, size_t opt_infolen,
	size_t L, uint8_t *okm)
{
	HMAC_CTX hmac_ctx;
	uint8_t T[HMAC_MAX_SIZE];
	uint8_t counter = 0x01;
	size_t len;

	if (L > 0) {
		if (hmac_init(&hmac_ctx, digest, prk, prklen) != 1
			|| hmac_update(&hmac_ctx, opt_info, opt_infolen) < 0
			|| hmac_update(&hmac_ctx, &counter, 1) != 1
			|| hmac_finish(&hmac_ctx, T, &len) != 1) {
			error_print();
			return -1;
		}
		counter++;
		if (len > L) {
			len = L;
		}
		memcpy(okm, T, len);
		okm += len;
		L -= len;
	}
	while (L > 0) {
		if (counter == 0) {
			error_print();
			return -1;
		}
		if (hmac_init(&hmac_ctx, digest, prk, prklen) != 1
			|| hmac_update(&hmac_ctx, T, len) != 1
			|| hmac_update(&hmac_ctx, opt_info, opt_infolen) < 0
			|| hmac_update(&hmac_ctx, &counter, 1) != 1
			|| hmac_finish(&hmac_ctx, T, &len) != 1) {
			error_print();
			return -1;
		}
		counter++;
		if (len > L) {
			len = L;
		}
		memcpy(okm, T, len);
		okm += len;
		L -= len;
	}
	return 1;
}

/*
int sm3_hkdf_extract(const uint8_t *salt, size_t saltlen,
	const uint8_t *ikm, size_t ikmlen,
	uint8_t *prk, size_t *prklen)
{
	SM3_HMAC_CTX hmac_ctx;

	if (!salt || saltlen == 0) {
		uint8_t zeros[SM3_HMAC_SIZE] = {0};
		if (sm3_hmac_init(&hmac_ctx, zeros, SM3_HMAC_SIZE) != 1) {
			error_print();
			return -1;
		}
	} else {
		if (sm3_hmac_init(&hmac_ctx, salt, saltlen) != 1) {
			error_print();
			return -1;
		}
	}

	if (sm3_hmac_update(&hmac_ctx, ikm, ikmlen) != 1
		|| sm3_hmac_finish(&hmac_ctx, prk) != 1) {
		error_print();
		return -1;
	}
	*prklen = SM3_HMAC_SIZE;
	return 1;
}

int sm3_hkdf_expand(const uint8_t *prk, size_t prklen,
	const uint8_t *opt_info, size_t opt_infolen,
	size_t L, uint8_t *okm)
{
	SM3_HMAC_CTX hmac_ctx;
	uint8_t T[SM3_HMAC_SIZE];
	uint8_t counter = 0x01;
	size_t len;

	if (L > 0) {
		if (sm3_hmac_init(&hmac_ctx, prk, prklen) != 1
			|| sm3_hmac_update(&hmac_ctx, opt_info, opt_infolen) < 0
			|| sm3_hmac_update(&hmac_ctx, &counter, 1) != 1
			|| sm3_hmac_finish(&hmac_ctx, T) != 1) {
			error_print();
			return -1;
		}
		counter++;
		len = SM3_HMAC_SIZE;
		if (len > L) {
			len = L;
		}
		memcpy(okm, T, len);
		okm += len;
		L -= len;
	}
	while (L > 0) {
		if (counter == 0) {
			error_print();
			return -1;
		}
		if (sm3_hmac_init(&hmac_ctx, digest, prk, prklen) != 1
			|| sm3_hmac_update(&hmac_ctx, T, len) != 1
			|| sm3_hmac_update(&hmac_ctx, opt_info, opt_infolen) < 0
			|| sm3_hmac_update(&hmac_ctx, &counter, 1) != 1
			|| sm3_hmac_finish(&hmac_ctx, T) != 1) {
			error_print();
			return -1;
		}
		counter++;
		len = SM3_HMAC_SIZE;
		if (len > L) {
			len = L;
		}
		memcpy(okm, T, len);
		okm += len;
		L -= len;
	}
	return 1;
}
*/
