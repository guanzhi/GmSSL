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
#include <gmssl/mem.h>
#include <gmssl/asn1.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include <gmssl/sm2_commit.h>


#define SM2_COMMIT_SEED "GmSSL SM2 Pederson Commitment Generator H"


// C = rG + xH
int sm2_commit_generate(const uint8_t x[32], uint8_t r[32], uint8_t commit[65], size_t *commitlen)
{
	SM2_POINT H;
	SM2_POINT C;
	SM2_BN r_;

	if (sm2_point_from_hash(&H, (uint8_t *)SM2_COMMIT_SEED, sizeof(SM2_COMMIT_SEED)-1) != 1) {
		error_print();
		return -1;
	}

	do {
		sm2_fn_rand(r_);
	} while (sm2_bn_is_zero(r_));

	sm2_bn_to_bytes(r_, r);
	gmssl_secure_clear(r_, sizeof(r_));

	// C = xH + rG
	sm2_point_mul_sum(&C, x, &H, r);

	sm2_point_to_compressed_octets(&C, commit);
	*commitlen = 33;
	return 1;
}

int sm2_commit_open(const uint8_t x[32], const uint8_t r[32], const uint8_t *commit, size_t commitlen)
{
	SM2_POINT H;
	SM2_POINT C;
	SM2_POINT C_;

	if (sm2_point_from_octets(&C, commit, commitlen) != 1) {
		error_print();
		return -1;
	}

	if (sm2_point_from_hash(&H, (uint8_t *)SM2_COMMIT_SEED, sizeof(SM2_COMMIT_SEED)-1) != 1) {
		error_print();
		return -1;
	}

	// C' = xH + rG
	if (sm2_point_mul_sum(&C_, x, &H, r) != 1) {
		error_print();
		return -1;
	}

	if (memcmp(&C, &C_, sizeof(SM2_POINT)) != 0) {
		error_print();
		return 0;
	}
	return 1;
}

// C = r*G + x1*H1 + x2*H2 + ...
int sm2_commit_vector_generate(const sm2_bn_t *x, size_t count, uint8_t r[32], uint8_t commit[65], size_t *commitlen)
{
	SM2_POINT H;
	SM2_POINT C;
	SM2_Fn r_;
	size_t i;

	if (count < 1) {
		error_print();
		return -1;
	}

	if (sm2_point_from_hash(&H, (uint8_t *)SM2_COMMIT_SEED, sizeof(SM2_COMMIT_SEED)-1) != 1) {
		error_print();
		return -1;
	}

	do {
		sm2_fn_rand(r_);
	} while (sm2_bn_is_zero(r_));

	sm2_bn_to_bytes(r_, r);
	gmssl_secure_clear(r_, sizeof(r_));

	if (sm2_point_mul_sum(&C, x[0], &H, r) != 1) {
		error_print();
		return -1;
	}

	for (i = 1; i < count; i++) {
		SM2_POINT xH;

		if (sm2_point_from_hash(&H, (uint8_t *)&H, sizeof(H)) != 1
			|| sm2_point_mul(&xH, x[i], &H) != 1
			|| sm2_point_add(&C, &C, &xH) != 1) {
			error_print();
			return -1;
		}
	}

	sm2_point_to_compressed_octets(&C, commit);
	*commitlen = 33;
	return 1;
}

int sm2_commit_vector_open(const sm2_bn_t *x, size_t count, const uint8_t r[32], const uint8_t *commit, size_t commitlen)
{
	SM2_POINT H;
	SM2_POINT C;
	SM2_POINT C_;
	size_t i;

	if (count < 1) {
		error_print();
		return -1;
	}

	if (sm2_point_from_octets(&C, commit, commitlen) != 1) {
		error_print();
		return -1;
	}

	if (sm2_point_from_hash(&H, (uint8_t *)SM2_COMMIT_SEED, sizeof(SM2_COMMIT_SEED)-1) != 1) {
		error_print();
		return -1;
	}

	if (sm2_point_mul_sum(&C_, x[0], &H, r) != 1) {
		error_print();
		return -1;
	}

	for (i = 1; i< count; i++) {
		SM2_POINT xH;

		if (sm2_point_from_hash(&H, (uint8_t *)&H, sizeof(H)) != 1
			|| sm2_point_mul(&xH, x[i], &H) != 1
			|| sm2_point_add(&C_, &C_, &xH) != 1) {
			error_print();
			return -1;
		}
	}

	if (memcmp(&C, &C_, sizeof(SM2_POINT)) != 0) {
		error_print();
		return -1;
	}
	return 1;
}
