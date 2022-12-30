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
#include <assert.h>
#include <gmssl/mem.h>
#include <gmssl/sm2_elgamal.h>
#include <gmssl/asn1.h>
#include <gmssl/error.h>


extern const SM2_JACOBIAN_POINT *SM2_G;



// generate baby-step table
int sm2_elgamal_decrypt_pre_compute(SM2_PRE_COMPUTE table[1<<16])
{
	SM2_JACOBIAN_POINT P;
	SM2_BN x;
	uint32_t i, j;

	memset(table, 0, sizeof(SM2_PRE_COMPUTE) * (1<<16));

	sm2_jacobian_point_set_infinity(&P);
	for (i = 0; i < (1<<16); i++) {
		sm2_jacobian_point_add(&P, &P, SM2_G);
		sm2_jacobian_point_get_xy(&P, x, NULL);
		sm2_bn_to_bytes(x, table[i].x_coordinate);

		j = ((uint16_t)table[i].x_coordinate[30] << 8) | table[i].x_coordinate[31];
		assert(table[j].offset_count <= SM2_PRE_COMPUTE_MAX_OFFSETS);

		table[j].offset[ table[j].offset_count ] = (uint16_t)i;
		(table[j].offset_count)++;
	}
	return 1;
}

static int sm2_pre_compute_get_offset(const SM2_PRE_COMPUTE table[1<<16], const uint8_t x[32], uint16_t *offset)
{
	uint32_t i = ((uint16_t)x[30] << 8) | x[31];
	uint16_t j;
	uint8_t w;

	for (w = 0; w < table[i].offset_count; w++) {
		j = table[i].offset[w];
		if (memcmp(x, table[j].x_coordinate, 32) == 0) {
			*offset = j;
			return 1;
		}
	}
	return 0;
}

// run gaint-step
int sm2_elgamal_solve_ecdlp(const SM2_PRE_COMPUTE table[1<<16], const SM2_POINT *point, uint32_t *private)
{
	int ret = 0;
	SM2_JACOBIAN_POINT P;
	SM2_JACOBIAN_POINT Q;
	SM2_BN k;
	SM2_BN x;
	uint8_t x_bytes[32];
	uint8_t Q_bytes[64];
	uint32_t i;
	uint16_t j;

	sm2_jacobian_point_from_bytes(&P, (uint8_t *)point);

	// Q = -[2^16]G
	sm2_bn_set_word(k, 65536);
	sm2_jacobian_point_mul_generator(&Q, k);
	sm2_jacobian_point_neg(&Q, &Q);

	// Q to Affine
	sm2_jacobian_point_to_bytes(&Q, Q_bytes);
	sm2_jacobian_point_from_bytes(&Q, Q_bytes);

	for (i = 0; i < (1<<16); i++) {
		// P - i*(kG) == O ==> d = i*k
		if (sm2_jacobian_point_is_at_infinity(&P)) {
			*private = (i << 16);
			ret = 1;
			goto ok;
		}

		sm2_jacobian_point_get_xy(&P, x, NULL);
		sm2_bn_to_bytes(x, x_bytes);
		if (sm2_pre_compute_get_offset(table, x_bytes, &j) == 1) {
			// P - i*(kG) == j*G ==> d = j + i*k
			*private = (i<<16) + j + 1; // table[0] is 1*G, so j + 1
			ret = 1;
			goto ok;
		}
		sm2_jacobian_point_add(&P, &P, &Q);
	}
	printf("gaint steps failed\n");

ok:
	i = j = 0;
	gmssl_secure_clear(x, sizeof(x));
	return ret;
}

int sm2_elgamal_do_encrypt(const SM2_KEY *pub_key, uint32_t in, SM2_ELGAMAL_CIPHERTEXT *out)
{
	int ret = -1;
	SM2_Fn k;
	SM2_Fn m;
	uint8_t k_bytes[32];
	uint8_t m_bytes[32];

	if (!pub_key || !out) {
		error_print();
		return -1;
	}

	do {
		if (sm2_fn_rand(k) != 1) {
			error_print();
			return -1;
		}
	} while (sm2_bn_is_zero(k));
	sm2_bn_to_bytes(k, k_bytes);

	// C1 = k * G
	if (sm2_point_mul_generator(&out->C1, k_bytes) != 1) {
		error_print();
		goto end;
	}

	// C2 = k * P + m * G
	sm2_bn_set_word(m, in);
	sm2_bn_to_bytes(m, m_bytes);
	if (sm2_point_mul_sum(&out->C2, k_bytes, &pub_key->public_key, m_bytes) != 1) {
		error_print();
		goto end;
	}
	ret = 1;

end:
	gmssl_secure_clear(k, sizeof(k));
	gmssl_secure_clear(m, sizeof(m));
	gmssl_secure_clear(k_bytes, sizeof(k_bytes));
	gmssl_secure_clear(m_bytes, sizeof(m_bytes));
	return ret;
}

// M = m*G = -x*C1 + C2
int sm2_elgamal_do_decrypt(const SM2_KEY *key, const SM2_ELGAMAL_CIPHERTEXT *in, uint32_t *out)
{
	static SM2_PRE_COMPUTE *table = NULL;
	SM2_POINT M;

	if (!key || !in || !out) {
		error_print();
		return -1;
	}

	sm2_point_mul(&M, key->private_key, &in->C1);
	sm2_point_sub(&M, &in->C2, &M);

	if (!table) {
		if (!(table = malloc(sizeof(SM2_PRE_COMPUTE) * (1<<16)))) {
			error_print();
			return -1;
		}
		sm2_elgamal_decrypt_pre_compute(table);
	}

	if (sm2_elgamal_solve_ecdlp(table, &M, out) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

// (A1, A2) = (k1*G, m1*G + k1*P)
// (B1, B2) = (k2*G, m2*G + k2*P)
// (R1, R2) = (A1 + B1 + k*G, A2 + B2 + k*P)
int sm2_elgamal_ciphertext_add(SM2_ELGAMAL_CIPHERTEXT *r,
	const SM2_ELGAMAL_CIPHERTEXT *a,
	const SM2_ELGAMAL_CIPHERTEXT *b,
	const SM2_KEY *pub_key)
{
	SM2_Fn k;
	uint8_t k_bytes[32];
	SM2_POINT R;

	if (!r || !a || !b || !pub_key) {
		error_print();
		return -1;
	}

	do {
		if (sm2_fn_rand(k) != 1) {
			error_print();
			return -1;
		}
	} while (sm2_bn_is_zero(k));
	sm2_bn_to_bytes(k, k_bytes);

	// R1 = A1 + B1 + k*G
	sm2_point_add(&r->C1, &a->C1, &b->C1);
	sm2_point_mul_generator(&R, k_bytes);
	sm2_point_add(&r->C1, &r->C1, &R);

	// R2 = A2 + B2 + k*P
	sm2_point_add(&r->C2, &a->C2, &b->C2);
	sm2_point_mul(&R, k_bytes, &pub_key->public_key);
	sm2_point_add(&r->C2, &r->C2, &R);

	gmssl_secure_clear(k, sizeof(k));
	gmssl_secure_clear(k_bytes, sizeof(k_bytes));
	return 1;
}

int sm2_elgamal_cipehrtext_sub(SM2_ELGAMAL_CIPHERTEXT *r,
	const SM2_ELGAMAL_CIPHERTEXT *a, const SM2_ELGAMAL_CIPHERTEXT *b,
	const SM2_KEY *pub_key)
{
	SM2_Fn k;
	uint8_t k_bytes[32];
	SM2_POINT R;

	if (!r || !a || !b || !pub_key) {
		error_print();
		return -1;
	}

	do {
		if (sm2_fn_rand(k) != 1) {
			error_print();
			return -1;
		}
	} while (sm2_bn_is_zero(k));
	sm2_bn_to_bytes(k, k_bytes);

	// R1 = A1 - B1 + k*G
	sm2_point_sub(&r->C1, &a->C1, &b->C1);
	sm2_point_mul_generator(&R, k_bytes);
	sm2_point_add(&r->C1, &a->C1, &R);

	// R2 = A2 - B2 + k*P
	sm2_point_sub(&r->C2, &a->C2, &b->C2);
	sm2_point_mul(&R, k_bytes, &pub_key->public_key);
	sm2_point_add(&r->C2, &r->C2, &R);

	gmssl_secure_clear(k, sizeof(k));
	gmssl_secure_clear(k_bytes, sizeof(k_bytes));
	return 1;
}

int sm2_elgamal_cipehrtext_neg(SM2_ELGAMAL_CIPHERTEXT *r,
	const SM2_ELGAMAL_CIPHERTEXT *a, const SM2_KEY *pub_key)
{
	SM2_Fn k;
	uint8_t k_bytes[32];
	SM2_POINT R;

	if (!r || !a || !pub_key) {
		error_print();
		return -1;
	}

	do {
		if (sm2_fn_rand(k) != 1) {
			error_print();
			return -1;
		}
	} while (sm2_bn_is_zero(k));
	sm2_bn_to_bytes(k, k_bytes);

	// R1 = -A1 + k*G = -r*G + k*G
	sm2_point_mul_generator(&R, k_bytes);
	sm2_point_sub(&r->C1, &R, &a->C1);

	// R2 = -A2 + k*P = -m*G -r*P + k*P
	sm2_point_mul(&R, k_bytes, &pub_key->public_key);
	sm2_point_sub(&r->C2, &R, &a->C2);

	gmssl_secure_clear(k, sizeof(k));
	gmssl_secure_clear(k_bytes, sizeof(k_bytes));
	return 1;
}

// s * (C1, C2) := (s*C1 + r*G, s*C2 + r*P)
int sm2_elgamal_ciphertext_scalar_mul(SM2_ELGAMAL_CIPHERTEXT *R,
	const uint8_t scalar[32], const SM2_ELGAMAL_CIPHERTEXT *A,
	const SM2_KEY *pub_key)
{
	SM2_Fn k;
	uint8_t k_bytes[32];
	SM2_POINT kP;

	if (!R || !scalar || !A || !pub_key) {
		error_print();
		return -1;
	}

	do {
		if (sm2_fn_rand(k) != 1) {
			error_print();
			return -1;
		}
	} while (sm2_bn_is_zero(k));
	sm2_bn_to_bytes(k, k_bytes);

	// R1 = s*C1 + k*G
	sm2_point_mul_sum(&R->C1, scalar, &A->C1, k_bytes);

	// R2 = s*C2 + r*P
	sm2_point_mul(&kP, k_bytes, &pub_key->public_key);
	sm2_point_mul(&R->C2, scalar, &A->C2);
	sm2_point_add(&R->C2, &R->C2, &kP);

	gmssl_secure_clear(k, sizeof(k));
	gmssl_secure_clear(k_bytes, sizeof(k_bytes));
	return 1;
}

int sm2_elgamal_ciphertext_to_der(const SM2_ELGAMAL_CIPHERTEXT *c, uint8_t **out, size_t *outlen)
{
	uint8_t c1[65];
	uint8_t c2[65];
	size_t len;

	sm2_point_to_uncompressed_octets(&c->C1, c1);
	sm2_point_to_uncompressed_octets(&c->C2, c2);

	if (asn1_octet_string_to_der(c1, sizeof(c1), NULL, &len) != 1
		|| asn1_octet_string_to_der(c2, sizeof(c2), NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_octet_string_to_der(c1, sizeof(c1), out, outlen) != 1
		|| asn1_octet_string_to_der(c2, sizeof(c2), out, outlen) != 1) {
		error_print();
		return -1;
	}

	return 1;
}

int sm2_elgamal_ciphertext_from_der(SM2_ELGAMAL_CIPHERTEXT *c, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;
	const uint8_t *c1;
	size_t c1len;
	const uint8_t *c2;
	size_t c2len;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		error_print();
		return -1;
	}
	if (asn1_octet_string_from_der(&c1, &c1len, &d, &dlen) != 1
		|| asn1_octet_string_from_der(&c2, &c2len, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	if (sm2_point_from_octets(&c->C1, c1, c1len) != 1
		|| sm2_point_from_octets(&c->C2, c2, c2len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_elgamal_encrypt(const SM2_KEY *pub_key, uint32_t in, uint8_t *out, size_t *outlen)
{
	SM2_ELGAMAL_CIPHERTEXT C;

	if (sm2_elgamal_do_encrypt(pub_key, in, &C) != 1) {
		error_print();
		return -1;
	}
	*outlen = 0;
	if (sm2_elgamal_ciphertext_to_der(&C, &out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_elgamal_decrypt(SM2_KEY *key, const uint8_t *in, size_t inlen, uint32_t *out)
{
	SM2_ELGAMAL_CIPHERTEXT C;

	if (sm2_elgamal_ciphertext_from_der(&C, &in, &inlen) != 1
		|| asn1_length_is_zero(inlen) != 1) {
		error_print();
		return -1;
	}
	if (sm2_elgamal_do_decrypt(key, &C, out) != 1) {
		error_print();
		return -1;
	}
	return 1;
}
