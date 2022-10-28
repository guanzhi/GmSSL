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
#include <gmssl/asn1.h>
#include <gmssl/error.h>
#include "sm2_elgamal.h"


int sm2_elgamal_encrypt(const SM2_KEY *pub_key, sm2_elgamal_plaintext_t in, SM2_ELGAMAL_CIPHERTEXT *out)
{
	SM2_Fn k;
	uint8_t k_bytes[32];
	SM2_Fn m;
	uint8_t m_bytes[32];

	do {
		sm2_fn_rand(k); // FIXME: sm2_fn_rand() return value!
	} while (sm2_bn_is_zero(k));
	sm2_bn_to_bytes(k, k_bytes);


	if (sm2_point_mul_generator(&out->C1, k_bytes) != 1) {
		error_print();
		return -1;
	}

	sm2_bn_set_word(m, in);
	sm2_bn_to_bytes(m, m_bytes);

	if (sm2_point_mul_sum(&out->C2, k_bytes, &pub_key->public_key, m_bytes) != 1) {
		error_print();
		return -1;
	}
	return 1;
}


// M = m * G = -[x]C1 + C2
int sm2_elgamal_decrypt(const SM2_KEY *key, const SM2_ELGAMAL_CIPHERTEXT *in, sm2_elgamal_plaintext_t *out)
{
	SM2_Fn x;
	SM2_JACOBIAN_POINT M;
	SM2_JACOBIAN_POINT M_;
	SM2_JACOBIAN_POINT C1;
	SM2_JACOBIAN_POINT C2;
	uint8_t bytes[64];
	uint32_t m;

	sm2_bn_from_bytes(x, key->private_key);
	sm2_jacobian_point_from_bytes(&C1, (const uint8_t *)&in->C1);
	sm2_jacobian_point_from_bytes(&C2, (const uint8_t *)&in->C2);

	sm2_jacobian_point_mul(&C1, x, &C1);
	sm2_jacobian_point_neg(&C1, &C1);
	sm2_jacobian_point_add(&M, &C1, &C2);

	sm2_jacobian_point_to_bytes(&M, bytes);

	sm2_jacobian_point_init(&M_);

	// TODO: a real algor required
	for (m = 1; m < INT_MAX; m++) {
		uint8_t point[64];

		sm2_jacobian_point_add(&M_, &M_, SM2_G);
		sm2_jacobian_point_to_bytes(&M_, point);
		if (memcmp(point, bytes, 64) == 0) {
			*out = m;
			return 1;
		}
	}

	error_print();
	return -1;
}

int test_sm2_elgamal_encrypt(void)
{
	SM2_KEY key;
	SM2_ELGAMAL_CIPHERTEXT C1;
	SM2_ELGAMAL_CIPHERTEXT C2;
	sm2_elgamal_plaintext_t m = 1555;


	sm2_key_generate(&key);
	sm2_elgamal_encrypt(&key, m, &C1);

	m = 0;
	sm2_elgamal_decrypt(&key, &C1, &m);

	printf("m = %u\n", m);

	return 1;

}


// ([k1]G, [m1]G + [k1]P) + ([k2]G, [m2]G + [k2]P) =>
// ([k1]G + [k2]G + [r]G, [m1]G + [m2]G + [k1]P + [k2]P + [r]P)

int sm2_elgamal_ciphertext_add(SM2_ELGAMAL_CIPHERTEXT *r,
	const SM2_ELGAMAL_CIPHERTEXT *a,
	const SM2_ELGAMAL_CIPHERTEXT *b,
	const SM2_KEY *pub_key)
{
	SM2_Fn k;
	SM2_JACOBIAN_POINT A1;
	SM2_JACOBIAN_POINT A2;
	SM2_JACOBIAN_POINT B1;
	SM2_JACOBIAN_POINT B2;
	SM2_JACOBIAN_POINT R1;
	SM2_JACOBIAN_POINT R2;

	sm2_jacobian_point_from_bytes(&A1, (uint8_t *)&a->C1);
	sm2_jacobian_point_from_bytes(&A2, (uint8_t *)&a->C2);
	sm2_jacobian_point_from_bytes(&B1, (uint8_t *)&b->C1);
	sm2_jacobian_point_from_bytes(&B2, (uint8_t *)&b->C2);

	sm2_jacobian_point_add(&A1, &A1, &B1);
	sm2_jacobian_point_add(&A2, &A2, &B2);

	do {
		sm2_fn_rand(k);
	} while (sm2_bn_is_zero(k));

	sm2_jacobian_point_mul_generator(&R1, k);
	sm2_jacobian_point_add(&A1, &A1, &R1);


	sm2_jacobian_point_from_bytes(&R2, (const uint8_t *)&pub_key->public_key);
	sm2_jacobian_point_mul(&R2, k, &R2);
	sm2_jacobian_point_add(&A2, &A2, &R2);


	sm2_jacobian_point_to_bytes(&A1, (uint8_t *)&r->C1);
	sm2_jacobian_point_to_bytes(&A2, (uint8_t *)&r->C2);

	return 1;
}

int sm2_elgamal_cipehrtext_sub(SM2_ELGAMAL_CIPHERTEXT *r,
	const SM2_ELGAMAL_CIPHERTEXT *a, const SM2_ELGAMAL_CIPHERTEXT *b,
	const SM2_KEY *pub_key)
{
	error_print();
	return -1;
}

int sm2_elgamal_cipehrtext_neg(SM2_ELGAMAL_CIPHERTEXT *r, const SM2_ELGAMAL_CIPHERTEXT *a, const SM2_KEY *pub_key)
{
	error_print();
	return -1;
}

// s * (C1, C2) := ([s]C1 + [r]G, [s]C2 + [r]P)
int sm2_elgamal_ciphertext_scalar_mul(SM2_ELGAMAL_CIPHERTEXT *r, const uint8_t scalar[32], const SM2_ELGAMAL_CIPHERTEXT *a, const SM2_KEY *pub_key)
{
	SM2_BN r;
	uint8_t r_bytes[32];

	SM2_BN s;
	SM2_JACOBIAN_POINT C;
	SM2_JACOBIAN_POINT P;

	do {
		sm2_fn_rand(r);  // FIXME: return value
	} while (sm2_bn_is_zero(r));
	sm2_bn_to_bytes(r, r_bytes);

	sm2_point_mul_sum(&r->C1, scalar, &a->C1, r_bytes);

	sm2_bn_from_bytes(s, scalar);
	sm2_jacobian_point_from_bytes(&C, &a->C2);
	sm2_jacobian_point_from_bytes(&P, &pub_key->public_key);
	sm2_jacobian_point_mul(&C, s, &C);
	sm2_jacobian_point_mul(&P, r, &P);
	sm2_jacobian_point_add(&C, &C, &P);
	sm2_jacobian_point_to_bytes(&C, (uint8_t *)&r->C2);

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

#if 0
int main(void)
{

	test_sm2_elgamal_encrypt();

	return 0;
}
#endif

