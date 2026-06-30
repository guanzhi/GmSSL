/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <gmssl/bn.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include <gmssl/secp256r1.h>


const secp256r1_t SECP256R1_P = {
	0xffffffff, 0xffffffff, 0xffffffff, 0x00000000,
	0x00000000, 0x00000000, 0x00000001, 0xffffffff,
};

const secp256r1_t SECP256R1_B = {
	0x27d2604b, 0x3bce3c3e, 0xcc53b0f6, 0x651d06b0,
	0x769886bc, 0xb3ebbd55, 0xaa3a93e7, 0x5ac635d8,
};

const secp256r1_t SECP256R1_N = {
	0xfc632551, 0xf3b9cac2, 0xa7179e84, 0xbce6faad,
	0xffffffff, 0xffffffff, 0x00000000, 0xffffffff,
};

const uint32_t SECP256R1_U_P[9] = {
	0x00000003, 0x00000000, 0xffffffff, 0xfffffffe,
	0xfffffffe, 0xfffffffe, 0xffffffff, 0x00000000,
	0x00000001,
};

const uint32_t SECP256R1_U_N[9] = {
	0xeedf9bfe, 0x012ffd85, 0xdf1a6c21, 0x43190552,
	0xffffffff, 0xfffffffe, 0xffffffff, 0x00000000,
	0x00000001,
};

int secp256r1_is_zero(const secp256r1_t a) {
	return bn_is_zero(a, SECP256R1_K);
}

int secp256r1_is_one(const secp256r1_t a) {
	return bn_is_one(a, SECP256R1_K);
}

int secp256r1_cmp(const secp256r1_t a, const secp256r1_t b) {
	return bn_cmp(a, b, SECP256R1_K);
}

int secp256r1_set_zero(secp256r1_t r) {
	bn_set_word(r, 0, SECP256R1_K);
	return 1;
}

int secp256r1_set_one(secp256r1_t r) {
	bn_set_word(r, 1, SECP256R1_K);
	return 1;
}

int secp256r1_copy(secp256r1_t r, const secp256r1_t a) {
	bn_copy(r, a, SECP256R1_K);
	return 1;
}

int secp256r1_to_32bytes(const secp256r1_t a, uint8_t out[32]) {
	bn_to_bytes(a, SECP256R1_K, out);
	return 1;
}

int secp256r1_from_32bytes(secp256r1_t r, const uint8_t in[32]) {
	bn_from_bytes(r, SECP256R1_K, in);
	return 1;
}

int secp256r1_print(FILE *fp, int fmt, int ind, const char *label, const secp256r1_t a) {
	uint8_t bytes[32];
	if (secp256r1_to_32bytes(a, bytes) != 1) {
		error_print();
		return -1;
	}
	format_bytes(fp, fmt, ind, label, bytes, 32);
	return 1;
}

int secp256r1_modp_add(secp256r1_t r, const secp256r1_t a, const secp256r1_t b) {
	bn_mod_add(r, a, b, SECP256R1_P, SECP256R1_K);
	return 1;
}

int secp256r1_modp_dbl(secp256r1_t r, const secp256r1_t a) {
	bn_mod_add(r, a, a, SECP256R1_P, SECP256R1_K);
	return 1;
}

int secp256r1_modp_tri(secp256r1_t r, const secp256r1_t a) {
	secp256r1_t tmp;

	bn_mod_add(tmp, a, a, SECP256R1_P, SECP256R1_K);
	bn_mod_add(r, tmp, a, SECP256R1_P, SECP256R1_K);
	return 1;
}

int secp256r1_modp_sub(secp256r1_t r, const secp256r1_t a, const secp256r1_t b) {
	bn_mod_sub(r, a, b, SECP256R1_P, SECP256R1_K);
	return 1;
}

int secp256r1_modp_neg(secp256r1_t r, const secp256r1_t a) {
	if (secp256r1_is_zero(a)) {
		secp256r1_set_zero(r);
	} else {
		bn_mod_neg(r, a, SECP256R1_P, SECP256R1_K);
	}
	return 1;
}

int secp256r1_modp_haf(secp256r1_t r, const secp256r1_t a) {
	int c = 0;
	if (a[0] & 1) {
		c = bn_add(r, a, SECP256R1_P, SECP256R1_K);
	} else {
		bn_copy(r, a, SECP256R1_K);
	}

	r[0] = (r[0] >> 1) | ((r[1] & 1) << 31);
	r[1] = (r[1] >> 1) | ((r[2] & 1) << 31);
	r[2] = (r[2] >> 1) | ((r[3] & 1) << 31);
	r[3] = (r[3] >> 1) | ((r[4] & 1) << 31);
	r[4] = (r[4] >> 1) | ((r[5] & 1) << 31);
	r[5] = (r[5] >> 1) | ((r[6] & 1) << 31);
	r[6] = (r[6] >> 1) | ((r[7] & 1) << 31);
	r[7] = (r[7] >> 1) | ((c & 1) << 31);
	return 1;
}

int secp256r1_modp_mul(secp256r1_t r, const secp256r1_t a, const secp256r1_t b) {
	uint32_t tmp[6*8 + 4];
	bn_barrett_mod_mul(r, a, b, SECP256R1_P, SECP256R1_U_P, tmp, SECP256R1_K);
	return 1;
}

int secp256r1_modp_sqr(secp256r1_t r, const secp256r1_t a) {
	uint32_t tmp[6*8 + 4];
	bn_barrett_mod_mul(r, a, a, SECP256R1_P, SECP256R1_U_P, tmp, SECP256R1_K);
	return 1;
}

int secp256r1_modp_exp(secp256r1_t r, const secp256r1_t a, const secp256r1_t e) {
	uint32_t tmp[7*8 + 4];
	bn_barrett_mod_exp(r, a, e, SECP256R1_P, SECP256R1_U_P, tmp, SECP256R1_K);
	return 1;
}

int secp256r1_modp_inv(secp256r1_t r, const secp256r1_t a) {
	uint32_t tmp[8*8 + 4];

	if (secp256r1_is_zero(a)) {
		error_print();
		return -1;
	}
	bn_barrett_mod_inv(r, a, SECP256R1_P, SECP256R1_U_P, tmp, SECP256R1_K);
	return 1;
}


int secp256r1_modn(secp256r1_t r, const secp256r1_t a) {
	if (bn_cmp(a, SECP256R1_N, SECP256R1_K) >= 0) {
		bn_sub(r, a, SECP256R1_N, SECP256R1_K);
	} else {
		bn_copy(r, a, SECP256R1_K);
	}
	return 1;
}

int secp256r1_modn_add(secp256r1_t r, const secp256r1_t a, const secp256r1_t b) {
	bn_mod_add(r, a, b, SECP256R1_N, SECP256R1_K);
	return 1;
}

int secp256r1_modn_dbl(secp256r1_t r, const secp256r1_t a) {
	bn_mod_add(r, a, a, SECP256R1_N, SECP256R1_K);
	return 1;
}

int secp256r1_modn_tri(secp256r1_t r, const secp256r1_t a) {
	secp256r1_t tmp;
	bn_mod_add(tmp, a, a, SECP256R1_N, SECP256R1_K);
	bn_mod_add(r, tmp, a, SECP256R1_N, SECP256R1_K);
	return 1;
}

int secp256r1_modn_sub(secp256r1_t r, const secp256r1_t a, const secp256r1_t b) {
	bn_mod_sub(r, a, b, SECP256R1_N, SECP256R1_K);
	return 1;
}

int secp256r1_modn_neg(secp256r1_t r, const secp256r1_t a) {
	if (secp256r1_is_zero(a)) {
		secp256r1_set_zero(r);
	} else {
		bn_mod_neg(r, a, SECP256R1_N, SECP256R1_K);
	}
	return 1;
}

int secp256r1_modn_mul(secp256r1_t r, const secp256r1_t a, const secp256r1_t b) {
	uint32_t tmp[6*8 + 4];
	bn_barrett_mod_mul(r, a, b, SECP256R1_N, SECP256R1_U_N, tmp, SECP256R1_K);
	return 1;
}

int secp256r1_modn_sqr(secp256r1_t r, const secp256r1_t a) {
	uint32_t tmp[6*8 + 4];
	bn_barrett_mod_mul(r, a, a, SECP256R1_N, SECP256R1_U_N, tmp, SECP256R1_K);
	return 1;
}

int secp256r1_modn_exp(secp256r1_t r, const secp256r1_t a, const secp256r1_t e) {
	uint32_t tmp[7*8 + 4];
	bn_barrett_mod_exp(r, a, e, SECP256R1_N, SECP256R1_U_N, tmp, SECP256R1_K);
	return 1;
}

int secp256r1_modn_inv(secp256r1_t r, const secp256r1_t a) {
	uint32_t tmp[8*8 + 4];

	if (secp256r1_is_zero(a)) {
		error_print();
		return -1;
	}
	bn_barrett_mod_inv(r, a, SECP256R1_N, SECP256R1_U_N, tmp, SECP256R1_K);
	return 1;
}


static const SECP256R1_POINT secp256r1_generator_point = {
	{ 0xd898c296, 0xf4a13945, 0x2deb33a0, 0x77037d81,
	  0x63a440f2, 0xf8bce6e5, 0xe12c4247, 0x6b17d1f2, },
	{ 0x37bf51f5, 0xcbb64068, 0x6b315ece, 0x2bce3357,
	  0x7c0f9e16, 0x8ee7eb4a, 0xfe1a7f9b, 0x4fe342e2, },
	{ 1,0,0,0,0,0,0,0, },
};

const SECP256R1_POINT *secp256r1_generator(void)
{
	return &secp256r1_generator_point;
}

int secp256r1_point_set_infinity(SECP256R1_POINT *R)
{
	if (secp256r1_set_one(R->X) != 1
		|| secp256r1_set_one(R->Y) != 1
		|| secp256r1_set_zero(R->Z) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp256r1_point_is_at_infinity(const SECP256R1_POINT *P)
{
	if (secp256r1_is_zero(P->Z)) {
		return 1;
	}
	return 0;
}

int secp256r1_point_is_on_curve(const SECP256R1_POINT *P)
{
	secp256r1_t t0;
	secp256r1_t t1;
	secp256r1_t t2;

	if (secp256r1_point_is_at_infinity(P)) {
		return 1;
	}

	// check Y^2 + 3 * X * Z^4 == X^3 + b * Z^6

	// t0 = Y^2
	if (secp256r1_modp_sqr(t0, P->Y) != 1) goto err;

	// t1 = Z^2
	if (secp256r1_modp_sqr(t1, P->Z) != 1) goto err;

	// t2 = Z^4
	if (secp256r1_modp_sqr(t2, t1) != 1) goto err;

	// t1 = Z^6
	if (secp256r1_modp_mul(t1, t1, t2) != 1) goto err;

	// t1 = b * Z^6
	if (secp256r1_modp_mul(t1, t1, SECP256R1_B) != 1) goto err;

	// t2 = X * Z^4
	if (secp256r1_modp_mul(t2, t2, P->X) != 1) goto err;

	// t0 = Y^2 + 3 * X * Z^4
	if (secp256r1_modp_add(t0, t0, t2) != 1
		|| secp256r1_modp_add(t0, t0, t2) != 1
		|| secp256r1_modp_add(t0, t0, t2) != 1) goto err;

	// t2 = X^2
	if (secp256r1_modp_sqr(t2, P->X) != 1) goto err;

	// t2 = X^3
	if (secp256r1_modp_mul(t2, t2, P->X) != 1) goto err;

	// t1 = b * Z^6 + X^3
	if (secp256r1_modp_add(t1, t1, t2) != 1) goto err;

	if (secp256r1_cmp(t0, t1) != 0) {
		return 0;
	}
	return 1;
err:
	error_print();
	return -1;
}

int secp256r1_point_copy(SECP256R1_POINT *R, const SECP256R1_POINT *P)
{
	if (secp256r1_copy(R->X, P->X) != 1
		|| secp256r1_copy(R->Y, P->Y) != 1
		|| secp256r1_copy(R->Z, P->Z) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp256r1_point_set_xy(SECP256R1_POINT *R, const secp256r1_t x, const secp256r1_t y)
{
	if (secp256r1_cmp(x, SECP256R1_P) >= 0) {
		error_print();
		return -1;
	}
	if (secp256r1_cmp(y, SECP256R1_P) >= 0) {
		error_print();
		return -1;
	}
	if (secp256r1_copy(R->X, x) != 1
		|| secp256r1_copy(R->Y, y) != 1
		|| secp256r1_set_one(R->Z) != 1) {
		error_print();
		return -1;
	}


	if (secp256r1_point_is_on_curve(R) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp256r1_point_get_xy(const SECP256R1_POINT *P, secp256r1_t x, secp256r1_t y)
{
	secp256r1_t Z_inv;

	if (secp256r1_point_is_at_infinity(P)) {
		error_print();
		return -1;
	}
	if (secp256r1_modp_inv(Z_inv, P->Z) != 1
		|| secp256r1_modp_mul(y, P->Y, Z_inv) != 1
		|| secp256r1_modp_sqr(Z_inv, Z_inv) != 1
		|| secp256r1_modp_mul(x, P->X, Z_inv) != 1
		|| secp256r1_modp_mul(y, y, Z_inv) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp256r1_point_dbl(SECP256R1_POINT *R, const SECP256R1_POINT *P)
{
	/*
	secp256r1_t T_0;
	secp256r1_t T_1;
	secp256r1_t T_2;
	secp256r1_t T_3;
	secp256r1_t T_4;

	if (secp256r1_point_is_at_infinity(P)) {
		secp256r1_point_set_infinity(R);
		return;
	}

	secp256r1_modp_sqr(T_0, P->X);
	secp256r1_modp_tri(T_0, T_0);
	secp256r1_modp_sqr(T_1, T_0);
	secp256r1_modp_sqr(T_2, P->Y);
	secp256r1_modp_mul(T_3, P->X, T_2);
	secp256r1_modp_dbl(T_3, T_3);
	secp256r1_modp_dbl(T_3, T_3);
	secp256r1_modp_dbl(T_4, T_3);
	secp256r1_modp_sub(T_1, T_1, T_4);
	secp256r1_modp_sub(T_3, T_3, T_1);
	secp256r1_modp_mul(T_0, T_0, T_3);
	secp256r1_modp_dbl(T_2, T_2);
	secp256r1_modp_sqr(T_2, T_2);
	secp256r1_modp_dbl(T_2, T_2);
	secp256r1_modp_sub(T_0, T_0, T_2);
	secp256r1_modp_mul(T_2, P->Y, P->Z);
	secp256r1_modp_dbl(T_2, T_2);

	secp256r1_copy(R->X, T_1);
	secp256r1_copy(R->Y, T_0);
	secp256r1_copy(R->Z, T_2);
	*/

	const uint32_t *X1 = P->X;
	const uint32_t *Y1 = P->Y;
	const uint32_t *Z1 = P->Z;
	uint32_t *X3 = R->X;
	uint32_t *Y3 = R->Y;
	uint32_t *Z3 = R->Z;
	secp256r1_t S;
	secp256r1_t M;
	secp256r1_t Zsqr;
	secp256r1_t tmp0;

	if (secp256r1_point_is_at_infinity(P)) {
		return secp256r1_point_set_infinity(R);
	}

	// 1. S = 2Y
	if (secp256r1_modp_dbl(S, Y1) != 1) goto err;

	// 2. Zsqr = Z^2
	if (secp256r1_modp_sqr(Zsqr, Z1) != 1) goto err;

	// 3. S = S^2 = 4Y^2
	if (secp256r1_modp_sqr(S, S) != 1) goto err;

	// 4. Z = Z*Y
	if (secp256r1_modp_mul(Z3, Z1, Y1) != 1) goto err;

	// 5. Z = 2*Z = 2*Y*Z ===> Z3
	if (secp256r1_modp_dbl(Z3, Z3) != 1) goto err;

	// 6. M = X + Zsqr = X + Z^2
	if (secp256r1_modp_add(M, X1, Zsqr) != 1) goto err;

	// 7. Zsqr = X - Zsqr = X - Z^2
	if (secp256r1_modp_sub(Zsqr, X1, Zsqr) != 1) goto err;

	// 8. Y = S^2 = 16Y^4
	if (secp256r1_modp_sqr(Y3, S) != 1) goto err;

	// 9. Y = Y/2 = 8Y^4
	if (secp256r1_modp_haf(Y3, Y3) != 1) goto err;

	// 10. M = M * Zsqr = (X + Z^2)*(X - Z^2) = X^2 - Z^4
	if (secp256r1_modp_mul(M, M, Zsqr) != 1) goto err;

	// 11. M = 3M = 3X^2 - 3Z^4
	if (secp256r1_modp_tri(M, M) != 1) goto err;

	// 12. S = S * X = 4X*Y^2
	if (secp256r1_modp_mul(S, S, X1) != 1) goto err;

	// 13. tmp0 = 2 * S = 8X*Y^2
	if (secp256r1_modp_dbl(tmp0, S) != 1) goto err;

	// 14. X = M^2 = (3X^2 - 3Z^4)^2
	if (secp256r1_modp_sqr(X3, M) != 1) goto err;

	// 15. X = X - tmp0 = (3X^2 - 3Z^4)^2 - 8X*Y^2 ===> X3
	if (secp256r1_modp_sub(X3, X3, tmp0) != 1) goto err;

	// 16. S = S - X3 = 4X*Y^2 - X3
	if (secp256r1_modp_sub(S, S, X3) != 1) goto err;

	// 17. S = S * M = (3X^2 - 3Z^4)*(4X*Y^2 - X3)
	if (secp256r1_modp_mul(S, S, M) != 1) goto err;

	// 18. Y = S - Y = (3X^2 - 3Z^4)*(4X*Y^2 - X3) - 8Y^4 ===> Y3
	if (secp256r1_modp_sub(Y3, S, Y3) != 1) goto err;

	return 1;
err:
	error_print();
	return -1;
}

int secp256r1_point_add(SECP256R1_POINT *R, const SECP256R1_POINT *P, const SECP256R1_POINT *Q)
{
	secp256r1_t T_1;
	secp256r1_t T_2;
	secp256r1_t T_3;
	secp256r1_t T_4;
	secp256r1_t T_5;
	secp256r1_t T_6;
	secp256r1_t T_7;
	secp256r1_t T_8;

	if (secp256r1_point_is_at_infinity(P)) {
		return secp256r1_point_copy(R, Q);
	}
	if (secp256r1_point_is_at_infinity(Q)) {
		return secp256r1_point_copy(R, P);
	}

	if (secp256r1_modp_sqr(T_1, P->Z) != 1		// T_1 = Z_1^2
		|| secp256r1_modp_sqr(T_2, Q->Z) != 1	// T_2 = Z_2^2
		|| secp256r1_modp_mul(T_3, Q->X, T_1) != 1	// T_3 = X_2 * Z_1^2
		|| secp256r1_modp_mul(T_4, P->X, T_2) != 1 	// T_4 = X_1 * Z_2^2
		|| secp256r1_modp_add(T_5, T_3, T_4) != 1	// T_5 = X_2 * Z_1^2 + X_1 * Z_2^2 = C
		|| secp256r1_modp_sub(T_3, T_3, T_4) != 1	// T_3 = X_2 * Z_1^2 - X_1 * Z_2^2 = B
		|| secp256r1_modp_mul(T_1, T_1, P->Z) != 1	// T_1 = Z_1^3
		|| secp256r1_modp_mul(T_1, T_1, Q->Y) != 1	// T_1 = Y_2 * Z_1^3
		|| secp256r1_modp_mul(T_2, T_2, Q->Z) != 1	// T_2 = Z_2^3
		|| secp256r1_modp_mul(T_2, T_2, P->Y) != 1	// T_2 = Y_1 * Z_2^3
		|| secp256r1_modp_add(T_6, T_1, T_2) != 1	// T_6 = Y_2 * Z_1^3 + Y_1 * Z_2^3 = D
		|| secp256r1_modp_sub(T_1, T_1, T_2) != 1) {	// T_1 = Y_2 * Z_1^3 - Y_1 * Z_2^3 = A
		error_print();
		return -1;
	}

	if (secp256r1_is_zero(T_1) && secp256r1_is_zero(T_3)) {
		return secp256r1_point_dbl(R, P);
	}

	if (secp256r1_is_zero(T_3) && secp256r1_is_zero(T_6)) {
		return secp256r1_point_set_infinity(R);
	}

	if (secp256r1_modp_sqr(T_6, T_1) != 1		// T_6 = A^2
		|| secp256r1_modp_mul(T_7, T_3, P->Z) != 1	// T_7 = B * Z_1
		|| secp256r1_modp_mul(T_7, T_7, Q->Z) != 1	// T_7 = B * Z_1 * Z_2 = Z_3
		|| secp256r1_modp_sqr(T_8, T_3) != 1		// T_8 = B^2
		|| secp256r1_modp_mul(T_5, T_5, T_8) != 1	// T_5 = B^2 * C
		|| secp256r1_modp_mul(T_3, T_3, T_8) != 1	// T_3 = B^3
		|| secp256r1_modp_mul(T_4, T_4, T_8) != 1	// T_4 = B^2 * X_1 * Z_2^2
		|| secp256r1_modp_sub(T_6, T_6, T_5) != 1	// T_6 = A^2 - B^2 * C = X_3
		|| secp256r1_modp_sub(T_4, T_4, T_6) != 1	// T_4 = B^2 * X_1 * Z_2^2 - X_3
		|| secp256r1_modp_mul(T_1, T_1, T_4) != 1	// T_1 = A * (B^2 * X_1 * Z_2^2 - X_3)
		|| secp256r1_modp_mul(T_2, T_2, T_3) != 1	// T_2 = B^3 * Y_1 * Z_1^3
		|| secp256r1_modp_sub(T_1, T_1, T_2) != 1) {	// T_1 = A * (B^2 * X_1 * Z_2^2 - X_3) - B^3 * Y_1 * Z_1^3 = Y_3
		error_print();
		return -1;
	}

	if (secp256r1_copy(R->X, T_6) != 1
		|| secp256r1_copy(R->Y, T_1) != 1
		|| secp256r1_copy(R->Z, T_7) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp256r1_point_neg(SECP256R1_POINT *R, const SECP256R1_POINT *P)
{
	if (secp256r1_point_is_at_infinity(P)) {
		return secp256r1_point_set_infinity(R);
	}
	if (secp256r1_copy(R->X, P->X) != 1
		|| secp256r1_modp_neg(R->Y, P->Y) != 1
		|| secp256r1_copy(R->Z, P->Z) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp256r1_point_sub(SECP256R1_POINT *R, const SECP256R1_POINT *P, const SECP256R1_POINT *Q)
{
	SECP256R1_POINT T;
	if (secp256r1_point_neg(&T, Q) != 1
		|| secp256r1_point_add(R, P, &T) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp256r1_point_mul(SECP256R1_POINT *R, const secp256r1_t k, const SECP256R1_POINT *P)
{
	SECP256R1_POINT T;
	uint32_t bits;
	int nbits;
	int i;

	if (secp256r1_point_set_infinity(&T) != 1) {
		error_print();
		return -1;
	}

	for (i = 7; i >= 0; i--) {
		bits = k[i];
		nbits = 32;
		while (nbits-- > 0) {
			if (secp256r1_point_dbl(&T, &T) != 1) {
				error_print();
				return -1;
			}
			if (bits & 0x80000000) {
				if (secp256r1_point_add(&T, &T, P) != 1) {
					error_print();
					return -1;
				}
			}
			bits <<= 1;
		}
	}

	if (secp256r1_point_copy(R, &T) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp256r1_point_mul_generator(SECP256R1_POINT *R, const secp256r1_t k)
{
	return secp256r1_point_mul(R, k, secp256r1_generator());
}

int secp256r1_point_print(FILE *fp, int fmt, int ind, const char *label, const SECP256R1_POINT *P)
{
	uint8_t bytes[32];

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	if (secp256r1_to_32bytes(P->X, bytes) != 1) {
		error_print();
		return -1;
	}
	format_bytes(fp, fmt, ind, "X", bytes, 32);
	if (secp256r1_to_32bytes(P->Y, bytes) != 1) {
		error_print();
		return -1;
	}
	format_bytes(fp, fmt, ind, "Y", bytes, 32);
	if (secp256r1_to_32bytes(P->Z, bytes) != 1) {
		error_print();
		return -1;
	}
	format_bytes(fp, fmt, ind, "Z", bytes, 32);
	return 1;
}

int secp256r1_point_to_uncompressed_octets(const SECP256R1_POINT *P, uint8_t octets[65])
{
	secp256r1_t x;
	secp256r1_t y;

	if (secp256r1_point_get_xy(P, x, y) != 1) {
		error_print();
		return -1;
	}
	octets[0] = 0x04;
	if (secp256r1_to_32bytes(x, octets + 1) != 1
		|| secp256r1_to_32bytes(y, octets + 33) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp256r1_point_from_uncompressed_octets(SECP256R1_POINT *P, const uint8_t octets[65])
{
	secp256r1_t x;
	secp256r1_t y;

	if (octets[0] != 0x04) {
		error_print();
		return -1;
	}
	if (secp256r1_from_32bytes(x, octets + 1) != 1
		|| secp256r1_from_32bytes(y, octets + 33) != 1) {
		error_print();
		return -1;
	}

	if (secp256r1_point_set_xy(P, x, y) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp256r1_point_equ(const SECP256R1_POINT *P, const SECP256R1_POINT *Q)
{
	secp256r1_t t0;
	secp256r1_t t1;
	secp256r1_t t2;
	secp256r1_t t3;

	if (secp256r1_point_is_at_infinity(P)) {
		return secp256r1_point_is_at_infinity(Q);
	}
	if (secp256r1_point_is_at_infinity(Q)) {
		return 0;
	}

	if (secp256r1_modp_sqr(t0, P->Z) != 1		// t0 = Z1^2
		|| secp256r1_modp_sqr(t1, Q->Z) != 1	// t1 = Z2^2
		|| secp256r1_modp_mul(t2, Q->X, t0) != 1	// t2 = X2 * Z1^2
		|| secp256r1_modp_mul(t3, P->X, t1) != 1) {	// t3 = X1 * Z2^2
		error_print();
		return -1;
	}
	if (secp256r1_cmp(t2, t3) != 0) {
		return 0;
	}

	if (secp256r1_modp_mul(t0, t0, P->Z) != 1	// t0 = Z1^3
		|| secp256r1_modp_mul(t0, t0, Q->Y) != 1	// t0 = Y2 * Z1^3
		|| secp256r1_modp_mul(t1, t1, Q->Z) != 1	// t1 = Z2^3
		|| secp256r1_modp_mul(t1, t1, P->Y) != 1) {	// t1 = Y1 * Z2^3
		error_print();
		return -1;
	}

	return secp256r1_cmp(t0, t1) == 0;
}

/* secp256r1 key, ECDH and ECDSA */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <gmssl/bn.h>
#include <gmssl/x509_key.h>
#include <gmssl/mem.h>
#include <gmssl/oid.h>
#include <gmssl/sm4.h>
#include <gmssl/rand.h>
#include <gmssl/asn1.h>
#include <gmssl/pem.h>
#include <gmssl/error.h>
#include <gmssl/ec.h>
#include <gmssl/pkcs8.h>
#include <gmssl/x509_alg.h>
#include <gmssl/secp256r1.h>


int secp256r1_key_generate(SECP256R1_KEY *key)
{
	do {
		if (rand_bytes((uint8_t *)key->private_key, sizeof(secp256r1_t)) != 1) {
			error_print();
			return -1;
		}
	} while (secp256r1_is_zero(key->private_key) || secp256r1_cmp(key->private_key, SECP256R1_N) >= 0);

	if (secp256r1_point_mul_generator(&key->public_key, key->private_key) != 1) {
		error_print();
		return -1;
	}

	return 1;
}

int secp256r1_key_set_private_key(SECP256R1_KEY *key, const secp256r1_t private_key)
{
	if (!key || !private_key) {
		error_print();
		return -1;
	}
	if (secp256r1_is_zero(private_key) || secp256r1_cmp(private_key, SECP256R1_N) >= 0) {
		error_print();
		return -1;
	}
	memset(key, 0, sizeof(SECP256R1_KEY));

	if (secp256r1_copy(key->private_key, private_key) != 1
		|| secp256r1_point_mul_generator(&key->public_key, key->private_key) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp256r1_public_key_equ(const SECP256R1_KEY *key, const SECP256R1_KEY *pub)
{
	if (secp256r1_point_equ(&key->public_key, &pub->public_key) == 1) {
		return 1;
	} else {
		return 0;
	}
}


// SM2将这个命名为_to_octets，应该更准确一些
int secp256r1_public_key_to_bytes(const SECP256R1_KEY *key, uint8_t **out, size_t *outlen)
{
	if (!key || !outlen) {
		error_print();
		return -1;
	}
	if (out && *out) {
		if (secp256r1_point_to_uncompressed_octets(&key->public_key, *out) != 1) {
			error_print();
			return -1;
		}
		*out += 65;
	}
	*outlen += 65;
	return 1;
}

int secp256r1_public_key_from_bytes(SECP256R1_KEY *key, const uint8_t **in, size_t *inlen)
{
	if (!key || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	if (*inlen < 65) {
		error_print();
		return -1;
	}
	memset(key, 0, sizeof(SECP256R1_KEY));

	if (secp256r1_point_from_uncompressed_octets(&key->public_key, *in) != 1) {
		error_print();
		return -1;
	}
	*in += 65;
	*inlen -= 65;

	return 1;
}

int secp256r1_private_key_to_bytes(const SECP256R1_KEY *key, uint8_t **out, size_t *outlen)
{
	if (!key || !outlen) {
		error_print();
		return -1;
	}
	if (out && *out) {
		if (secp256r1_to_32bytes(key->private_key, *out) != 1) {
			error_print();
			return -1;
		}
		*out += 32;
	}
	*outlen += 32;
	return 1;
}

int secp256r1_private_key_from_bytes(SECP256R1_KEY *key, const uint8_t **in, size_t *inlen)
{
	secp256r1_t private_key;

	if (!key || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	if (*inlen < 32) {
		error_print();
		return -1;
	}
	if (secp256r1_from_32bytes(private_key, *in) != 1
		|| secp256r1_key_set_private_key(key, private_key) != 1) {
		gmssl_secure_clear(private_key, sizeof(private_key));
		error_print();
		return -1;
	}
	gmssl_secure_clear(private_key, sizeof(private_key));
	*in += 32;
	*inlen -= 32;
	return 1;
}

int secp256r1_public_key_print(FILE *fp, int fmt, int ind, const char *label, const SECP256R1_KEY *key)
{
	secp256r1_t x;
	secp256r1_t y;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (secp256r1_print(fp, fmt, ind, "X", key->public_key.X) != 1
		|| secp256r1_print(fp, fmt, ind, "Y", key->public_key.Y) != 1
		|| secp256r1_print(fp, fmt, ind, "Z", key->public_key.Z) != 1) {
		error_print();
		return -1;
	}

	if (secp256r1_point_get_xy(&key->public_key, x, y) != 1
		|| secp256r1_print(fp, fmt, ind, "x", x) != 1
		|| secp256r1_print(fp, fmt, ind, "y", y) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp256r1_private_key_print(FILE *fp, int fmt, int ind, const char *label, const SECP256R1_KEY *key)
{
	uint8_t buf[32];

	if (secp256r1_to_32bytes(key->private_key, buf) != 1) {
		error_print();
		return -1;
	}

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	if (secp256r1_public_key_print(fp, fmt, ind, "public_key", key) != 1) {
		error_print();
		return -1;
	}
	format_bytes(fp, fmt, ind, "private_key", buf, 32);
	return 1;
}

int secp256r1_public_key_to_der(const SECP256R1_KEY *key, uint8_t **out, size_t *outlen)
{
	uint8_t octets[65];
	uint8_t *p = octets;
	size_t len = 0;

	if (!key) {
		return 0;
	}

	// different from SM2
	if (out && *out) {
		if (secp256r1_public_key_to_bytes(key, &p, &len) != 1) {
			error_print();
			return -1;
		}
	}

	if (asn1_bit_octets_to_der(octets, sizeof(octets), out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp256r1_public_key_from_der(SECP256R1_KEY *key, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_bit_octets_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (secp256r1_public_key_from_bytes(key, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	if (dlen) {
		error_print();
		return -1;
	}
	return 1;
}


// 这里应该提供public_key_info_to_pem 和SM2完全一样的功能
// 这样才可以生成证书

















int secp256r1_private_key_to_der(const SECP256R1_KEY *key, uint8_t **out, size_t *outlen)
{
	uint8_t prikey[32];
	uint8_t pubkey[65];
	uint8_t params[32];
	uint8_t pubkey_der[128];
	uint8_t *p;
	uint8_t *params_ptr = params;
	uint8_t *pubkey_ptr = pubkey_der;
	size_t len;
	size_t params_len = 0;
	size_t pubkey_der_len = 0;
	size_t seqlen = 0;
	int ret;

	if (!key) {
		error_print();
		return -1;
	}
	p = prikey;
	len = 0;
	if (secp256r1_private_key_to_bytes(key, &p, &len) != 1) {
		error_print();
		return -1;
	}
	p = pubkey;
	len = 0;
	if (secp256r1_public_key_to_bytes(key, &p, &len) != 1) {
		gmssl_secure_clear(prikey, sizeof(prikey));
		error_print();
		return -1;
	}
	ret = ec_named_curve_to_der(OID_secp256r1, &params_ptr, &params_len);
	if (ret == 1) {
		ret = asn1_bit_octets_to_der(pubkey, sizeof(pubkey), &pubkey_ptr, &pubkey_der_len);
	}
	if (ret == 1
		&& (asn1_int_to_der(1, NULL, &seqlen) != 1
		|| asn1_octet_string_to_der(prikey, sizeof(prikey), NULL, &seqlen) != 1
		|| asn1_explicit_to_der(0, params, params_len, NULL, &seqlen) < 0
		|| asn1_explicit_to_der(1, pubkey_der, pubkey_der_len, NULL, &seqlen) < 0
		|| asn1_sequence_header_to_der(seqlen, out, outlen) != 1
		|| asn1_int_to_der(1, out, outlen) != 1
		|| asn1_octet_string_to_der(prikey, sizeof(prikey), out, outlen) != 1
		|| asn1_explicit_to_der(0, params, params_len, out, outlen) < 0
		|| asn1_explicit_to_der(1, pubkey_der, pubkey_der_len, out, outlen) < 0)) {
		ret = -1;
	}
	gmssl_secure_clear(prikey, sizeof(prikey));
	if (ret != 1) {
		error_print();
		return -1;
	}
	return ret;
}

int secp256r1_private_key_from_der(SECP256R1_KEY *key, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *prikey;
	const uint8_t *pubkey;
	const uint8_t *params;
	size_t prikey_len, pubkey_len, params_len;
	int curve;
	int version;
	const uint8_t *d;
	size_t dlen;
	SECP256R1_KEY tmp_key;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_int_from_der(&version, &d, &dlen) != 1
		|| asn1_octet_string_from_der(&prikey, &prikey_len, &d, &dlen) != 1
		|| asn1_explicit_from_der(0, &params, &params_len, &d, &dlen) < 0
		|| asn1_explicit_from_der(1, &pubkey, &pubkey_len, &d, &dlen) < 0
		|| asn1_check(version == 1) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	if (params) {
		if (ec_named_curve_from_der(&curve, &params, &params_len) != 1
			|| asn1_length_is_zero(params_len) != 1) {
			error_print();
			return -1;
		}
	} else {
		curve = OID_undef;
	}
	if (curve != OID_secp256r1 || !pubkey) {
		error_print();
		return -1;
	}
	{
		const uint8_t *pubkey_octets;
		size_t pubkey_octets_len;

		if (asn1_bit_octets_from_der(&pubkey_octets, &pubkey_octets_len, &pubkey, &pubkey_len) != 1
			|| asn1_length_is_zero(pubkey_len) != 1
			|| secp256r1_public_key_from_bytes(&tmp_key, &pubkey_octets, &pubkey_octets_len) != 1
			|| asn1_length_is_zero(pubkey_octets_len) != 1) {
			error_print();
			return -1;
		}
	}

	if (secp256r1_private_key_from_bytes(key, &prikey, &prikey_len) != 1
		|| asn1_length_is_zero(prikey_len) != 1) {
		error_print();
		return -1;
	}

	// check
	if (secp256r1_public_key_equ(key, &tmp_key) != 1) {
		gmssl_secure_clear(key, sizeof(SECP256R1_KEY));
		error_print();
		return -1;
	}

	return 1;
}

int secp256r1_private_key_info_to_der(const SECP256R1_KEY *key, uint8_t **out, size_t *outlen)
{
	X509_KEY x509_key;

	if (x509_key_set_secp256r1_key(&x509_key, key) != 1
		|| x509_private_key_info_to_der(&x509_key, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp256r1_private_key_info_from_der(SECP256R1_KEY *key, const uint8_t **attrs, size_t *attrslen,
	const uint8_t **in, size_t *inlen)
{
	X509_KEY x509_key;

	if (x509_private_key_info_from_der(&x509_key, attrs, attrslen, in, inlen) != 1
		|| x509_key.algor != OID_ec_public_key
		|| x509_key.algor_param != OID_secp256r1) {
		error_print();
		return -1;
	}
	*key = x509_key.u.secp256r1_key;
	return 1;
}

int secp256r1_private_key_info_encrypt_to_der(const SECP256R1_KEY *ec_key, const char *pass,
	uint8_t **out, size_t *outlen)
{
	X509_KEY x509_key;

	if (!ec_key || !pass || !outlen) {
		error_print();
		return -1;
	}
	if (x509_key_set_secp256r1_key(&x509_key, ec_key) != 1
		|| x509_private_key_info_encrypt_to_der(&x509_key, pass, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp256r1_private_key_info_decrypt_from_der(SECP256R1_KEY *ec_key,
	const uint8_t **attrs, size_t *attrs_len,
	const char *pass, const uint8_t **in, size_t *inlen)
{
	X509_KEY x509_key;

	if (!ec_key || !attrs || !attrs_len || !pass || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	if (x509_private_key_info_decrypt_from_der(&x509_key, attrs, attrs_len, pass, in, inlen) != 1
		|| x509_key.algor != OID_ec_public_key
		|| x509_key.algor_param != OID_secp256r1) {
		error_print();
		return -1;
	}
	*ec_key = x509_key.u.secp256r1_key;
	return 1;
}

int secp256r1_private_key_info_encrypt_to_pem(const SECP256R1_KEY *key, const char *pass, FILE *fp)
{
	X509_KEY x509_key;

	if (!fp) {
		error_print();
		return -1;
	}
	if (x509_key_set_secp256r1_key(&x509_key, key) != 1
		|| x509_private_key_info_encrypt_to_pem(&x509_key, pass, fp) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp256r1_private_key_info_decrypt_from_pem(SECP256R1_KEY *key, const char *pass, FILE *fp)
{
	X509_KEY x509_key;
	const uint8_t *attrs;
	size_t attrs_len;

	if (!key || !pass || !fp) {
		error_print();
		return -1;
	}
	if (x509_private_key_info_decrypt_from_pem(&x509_key, &attrs, &attrs_len, pass, fp) != 1
		|| x509_key.algor != OID_ec_public_key
		|| x509_key.algor_param != OID_secp256r1) {
		error_print();
		return -1;
	}
	*key = x509_key.u.secp256r1_key;
	return 1;
}

// FIXME: side-channel of Base64
int secp256r1_private_key_to_pem(const SECP256R1_KEY *a, FILE *fp)
{
	uint8_t buf[512];
	uint8_t *p = buf;
	size_t len = 0;

	if (secp256r1_private_key_to_der(a, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (pem_write(fp, "EC PRIVATE KEY", buf, len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp256r1_private_key_from_pem(SECP256R1_KEY *a, FILE *fp)
{
	uint8_t buf[512];
	const uint8_t *cp = buf;
	size_t len;

	if (pem_read(fp, "EC PRIVATE KEY", buf, &len, sizeof(buf)) != 1
		|| secp256r1_private_key_from_der(a, &cp, &len) != 1
		|| len > 0) {
		error_print();
		return -1;
	}
	return 1;
}

#include <gmssl/mem.h>

#include <gmssl/secp256r1.h>

int secp256r1_do_ecdh(const SECP256R1_KEY *key, const SECP256R1_KEY *peer_key, uint8_t out[32])
{
	SECP256R1_POINT point;
	secp256r1_t x;
	secp256r1_t y;

	if (!key || !peer_key || !out) {
		error_print();
		return -1;
	}
	if (secp256r1_point_mul(&point, key->private_key, &peer_key->public_key) != 1
		|| secp256r1_point_get_xy(&point, x, y) != 1
		|| secp256r1_to_32bytes(x, out) != 1) {
		error_print();
		gmssl_secure_clear(&point, sizeof(SECP256R1_POINT));
		return -1;
	}

	gmssl_secure_clear(&point, sizeof(SECP256R1_POINT));
	gmssl_secure_clear(x, sizeof(secp256r1_t));
	gmssl_secure_clear(y, sizeof(secp256r1_t));
	return 1;
}

int secp256r1_ecdh(const SECP256R1_KEY *key, const uint8_t uncompressed_point[65], uint8_t out[32])
{
	SECP256R1_POINT point;
	secp256r1_t x;
	secp256r1_t y;

	if (!key || !uncompressed_point || !out) {
		error_print();
		return -1;
	}
	if (secp256r1_point_from_uncompressed_octets(&point, uncompressed_point) != 1) {
		error_print();
		return -1;
	}
	if (secp256r1_point_mul(&point, key->private_key, &point) != 1
		|| secp256r1_point_get_xy(&point, x, y) != 1
		|| secp256r1_to_32bytes(x, out) != 1) {
		error_print();
		gmssl_secure_clear(&point, sizeof(SECP256R1_POINT));
		return -1;
	}

	gmssl_secure_clear(&point, sizeof(SECP256R1_POINT));
	gmssl_secure_clear(x, sizeof(secp256r1_t));
	gmssl_secure_clear(y, sizeof(secp256r1_t));
	return 1;
}

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/asn1.h>
#include <gmssl/digest.h>
#include <gmssl/sha2.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include <gmssl/secp256r1.h>
#include <gmssl/bn.h>
#include <gmssl/sm2.h>


int secp256r1_ecdsa_signature_print_ex(FILE *fp, int fmt, int ind, const char *label, const SECP256R1_ECDSA_SIGNATURE *sig)
{
	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	if (secp256r1_print(fp, fmt, ind, "r", sig->r) != 1
		|| secp256r1_print(fp, fmt, ind, "s", sig->s) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp256r1_ecdsa_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *sigbuf, size_t siglen)
{
	SECP256R1_ECDSA_SIGNATURE sig;

	if (secp256r1_ecdsa_signature_from_der(&sig, &sigbuf, &siglen) != 1) {
		error_print();
		return -1;
	}
	secp256r1_ecdsa_signature_print_ex(fp, fmt, ind, label, &sig);
	if (siglen) {
		error_print();
		return -1;
	}
	return 1;
}

static int secp256r1_ecdsa_digest_to_e(secp256r1_t e, const uint8_t *dgst, size_t dgstlen)
{
	uint8_t buf[SHA256_DIGEST_SIZE];

	if (!dgst) {
		error_print();
		return -1;
	}
	if (dgstlen != SHA256_DIGEST_SIZE && dgstlen != SHA384_DIGEST_SIZE) {
		error_print();
		return -1;
	}

	memcpy(buf, dgst, sizeof(buf));
	if (secp256r1_from_32bytes(e, buf) != 1
		|| secp256r1_modn(e, e) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp256r1_ecdsa_do_sign_ex(const SECP256R1_KEY *key, const secp256r1_t k,
	const uint8_t *dgst, size_t dgstlen, SECP256R1_ECDSA_SIGNATURE *sig)
{
	secp256r1_t e;
	secp256r1_t x1;
	secp256r1_t y1;
	secp256r1_t k_inv;
	SECP256R1_POINT P;

	// e = hash(m)
	if (secp256r1_ecdsa_digest_to_e(e, dgst, dgstlen) != 1) {
		error_print();
		return -1;
	}

	// (x1, y1) = k*G
	if (secp256r1_point_mul_generator(&P, k) != 1
		|| secp256r1_point_get_xy(&P, x1, y1) != 1) {
		error_print();
		return -1;
	}

	// r = x1 mod n
	if (secp256r1_modn(sig->r, x1) != 1) {
		error_print();
		return -1;
	}

	// s = k^-1 * (e + d * r) mod n
	if (secp256r1_modn_inv(k_inv, k) != 1
		|| secp256r1_modn_mul(sig->s, key->private_key, sig->r) != 1
		|| secp256r1_modn_add(sig->s, sig->s, e) != 1
		|| secp256r1_modn_mul(sig->s, sig->s, k_inv) != 1) {
		error_print();
		return -1;
	}

	return 1;
}

int secp256r1_ecdsa_do_sign(const SECP256R1_KEY *key,
	const uint8_t *dgst, size_t dgstlen, SECP256R1_ECDSA_SIGNATURE *sig)
{
	secp256r1_t k;

	// rand k in [1, n-1]
	do {
		if (rand_bytes((uint8_t *)k, sizeof(k)) != 1) {
			error_print();
			return -1;
		}
	} while (secp256r1_is_zero(k) || secp256r1_cmp(k, SECP256R1_N) >= 0);

	if (secp256r1_ecdsa_do_sign_ex(key, k, dgst, dgstlen, sig) != 1) {
		error_print();
		return -1;
	}
	return 1;
}


int secp256r1_ecdsa_do_verify(const SECP256R1_KEY *key,
	const uint8_t *dgst, size_t dgstlen, const SECP256R1_ECDSA_SIGNATURE *sig)
{
	secp256r1_t e;
	secp256r1_t w;
	secp256r1_t u1;
	secp256r1_t u2;
	secp256r1_t x1;
	secp256r1_t y1;
	SECP256R1_POINT P;
	SECP256R1_POINT Q;
	SECP256R1_POINT R;

	// check r, s in [1, n-1]
	if (secp256r1_is_zero(sig->r)
		|| secp256r1_cmp(sig->r, SECP256R1_N) >= 0
		|| secp256r1_is_zero(sig->s)
		|| secp256r1_cmp(sig->s, SECP256R1_N) >= 0) {
		error_print();
		return -1;
	}

	// e = hash(m)
	if (secp256r1_ecdsa_digest_to_e(e, dgst, dgstlen) != 1) {
		error_print();
		return -1;
	}

	// w = s^-1 (mod n)
	if (secp256r1_modn_inv(w, sig->s) != 1) {
		error_print();
		return -1;
	}

	// u1 = e * w (mod n)
	if (secp256r1_modn_mul(u1, e, w) != 1) {
		error_print();
		return -1;
	}

	// u2 = r * w (mod n)
	if (secp256r1_modn_mul(u2, sig->r, w) != 1) {
		error_print();
		return -1;
	}

	// (x1, y1) = u1*G + u2*Q
	if (secp256r1_point_mul_generator(&P, u1) != 1
		|| secp256r1_point_mul(&Q, u2, &key->public_key) != 1
		|| secp256r1_point_add(&R, &P, &Q) != 1) {
		error_print();
		return -1;
	}
	if (secp256r1_point_get_xy(&R, x1, y1) != 1) {
		return 0;
	}

	// x1 = x1 mod n
	if (secp256r1_modn(x1, x1) != 1) {
		error_print();
		return -1;
	}

	if (secp256r1_cmp(x1, sig->r) != 0) {
		return 0;
	}
	return 1;
}

int secp256r1_ecdsa_signature_to_der(const SECP256R1_ECDSA_SIGNATURE *sig, uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	uint8_t r[32];
	uint8_t s[32];

	if (!sig) {
		return 0;
	}

	if (secp256r1_to_32bytes(sig->r, r) != 1
		|| secp256r1_to_32bytes(sig->s, s) != 1) {
		error_print();
		return -1;
	}

	if (asn1_integer_to_der(r, 32, NULL, &len) != 1
		|| asn1_integer_to_der(s, 32, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_integer_to_der(r, 32, out, outlen) != 1
		|| asn1_integer_to_der(s, 32, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp256r1_ecdsa_signature_from_der(SECP256R1_ECDSA_SIGNATURE *sig, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	const uint8_t *r;
	const uint8_t *s;
	uint8_t rbuf[32] = {0};
	uint8_t sbuf[32] = {0};
	size_t dlen, rlen, slen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_integer_from_der(&r, &rlen, &d, &dlen) != 1
		|| asn1_integer_from_der(&s, &slen, &d, &dlen) != 1
		|| asn1_length_le(rlen, 32) != 1
		|| asn1_length_le(slen, 32) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}

	memcpy(rbuf + sizeof(rbuf) - rlen, r, rlen);
	memcpy(sbuf + sizeof(sbuf) - slen, s, slen);
	if (secp256r1_from_32bytes(sig->r, rbuf) != 1
		|| secp256r1_from_32bytes(sig->s, sbuf) != 1) {
		error_print();
		return -1;
	}

	return 1;
}

int secp256r1_ecdsa_sign(const SECP256R1_KEY *key,
	const uint8_t *dgst, size_t dgstlen, uint8_t *sigbuf, size_t *siglen)
{
	SECP256R1_ECDSA_SIGNATURE sig;

	if (secp256r1_ecdsa_do_sign(key, dgst, dgstlen, &sig) != 1) {
		error_print();
		return -1;
	}
	*siglen = 0;
	if (secp256r1_ecdsa_signature_to_der(&sig, &sigbuf, siglen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp256r1_ecdsa_sign_fixlen(const SECP256R1_KEY *key,
	const uint8_t *dgst, size_t dgstlen, size_t siglen, uint8_t *sig)
{
	unsigned int trys = 200;
	uint8_t buf[SECP256R1_ECDSA_SIGNATURE_MAX_SIZE];
	size_t len;

	switch (siglen) {
	case SECP256R1_ECDSA_SIGNATURE_COMPACT_SIZE:
	case SECP256R1_ECDSA_SIGNATURE_TYPICAL_SIZE:
	case SECP256R1_ECDSA_SIGNATURE_MAX_SIZE:
		break;
	default:
		error_print();
		return -1;
	}

	while (trys--) {
		if (secp256r1_ecdsa_sign(key, dgst, dgstlen, buf, &len) != 1) {
			error_print();
			return -1;
		}
		if (len == siglen) {
			memcpy(sig, buf, len);
			return 1;
		}
	}

	// might caused by bad randomness
	error_print();
	return -1;
}


int secp256r1_ecdsa_verify(const SECP256R1_KEY *key,
	const uint8_t *dgst, size_t dgstlen, const uint8_t *sigbuf, size_t siglen)
{
	int ret;
	SECP256R1_ECDSA_SIGNATURE sig;

	if (secp256r1_ecdsa_signature_from_der(&sig, &sigbuf, &siglen) != 1) {
		error_print();
		return -1;
	}
	if (siglen) {
		error_print();
		return -1;
	}
	if ((ret = secp256r1_ecdsa_do_verify(key, dgst, dgstlen, &sig)) < 0) {
		error_print();
		return -1;
	}
	return ret;
}

int secp256r1_ecdsa_sign_init(SECP256R1_ECDSA_SIGN_CTX *ctx, const SECP256R1_KEY *key, const DIGEST *digest)
{
	if (!ctx || !key) {
		error_print();
		return -1;
	}
	if (!digest) {
		digest = DIGEST_sha256();
	}
	memset(ctx, 0, sizeof(SECP256R1_ECDSA_SIGN_CTX));

	ctx->key = *key;

	if (digest_init(&ctx->digest_ctx, digest) != 1) {
		error_print();
		return -1;
	}

	return 1;
}

int secp256r1_ecdsa_sign_update(SECP256R1_ECDSA_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	if (digest_update(&ctx->digest_ctx, data, datalen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp256r1_ecdsa_sign_finish(SECP256R1_ECDSA_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen)
{
	uint8_t dgst[DIGEST_MAX_SIZE];
	size_t dgstlen;

	if (!ctx || !sig || !siglen) {
		error_print();
		return -1;
	}

	if (digest_finish(&ctx->digest_ctx, dgst, &dgstlen) != 1) {
		error_print();
		return -1;
	}

	if (secp256r1_ecdsa_sign(&ctx->key, dgst, dgstlen, sig, siglen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp256r1_ecdsa_sign_finish_fixlen(SECP256R1_ECDSA_SIGN_CTX *ctx, size_t siglen, uint8_t *sig)
{
	uint8_t dgst[DIGEST_MAX_SIZE];
	size_t dgstlen;

	if (!ctx || !sig || !siglen) {
		error_print();
		return -1;
	}

	if (digest_finish(&ctx->digest_ctx, dgst, &dgstlen) != 1) {
		error_print();
		return -1;
	}

	if (secp256r1_ecdsa_sign_fixlen(&ctx->key, dgst, dgstlen, siglen, sig) != 1) {
		error_print();
		return -1;
	}
	return 1;
}






int secp256r1_ecdsa_verify_init(SECP256R1_ECDSA_SIGN_CTX *ctx, const SECP256R1_KEY *key, const DIGEST *digest,
	const uint8_t *sig, size_t siglen)
{
	if (!ctx || !key || !sig || !siglen) {
		error_print();
		return -1;
	}

	if (secp256r1_ecdsa_signature_from_der(&ctx->sig, &sig, &siglen) != 1) {
		error_print();
		return -1;
	}
	if (siglen) {
		error_print();
		return -1;
	}

	ctx->key = *key;

	if (!digest) {
		digest = DIGEST_sha256();
	}
	if (digest_init(&ctx->digest_ctx, digest) != 1) {
		error_print();
		return -1;
	}

	return 1;
}


int secp256r1_ecdsa_verify_update(SECP256R1_ECDSA_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	if (digest_update(&ctx->digest_ctx, data, datalen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}


int secp256r1_ecdsa_verify_finish(SECP256R1_ECDSA_SIGN_CTX *ctx)
{
	uint8_t dgst[DIGEST_MAX_SIZE];
	size_t dgstlen;
	int ret;

	if (!ctx) {
		error_print();
		return -1;
	}

	if (digest_finish(&ctx->digest_ctx, dgst, &dgstlen) != 1) {
		error_print();
		return -1;
	}

	if ((ret = secp256r1_ecdsa_do_verify(&ctx->key, dgst, dgstlen, &ctx->sig)) < 0) {
		error_print();
		return -1;
	}
	return ret;
}
