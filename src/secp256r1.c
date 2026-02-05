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

void secp256r1_set_zero(secp256r1_t r) {
	bn_set_word(r, 0, SECP256R1_K);
}

void secp256r1_set_one(secp256r1_t r) {
	bn_set_word(r, 1, SECP256R1_K);
}

void secp256r1_copy(secp256r1_t r, const secp256r1_t a) {
	bn_copy(r, a, SECP256R1_K);
}

void secp256r1_to_32bytes(const secp256r1_t a, uint8_t out[32]) {
	bn_to_bytes(a, SECP256R1_K, out);
}

void secp256r1_from_32bytes(secp256r1_t r, const uint8_t in[32]) {
	bn_from_bytes(r, SECP256R1_K, in);
}

int secp256r1_print(FILE *fp, int fmt, int ind, const char *label, const secp256r1_t a) {
	uint8_t bytes[32];
	secp256r1_to_32bytes(a, bytes);
	format_bytes(fp, fmt, ind, label, bytes, 32);
	return 1;
}

void secp256r1_modp_add(secp256r1_t r, const secp256r1_t a, const secp256r1_t b) {
	bn_mod_add(r, a, b, SECP256R1_P, SECP256R1_K);
}

void secp256r1_modp_dbl(secp256r1_t r, const secp256r1_t a) {
	bn_mod_add(r, a, a, SECP256R1_P, SECP256R1_K);
}

void secp256r1_modp_tri(secp256r1_t r, const secp256r1_t a) {
	secp256r1_t tmp;

	// 这里就出错了，真是太奇怪了！
	bn_mod_add(tmp, a, a, SECP256R1_P, SECP256R1_K);
	bn_mod_add(r, tmp, a, SECP256R1_P, SECP256R1_K);
}

void secp256r1_modp_sub(secp256r1_t r, const secp256r1_t a, const secp256r1_t b) {
	bn_mod_sub(r, a, b, SECP256R1_P, SECP256R1_K);
}

void secp256r1_modp_neg(secp256r1_t r, const secp256r1_t a) {
	bn_mod_neg(r, a, SECP256R1_P, SECP256R1_K);
}

void secp256r1_modp_haf(secp256r1_t r, const secp256r1_t a) {
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
}

void secp256r1_modp_mul(secp256r1_t r, const secp256r1_t a, const secp256r1_t b) {
	uint32_t tmp[6*8 + 4];
	bn_barrett_mod_mul(r, a, b, SECP256R1_P, SECP256R1_U_P, tmp, SECP256R1_K);
}

void secp256r1_modp_sqr(secp256r1_t r, const secp256r1_t a) {
	uint32_t tmp[6*8 + 4];
	bn_barrett_mod_mul(r, a, a, SECP256R1_P, SECP256R1_U_P, tmp, SECP256R1_K);
}

void secp256r1_modp_exp(secp256r1_t r, const secp256r1_t a, const secp256r1_t e) {
	uint32_t tmp[7*8 + 4];
	bn_barrett_mod_exp(r, a, e, SECP256R1_P, SECP256R1_U_P, tmp, SECP256R1_K);
}

// FIXME: 如果 a = 0 (mod p) 会发生什么			
void secp256r1_modp_inv(secp256r1_t r, const secp256r1_t a) {
	uint32_t tmp[8*8 + 4];
	bn_barrett_mod_inv(r, a, SECP256R1_P, SECP256R1_U_P, tmp, SECP256R1_K);
}


void secp256r1_modn(secp256r1_t r, const secp256r1_t a) {
	if (bn_cmp(a, SECP256R1_N, SECP256R1_K) >= 0) {
		bn_sub(r, a, SECP256R1_N, SECP256R1_K);
	} else {
		bn_copy(r, a, SECP256R1_K);
	}
}

void secp256r1_modn_add(secp256r1_t r, const secp256r1_t a, const secp256r1_t b) {
	bn_mod_add(r, a, b, SECP256R1_N, SECP256R1_K);
}

void secp256r1_modn_dbl(secp256r1_t r, const secp256r1_t a) {
	bn_mod_add(r, a, a, SECP256R1_N, SECP256R1_K);
}

void secp256r1_modn_tri(secp256r1_t r, const secp256r1_t a) {
	secp256r1_t tmp;
	bn_mod_add(tmp, a, a, SECP256R1_N, SECP256R1_K);
	bn_mod_add(r, tmp, a, SECP256R1_N, SECP256R1_K);
}

void secp256r1_modn_sub(secp256r1_t r, const secp256r1_t a, const secp256r1_t b) {
	bn_mod_sub(r, a, b, SECP256R1_N, SECP256R1_K);
}

void secp256r1_modn_neg(secp256r1_t r, const secp256r1_t a) {
	bn_mod_neg(r, a, SECP256R1_N, SECP256R1_K);
}

void secp256r1_modn_mul(secp256r1_t r, const secp256r1_t a, const secp256r1_t b) {
	uint32_t tmp[6*8 + 4];
	bn_barrett_mod_mul(r, a, b, SECP256R1_N, SECP256R1_U_N, tmp, SECP256R1_K);
}

void secp256r1_modn_sqr(secp256r1_t r, const secp256r1_t a) {
	uint32_t tmp[6*8 + 4];
	bn_barrett_mod_mul(r, a, a, SECP256R1_N, SECP256R1_U_N, tmp, SECP256R1_K);
}

void secp256r1_modn_exp(secp256r1_t r, const secp256r1_t a, const secp256r1_t e) {
	uint32_t tmp[7*8 + 4];
	bn_barrett_mod_exp(r, a, e, SECP256R1_N, SECP256R1_U_N, tmp, SECP256R1_K);
}

// FIXME: 如果 a = 0 (mod p) 会发生什么			
void secp256r1_modn_inv(secp256r1_t r, const secp256r1_t a) {
	uint32_t tmp[8*8 + 4];
	bn_barrett_mod_inv(r, a, SECP256R1_N, SECP256R1_U_N, tmp, SECP256R1_K);
}


const SECP256R1_POINT SECP256R1_POINT_G = {
	{ 0xd898c296, 0xf4a13945, 0x2deb33a0, 0x77037d81,
	  0x63a440f2, 0xf8bce6e5, 0xe12c4247, 0x6b17d1f2, },
	{ 0x37bf51f5, 0xcbb64068, 0x6b315ece, 0x2bce3357,
	  0x7c0f9e16, 0x8ee7eb4a, 0xfe1a7f9b, 0x4fe342e2, },
	{ 1,0,0,0,0,0,0,0, },
};

void secp256r1_point_set_infinity(SECP256R1_POINT *R)
{
	secp256r1_set_one(R->X);
	secp256r1_set_one(R->Y);
	secp256r1_set_zero(R->Z);
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
	secp256r1_modp_sqr(t0, P->Y);

	// t1 = Z^2
	secp256r1_modp_sqr(t1, P->Z);

	// t2 = Z^4
	secp256r1_modp_sqr(t2, t1);

	// t1 = Z^6
	secp256r1_modp_mul(t1, t1, t2);

	// t1 = b * Z^6
	secp256r1_modp_mul(t1, t1, SECP256R1_B);

	// t2 = X * Z^4
	secp256r1_modp_mul(t2, t2, P->X);

	// t0 = Y^2 + 3 * X * Z^4
	secp256r1_modp_add(t0, t0, t2);
	secp256r1_modp_add(t0, t0, t2);
	secp256r1_modp_add(t0, t0, t2);

	// t2 = X^2
	secp256r1_modp_sqr(t2, P->X);

	// t2 = X^3
	secp256r1_modp_mul(t2, t2, P->X);

	// t1 = b * Z^6 + X^3
	secp256r1_modp_add(t1, t1, t2);

	if (secp256r1_cmp(t0, t1) != 0) {
		return 0;
	}
	return 1;
}

void secp256r1_point_copy(SECP256R1_POINT *R, const SECP256R1_POINT *P)
{
	secp256r1_copy(R->X, P->X);
	secp256r1_copy(R->Y, P->Y);
	secp256r1_copy(R->Z, P->Z);
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
	secp256r1_copy(R->X, x);
	secp256r1_copy(R->Y, y);
	secp256r1_set_one(R->Z);


	if (!secp256r1_point_is_on_curve(R)) {
		error_print();
		return -1;
	}
	return 1;
}

int secp256r1_point_get_xy(const SECP256R1_POINT *P, secp256r1_t x, secp256r1_t y)
{
	secp256r1_t Z_inv;

	if (secp256r1_point_is_at_infinity(P)) {
		return 0;
	}
	secp256r1_modp_inv(Z_inv, P->Z);
	secp256r1_modp_mul(y, P->Y, Z_inv);
	secp256r1_modp_sqr(Z_inv, Z_inv);
	secp256r1_modp_mul(x, P->X, Z_inv);
	secp256r1_modp_mul(y, y, Z_inv);
	return 1;
}

void secp256r1_point_dbl(SECP256R1_POINT *R, const SECP256R1_POINT *P)
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

	// 1. S = 2Y
	secp256r1_modp_dbl(S, Y1);

	// 2. Zsqr = Z^2
	secp256r1_modp_sqr(Zsqr, Z1);

	// 3. S = S^2 = 4Y^2
	secp256r1_modp_sqr(S, S);

	// 4. Z = Z*Y
	secp256r1_modp_mul(Z3, Z1, Y1);

	// 5. Z = 2*Z = 2*Y*Z ===> Z3
	secp256r1_modp_dbl(Z3, Z3);

	// 6. M = X + Zsqr = X + Z^2
	secp256r1_modp_add(M, X1, Zsqr);

	// 7. Zsqr = X - Zsqr = X - Z^2
	secp256r1_modp_sub(Zsqr, X1, Zsqr);

	// 8. Y = S^2 = 16Y^4
	secp256r1_modp_sqr(Y3, S);

	// 9. Y = Y/2 = 8Y^4
	secp256r1_modp_haf(Y3, Y3);

	// 10. M = M * Zsqr = (X + Z^2)*(X - Z^2) = X^2 - Z^4
	secp256r1_modp_mul(M, M, Zsqr);

	// 11. M = 3M = 3X^2 - 3Z^4
	secp256r1_modp_tri(M, M);

	// 12. S = S * X = 4X*Y^2
	secp256r1_modp_mul(S, S, X1);

	// 13. tmp0 = 2 * S = 8X*Y^2
	secp256r1_modp_dbl(tmp0, S);

	// 14. X = M^2 = (3X^2 - 3Z^4)^2
	secp256r1_modp_sqr(X3, M);

	// 15. X = X - tmp0 = (3X^2 - 3Z^4)^2 - 8X*Y^2 ===> X3
	secp256r1_modp_sub(X3, X3, tmp0);

	// 16. S = S - X3 = 4X*Y^2 - X3
	secp256r1_modp_sub(S, S, X3);

	// 17. S = S * M = (3X^2 - 3Z^4)*(4X*Y^2 - X3)
	secp256r1_modp_mul(S, S, M);

	// 18. Y = S - Y = (3X^2 - 3Z^4)*(4X*Y^2 - X3) - 8Y^4 ===> Y3
	secp256r1_modp_sub(Y3, S, Y3);
}

void secp256r1_point_add(SECP256R1_POINT *R, const SECP256R1_POINT *P, const SECP256R1_POINT *Q)
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
		*R = *Q;
		return;
	}
	if (secp256r1_point_is_at_infinity(Q)) {
		*R = *P;
		return;
	}

	// 这里的代码是来自zkrypt的，不确定是否有问题
	secp256r1_modp_sqr(T_1, P->Z);		// T_1 = Z_1^2
	secp256r1_modp_sqr(T_2, Q->Z);		// T_2 = Z_2^2
	secp256r1_modp_mul(T_3, Q->X, T_1);	// T_3 = X_2 * Z_1^2
	secp256r1_modp_mul(T_4, P->X, T_2); 	// T_4 = X_1 * Z_2^2
	secp256r1_modp_add(T_5, T_3, T_4);	// T_5 = X_2 * Z_1^2 + X_1 * Z_2^2 = C
	secp256r1_modp_sub(T_3, T_3, T_4);	// T_3 = X_2 * Z_1^2 - X_1 * Z_2^2 = B
	secp256r1_modp_mul(T_1, T_1, P->Z);	// T_1 = Z_1^3
	secp256r1_modp_mul(T_1, T_1, Q->Y);	// T_1 = Y_2 * Z_1^3
	secp256r1_modp_mul(T_2, T_2, Q->Z);	// T_2 = Z_2^3
	secp256r1_modp_mul(T_2, T_2, P->Y);	// T_2 = Y_1 * Z_2^3
	secp256r1_modp_add(T_6, T_1, T_2);	// T_6 = Y_2 * Z_1^3 + Y_1 * Z_2^3 = D
	secp256r1_modp_sub(T_1, T_1, T_2);	// T_1 = Y_2 * Z_1^3 - Y_1 * Z_2^3 = A

	if (secp256r1_is_zero(T_1) && secp256r1_is_zero(T_3)) {
		secp256r1_point_dbl(R, P);
		return;
	}

	if (secp256r1_is_one(T_1) && secp256r1_is_zero(T_6)) {
		secp256r1_point_set_infinity(R);
		return;
	}

	secp256r1_modp_sqr(T_6, T_1);		// T_6 = A^2
	secp256r1_modp_mul(T_7, T_3, P->Z);	// T_7 = B * Z_1
	secp256r1_modp_mul(T_7, T_7, Q->Z);	// T_7 = B * Z_1 * Z_2 = Z_3
	secp256r1_modp_sqr(T_8, T_3);		// T_8 = B^2
	secp256r1_modp_mul(T_5, T_5, T_8);	// T_5 = B^2 * C
	secp256r1_modp_mul(T_3, T_3, T_8);	// T_3 = B^3
	secp256r1_modp_mul(T_4, T_4, T_8);	// T_4 = B^2 * X_1 * Z_2^2
	secp256r1_modp_sub(T_6, T_6, T_5);	// T_6 = A^2 - B^2 * C = X_3
	secp256r1_modp_sub(T_4, T_4, T_6);	// T_4 = B^2 * X_1 * Z_2^2 - X_3
	secp256r1_modp_mul(T_1, T_1, T_4);	// T_1 = A * (B^2 * X_1 * Z_2^2 - X_3)
	secp256r1_modp_mul(T_2, T_2, T_3);	// T_2 = B^3 * Y_1 * Z_1^3
	secp256r1_modp_sub(T_1, T_1, T_2);	// T_1 = A * (B^2 * X_1 * Z_2^2 - X_3) - B^3 * Y_1 * Z_1^3 = Y_3

	secp256r1_copy(R->X, T_6);
	secp256r1_copy(R->Y, T_1);
	secp256r1_copy(R->Z, T_7);
}

void secp256r1_point_neg(SECP256R1_POINT *R, const SECP256R1_POINT *P)
{
	if (secp256r1_point_is_at_infinity(P)) {
		secp256r1_point_set_infinity(R);
		return;
	}
	secp256r1_copy(R->X, P->X);
	secp256r1_modp_neg(R->Y, P->Y);
	secp256r1_copy(R->Z, P->Z);
}

void secp256r1_point_sub(SECP256R1_POINT *R, const SECP256R1_POINT *P, const SECP256R1_POINT *Q)
{
	SECP256R1_POINT T;
	secp256r1_point_neg(&T, Q);
	secp256r1_point_add(R, P, &T);
}

void secp256r1_point_mul(SECP256R1_POINT *R, const secp256r1_t k, const SECP256R1_POINT *P)
{
	SECP256R1_POINT T;
	uint32_t bits;
	int nbits;
	int i;

	secp256r1_point_set_infinity(&T);

	for (i = 7; i >= 0; i--) {
		bits = k[i];
		nbits = 32;
		while (nbits-- > 0) {
			secp256r1_point_dbl(&T, &T);
			if (bits & 0x80000000) {
				secp256r1_point_add(&T, &T, P);
			}
			bits <<= 1;
		}
	}

	secp256r1_point_copy(R, &T);
}

void secp256r1_point_mul_generator(SECP256R1_POINT *R, const secp256r1_t k)
{
	secp256r1_point_mul(R, k, &SECP256R1_POINT_G);
}

int secp256r1_point_print(FILE *fp, int fmt, int ind, const char *label, const SECP256R1_POINT *P)
{
	uint8_t bytes[32];

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	secp256r1_to_32bytes(P->X, bytes);
	format_bytes(fp, fmt, ind, "X", bytes, 32);
	secp256r1_to_32bytes(P->Y, bytes);
	format_bytes(fp, fmt, ind, "Y", bytes, 32);
	secp256r1_to_32bytes(P->Z, bytes);
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
	secp256r1_to_32bytes(x, octets + 1);
	secp256r1_to_32bytes(y, octets + 33);
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
	secp256r1_from_32bytes(x, octets + 1);
	secp256r1_from_32bytes(y, octets + 33);

	if (secp256r1_point_set_xy(P, x, y) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp256r1_point_equ(const SECP256R1_POINT *P, const SECP256R1_POINT *Q)
{
	uint8_t p_octets[65];
	uint8_t q_octets[65];

	(void)secp256r1_point_to_uncompressed_octets(P, p_octets);
	(void)secp256r1_point_to_uncompressed_octets(Q, q_octets);

	if (memcmp(p_octets, q_octets, 65) == 0) {
		return 1;
	} else {
		return 0;
	}
}


