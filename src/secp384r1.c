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
#include <gmssl/secp384r1.h>


const secp384r1_t SECP384R1_P = {
	0xffffffff, 0x00000000, 0x00000000, 0xffffffff,
	0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff,
	0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
};

const secp384r1_t SECP384R1_B = {
	0xd3ec2aef, 0x2a85c8ed, 0x8a2ed19d, 0xc656398d,
	0x5013875a, 0x0314088f, 0xfe814112, 0x181d9c6e,
	0xe3f82d19, 0x988e056b, 0xe23ee7e4, 0xb3312fa7,
};

const secp384r1_t SECP384R1_N = {
	0xccc52973, 0xecec196a, 0x48b0a77a, 0x581a0db2,
	0xf4372ddf, 0xc7634d81, 0xffffffff, 0xffffffff,
	0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
};

const uint32_t SECP384R1_U_P[13] = {
	0x00000001, 0xffffffff, 0xffffffff, 0x00000000,
	0x00000001, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000001,
};

const uint32_t SECP384R1_U_N[13] = {
	0x333ad68d, 0x1313e695, 0xb74f5885, 0xa7e5f24d,
	0x0bc8d220, 0x389cb27e, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000001,
};

int secp384r1_is_zero(const secp384r1_t a) {
	return bn_is_zero(a, SECP384R1_K);
}

int secp384r1_is_one(const secp384r1_t a) {
	return bn_is_one(a, SECP384R1_K);
}

int secp384r1_cmp(const secp384r1_t a, const secp384r1_t b) {
	return bn_cmp(a, b, SECP384R1_K);
}

int secp384r1_set_zero(secp384r1_t r) {
	bn_set_word(r, 0, SECP384R1_K);
	return 1;
}

int secp384r1_set_one(secp384r1_t r) {
	bn_set_word(r, 1, SECP384R1_K);
	return 1;
}

int secp384r1_copy(secp384r1_t r, const secp384r1_t a) {
	bn_copy(r, a, SECP384R1_K);
	return 1;
}

int secp384r1_to_48bytes(const secp384r1_t a, uint8_t out[48]) {
	bn_to_bytes(a, SECP384R1_K, out);
	return 1;
}

int secp384r1_from_48bytes(secp384r1_t r, const uint8_t in[48]) {
	bn_from_bytes(r, SECP384R1_K, in);
	return 1;
}

int secp384r1_print(FILE *fp, int fmt, int ind, const char *label, const secp384r1_t a) {
	uint8_t bytes[48];
	if (secp384r1_to_48bytes(a, bytes) != 1) {
		error_print();
		return -1;
	}
	format_bytes(fp, fmt, ind, label, bytes, 48);
	return 1;
}

int secp384r1_modp_add(secp384r1_t r, const secp384r1_t a, const secp384r1_t b) {
	bn_mod_add(r, a, b, SECP384R1_P, SECP384R1_K);
	return 1;
}

int secp384r1_modp_dbl(secp384r1_t r, const secp384r1_t a) {
	bn_mod_add(r, a, a, SECP384R1_P, SECP384R1_K);
	return 1;
}

int secp384r1_modp_tri(secp384r1_t r, const secp384r1_t a) {
	secp384r1_t tmp;

	bn_mod_add(tmp, a, a, SECP384R1_P, SECP384R1_K);
	bn_mod_add(r, tmp, a, SECP384R1_P, SECP384R1_K);
	return 1;
}

int secp384r1_modp_sub(secp384r1_t r, const secp384r1_t a, const secp384r1_t b) {
	bn_mod_sub(r, a, b, SECP384R1_P, SECP384R1_K);
	return 1;
}

int secp384r1_modp_neg(secp384r1_t r, const secp384r1_t a) {
	if (secp384r1_is_zero(a)) {
		secp384r1_set_zero(r);
	} else {
		bn_mod_neg(r, a, SECP384R1_P, SECP384R1_K);
	}
	return 1;
}

int secp384r1_modp_haf(secp384r1_t r, const secp384r1_t a) {
	int c = 0;
	if (a[0] & 1) {
		c = bn_add(r, a, SECP384R1_P, SECP384R1_K);
	} else {
		bn_copy(r, a, SECP384R1_K);
	}

	r[0] = (r[0] >> 1) | ((r[1] & 1) << 31);
	r[1] = (r[1] >> 1) | ((r[2] & 1) << 31);
	r[2] = (r[2] >> 1) | ((r[3] & 1) << 31);
	r[3] = (r[3] >> 1) | ((r[4] & 1) << 31);
	r[4] = (r[4] >> 1) | ((r[5] & 1) << 31);
	r[5] = (r[5] >> 1) | ((r[6] & 1) << 31);
	r[6] = (r[6] >> 1) | ((r[7] & 1) << 31);
	r[7] = (r[7] >> 1) | ((r[8] & 1) << 31);
	r[8] = (r[8] >> 1) | ((r[9] & 1) << 31);
	r[9] = (r[9] >> 1) | ((r[10] & 1) << 31);
	r[10] = (r[10] >> 1) | ((r[11] & 1) << 31);
	r[11] = (r[11] >> 1) | ((c & 1) << 31);
	return 1;
}

int secp384r1_modp_mul(secp384r1_t r, const secp384r1_t a, const secp384r1_t b) {
	uint32_t tmp[6*12 + 4];
	bn_barrett_mod_mul(r, a, b, SECP384R1_P, SECP384R1_U_P, tmp, SECP384R1_K);
	return 1;
}

int secp384r1_modp_sqr(secp384r1_t r, const secp384r1_t a) {
	uint32_t tmp[6*12 + 4];
	bn_barrett_mod_mul(r, a, a, SECP384R1_P, SECP384R1_U_P, tmp, SECP384R1_K);
	return 1;
}

int secp384r1_modp_exp(secp384r1_t r, const secp384r1_t a, const secp384r1_t e) {
	uint32_t tmp[7*12 + 4];
	bn_barrett_mod_exp(r, a, e, SECP384R1_P, SECP384R1_U_P, tmp, SECP384R1_K);
	return 1;
}

int secp384r1_modp_inv(secp384r1_t r, const secp384r1_t a) {
	uint32_t tmp[8*12 + 4];

	if (secp384r1_is_zero(a)) {
		error_print();
		return -1;
	}
	bn_barrett_mod_inv(r, a, SECP384R1_P, SECP384R1_U_P, tmp, SECP384R1_K);
	return 1;
}


int secp384r1_modn(secp384r1_t r, const secp384r1_t a) {
	if (bn_cmp(a, SECP384R1_N, SECP384R1_K) >= 0) {
		bn_sub(r, a, SECP384R1_N, SECP384R1_K);
	} else {
		bn_copy(r, a, SECP384R1_K);
	}
	return 1;
}

int secp384r1_modn_add(secp384r1_t r, const secp384r1_t a, const secp384r1_t b) {
	bn_mod_add(r, a, b, SECP384R1_N, SECP384R1_K);
	return 1;
}

int secp384r1_modn_dbl(secp384r1_t r, const secp384r1_t a) {
	bn_mod_add(r, a, a, SECP384R1_N, SECP384R1_K);
	return 1;
}

int secp384r1_modn_tri(secp384r1_t r, const secp384r1_t a) {
	secp384r1_t tmp;
	bn_mod_add(tmp, a, a, SECP384R1_N, SECP384R1_K);
	bn_mod_add(r, tmp, a, SECP384R1_N, SECP384R1_K);
	return 1;
}

int secp384r1_modn_sub(secp384r1_t r, const secp384r1_t a, const secp384r1_t b) {
	bn_mod_sub(r, a, b, SECP384R1_N, SECP384R1_K);
	return 1;
}

int secp384r1_modn_neg(secp384r1_t r, const secp384r1_t a) {
	if (secp384r1_is_zero(a)) {
		secp384r1_set_zero(r);
	} else {
		bn_mod_neg(r, a, SECP384R1_N, SECP384R1_K);
	}
	return 1;
}

int secp384r1_modn_mul(secp384r1_t r, const secp384r1_t a, const secp384r1_t b) {
	uint32_t tmp[6*12 + 4];
	bn_barrett_mod_mul(r, a, b, SECP384R1_N, SECP384R1_U_N, tmp, SECP384R1_K);
	return 1;
}

int secp384r1_modn_sqr(secp384r1_t r, const secp384r1_t a) {
	uint32_t tmp[6*12 + 4];
	bn_barrett_mod_mul(r, a, a, SECP384R1_N, SECP384R1_U_N, tmp, SECP384R1_K);
	return 1;
}

int secp384r1_modn_exp(secp384r1_t r, const secp384r1_t a, const secp384r1_t e) {
	uint32_t tmp[7*12 + 4];
	bn_barrett_mod_exp(r, a, e, SECP384R1_N, SECP384R1_U_N, tmp, SECP384R1_K);
	return 1;
}

int secp384r1_modn_inv(secp384r1_t r, const secp384r1_t a) {
	uint32_t tmp[8*12 + 4];

	if (secp384r1_is_zero(a)) {
		error_print();
		return -1;
	}
	bn_barrett_mod_inv(r, a, SECP384R1_N, SECP384R1_U_N, tmp, SECP384R1_K);
	return 1;
}


static const SECP384R1_POINT secp384r1_generator_point = {
	{ 0x72760ab7, 0x3a545e38, 0xbf55296c, 0x5502f25d,
	  0x82542a38, 0x59f741e0, 0x8ba79b98, 0x6e1d3b62,
	  0xf320ad74, 0x8eb1c71e, 0xbe8b0537, 0xaa87ca22, },
	{ 0x90ea0e5f, 0x7a431d7c, 0x1d7e819d, 0x0a60b1ce,
	  0xb5f0b8c0, 0xe9da3113, 0x289a147c, 0xf8f41dbd,
	  0x9292dc29, 0x5d9e98bf, 0x96262c6f, 0x3617de4a, },
	{ 1,0,0,0,0,0,0,0,0,0,0,0, },
};

const SECP384R1_POINT *secp384r1_generator(void)
{
	return &secp384r1_generator_point;
}

int secp384r1_point_set_infinity(SECP384R1_POINT *R)
{
	if (secp384r1_set_one(R->X) != 1
		|| secp384r1_set_one(R->Y) != 1
		|| secp384r1_set_zero(R->Z) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp384r1_point_is_at_infinity(const SECP384R1_POINT *P)
{
	if (secp384r1_is_zero(P->Z)) {
		return 1;
	}
	return 0;
}

int secp384r1_point_is_on_curve(const SECP384R1_POINT *P)
{
	secp384r1_t t0;
	secp384r1_t t1;
	secp384r1_t t2;

	if (secp384r1_point_is_at_infinity(P)) {
		return 1;
	}

	// check Y^2 + 3 * X * Z^4 == X^3 + b * Z^6

	// t0 = Y^2
	if (secp384r1_modp_sqr(t0, P->Y) != 1) goto err;

	// t1 = Z^2
	if (secp384r1_modp_sqr(t1, P->Z) != 1) goto err;

	// t2 = Z^4
	if (secp384r1_modp_sqr(t2, t1) != 1) goto err;

	// t1 = Z^6
	if (secp384r1_modp_mul(t1, t1, t2) != 1) goto err;

	// t1 = b * Z^6
	if (secp384r1_modp_mul(t1, t1, SECP384R1_B) != 1) goto err;

	// t2 = X * Z^4
	if (secp384r1_modp_mul(t2, t2, P->X) != 1) goto err;

	// t0 = Y^2 + 3 * X * Z^4
	if (secp384r1_modp_add(t0, t0, t2) != 1
		|| secp384r1_modp_add(t0, t0, t2) != 1
		|| secp384r1_modp_add(t0, t0, t2) != 1) goto err;

	// t2 = X^2
	if (secp384r1_modp_sqr(t2, P->X) != 1) goto err;

	// t2 = X^3
	if (secp384r1_modp_mul(t2, t2, P->X) != 1) goto err;

	// t1 = b * Z^6 + X^3
	if (secp384r1_modp_add(t1, t1, t2) != 1) goto err;

	if (secp384r1_cmp(t0, t1) != 0) {
		return 0;
	}
	return 1;
err:
	error_print();
	return -1;
}

int secp384r1_point_copy(SECP384R1_POINT *R, const SECP384R1_POINT *P)
{
	if (secp384r1_copy(R->X, P->X) != 1
		|| secp384r1_copy(R->Y, P->Y) != 1
		|| secp384r1_copy(R->Z, P->Z) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp384r1_point_set_xy(SECP384R1_POINT *R, const secp384r1_t x, const secp384r1_t y)
{
	if (secp384r1_cmp(x, SECP384R1_P) >= 0) {
		error_print();
		return -1;
	}
	if (secp384r1_cmp(y, SECP384R1_P) >= 0) {
		error_print();
		return -1;
	}
	if (secp384r1_copy(R->X, x) != 1
		|| secp384r1_copy(R->Y, y) != 1
		|| secp384r1_set_one(R->Z) != 1) {
		error_print();
		return -1;
	}


	if (secp384r1_point_is_on_curve(R) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp384r1_point_get_xy(const SECP384R1_POINT *P, secp384r1_t x, secp384r1_t y)
{
	secp384r1_t Z_inv;

	if (secp384r1_point_is_at_infinity(P)) {
		error_print();
		return -1;
	}
	if (secp384r1_modp_inv(Z_inv, P->Z) != 1
		|| secp384r1_modp_mul(y, P->Y, Z_inv) != 1
		|| secp384r1_modp_sqr(Z_inv, Z_inv) != 1
		|| secp384r1_modp_mul(x, P->X, Z_inv) != 1
		|| secp384r1_modp_mul(y, y, Z_inv) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp384r1_point_dbl(SECP384R1_POINT *R, const SECP384R1_POINT *P)
{
	/*
	secp384r1_t T_0;
	secp384r1_t T_1;
	secp384r1_t T_2;
	secp384r1_t T_3;
	secp384r1_t T_4;

	if (secp384r1_point_is_at_infinity(P)) {
		secp384r1_point_set_infinity(R);
		return;
	}

	secp384r1_modp_sqr(T_0, P->X);
	secp384r1_modp_tri(T_0, T_0);
	secp384r1_modp_sqr(T_1, T_0);
	secp384r1_modp_sqr(T_2, P->Y);
	secp384r1_modp_mul(T_3, P->X, T_2);
	secp384r1_modp_dbl(T_3, T_3);
	secp384r1_modp_dbl(T_3, T_3);
	secp384r1_modp_dbl(T_4, T_3);
	secp384r1_modp_sub(T_1, T_1, T_4);
	secp384r1_modp_sub(T_3, T_3, T_1);
	secp384r1_modp_mul(T_0, T_0, T_3);
	secp384r1_modp_dbl(T_2, T_2);
	secp384r1_modp_sqr(T_2, T_2);
	secp384r1_modp_dbl(T_2, T_2);
	secp384r1_modp_sub(T_0, T_0, T_2);
	secp384r1_modp_mul(T_2, P->Y, P->Z);
	secp384r1_modp_dbl(T_2, T_2);

	secp384r1_copy(R->X, T_1);
	secp384r1_copy(R->Y, T_0);
	secp384r1_copy(R->Z, T_2);
	*/

	const uint32_t *X1 = P->X;
	const uint32_t *Y1 = P->Y;
	const uint32_t *Z1 = P->Z;
	uint32_t *X3 = R->X;
	uint32_t *Y3 = R->Y;
	uint32_t *Z3 = R->Z;
	secp384r1_t S;
	secp384r1_t M;
	secp384r1_t Zsqr;
	secp384r1_t tmp0;

	if (secp384r1_point_is_at_infinity(P)) {
		return secp384r1_point_set_infinity(R);
	}

	// 1. S = 2Y
	if (secp384r1_modp_dbl(S, Y1) != 1) goto err;

	// 2. Zsqr = Z^2
	if (secp384r1_modp_sqr(Zsqr, Z1) != 1) goto err;

	// 3. S = S^2 = 4Y^2
	if (secp384r1_modp_sqr(S, S) != 1) goto err;

	// 4. Z = Z*Y
	if (secp384r1_modp_mul(Z3, Z1, Y1) != 1) goto err;

	// 5. Z = 2*Z = 2*Y*Z ===> Z3
	if (secp384r1_modp_dbl(Z3, Z3) != 1) goto err;

	// 6. M = X + Zsqr = X + Z^2
	if (secp384r1_modp_add(M, X1, Zsqr) != 1) goto err;

	// 7. Zsqr = X - Zsqr = X - Z^2
	if (secp384r1_modp_sub(Zsqr, X1, Zsqr) != 1) goto err;

	// 8. Y = S^2 = 16Y^4
	if (secp384r1_modp_sqr(Y3, S) != 1) goto err;

	// 9. Y = Y/2 = 8Y^4
	if (secp384r1_modp_haf(Y3, Y3) != 1) goto err;

	// 10. M = M * Zsqr = (X + Z^2)*(X - Z^2) = X^2 - Z^4
	if (secp384r1_modp_mul(M, M, Zsqr) != 1) goto err;

	// 11. M = 3M = 3X^2 - 3Z^4
	if (secp384r1_modp_tri(M, M) != 1) goto err;

	// 12. S = S * X = 4X*Y^2
	if (secp384r1_modp_mul(S, S, X1) != 1) goto err;

	// 13. tmp0 = 2 * S = 8X*Y^2
	if (secp384r1_modp_dbl(tmp0, S) != 1) goto err;

	// 14. X = M^2 = (3X^2 - 3Z^4)^2
	if (secp384r1_modp_sqr(X3, M) != 1) goto err;

	// 15. X = X - tmp0 = (3X^2 - 3Z^4)^2 - 8X*Y^2 ===> X3
	if (secp384r1_modp_sub(X3, X3, tmp0) != 1) goto err;

	// 16. S = S - X3 = 4X*Y^2 - X3
	if (secp384r1_modp_sub(S, S, X3) != 1) goto err;

	// 17. S = S * M = (3X^2 - 3Z^4)*(4X*Y^2 - X3)
	if (secp384r1_modp_mul(S, S, M) != 1) goto err;

	// 18. Y = S - Y = (3X^2 - 3Z^4)*(4X*Y^2 - X3) - 8Y^4 ===> Y3
	if (secp384r1_modp_sub(Y3, S, Y3) != 1) goto err;

	return 1;
err:
	error_print();
	return -1;
}

int secp384r1_point_add(SECP384R1_POINT *R, const SECP384R1_POINT *P, const SECP384R1_POINT *Q)
{
	secp384r1_t T_1;
	secp384r1_t T_2;
	secp384r1_t T_3;
	secp384r1_t T_4;
	secp384r1_t T_5;
	secp384r1_t T_6;
	secp384r1_t T_7;
	secp384r1_t T_8;

	if (secp384r1_point_is_at_infinity(P)) {
		return secp384r1_point_copy(R, Q);
	}
	if (secp384r1_point_is_at_infinity(Q)) {
		return secp384r1_point_copy(R, P);
	}

	if (secp384r1_modp_sqr(T_1, P->Z) != 1		// T_1 = Z_1^2
		|| secp384r1_modp_sqr(T_2, Q->Z) != 1	// T_2 = Z_2^2
		|| secp384r1_modp_mul(T_3, Q->X, T_1) != 1	// T_3 = X_2 * Z_1^2
		|| secp384r1_modp_mul(T_4, P->X, T_2) != 1 	// T_4 = X_1 * Z_2^2
		|| secp384r1_modp_add(T_5, T_3, T_4) != 1	// T_5 = X_2 * Z_1^2 + X_1 * Z_2^2 = C
		|| secp384r1_modp_sub(T_3, T_3, T_4) != 1	// T_3 = X_2 * Z_1^2 - X_1 * Z_2^2 = B
		|| secp384r1_modp_mul(T_1, T_1, P->Z) != 1	// T_1 = Z_1^3
		|| secp384r1_modp_mul(T_1, T_1, Q->Y) != 1	// T_1 = Y_2 * Z_1^3
		|| secp384r1_modp_mul(T_2, T_2, Q->Z) != 1	// T_2 = Z_2^3
		|| secp384r1_modp_mul(T_2, T_2, P->Y) != 1	// T_2 = Y_1 * Z_2^3
		|| secp384r1_modp_add(T_6, T_1, T_2) != 1	// T_6 = Y_2 * Z_1^3 + Y_1 * Z_2^3 = D
		|| secp384r1_modp_sub(T_1, T_1, T_2) != 1) {	// T_1 = Y_2 * Z_1^3 - Y_1 * Z_2^3 = A
		error_print();
		return -1;
	}

	if (secp384r1_is_zero(T_1) && secp384r1_is_zero(T_3)) {
		return secp384r1_point_dbl(R, P);
	}

	if (secp384r1_is_zero(T_3) && secp384r1_is_zero(T_6)) {
		return secp384r1_point_set_infinity(R);
	}

	if (secp384r1_modp_sqr(T_6, T_1) != 1		// T_6 = A^2
		|| secp384r1_modp_mul(T_7, T_3, P->Z) != 1	// T_7 = B * Z_1
		|| secp384r1_modp_mul(T_7, T_7, Q->Z) != 1	// T_7 = B * Z_1 * Z_2 = Z_3
		|| secp384r1_modp_sqr(T_8, T_3) != 1		// T_8 = B^2
		|| secp384r1_modp_mul(T_5, T_5, T_8) != 1	// T_5 = B^2 * C
		|| secp384r1_modp_mul(T_3, T_3, T_8) != 1	// T_3 = B^3
		|| secp384r1_modp_mul(T_4, T_4, T_8) != 1	// T_4 = B^2 * X_1 * Z_2^2
		|| secp384r1_modp_sub(T_6, T_6, T_5) != 1	// T_6 = A^2 - B^2 * C = X_3
		|| secp384r1_modp_sub(T_4, T_4, T_6) != 1	// T_4 = B^2 * X_1 * Z_2^2 - X_3
		|| secp384r1_modp_mul(T_1, T_1, T_4) != 1	// T_1 = A * (B^2 * X_1 * Z_2^2 - X_3)
		|| secp384r1_modp_mul(T_2, T_2, T_3) != 1	// T_2 = B^3 * Y_1 * Z_1^3
		|| secp384r1_modp_sub(T_1, T_1, T_2) != 1) {	// T_1 = A * (B^2 * X_1 * Z_2^2 - X_3) - B^3 * Y_1 * Z_1^3 = Y_3
		error_print();
		return -1;
	}

	if (secp384r1_copy(R->X, T_6) != 1
		|| secp384r1_copy(R->Y, T_1) != 1
		|| secp384r1_copy(R->Z, T_7) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp384r1_point_neg(SECP384R1_POINT *R, const SECP384R1_POINT *P)
{
	if (secp384r1_point_is_at_infinity(P)) {
		return secp384r1_point_set_infinity(R);
	}
	if (secp384r1_copy(R->X, P->X) != 1
		|| secp384r1_modp_neg(R->Y, P->Y) != 1
		|| secp384r1_copy(R->Z, P->Z) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp384r1_point_sub(SECP384R1_POINT *R, const SECP384R1_POINT *P, const SECP384R1_POINT *Q)
{
	SECP384R1_POINT T;
	if (secp384r1_point_neg(&T, Q) != 1
		|| secp384r1_point_add(R, P, &T) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp384r1_point_mul(SECP384R1_POINT *R, const secp384r1_t k, const SECP384R1_POINT *P)
{
	SECP384R1_POINT T;
	uint32_t bits;
	int nbits;
	int i;

	if (secp384r1_point_set_infinity(&T) != 1) {
		error_print();
		return -1;
	}

	for (i = 11; i >= 0; i--) {
		bits = k[i];
		nbits = 32;
		while (nbits-- > 0) {
			if (secp384r1_point_dbl(&T, &T) != 1) {
				error_print();
				return -1;
			}
			if (bits & 0x80000000) {
				if (secp384r1_point_add(&T, &T, P) != 1) {
					error_print();
					return -1;
				}
			}
			bits <<= 1;
		}
	}

	if (secp384r1_point_copy(R, &T) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp384r1_point_mul_generator(SECP384R1_POINT *R, const secp384r1_t k)
{
	return secp384r1_point_mul(R, k, secp384r1_generator());
}

int secp384r1_point_print(FILE *fp, int fmt, int ind, const char *label, const SECP384R1_POINT *P)
{
	uint8_t bytes[48];

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	if (secp384r1_to_48bytes(P->X, bytes) != 1) {
		error_print();
		return -1;
	}
	format_bytes(fp, fmt, ind, "X", bytes, 48);
	if (secp384r1_to_48bytes(P->Y, bytes) != 1) {
		error_print();
		return -1;
	}
	format_bytes(fp, fmt, ind, "Y", bytes, 48);
	if (secp384r1_to_48bytes(P->Z, bytes) != 1) {
		error_print();
		return -1;
	}
	format_bytes(fp, fmt, ind, "Z", bytes, 48);
	return 1;
}

int secp384r1_point_to_uncompressed_octets(const SECP384R1_POINT *P, uint8_t octets[97])
{
	secp384r1_t x;
	secp384r1_t y;

	if (secp384r1_point_get_xy(P, x, y) != 1) {
		error_print();
		return -1;
	}
	octets[0] = 0x04;
	if (secp384r1_to_48bytes(x, octets + 1) != 1
		|| secp384r1_to_48bytes(y, octets + 49) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp384r1_point_from_uncompressed_octets(SECP384R1_POINT *P, const uint8_t octets[97])
{
	secp384r1_t x;
	secp384r1_t y;

	if (octets[0] != 0x04) {
		error_print();
		return -1;
	}
	if (secp384r1_from_48bytes(x, octets + 1) != 1
		|| secp384r1_from_48bytes(y, octets + 49) != 1) {
		error_print();
		return -1;
	}

	if (secp384r1_point_set_xy(P, x, y) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp384r1_point_equ(const SECP384R1_POINT *P, const SECP384R1_POINT *Q)
{
	secp384r1_t t0;
	secp384r1_t t1;
	secp384r1_t t2;
	secp384r1_t t3;

	if (secp384r1_point_is_at_infinity(P)) {
		return secp384r1_point_is_at_infinity(Q);
	}
	if (secp384r1_point_is_at_infinity(Q)) {
		return 0;
	}

	if (secp384r1_modp_sqr(t0, P->Z) != 1		// t0 = Z1^2
		|| secp384r1_modp_sqr(t1, Q->Z) != 1	// t1 = Z2^2
		|| secp384r1_modp_mul(t2, Q->X, t0) != 1	// t2 = X2 * Z1^2
		|| secp384r1_modp_mul(t3, P->X, t1) != 1) {	// t3 = X1 * Z2^2
		error_print();
		return -1;
	}
	if (secp384r1_cmp(t2, t3) != 0) {
		return 0;
	}

	if (secp384r1_modp_mul(t0, t0, P->Z) != 1	// t0 = Z1^3
		|| secp384r1_modp_mul(t0, t0, Q->Y) != 1	// t0 = Y2 * Z1^3
		|| secp384r1_modp_mul(t1, t1, Q->Z) != 1	// t1 = Z2^3
		|| secp384r1_modp_mul(t1, t1, P->Y) != 1) {	// t1 = Y1 * Z2^3
		error_print();
		return -1;
	}

	return secp384r1_cmp(t0, t1) == 0;
}
