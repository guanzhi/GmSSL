/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 * Copyright 2014-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
/******************************************************************************
 *                                                                            *
 * Copyright 2014 Intel Corporation                                           *
 *                                                                            *
 * Licensed under the Apache License, Version 2.0 (the "License");            *
 * you may not use this file except in compliance with the License.           *
 * You may obtain a copy of the License at                                    *
 *                                                                            *
 *    http://www.apache.org/licenses/LICENSE-2.0                              *
 *                                                                            *
 * Unless required by applicable law or agreed to in writing, software        *
 * distributed under the License is distributed on an "AS IS" BASIS,          *
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.   *
 * See the License for the specific language governing permissions and        *
 * limitations under the License.                                             *
 *                                                                            *
 ******************************************************************************
 *                                                                            *
 * Developers and authors:                                                    *
 * Shay Gueron (1, 2), and Vlad Krasnov (1)                                   *
 * (1) Intel Corporation, Israel Development Center                           *
 * (2) University of Haifa                                                    *
 * Reference:                                                                 *
 * S.Gueron and V.Krasnov, "Fast Prime Field Elliptic Curve Cryptography with *
 *                          256 Bit Primes"                                   *
 *                                                                            *
 ******************************************************************************/


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <gmssl/error.h>
#include <gmssl/hex.h>
#include <gmssl/endian.h>


// z256

void sm2_z256_copy(uint64_t r[4], const uint64_t a[4])
{
	r[3] = a[3];
	r[2] = a[2];
	r[1] = a[1];
	r[0] = a[0];
}

void sm2_z256_copy_conditional(uint64_t dst[4], const uint64_t src[4], uint64_t move)
{
	uint64_t mask1 = 0-move;
	uint64_t mask2 = ~mask1;

	dst[0] = (src[0] & mask1) ^ (dst[0] & mask2);
	dst[1] = (src[1] & mask1) ^ (dst[1] & mask2);
	dst[2] = (src[2] & mask1) ^ (dst[2] & mask2);
	dst[3] = (src[3] & mask1) ^ (dst[3] & mask2);
}

void sm2_z256_from_bytes(uint64_t r[4], const uint8_t in[32])
{
	r[3] = GETU64(in);
	r[2] = GETU64(in + 8);
	r[1] = GETU64(in + 16);
	r[0] = GETU64(in + 24);
}

void sm2_z256_to_bytes(const uint64_t a[4], uint8_t out[32])
{
	PUTU64(out, a[3]);
	PUTU64(out + 8, a[2]);
	PUTU64(out + 16, a[1]);
	PUTU64(out + 24, a[0]);
}

static uint64_t is_zero(uint64_t in)
{
	in |= (0 - in);
	in = ~in;
	in >>= 63;
	return in;
}

uint64_t sm2_z256_equ(const uint64_t a[4], const uint64_t b[4])
{
	uint64_t res;

	res = a[0] ^ b[0];
	res |= a[1] ^ b[1];
	res |= a[2] ^ b[2];
	res |= a[3] ^ b[3];

	return is_zero(res);
}

int sm2_z256_cmp(const uint64_t a[4], const uint64_t b[4])
{
	if (a[3] > b[3]) return 1;
	else if (a[3] < b[3]) return -1;
	if (a[2] > b[2]) return 1;
	else if (a[2] < b[2]) return -1;
	if (a[1] > b[1]) return 1;
	else if (a[1] < b[1]) return -1;
	if (a[0] > b[0]) return 1;
	else if (a[0] < b[0]) return -1;
	return 0;
}

uint64_t sm2_z256_add(uint64_t r[4], const uint64_t a[4], const uint64_t b[4])
{
	uint64_t t, c = 0;

	t = a[0] + b[0];
	c = t < a[0];
	r[0] = t;

	t = a[1] + c;
	c = t < a[1];
	r[1] = t + b[1];
	c += r[1] < t;

	t = a[2] + c;
	c = t < a[2];
	r[2] = t + b[2];
	c += r[2] < t;

	t = a[3] + c;
	c = t < a[3];
	r[3] = t + b[3];
	c += r[3] < t;

	return c;
}

uint64_t sm2_z256_sub(uint64_t r[4], const uint64_t a[4], const uint64_t b[4])
{
	uint64_t t, c = 0;

	t = a[0] - b[0];
	c = t > a[0];
	r[0] = t;

	t = a[1] - c;
	c = t > a[1];
	r[1] = t - b[1];
	c += r[1] > t;

	t = a[2] - c;
	c = t > a[2];
	r[2] = t - b[2];
	c += r[2] > t;

	t = a[3] - c;
	c = t > a[3];
	r[3] = t - b[3];
	c += r[3] > t;

	return c;
}

void sm2_z256_mul(uint64_t r[8], const uint64_t a[4], const uint64_t b[4])
{
	uint64_t a_[8];
	uint64_t b_[8];
	uint64_t s[16] = {0};
	uint64_t u;
	int i, j;

	for (i = 0; i < 4; i++) {
		a_[2 * i] = a[i] & 0xffffffff;
		b_[2 * i] = b[i] & 0xffffffff;
		a_[2 * i + 1] = a[i] >> 32;
		b_[2 * i + 1] = b[i] >> 32;
	}

	for (i = 0; i < 8; i++) {
		u = 0;
		for (j = 0; j < 8; j++) {
			u = s[i + j] + a_[i] * b_[j] + u;
			s[i + j] = u & 0xffffffff;
			u >>= 32;
		}
		s[i + 8] = u;
	}

	for (i = 0; i < 8; i++) {
		r[i] = (s[2 * i + 1] << 32) | s[2 * i];
	}
}

uint64_t sm2_z512_add(uint64_t r[8], const uint64_t a[8], const uint64_t b[8])
{
	uint64_t t, c = 0;

	t = a[0] + b[0];
	c = t < a[0];
	r[0] = t;

	t = a[1] + c;
	c = t < a[1];
	r[1] = t + b[1];
	c += r[1] < t;

	t = a[2] + c;
	c = t < a[2];
	r[2] = t + b[2];
	c += r[2] < t;

	t = a[3] + c;
	c = t < a[3];
	r[3] = t + b[3];
	c += r[3] < t;

	t = a[4] + c;
	c = t < a[4];
	r[4] = t + b[4];
	c += r[4] < t;

	t = a[5] + c;
	c = t < a[5];
	r[5] = t + b[5];
	c += r[5] < t;

	t = a[6] + c;
	c = t < a[6];
	r[6] = t + b[6];
	c += r[6] < t;

	t = a[7] + c;
	c = t < a[7];
	r[7] = t + b[7];
	c += r[7] < t;

	return c;
}

int sm2_z256_get_booth(const uint64_t a[4], unsigned int window_size, int i)
{
	uint64_t mask = (1 << window_size) - 1;
	uint64_t wbits;
	int n, j;

	if (i == 0) {
		return ((a[0] << 1) & mask) - (a[0] & mask);
	}

	j = i * window_size - 1;
	n = j / 64;
	j = j % 64;

	wbits = a[n] >> j;
	if ((64 - j) < (window_size + 1) && n < 3) {
		wbits |= a[n + 1] << (64 - j);
	}
	return (wbits & mask) - ((wbits >> 1) & mask);
}

void sm2_z256_from_hex(uint64_t r[4], const char *hex)
{
	uint8_t bytes[32];
	size_t len;

	hex_to_bytes(hex, 64, bytes, &len);
	sm2_z256_from_bytes(r, bytes);
}

int sm2_z256_print(FILE *fp, int ind, int fmt, const char *label, const uint64_t a[4])
{
	format_print(fp, ind, fmt, "%s: %016llx%016llx%016llx%016llx\n", label, a[3], a[2], a[1], a[0]);
	return 1;
}

int sm2_z512_print(FILE *fp, int ind, int fmt, const char *label, const uint64_t a[8])
{
	format_print(fp, ind, fmt, "%s: %016llx%016llx%016llx%016llx%016llx%016llx%016llx%016llx\n",
		label, a[7], a[6], a[5], a[4], a[3], a[2], a[1], a[0]);
	return 1;
}


// z256 mod p

// p = 2^256 - 2^224 - 2^96 + 2^64 - 1
const uint64_t SM2_Z256_P[4] = {
	0xffffffffffffffff, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffeffffffff
};

// mont(1) = 2^256 mod p = 2^224 + 2^96 - 2^64 + 1
const uint64_t SM2_Z256_NEG_P[4] = {
	1, ((uint64_t)1 << 32) - 1, 0, ((uint64_t)1 << 32) };


void sm2_z256_modp_add(uint64_t r[4], const uint64_t a[4], const uint64_t b[4])
{
	uint64_t c;

	c = sm2_z256_add(r, a, b);

	if (c) {
		// a + b - p = (a + b - 2^256) + (2^256 - p)
		(void)sm2_z256_add(r, r, SM2_Z256_NEG_P);
		return;
	}

	if (sm2_z256_cmp(r, SM2_Z256_P) >= 0) {

		(void)sm2_z256_sub(r, r, SM2_Z256_P);
	}
}

void sm2_z256_modp_sub(uint64_t r[4], const uint64_t a[4], const uint64_t b[4])
{
	uint64_t c;

	c = sm2_z256_sub(r, a, b);

	if (c) {
		// a - b + p = (a - b + 2^256) - (2^256 - p)
		(void)sm2_z256_sub(r, r, SM2_Z256_NEG_P);
	}
}

void sm2_z256_modp_mul_by_2(uint64_t r[4], const uint64_t a[4])
{
	sm2_z256_modp_add(r, a, a);
}

void sm2_z256_modp_mul_by_3(uint64_t r[4], const uint64_t a[4])
{
	uint64_t t[4];
	sm2_z256_modp_add(t, a, a);
	sm2_z256_modp_add(r, t, a);
}

void sm2_z256_modp_div_by_2(uint64_t r[4], const uint64_t a[4])
{
	uint64_t c = 0;

	if (a[0] & 1) {
		c = sm2_z256_add(r, a, SM2_Z256_P);
	} else {
		r[0] = a[0];
		r[1] = a[1];
		r[2] = a[2];
		r[3] = a[3];
	}

	r[0] = (r[0] >> 1) | ((r[1] & 1) << 63);
	r[1] = (r[1] >> 1) | ((r[2] & 1) << 63);
	r[2] = (r[2] >> 1) | ((r[3] & 1) << 63);
	r[3] = (r[3] >> 1) | ((c & 1) << 63);
}

void sm2_z256_modp_neg(uint64_t r[4], const uint64_t a[4])
{
	(void)sm2_z256_sub(r, SM2_Z256_P, a);
}


// montegomery

const uint64_t *SM2_Z256_MONT_ONE = SM2_Z256_NEG_P;

// z = xy
// c = (z + (z * p' mod 2^256) * p)/2^256
void sm2_z256_mont_mul(uint64_t r[4], const uint64_t a[4], const uint64_t b[4])
{
	uint64_t z[8];
	uint64_t t[8];
	uint64_t c;

	// p' = -p^(-1) mod 2^256 = fffffffc00000001fffffffe00000000ffffffff000000010000000000000001
	const uint64_t p_[4] = {
		0x0000000000000001, 0xffffffff00000001, 0xfffffffe00000000, 0xfffffffc00000001
	};

	//sm2_z256_print(stderr, 0, 0, "a", a);
	//sm2_z256_print(stderr, 0, 0, "b", b);

	// z = a * b
	sm2_z256_mul(z, a, b);
	//sm2_z512_print(stderr, 0, 0, "z", z);

	// t = low(z) * p'
	sm2_z256_mul(t, z, p_);
	//sm2_z256_print(stderr, 0, 0, "z * p' mod 2^256", t);

	// t = low(t) * p
	sm2_z256_mul(t, t, SM2_Z256_P);
	//sm2_z512_print(stderr, 0, 0, "(z * p' mod 2^256) * p", t);

	// z = z + t
	c = sm2_z512_add(z, z, t);
	//sm2_z512_print(stderr, 0, 0, "z", z);

	// r = high(r)
	sm2_z256_copy(r, z + 4);
	//sm2_z256_print(stderr, 0, 0, "r", r);

	if (c) {
		sm2_z256_add(r, r, SM2_Z256_MONT_ONE);
		//sm2_z256_print(stderr, 0, 0, "r1", r);

	} else if (sm2_z256_cmp(r, SM2_Z256_P) >= 0) {
		(void)sm2_z256_sub(r, r, SM2_Z256_P);
		//sm2_z256_print(stderr, 0, 0, "r2", r);
	}
}

void sm2_z256_mont_sqr(uint64_t r[4], const uint64_t a[4])
{
	sm2_z256_mont_mul(r, a, a);
}

void sm2_z256_mont_inv(uint64_t r[4], const uint64_t a[4])
{
	uint64_t a1[4];
	uint64_t a2[4];
	uint64_t a3[4];
	uint64_t a4[4];
	uint64_t a5[4];
	int i;

	sm2_z256_mont_sqr(a1, a);
	sm2_z256_mont_mul(a2, a1, a);
	sm2_z256_mont_sqr(a3, a2);
	sm2_z256_mont_sqr(a3, a3);
	sm2_z256_mont_mul(a3, a3, a2);
	sm2_z256_mont_sqr(a4, a3);
	sm2_z256_mont_sqr(a4, a4);
	sm2_z256_mont_sqr(a4, a4);
	sm2_z256_mont_sqr(a4, a4);
	sm2_z256_mont_mul(a4, a4, a3);
	sm2_z256_mont_sqr(a5, a4);
	for (i = 1; i < 8; i++) {
		sm2_z256_mont_sqr(a5, a5);
	}
	sm2_z256_mont_mul(a5, a5, a4);
	for (i = 0; i < 8; i++) {
		sm2_z256_mont_sqr(a5, a5);
	}
	sm2_z256_mont_mul(a5, a5, a4);
	for (i = 0; i < 4; i++) {
		sm2_z256_mont_sqr(a5, a5);
	}
	sm2_z256_mont_mul(a5, a5, a3);
	sm2_z256_mont_sqr(a5, a5);
	sm2_z256_mont_sqr(a5, a5);
	sm2_z256_mont_mul(a5, a5, a2);
	sm2_z256_mont_sqr(a5, a5);
	sm2_z256_mont_mul(a5, a5, a);
	sm2_z256_mont_sqr(a4, a5);
	sm2_z256_mont_mul(a3, a4, a1);
	sm2_z256_mont_sqr(a5, a4);
	for (i = 1; i< 31; i++) {
		sm2_z256_mont_sqr(a5, a5);
	}
	sm2_z256_mont_mul(a4, a5, a4);
	sm2_z256_mont_sqr(a4, a4);
	sm2_z256_mont_mul(a4, a4, a);
	sm2_z256_mont_mul(a3, a4, a2);
	for (i = 0; i < 33; i++) {
		sm2_z256_mont_sqr(a5, a5);
	}
	sm2_z256_mont_mul(a2, a5, a3);
	sm2_z256_mont_mul(a3, a2, a3);
	for (i = 0; i < 32; i++) {
		sm2_z256_mont_sqr(a5, a5);
	}
	sm2_z256_mont_mul(a2, a5, a3);
	sm2_z256_mont_mul(a3, a2, a3);
	sm2_z256_mont_mul(a4, a2, a4);
	for (i = 0; i < 32; i++) {
		sm2_z256_mont_sqr(a5, a5);
	}
	sm2_z256_mont_mul(a2, a5, a3);
	sm2_z256_mont_mul(a3, a2, a3);
	sm2_z256_mont_mul(a4, a2, a4);
	for (i = 0; i < 32; i++) {
		sm2_z256_mont_sqr(a5, a5);
	}
	sm2_z256_mont_mul(a2, a5, a3);
	sm2_z256_mont_mul(a3, a2, a3);
	sm2_z256_mont_mul(a4, a2, a4);
	for (i = 0; i < 32; i++) {
		sm2_z256_mont_sqr(a5, a5);
	}
	sm2_z256_mont_mul(a2, a5, a3);
	sm2_z256_mont_mul(a3, a2, a3);
	sm2_z256_mont_mul(a4, a2, a4);
	for (i = 0; i < 32; i++) {
		sm2_z256_mont_sqr(a5, a5);
	}
	sm2_z256_mont_mul(r, a4, a5);
}

// mont(mont(a), 1) = aR * 1 * R^-1 (mod p) = a (mod p)
void sm2_z256_from_mont(uint64_t r[4], const uint64_t a[4])
{
	const uint64_t SM2_Z256_ONE[4] = { 1,0,0,0 };
	sm2_z256_mont_mul(r, a, SM2_Z256_ONE);
}

// mont(a) = a * 2^256 (mod p) = mont_mul(a, 2^512 mod p)
void sm2_z256_to_mont(const uint64_t a[4], uint64_t r[4])
{
	// 2^512 (mod p)
	const uint64_t SM2_Z256_2e512modp[4] = {
		0x0000000200000003, 0x00000002ffffffff, 0x0000000100000001, 0x0000000400000002
	};

	sm2_z256_mont_mul(r, a, SM2_Z256_2e512modp);
}

int sm2_z256_mont_print(FILE *fp, int ind, int fmt, const char *label, const uint64_t a[4])
{
	uint64_t r[4];
	sm2_z256_from_mont(r, a);
	sm2_z256_print(fp, ind, fmt, label, r);
	return 1;
}

// Jacobian Point with Montgomery coordinates

void sm2_z256_point_dbl(SM2_Z256_POINT *R, const SM2_Z256_POINT *A)
{
	const uint64_t *X1 = A->X;
	const uint64_t *Y1 = A->Y;
	const uint64_t *Z1 = A->Z;
	uint64_t *X3 = R->X;
	uint64_t *Y3 = R->Y;
	uint64_t *Z3 = R->Z;
	uint64_t S[4];
	uint64_t M[4];
	uint64_t Zsqr[4];
	uint64_t tmp0[4];

	// S = 2*Y1
	sm2_z256_modp_mul_by_2(S, Y1);
	//sm2_z256_mont_print(stderr, 0, 0, "1", S);

	// Zsqr = Z1^2
	sm2_z256_mont_sqr(Zsqr, Z1);
	//sm2_z256_mont_print(stderr, 0, 0, "2", Zsqr);

	// S = S^2 = 4*Y1^2
	sm2_z256_mont_sqr(S, S);
	//sm2_z256_mont_print(stderr, 0, 0, "3", S);

	// Z3 = Z1 * Y1
	sm2_z256_mont_mul(Z3, Z1, Y1);
	//sm2_z256_mont_print(stderr, 0, 0, "4", Z3);

	// Z3 = 2 * Z3 = 2*Y1*Z1
	sm2_z256_modp_mul_by_2(Z3, Z3);
	//sm2_z256_mont_print(stderr, 0, 0, "5", Z3);

	// M = X1 + Zsqr = X1 + Z1^2
	sm2_z256_modp_add(M, X1, Zsqr);
	//sm2_z256_mont_print(stderr, 0, 0, "6", M);

	// Zsqr = X1 - Zsqr = X1 - Z1^2
	sm2_z256_modp_sub(Zsqr, X1, Zsqr);
	//sm2_z256_mont_print(stderr, 0, 0, "7", Zsqr);

	// Y3 = S^2 = 16 * Y1^4
	sm2_z256_mont_sqr(Y3, S);
	//sm2_z256_mont_print(stderr, 0, 0, "8", Y3);

	// Y3 = Y3/2 = 8 * Y1^4
	sm2_z256_modp_div_by_2(Y3, Y3);
	//sm2_z256_mont_print(stderr, 0, 0, "9", Y3);

	// M = M * Zsqr = (X1 + Z1^2)(X1 - Z1^2)
	sm2_z256_mont_mul(M, M, Zsqr);
	//sm2_z256_mont_print(stderr, 0, 0, "10", M);

	// M = 3*M = 3(X1 + Z1^2)(X1 - Z1^2)
	sm2_z256_modp_mul_by_3(M, M);
	//sm2_z256_mont_print(stderr, 0, 0, "11", M);

	// S = S * X1 = 4 * X1 * Y1^2
	sm2_z256_mont_mul(S, S, X1);
	//sm2_z256_mont_print(stderr, 0, 0, "12", S);

	// tmp0 = 2 * S = 8 * X1 * Y1^2
	sm2_z256_modp_mul_by_2(tmp0, S);
	//sm2_z256_mont_print(stderr, 0, 0, "13", tmp0);

	// X3 = M^2 = (3(X1 + Z1^2)(X1 - Z1^2))^2
	sm2_z256_mont_sqr(X3, M);
	//sm2_z256_mont_print(stderr, 0, 0, "14", X3);

	// X3 = X3 - tmp0 = (3(X1 + Z1^2)(X1 - Z1^2))^2 - 8 * X1 * Y1^2
	sm2_z256_modp_sub(X3, X3, tmp0);
	//sm2_z256_mont_print(stderr, 0, 0, "15", X3);

	// S = S - X3 = 4 * X1 * Y1^2 - X3
	sm2_z256_modp_sub(S, S, X3);
	//sm2_z256_mont_print(stderr, 0, 0, "16", S);

	// S = S * M = 3(X1 + Z1^2)(X1 - Z1^2)(4 * X1 * Y1^2 - X3)
	sm2_z256_mont_mul(S, S, M);
	//sm2_z256_mont_print(stderr, 0, 0, "17", S);

	// Y3 = S - Y3 = 3(X1 + Z1^2)(X1 - Z1^2)(4 * X1 * Y1^2 - X3) - 8 * Y1^4
	sm2_z256_modp_sub(Y3, S, Y3);
	//sm2_z256_mont_print(stderr, 0, 0, "18", Y3);
}

void sm2_z256_point_add(SM2_Z256_POINT *r, const SM2_Z256_POINT *a, const SM2_Z256_POINT *b)
{
	uint64_t U2[4], S2[4];
	uint64_t U1[4], S1[4];
	uint64_t Z1sqr[4];
	uint64_t Z2sqr[4];
	uint64_t H[4], R[4];
	uint64_t Hsqr[4];
	uint64_t Rsqr[4];
	uint64_t Hcub[4];

	uint64_t res_x[4];
	uint64_t res_y[4];
	uint64_t res_z[4];

	uint64_t in1infty, in2infty;

	const uint64_t *in1_x = a->X;
	const uint64_t *in1_y = a->Y;
	const uint64_t *in1_z = a->Z;

	const uint64_t *in2_x = b->X;
	const uint64_t *in2_y = b->Y;
	const uint64_t *in2_z = b->Z;

	/*
	* Infinity in encoded as (,,0)
	*/
	in1infty = (in1_z[0] | in1_z[1] | in1_z[2] | in1_z[3]);

	in2infty = (in2_z[0] | in2_z[1] | in2_z[2] | in2_z[3]);

	in1infty = is_zero(in1infty);
	in2infty = is_zero(in2infty);

	sm2_z256_mont_sqr(Z2sqr, in2_z);        /* Z2^2 */
	sm2_z256_mont_sqr(Z1sqr, in1_z);        /* Z1^2 */

	sm2_z256_mont_mul(S1, Z2sqr, in2_z);    /* S1 = Z2^3 */
	sm2_z256_mont_mul(S2, Z1sqr, in1_z);    /* S2 = Z1^3 */

	sm2_z256_mont_mul(S1, S1, in1_y);       /* S1 = Y1*Z2^3 */
	sm2_z256_mont_mul(S2, S2, in2_y);       /* S2 = Y2*Z1^3 */
	sm2_z256_modp_sub(R, S2, S1);                /* R = S2 - S1 */

	sm2_z256_mont_mul(U1, in1_x, Z2sqr);    /* U1 = X1*Z2^2 */
	sm2_z256_mont_mul(U2, in2_x, Z1sqr);    /* U2 = X2*Z1^2 */
	sm2_z256_modp_sub(H, U2, U1);                /* H = U2 - U1 */

	/*
	* This should not happen during sign/ecdh, so no constant time violation
	*/
	if (sm2_z256_equ(U1, U2) && !in1infty && !in2infty) {
		if (sm2_z256_equ(S1, S2)) {
			sm2_z256_point_dbl(r, a);
			return;
		} else {
			memset(r, 0, sizeof(*r));
			return;
		}
	}

	sm2_z256_mont_sqr(Rsqr, R);             /* R^2 */
	sm2_z256_mont_mul(res_z, H, in1_z);     /* Z3 = H*Z1*Z2 */
	sm2_z256_mont_sqr(Hsqr, H);             /* H^2 */
	sm2_z256_mont_mul(res_z, res_z, in2_z); /* Z3 = H*Z1*Z2 */
	sm2_z256_mont_mul(Hcub, Hsqr, H);       /* H^3 */

	sm2_z256_mont_mul(U2, U1, Hsqr);        /* U1*H^2 */
	sm2_z256_modp_mul_by_2(Hsqr, U2);            /* 2*U1*H^2 */

	sm2_z256_modp_sub(res_x, Rsqr, Hsqr);
	sm2_z256_modp_sub(res_x, res_x, Hcub);

	sm2_z256_modp_sub(res_y, U2, res_x);

	sm2_z256_mont_mul(S2, S1, Hcub);
	sm2_z256_mont_mul(res_y, R, res_y);
	sm2_z256_modp_sub(res_y, res_y, S2);

	sm2_z256_copy_conditional(res_x, in2_x, in1infty);			
	sm2_z256_copy_conditional(res_y, in2_y, in1infty);			
	sm2_z256_copy_conditional(res_z, in2_z, in1infty);			

	sm2_z256_copy_conditional(res_x, in1_x, in2infty);			
	sm2_z256_copy_conditional(res_y, in1_y, in2infty);			
	sm2_z256_copy_conditional(res_z, in1_z, in2infty);			

	memcpy(r->X, res_x, sizeof(res_x));
	memcpy(r->Y, res_y, sizeof(res_y));
	memcpy(r->Z, res_z, sizeof(res_z));
}

void sm2_z256_point_neg(SM2_Z256_POINT *R, const SM2_Z256_POINT *P)
{
	sm2_z256_copy(R->X, P->X);
	sm2_z256_modp_neg(R->Y, P->Y);
	sm2_z256_copy(R->Z, P->Z);
}

void sm2_z256_point_sub(SM2_Z256_POINT *R, const SM2_Z256_POINT *A, const SM2_Z256_POINT *B)
{
	SM2_Z256_POINT neg_B;
	sm2_z256_point_neg(&neg_B, B);
	sm2_z256_point_add(R, A, &neg_B);
}

void sm2_z256_point_get_affine(const SM2_Z256_POINT *P, uint64_t x[4], uint64_t y[4])
{
	uint64_t z_inv[4];
	uint64_t x_out[4];
	uint64_t y_out[4];

	// z_inv = 1/Z
	sm2_z256_mont_inv(z_inv, P->Z);

	// y_out = Y/Z
	if (y) {
		sm2_z256_mont_mul(y_out, P->Y, z_inv);
	}

	// z_inv = 1/Z^2
	sm2_z256_mont_sqr(z_inv, z_inv);

	// x_out = X/Z^2
	sm2_z256_mont_mul(x_out, P->X, z_inv);
	sm2_z256_from_mont(x, x_out);

	if (y) {
		// y_out = Y/Z^3
		sm2_z256_mont_mul(y_out, y_out, z_inv);
		sm2_z256_from_mont(y, y_out);
	}
}




void sm2_z256_point_copy_affine(SM2_Z256_POINT *R, const SM2_Z256_POINT_AFFINE *P)
{
	memcpy(R, P, sizeof(SM2_Z256_POINT_AFFINE));
	sm2_z256_copy(R->Z, SM2_Z256_MONT_ONE);
}

void sm2_z256_point_add_affine(SM2_Z256_POINT *r, const SM2_Z256_POINT *a, const SM2_Z256_POINT_AFFINE *b)
{
	uint64_t U2[4], S2[4];
	uint64_t Z1sqr[4];
	uint64_t H[4], R[4];
	uint64_t Hsqr[4];
	uint64_t Rsqr[4];
	uint64_t Hcub[4];

	uint64_t res_x[4];
	uint64_t res_y[4];
	uint64_t res_z[4];

	uint64_t in1infty, in2infty;

	const uint64_t *in1_x = a->X;
	const uint64_t *in1_y = a->Y;
	const uint64_t *in1_z = a->Z;

	const uint64_t *in2_x = b->x;
	const uint64_t *in2_y = b->y;

	/*
	* Infinity in encoded as (,,0)
	*/
	in1infty = (in1_z[0] | in1_z[1] | in1_z[2] | in1_z[3]);

	/*
	* In affine representation we encode infinity as (0,0), which is
	* not on the curve, so it is OK
	*/
	in2infty = (in2_x[0] | in2_x[1] | in2_x[2] | in2_x[3] | in2_y[0] | in2_y[1] | in2_y[2] | in2_y[3]);

	in1infty = is_zero(in1infty);
	in2infty = is_zero(in2infty);


	/* Z1^2 */
	sm2_z256_mont_sqr(Z1sqr, in1_z);

	/* U2 = X2*Z1^2 */
	sm2_z256_mont_mul(U2, in2_x, Z1sqr);
	/* H = U2 - U1 */
	sm2_z256_modp_sub(H, U2, in1_x);

	sm2_z256_mont_mul(S2, Z1sqr, in1_z);    /* S2 = Z1^3 */

	sm2_z256_mont_mul(res_z, H, in1_z);     /* Z3 = H*Z1*Z2 */

	sm2_z256_mont_mul(S2, S2, in2_y);       /* S2 = Y2*Z1^3 */
	sm2_z256_modp_sub(R, S2, in1_y);             /* R = S2 - S1 */

	sm2_z256_mont_sqr(Hsqr, H);             /* H^2 */
	sm2_z256_mont_sqr(Rsqr, R);             /* R^2 */
	sm2_z256_mont_mul(Hcub, Hsqr, H);       /* H^3 */

	sm2_z256_mont_mul(U2, in1_x, Hsqr);     /* U1*H^2 */
	sm2_z256_modp_mul_by_2(Hsqr, U2);            /* 2*U1*H^2 */

	sm2_z256_modp_sub(res_x, Rsqr, Hsqr);
	sm2_z256_modp_sub(res_x, res_x, Hcub);
	sm2_z256_modp_sub(H, U2, res_x);

	sm2_z256_mont_mul(S2, in1_y, Hcub);
	sm2_z256_mont_mul(H, H, R);
	sm2_z256_modp_sub(res_y, H, S2);

	sm2_z256_copy_conditional(res_x, in2_x, in1infty);			
	sm2_z256_copy_conditional(res_x, in1_x, in2infty);			

	sm2_z256_copy_conditional(res_y, in2_y, in1infty);			
	sm2_z256_copy_conditional(res_y, in1_y, in2infty);			

	sm2_z256_copy_conditional(res_z, SM2_Z256_MONT_ONE, in1infty);		
	sm2_z256_copy_conditional(res_z, in1_z, in2infty);			

	memcpy(r->X, res_x, sizeof(res_x));
	memcpy(r->Y, res_y, sizeof(res_y));
	memcpy(r->Z, res_z, sizeof(res_z));
}

void sm2_z256_point_sub_affine(SM2_Z256_POINT *R,
	const SM2_Z256_POINT *A, const SM2_Z256_POINT_AFFINE *B)
{
	SM2_Z256_POINT_AFFINE neg_B;

	sm2_z256_copy(neg_B.x, B->x);
	sm2_z256_modp_neg(neg_B.y, B->y);

	sm2_z256_point_add_affine(R, A, &neg_B);
}

int sm2_z256_point_print(FILE *fp, int fmt, int ind, const char *label, const SM2_Z256_POINT *P)
{
	uint64_t x[4];
	uint64_t y[4];
	uint8_t affine[64];

	sm2_z256_point_get_affine(P, x, y);
	sm2_z256_to_bytes(x, affine);
	sm2_z256_to_bytes(y, affine + 32);

	format_bytes(fp, fmt, ind, label, affine, 64);
	return 1;
}

int sm2_z256_point_affine_print(FILE *fp, int fmt, int ind, const char *label, const SM2_Z256_POINT_AFFINE *P)
{
	uint8_t affine[64];
	uint64_t a[4];

	sm2_z256_from_mont(a, P->x);
	sm2_z256_to_bytes(a, affine);

	sm2_z256_from_mont(a, P->y);
	sm2_z256_to_bytes(a, affine + 32);

	format_bytes(fp, fmt, ind, label, affine, 64);
	return 1;
}

extern const uint64_t sm2_z256_pre_comp[37][64 * 4 * 2];
static SM2_Z256_POINT_AFFINE (*g_pre_comp)[64] = (SM2_Z256_POINT_AFFINE (*)[64])sm2_z256_pre_comp;

void sm2_z256_point_mul_generator(SM2_Z256_POINT *R, const uint64_t k[4])
{
	size_t window_size = 7;
	int R_infinity = 1;
	int n = (256 + window_size - 1)/window_size;
	int i;

	for (i = n - 1; i >= 0; i--) {
		int booth = sm2_z256_get_booth(k, window_size, i);

		if (R_infinity) {
			if (booth != 0) {
				sm2_z256_point_copy_affine(R, &g_pre_comp[i][booth - 1]);
				R_infinity = 0;
			}
		} else {
			if (booth > 0) {
				sm2_z256_point_add_affine(R, R, &g_pre_comp[i][booth - 1]);
			} else if (booth < 0) {
				sm2_z256_point_sub_affine(R, R, &g_pre_comp[i][-booth - 1]);
			}
		}
	}

	if (R_infinity) {
		memset(R, 0, sizeof(*R));
	}
}

void sm2_z256_point_mul(SM2_Z256_POINT *R, const SM2_Z256_POINT *P, const uint64_t k[4])
{
	int window_size = 5;
	SM2_Z256_POINT T[16];
	int R_infinity = 1;
	int n = (256 + window_size - 1)/window_size;
	int i;

	// T[i] = (i + 1) * P
	memcpy(&T[0], P, sizeof(SM2_Z256_POINT));
	sm2_z256_point_dbl(&T[ 1], &T[ 0]);
	sm2_z256_point_add(&T[ 2], &T[ 1], P);
	sm2_z256_point_dbl(&T[ 3], &T[ 1]);
	sm2_z256_point_add(&T[ 4], &T[ 3], P);
	sm2_z256_point_dbl(&T[ 5], &T[ 2]);
	sm2_z256_point_add(&T[ 6], &T[ 5], P);
	sm2_z256_point_dbl(&T[ 7], &T[ 3]);
	sm2_z256_point_add(&T[ 8], &T[ 7], P);
	sm2_z256_point_dbl(&T[ 9], &T[ 4]);
	sm2_z256_point_add(&T[10], &T[ 9], P);
	sm2_z256_point_dbl(&T[11], &T[ 5]);
	sm2_z256_point_add(&T[12], &T[11], P);
	sm2_z256_point_dbl(&T[13], &T[ 6]);
	sm2_z256_point_add(&T[14], &T[13], P);
	sm2_z256_point_dbl(&T[15], &T[ 7]);

	for (i = n - 1; i >= 0; i--) {
		int booth = sm2_z256_get_booth(k, window_size, i);

		if (R_infinity) {
			if (booth != 0) {
				*R = T[booth - 1];
				R_infinity = 0;
			}
		} else {
			sm2_z256_point_dbl(R, R);
			sm2_z256_point_dbl(R, R);
			sm2_z256_point_dbl(R, R);
			sm2_z256_point_dbl(R, R);
			sm2_z256_point_dbl(R, R);

			if (booth > 0) {
				sm2_z256_point_add(R, R, &T[booth - 1]);
			} else if (booth < 0) {
				sm2_z256_point_sub(R, R, &T[-booth - 1]);
			}
		}
	}

	if (R_infinity) {
		memset(R, 0, sizeof(*R));
	}
}

// R = t*P + s*G
void sm2_z256_point_mul_sum(SM2_Z256_POINT *R, const uint64_t t[4], const SM2_Z256_POINT *P, const uint64_t s[4])
{
	SM2_Z256_POINT Q;
	sm2_z256_point_mul_generator(R, s);
	sm2_z256_point_mul(&Q, P, t);
	sm2_z256_point_add(R, R, &Q);
}
