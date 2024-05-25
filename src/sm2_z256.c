/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
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
#include <gmssl/rand.h>
#include <gmssl/endian.h>
#include <gmssl/sm2_z256.h>
#include <gmssl/sm3.h>
#include <gmssl/asn1.h>

/*
SM2 parameters

p = 0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff
a = 0xfffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc
b = 0x28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93
x = 0x32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7
y = 0xbc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0
n = 0xfffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123
h = 0x1
*/

const sm2_z256_t SM2_Z256_ONE = { 1,0,0,0 };

const uint64_t *sm2_z256_one(void) {
	return &SM2_Z256_ONE[0];
}

void sm2_z256_set_one(sm2_z256_t r)
{
	r[0] = 1;
	r[1] = 0;
	r[2] = 0;
	r[3] = 0;
}

void sm2_z256_set_zero(sm2_z256_t r)
{
	r[0] = 0;
	r[1] = 0;
	r[2] = 0;
	r[3] = 0;
}

int sm2_z256_rand_range(sm2_z256_t r, const sm2_z256_t range)
{
	unsigned int tries = 100;

	do {
		if (!tries) {
			// caller call this function again if return zero
			return 0;
		}
		if (rand_bytes((uint8_t *)r, 32) != 1) {
			error_print();
			return -1;
		}
		tries--;

	} while (sm2_z256_cmp(r, range) >= 0);

	return 1;
}

void sm2_z256_from_bytes(sm2_z256_t r, const uint8_t in[32])
{
	r[3] = GETU64(in);
	r[2] = GETU64(in + 8);
	r[1] = GETU64(in + 16);
	r[0] = GETU64(in + 24);
}

void sm2_z256_to_bytes(const sm2_z256_t a, uint8_t out[32])
{
	PUTU64(out, a[3]);
	PUTU64(out + 8, a[2]);
	PUTU64(out + 16, a[1]);
	PUTU64(out + 24, a[0]);
}

void sm2_z256_copy(sm2_z256_t r, const sm2_z256_t a)
{
	r[3] = a[3];
	r[2] = a[2];
	r[1] = a[1];
	r[0] = a[0];
}

void sm2_z256_copy_conditional(sm2_z256_t dst, const sm2_z256_t src, uint64_t move)
{
	uint64_t mask1 = 0-move;
	uint64_t mask2 = ~mask1;

	dst[0] = (src[0] & mask1) ^ (dst[0] & mask2);
	dst[1] = (src[1] & mask1) ^ (dst[1] & mask2);
	dst[2] = (src[2] & mask1) ^ (dst[2] & mask2);
	dst[3] = (src[3] & mask1) ^ (dst[3] & mask2);
}

static uint64_t is_zero(uint64_t in)
{
	in |= (0 - in);
	in = ~in;
	in >>= 63;
	return in;
}

uint64_t sm2_z256_equ(const sm2_z256_t a, const sm2_z256_t b)
{
	uint64_t res;

	res = a[0] ^ b[0];
	res |= a[1] ^ b[1];
	res |= a[2] ^ b[2];
	res |= a[3] ^ b[3];

	return is_zero(res);
}

int sm2_z256_cmp(const sm2_z256_t a, const sm2_z256_t b)
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

uint64_t sm2_z256_is_zero(const sm2_z256_t a)
{
	return
		is_zero(a[0]) &
		is_zero(a[1]) &
		is_zero(a[2]) &
		is_zero(a[3]);
}

void sm2_z256_rshift(sm2_z256_t r, const sm2_z256_t a, unsigned int nbits)
{
	nbits &= 0x3f;

	if (nbits) {
		r[0] = a[0] >> nbits;
		r[0] |= a[1] << (64 - nbits);
		r[1] = a[1] >> nbits;
		r[1] |= a[2] << (64 - nbits);
		r[2] = a[2] >> nbits;
		r[2] |= a[3] << (64 - nbits);
		r[3] = a[3] >> nbits;
	} else {
		sm2_z256_copy(r, a);
	}
}

uint64_t sm2_z256_add(sm2_z256_t r, const sm2_z256_t a, const sm2_z256_t b)
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

uint64_t sm2_z256_sub(sm2_z256_t r, const sm2_z256_t a, const sm2_z256_t b)
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

void sm2_z256_mul(sm2_z512_t r, const sm2_z256_t a, const sm2_z256_t b)
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

static uint64_t sm2_z512_add(sm2_z512_t r, const sm2_z512_t a, const sm2_z512_t b)
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

int sm2_z256_get_booth(const sm2_z256_t a, unsigned int window_size, int i)
{
	uint64_t mask = (1 << window_size) - 1;
	uint64_t wbits;
	int n, j;

	if (i == 0) {
		return (int)((a[0] << 1) & mask) - (int)(a[0] & mask);
	}

	j = i * window_size - 1;
	n = j / 64;
	j = j % 64;

	wbits = a[n] >> j;
	if ((64 - j) < (int)(window_size + 1) && n < 3) {
		wbits |= a[n + 1] << (64 - j);
	}
	return (int)(wbits & mask) - (int)((wbits >> 1) & mask);
}

void sm2_z256_from_hex(sm2_z256_t r, const char *hex)
{
	uint8_t bytes[32];
	size_t len;

	hex_to_bytes(hex, 64, bytes, &len);
	sm2_z256_from_bytes(r, bytes);
}

int sm2_z256_equ_hex(const sm2_z256_t a, const char *hex)
{
	sm2_z256_t b;
	sm2_z256_from_hex(b, hex);
	if (sm2_z256_cmp(a, b) == 0) {
		return 1;
	} else {
		return 0;
	}
}

int sm2_z256_print(FILE *fp, int ind, int fmt, const char *label, const sm2_z256_t a)
{
	format_print(fp, ind, fmt, "%s: %016llx%016llx%016llx%016llx\n", label, a[3], a[2], a[1], a[0]);
	return 1;
}


// GF(p)

// p = 2^256 - 2^224 - 2^96 + 2^64 - 1
//   = 0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff
const uint64_t SM2_Z256_P[4] = {
	0xffffffffffffffff, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffeffffffff,
};
// TODO: SM2_Z256_P[0] and SM2_Z256_P[2] are special values (fff...f), use this to optimize the ASM code	


const uint64_t *sm2_z256_prime(void) {
	return &SM2_Z256_P[0];
}


// 2^256 - p = 2^224 + 2^96 - 2^64 + 1
const uint64_t SM2_Z256_NEG_P[4] = {
	1, ((uint64_t)1 << 32) - 1, 0, ((uint64_t)1 << 32),
};

#if !defined(ENABLE_SM2_ARM64) && !defined(ENABLE_SM2_AMD64)
void sm2_z256_modp_add(sm2_z256_t r, const sm2_z256_t a, const sm2_z256_t b)
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

void sm2_z256_modp_sub(sm2_z256_t r, const sm2_z256_t a, const sm2_z256_t b)
{
	uint64_t c;

	c = sm2_z256_sub(r, a, b);

	if (c) {
		// a - b + p = (a - b + 2^256) - (2^256 - p)
		(void)sm2_z256_sub(r, r, SM2_Z256_NEG_P);
	}
}

void sm2_z256_modp_dbl(sm2_z256_t r, const sm2_z256_t a)
{
	sm2_z256_modp_add(r, a, a);
}

void sm2_z256_modp_tri(sm2_z256_t r, const sm2_z256_t a)
{
	sm2_z256_t t;
	sm2_z256_modp_add(t, a, a);
	sm2_z256_modp_add(r, t, a);
}

void sm2_z256_modp_neg(sm2_z256_t r, const sm2_z256_t a)
{
	(void)sm2_z256_sub(r, SM2_Z256_P, a);
}

void sm2_z256_modp_haf(sm2_z256_t r, const sm2_z256_t a)
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
#endif

// p' * p = -1 mod 2^256

// p' = -p^(-1) mod 2^256
//    = fffffffc00000001fffffffe00000000ffffffff000000010000000000000001
// sage: -(IntegerModRing(2^256)(p))^-1
const uint64_t SM2_Z256_P_PRIME[4] = {
	0x0000000000000001, 0xffffffff00000001, 0xfffffffe00000000, 0xfffffffc00000001,
};


// mont(1) (mod p) = 2^256 mod p = 2^256 - p
const uint64_t *SM2_Z256_MODP_MONT_ONE = SM2_Z256_NEG_P;

#if defined(ENABLE_SM2_ARM64) || defined(ENABLE_SM2_AMD64)
	// src/sm2_z256_armv8.S
#elif defined(ENABLE_SM2_Z256_NEON)
#include <arm_neon.h>

// precompute <<= 32
// How to use special values of SM2_Z256_P?
const uint64_t SM2_Z256_P_LEFT_32[8] = {
	0xffffffff00000000, 0xffffffff00000000, 0x0000000000000000, 0xffffffff00000000,
	0xffffffff00000000, 0xffffffff00000000, 0xffffffff00000000, 0xfffffffe00000000
};

//const uint32_t SM2_Z256_MU_32 = 0xffffffff; // -1

void sm2_z256_modp_mont_mul(sm2_z256_t r, const sm2_z256_t a, const sm2_z256_t b)
{
	int i;
	sm2_z512_t a_, b_;

	for (i = 0; i < 4; ++i) {
		a_[2 * i]     = a[i] & 0xffffffff;
		a_[2 * i + 1] = a[i] >> 32;
		b_[2 * i]     = b[i] & 0xffffffff;
		b_[2 * i + 1] = b[i] >> 32;
	}

	uint64x2_t d0, d1, d2, d3, d4, d5, d6, d7;
	uint64x2_t t, low32 = vmovq_n_u64(0xffffffff);
	uint32x2_t w0, w1;
	uint64_t q, d[16] = {};
	//uint32_t pre = SM2_Z256_MU_32 * b_[0]; // pre = -b_[0]

	d0 = vmovq_n_u64(0);
	d1 = vmovq_n_u64(0);
	d2 = vmovq_n_u64(0);
	d3 = vmovq_n_u64(0);
	d4 = vmovq_n_u64(0);
	d5 = vmovq_n_u64(0);
	d6 = vmovq_n_u64(0);
	d7 = vmovq_n_u64(0);

	for (i = 0; i < 8; i++) {
		q = -b_[0] * a_[i] + d[1] - d[0];
		q <<= 32;

		w0 = vcreate_u32(a_[i] | q);
		w1 = vcreate_u32(b_[0] | SM2_Z256_P_LEFT_32[0]);
		t = vmlal_u32(d0, w0, w1);
		t = vshrq_n_u64(t, 32);

		w1 = vcreate_u32(b_[1] | SM2_Z256_P_LEFT_32[1]);
		t = vmlal_u32(t, w0, w1);
		t = vaddq_u64(t, d1);
		d0 = vandq_u64(t, low32);
		t = vshrq_n_u64(t, 32);

		w1 = vcreate_u32(b_[2] | SM2_Z256_P_LEFT_32[2]);
		t = vmlal_u32(t, w0, w1);
		t = vaddq_u64(t, d2);
		d1 = vandq_u64(t, low32);
		t = vshrq_n_u64(t, 32);

		w1 = vcreate_u32(b_[3] | SM2_Z256_P_LEFT_32[3]);
		t = vmlal_u32(t, w0, w1);
		t = vaddq_u64(t, d3);
		d2 = vandq_u64(t, low32);
		t = vshrq_n_u64(t, 32);

		w1 = vcreate_u32(b_[4] | SM2_Z256_P_LEFT_32[4]);
		t = vmlal_u32(t, w0, w1);
		t = vaddq_u64(t, d4);
		d3 = vandq_u64(t, low32);
		t = vshrq_n_u64(t, 32);

		w1 = vcreate_u32(b_[5] | SM2_Z256_P_LEFT_32[5]);
		t = vmlal_u32(t, w0, w1);
		t = vaddq_u64(t, d5);
		d4 = vandq_u64(t, low32);
		t = vshrq_n_u64(t, 32);

		w1 = vcreate_u32(b_[6] | SM2_Z256_P_LEFT_32[6]);
		t = vmlal_u32(t, w0, w1);
		t = vaddq_u64(t, d6);
		d5 = vandq_u64(t, low32);
		t = vshrq_n_u64(t, 32);

		w1 = vcreate_u32(b_[7] | SM2_Z256_P_LEFT_32[7]);
		t = vmlal_u32(t, w0, w1);
		t = vaddq_u64(t, d7);
		d6 = vandq_u64(t, low32);

		d7 = vshrq_n_u64(t, 32);

		vst1q_u64(d, d0);
	}

	vst1q_u64(d, d0);
	vst1q_u64(d + 2, d1);
	vst1q_u64(d + 4, d2);
	vst1q_u64(d + 6, d3);
	vst1q_u64(d + 8, d4);
	vst1q_u64(d + 10, d5);
	vst1q_u64(d + 12, d6);
	vst1q_u64(d + 14, d7);

	sm2_z256_t e, f;
	for (i = 0; i < 4; ++i) {
		e[i] = d[4 * i]     | d[4 * i + 2] << 32;
		f[i] = d[4 * i + 1] | d[4 * i + 3] << 32;
	}

	if (sm2_z256_sub(r, e, f)) {
		sm2_z256_add(r, r, SM2_Z256_P);
	}
}

#else // ENABLE_SM2_Z256_NEON

// z = a*b
// c = (z + (z * p' mod 2^256) * p)/2^256
void sm2_z256_modp_mont_mul(sm2_z256_t r, const sm2_z256_t a, const sm2_z256_t b)
{
	sm2_z512_t z;
	sm2_z512_t t;
	uint64_t c;

	//sm2_z256_print(stderr, 0, 0, "a", a);
	//sm2_z256_print(stderr, 0, 0, "b", b);

	// z = a * b
	sm2_z256_mul(z, a, b);
	//sm2_z512_print(stderr, 0, 0, "z", z);

	// t = low(z) * p'
	sm2_z256_mul(t, z, SM2_Z256_P_PRIME);
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
		sm2_z256_add(r, r, SM2_Z256_MODP_MONT_ONE);
		//sm2_z256_print(stderr, 0, 0, "r1", r);

	} else if (sm2_z256_cmp(r, SM2_Z256_P) >= 0) {
		(void)sm2_z256_sub(r, r, SM2_Z256_P);
		//sm2_z256_print(stderr, 0, 0, "r2", r);
	}
}

void sm2_z256_modp_mont_sqr(sm2_z256_t r, const sm2_z256_t a)
{
	sm2_z256_modp_mont_mul(r, a, a);
}

// mont(mont(a), 1) = aR * 1 * R^-1 (mod p) = a (mod p)
void sm2_z256_modp_from_mont(sm2_z256_t r, const sm2_z256_t a)
{
	sm2_z256_modp_mont_mul(r, a, SM2_Z256_ONE);
}

// 2^512 (mod p)
const uint64_t SM2_Z256_2e512modp[4] = {
	0x0000000200000003, 0x00000002ffffffff, 0x0000000100000001, 0x0000000400000002
};

// mont(a) = a * 2^256 (mod p) = mont_mul(a, 2^512 mod p)
void sm2_z256_modp_to_mont(const sm2_z256_t a, uint64_t r[4])
{
	sm2_z256_modp_mont_mul(r, a, SM2_Z256_2e512modp);
}
#endif

void sm2_z256_modp_mont_exp(sm2_z256_t r, const sm2_z256_t a, const sm2_z256_t e)
{
	sm2_z256_t t;
	uint64_t w;
	int i, j;

	// t = mont(1) (mod p)
	sm2_z256_copy(t, SM2_Z256_MODP_MONT_ONE);

	for (i = 3; i >= 0; i--) {
		w = e[i];
		for (j = 0; j < 64; j++) {
			sm2_z256_modp_mont_sqr(t, t);
			if (w & 0x8000000000000000) {
				sm2_z256_modp_mont_mul(t, t, a);
			}
			w <<= 1;
		}
	}

	sm2_z256_copy(r, t);
}

// caller should check a != 0
void sm2_z256_modp_mont_inv(sm2_z256_t r, const sm2_z256_t a)
{
	sm2_z256_t a1;
	sm2_z256_t a2;
	sm2_z256_t a3;
	sm2_z256_t a4;
	sm2_z256_t a5;
	int i;

	sm2_z256_modp_mont_sqr(a1, a);
	sm2_z256_modp_mont_mul(a2, a1, a);
	sm2_z256_modp_mont_sqr(a3, a2);
	sm2_z256_modp_mont_sqr(a3, a3);
	sm2_z256_modp_mont_mul(a3, a3, a2);
	sm2_z256_modp_mont_sqr(a4, a3);
	sm2_z256_modp_mont_sqr(a4, a4);
	sm2_z256_modp_mont_sqr(a4, a4);
	sm2_z256_modp_mont_sqr(a4, a4);
	sm2_z256_modp_mont_mul(a4, a4, a3);
	sm2_z256_modp_mont_sqr(a5, a4);
	for (i = 1; i < 8; i++) {
		sm2_z256_modp_mont_sqr(a5, a5);
	}
	sm2_z256_modp_mont_mul(a5, a5, a4);
	for (i = 0; i < 8; i++) {
		sm2_z256_modp_mont_sqr(a5, a5);
	}
	sm2_z256_modp_mont_mul(a5, a5, a4);
	for (i = 0; i < 4; i++) {
		sm2_z256_modp_mont_sqr(a5, a5);
	}
	sm2_z256_modp_mont_mul(a5, a5, a3);
	sm2_z256_modp_mont_sqr(a5, a5);
	sm2_z256_modp_mont_sqr(a5, a5);
	sm2_z256_modp_mont_mul(a5, a5, a2);
	sm2_z256_modp_mont_sqr(a5, a5);
	sm2_z256_modp_mont_mul(a5, a5, a);
	sm2_z256_modp_mont_sqr(a4, a5);
	sm2_z256_modp_mont_mul(a3, a4, a1);
	sm2_z256_modp_mont_sqr(a5, a4);
	for (i = 1; i< 31; i++) {
		sm2_z256_modp_mont_sqr(a5, a5);
	}
	sm2_z256_modp_mont_mul(a4, a5, a4);
	sm2_z256_modp_mont_sqr(a4, a4);
	sm2_z256_modp_mont_mul(a4, a4, a);
	sm2_z256_modp_mont_mul(a3, a4, a2);
	for (i = 0; i < 33; i++) {
		sm2_z256_modp_mont_sqr(a5, a5);
	}
	sm2_z256_modp_mont_mul(a2, a5, a3);
	sm2_z256_modp_mont_mul(a3, a2, a3);
	for (i = 0; i < 32; i++) {
		sm2_z256_modp_mont_sqr(a5, a5);
	}
	sm2_z256_modp_mont_mul(a2, a5, a3);
	sm2_z256_modp_mont_mul(a3, a2, a3);
	sm2_z256_modp_mont_mul(a4, a2, a4);
	for (i = 0; i < 32; i++) {
		sm2_z256_modp_mont_sqr(a5, a5);
	}
	sm2_z256_modp_mont_mul(a2, a5, a3);
	sm2_z256_modp_mont_mul(a3, a2, a3);
	sm2_z256_modp_mont_mul(a4, a2, a4);
	for (i = 0; i < 32; i++) {
		sm2_z256_modp_mont_sqr(a5, a5);
	}
	sm2_z256_modp_mont_mul(a2, a5, a3);
	sm2_z256_modp_mont_mul(a3, a2, a3);
	sm2_z256_modp_mont_mul(a4, a2, a4);
	for (i = 0; i < 32; i++) {
		sm2_z256_modp_mont_sqr(a5, a5);
	}
	sm2_z256_modp_mont_mul(a2, a5, a3);
	sm2_z256_modp_mont_mul(a3, a2, a3);
	sm2_z256_modp_mont_mul(a4, a2, a4);
	for (i = 0; i < 32; i++) {
		sm2_z256_modp_mont_sqr(a5, a5);
	}
	sm2_z256_modp_mont_mul(r, a4, a5);
}

// (p+1)/4 = 3fffffffbfffffffffffffffffffffffffffffffc00000004000000000000000
const uint64_t SM2_Z256_SQRT_EXP[4] = {
	0x4000000000000000, 0xffffffffc0000000, 0xffffffffffffffff, 0x3fffffffbfffffff,
};

// -r (mod p), i.e. (p - r) is also a square root of a
int sm2_z256_modp_mont_sqrt(sm2_z256_t r, const sm2_z256_t a)
{
	sm2_z256_t a_;
	sm2_z256_t r_; // temp result, prevent call sm2_fp_sqrt(a, a)

	// r = a^((p + 1)/4) when p = 3 (mod 4)
	sm2_z256_modp_mont_exp(r_, a, SM2_Z256_SQRT_EXP);

	// check r^2 == a
	sm2_z256_modp_mont_sqr(a_, r_);
	if (sm2_z256_cmp(a_, a) != 0) {
		// not every number has a square root, so it is not an error
		// `sm2_z256_point_from_hash` need a non-negative return value
		return 0;
	}

	sm2_z256_copy(r, r_);
	return 1;
}

// GF(n)

// n = 0xfffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123
const uint64_t SM2_Z256_N[4] = {
	0x53bbf40939d54123, 0x7203df6b21c6052b, 0xffffffffffffffff, 0xfffffffeffffffff,
};

const uint64_t SM2_Z256_N_MINUS_ONE[4] = {
	0x53bbf40939d54122, 0x7203df6b21c6052b, 0xffffffffffffffff, 0xfffffffeffffffff,
};


// 2^256 - n = 0x10000000000000000000000008dfc2094de39fad4ac440bf6c62abedd
const uint64_t SM2_Z256_NEG_N[4] = {
	0xac440bf6c62abedd, 0x8dfc2094de39fad4, 0x0000000000000000, 0x0000000100000000,
};

#if !defined(ENABLE_SM2_ARM64)
void sm2_z256_modn_add(sm2_z256_t r, const sm2_z256_t a, const sm2_z256_t b)
{
	uint64_t c;

	c = sm2_z256_add(r, a, b);

	if (c) {
		// a + b - n = (a + b - 2^256) + (2^256 - n)
		(void)sm2_z256_add(r, r, SM2_Z256_NEG_N);
		return;
	}

	if (sm2_z256_cmp(r, SM2_Z256_N) >= 0) {
		(void)sm2_z256_sub(r, r, SM2_Z256_N);
	}
}

void sm2_z256_modn_sub(sm2_z256_t r, const sm2_z256_t a, const sm2_z256_t b)
{
	uint64_t c;

	c = sm2_z256_sub(r, a, b);

	if (c) {
		// a - b + n = (a - b + 2^256) - (2^256 - n)
		(void)sm2_z256_sub(r, r, SM2_Z256_NEG_N);
	}
}

void sm2_z256_modn_neg(sm2_z256_t r, const sm2_z256_t a)
{
	(void)sm2_z256_sub(r, SM2_Z256_N, a);
}
#endif

// n' = -n^(-1) mod 2^256
//    = 0x6f39132f82e4c7bc2b0068d3b08941d4df1e8d34fc8319a5327f9e8872350975
// sage: -(IntegerModRing(2^256)(n))^-1
const uint64_t SM2_Z256_N_PRIME[4] = {
	0x327f9e8872350975, 0xdf1e8d34fc8319a5, 0x2b0068d3b08941d4, 0x6f39132f82e4c7bc,
};

const uint64_t *sm2_z256_order(void) {
	return &SM2_Z256_N[0];
}

const uint64_t *sm2_z256_order_minus_one(void) {
	return &SM2_Z256_N_MINUS_ONE[0];
}


// mont(1) (mod n) = 2^256 - n
const uint64_t *SM2_Z256_MODN_MONT_ONE = SM2_Z256_NEG_N;


#if !defined(ENABLE_SM2_ARM64) 
void sm2_z256_modn_mont_mul(sm2_z256_t r, const sm2_z256_t a, const sm2_z256_t b)
{
	sm2_z512_t z;
	sm2_z512_t t;
	uint64_t c;

	// z = a * b
	sm2_z256_mul(z, a, b);
	//sm2_z512_print(stderr, 0, 0, "z", z);

	// t = low(z) * n'
	sm2_z256_mul(t, z, SM2_Z256_N_PRIME);
	//sm2_z256_print(stderr, 0, 0, "z * n' mod 2^256", t);

	// t = low(t) * n
	sm2_z256_mul(t, t, SM2_Z256_N);
	//sm2_z512_print(stderr, 0, 0, "(z * n' mod 2^256) * n", t);

	// z = z + t
	c = sm2_z512_add(z, z, t);
	//sm2_z512_print(stderr, 0, 0, "z", z);

	// r = high(r)
	sm2_z256_copy(r, z + 4);
	//sm2_z256_print(stderr, 0, 0, "r", r);

	if (c) {
		sm2_z256_add(r, r, SM2_Z256_MODN_MONT_ONE);
		//sm2_z256_print(stderr, 0, 0, "r1", r);

	} else if (sm2_z256_cmp(r, SM2_Z256_N) >= 0) {
		(void)sm2_z256_sub(r, r, SM2_Z256_N);
		//sm2_z256_print(stderr, 0, 0, "r2", r);
	}
}
#endif

void sm2_z256_modn_mul(sm2_z256_t r, const sm2_z256_t a, const sm2_z256_t b)
{
	sm2_z256_t mont_a;
	sm2_z256_t mont_b;

	sm2_z256_modn_to_mont(a, mont_a);
	sm2_z256_modn_to_mont(b, mont_b);
	sm2_z256_modn_mont_mul(r, mont_a, mont_b);
	sm2_z256_modn_from_mont(r, r);
}

#if !defined(ENABLE_SM2_ARM64)
void sm2_z256_modn_mont_sqr(sm2_z256_t r, const sm2_z256_t a)
{
	sm2_z256_modn_mont_mul(r, a, a);
}
#endif

void sm2_z256_modn_sqr(sm2_z256_t r, const sm2_z256_t a)
{
	sm2_z256_t mont_a;

	sm2_z256_modn_to_mont(a, mont_a);
	sm2_z256_modn_mont_sqr(r, mont_a);
	sm2_z256_modn_from_mont(r, r);
}

void sm2_z256_modn_mont_exp(sm2_z256_t r, const sm2_z256_t a, const sm2_z256_t e)
{
	sm2_z256_t t;
	uint64_t w;
	int i, j;

	// t = mont(1)
	sm2_z256_copy(t, SM2_Z256_MODN_MONT_ONE);

	for (i = 3; i >= 0; i--) {
		w = e[i];
		for (j = 0; j < 64; j++) {
			sm2_z256_modn_mont_sqr(t, t);
			if (w & 0x8000000000000000) {
				sm2_z256_modn_mont_mul(t, t, a);
			}
			w <<= 1;
		}
	}

	sm2_z256_copy(r, t);
}

void sm2_z256_modn_exp(sm2_z256_t r, const sm2_z256_t a, const sm2_z256_t e)
{
	sm2_z256_t mont_a;

	sm2_z256_modn_to_mont(a, mont_a);
	sm2_z256_modn_mont_exp(r, mont_a, e);
	sm2_z256_modn_from_mont(r, r);
}

// n - 2 = 0xfffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54121
const uint64_t SM2_Z256_N_MINUS_TWO[4] = {
	0x53bbf40939d54121, 0x7203df6b21c6052b, 0xffffffffffffffff, 0xfffffffeffffffff,
};
// TODO: use the special form of SM2_Z256_N_MINUS_TWO[2, 3]		

void sm2_z256_modn_mont_inv(sm2_z256_t r, const sm2_z256_t a)
{
	// expand sm2_z256_modn_mont_exp(r, a, SM2_Z256_N_MINUS_TWO)
	sm2_z256_t t;
	uint64_t w;
	int i;
	int k = 0;

	sm2_z256_copy(t, a);

	for (i = 0; i < 30; i++) {
		sm2_z256_modn_mont_sqr(t, t);
		sm2_z256_modn_mont_mul(t, t, a);
	}
	sm2_z256_modn_mont_sqr(t, t);
	for (i = 0; i < 96; i++) {
		sm2_z256_modn_mont_sqr(t, t);
		sm2_z256_modn_mont_mul(t, t, a);
	}
	w = SM2_Z256_N_MINUS_TWO[1];
	for (i = 0; i < 64; i++) {
		sm2_z256_modn_mont_sqr(t, t);
		if (w & 0x8000000000000000) {
			sm2_z256_modn_mont_mul(t, t, a);
		}
		w <<= 1;
	}
	w = SM2_Z256_N_MINUS_TWO[0];
	for (i = 0; i < 64; i++) {
		sm2_z256_modn_mont_sqr(t, t);
		if (w & 0x8000000000000000) {
			sm2_z256_modn_mont_mul(t, t, a);
		}
		w <<= 1;
	}

	sm2_z256_copy(r, t);
}

void sm2_z256_modn_inv(sm2_z256_t r, const sm2_z256_t a)
{
	sm2_z256_t mont_a;

	sm2_z256_modn_to_mont(a, mont_a);
	sm2_z256_modn_mont_inv(r, mont_a);
	sm2_z256_modn_from_mont(r, r);
}


#if !defined(ENABLE_SM2_ARM64)

// mont(mont(a), 1) = aR * 1 * R^-1 (mod n) = a (mod p)
void sm2_z256_modn_from_mont(sm2_z256_t r, const sm2_z256_t a)
{
	sm2_z256_modn_mont_mul(r, a, SM2_Z256_ONE);
}

// 2^512 (mod n) = 0x1eb5e412a22b3d3b620fc84c3affe0d43464504ade6fa2fa901192af7c114f20
const uint64_t SM2_Z256_2e512modn[4] = {
	0x901192af7c114f20, 0x3464504ade6fa2fa, 0x620fc84c3affe0d4, 0x1eb5e412a22b3d3b,
};

// mont(a) = a * 2^256 (mod n) = mont_mul(a, 2^512 mod n)
void sm2_z256_modn_to_mont(const sm2_z256_t a, uint64_t r[4])
{
	sm2_z256_modn_mont_mul(r, a, SM2_Z256_2e512modn);
}
#endif


// Jacobian Point with Montgomery coordinates

void sm2_z256_point_set_infinity(SM2_Z256_POINT *P)
{
	sm2_z256_copy(P->X, SM2_Z256_MODP_MONT_ONE);
	sm2_z256_copy(P->Y, SM2_Z256_MODP_MONT_ONE);
	sm2_z256_set_zero(P->Z);
}

// point at infinity should be like (k^2 : k^3 : 0), k in [0, p-1]
int sm2_z256_point_is_at_infinity(const SM2_Z256_POINT *P)
{
	if (sm2_z256_is_zero(P->Z)) {
		sm2_z256_t X_cub;
		sm2_z256_t Y_sqr;

		sm2_z256_modp_mont_sqr(X_cub, P->X);
		sm2_z256_modp_mont_mul(X_cub, X_cub, P->X);
		sm2_z256_modp_mont_sqr(Y_sqr, P->Y);

		if (sm2_z256_cmp(X_cub, Y_sqr) != 0) {
			error_print();
			return 0;
		}

		return 1;
	} else {
		return 0;
	}
}

// mont(b), b = 0x28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93
const uint64_t SM2_Z256_MODP_MONT_B[4] = {
	0x90d230632bc0dd42, 0x71cf379ae9b537ab, 0x527981505ea51c3c, 0x240fe188ba20e2c8,
};

int sm2_z256_point_is_on_curve(const SM2_Z256_POINT *P)
{
	sm2_z256_t t0;
	sm2_z256_t t1;
	sm2_z256_t t2;

	if (sm2_z256_cmp(P->Z, SM2_Z256_MODP_MONT_ONE) == 0) {
		// if Z == 1, check y^2 + 3*x == x^3 + b
		sm2_z256_modp_mont_sqr(t0, P->Y);
		sm2_z256_modp_add(t0, t0, P->X);
		sm2_z256_modp_add(t0, t0, P->X);
		sm2_z256_modp_add(t0, t0, P->X);
		sm2_z256_modp_mont_sqr(t1, P->X);
		sm2_z256_modp_mont_mul(t1, t1, P->X);
		sm2_z256_modp_add(t1, t1, SM2_Z256_MODP_MONT_B);
	} else {
		// check Y^2 + 3 * X * Z^4 == X^3 + b * Z^6
		// if Z == 0, Y^2 == X^3, i.e. Y == X is checked
		sm2_z256_modp_mont_sqr(t0, P->Y);
		sm2_z256_modp_mont_sqr(t1, P->Z);
		sm2_z256_modp_mont_sqr(t2, t1);
		sm2_z256_modp_mont_mul(t1, t1, t2);
		sm2_z256_modp_mont_mul(t1, t1, SM2_Z256_MODP_MONT_B);
		sm2_z256_modp_mont_mul(t2, t2, P->X);
		sm2_z256_modp_add(t0, t0, t2);
		sm2_z256_modp_add(t0, t0, t2);
		sm2_z256_modp_add(t0, t0, t2);
		sm2_z256_modp_mont_sqr(t2, P->X);
		sm2_z256_modp_mont_mul(t2, t2, P->X);
		sm2_z256_modp_add(t1, t1, t2);
	}

	if (sm2_z256_cmp(t0, t1) != 0) {
		return 0;
	}
	return 1;
}

int sm2_z256_point_get_xy(const SM2_Z256_POINT *P, uint64_t x[4], uint64_t y[4])
{
	if (sm2_z256_point_is_at_infinity(P) == 1) {
		sm2_z256_set_zero(x);
		if (y) {
			sm2_z256_set_zero(y);
		}
		return 0;
	}

	if (sm2_z256_cmp(P->Z, SM2_Z256_MODP_MONT_ONE) == 0) {
		sm2_z256_modp_from_mont(x, P->X);
		if (y) {
			sm2_z256_modp_from_mont(y, P->Y);
		}
	} else {
		sm2_z256_t z_inv;

		sm2_z256_modp_mont_inv(z_inv, P->Z);
		if (y) {
			sm2_z256_modp_mont_mul(y, P->Y, z_inv);
		}
		sm2_z256_modp_mont_sqr(z_inv, z_inv);
		sm2_z256_modp_mont_mul(x, P->X, z_inv);
		sm2_z256_modp_from_mont(x, x);
		if (y) {
			sm2_z256_modp_mont_mul(y, y, z_inv);
			sm2_z256_modp_from_mont(y, y);
		}
	}

	return 1;
}

#if !defined(ENABLE_SM2_ARM64) && !defined(ENABLE_SM2_AMD64)
void sm2_z256_point_dbl(SM2_Z256_POINT *R, const SM2_Z256_POINT *A)
{
	const uint64_t *X1 = A->X;
	const uint64_t *Y1 = A->Y;
	const uint64_t *Z1 = A->Z;
	uint64_t *X3 = R->X;
	uint64_t *Y3 = R->Y;
	uint64_t *Z3 = R->Z;
	sm2_z256_t S;
	sm2_z256_t M;
	sm2_z256_t Zsqr;
	sm2_z256_t tmp0;

	// 1. S = 2Y
	sm2_z256_modp_dbl(S, Y1);

	// 2. Zsqr = Z^2
	sm2_z256_modp_mont_sqr(Zsqr, Z1);

	// 3. S = S^2 = 4Y^2
	sm2_z256_modp_mont_sqr(S, S);

	// 4. Z = Z*Y
	sm2_z256_modp_mont_mul(Z3, Z1, Y1);

	// 5. Z = 2*Z = 2*Y*Z ===> Z3
	sm2_z256_modp_dbl(Z3, Z3);

	// 6. M = X + Zsqr = X + Z^2
	sm2_z256_modp_add(M, X1, Zsqr);

	// 7. Zsqr = X - Zsqr = X - Z^2
	sm2_z256_modp_sub(Zsqr, X1, Zsqr);

	// 8. Y = S^2 = 16Y^4
	sm2_z256_modp_mont_sqr(Y3, S);

	// 9. Y = Y/2 = 8Y^4
	sm2_z256_modp_haf(Y3, Y3);

	// 10. M = M * Zsqr = (X + Z^2)*(X - Z^2) = X^2 - Z^4
	sm2_z256_modp_mont_mul(M, M, Zsqr);

	// 11. M = 3M = 3X^2 - 3Z^4
	sm2_z256_modp_tri(M, M);

	// 12. S = S * X = 4X*Y^2
	sm2_z256_modp_mont_mul(S, S, X1);

	// 13. tmp0 = 2 * S = 8X*Y^2
	sm2_z256_modp_dbl(tmp0, S);

	// 14. X = M^2 = (3X^2 - 3Z^4)^2
	sm2_z256_modp_mont_sqr(X3, M);

	// 15. X = X - tmp0 = (3X^2 - 3Z^4)^2 - 8X*Y^2 ===> X3
	sm2_z256_modp_sub(X3, X3, tmp0);

	// 16. S = S - X3 = 4X*Y^2 - X3
	sm2_z256_modp_sub(S, S, X3);

	// 17. S = S * M = (3X^2 - 3Z^4)*(4X*Y^2 - X3)
	sm2_z256_modp_mont_mul(S, S, M);

	// 18. Y = S - Y = (3X^2 - 3Z^4)*(4X*Y^2 - X3) - 8Y^4 ===> Y3
	sm2_z256_modp_sub(Y3, S, Y3);
}

/*
  (X1:Y1:Z1) + (X2:Y2:Z2) => (X3:Y3:Z3)

	A = Y2 * Z1^3 - Y1 * Z2^3
	B = X2 * Z1^2 - X1 * Z2^2

	X3 = A^2 - B^2 * (X2 * Z1^2 + X1 * Z2^2)
	   = A^2 - B^3 - 2 * B^2 * X1 * Z2^2
	Y3 = A * (X1 * B^2 * Z2^2 - X3) - Y1 * B^3 * Z2^3
	Z3 = B * Z1 * Z2

  P + (-P) = (X:Y:Z) + (k^2*X : k^3*Y : k*Z) => (0:0:0)
*/
void sm2_z256_point_add(SM2_Z256_POINT *r, const SM2_Z256_POINT *a, const SM2_Z256_POINT *b)
{
	sm2_z256_t U2, S2;
	sm2_z256_t U1, S1;
	sm2_z256_t Z1sqr;
	sm2_z256_t Z2sqr;
	sm2_z256_t H, R;
	sm2_z256_t Hsqr;
	sm2_z256_t Rsqr;
	sm2_z256_t Hcub;

	sm2_z256_t res_x;
	sm2_z256_t res_y;
	sm2_z256_t res_z;

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

	// TODO: can we parallel on the following code?		
	sm2_z256_modp_mont_sqr(Z2sqr, in2_z);        /* Z2^2 */
	sm2_z256_modp_mont_sqr(Z1sqr, in1_z);        /* Z1^2 */

	sm2_z256_modp_mont_mul(S1, Z2sqr, in2_z);    /* S1 = Z2^3 */
	sm2_z256_modp_mont_mul(S2, Z1sqr, in1_z);    /* S2 = Z1^3 */

	sm2_z256_modp_mont_mul(S1, S1, in1_y);       /* S1 = Y1*Z2^3 */
	sm2_z256_modp_mont_mul(S2, S2, in2_y);       /* S2 = Y2*Z1^3 */
	sm2_z256_modp_sub(R, S2, S1);                /* R = S2 - S1 */

	sm2_z256_modp_mont_mul(U1, in1_x, Z2sqr);    /* U1 = X1*Z2^2 */
	sm2_z256_modp_mont_mul(U2, in2_x, Z1sqr);    /* U2 = X2*Z1^2 */
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

	sm2_z256_modp_mont_sqr(Rsqr, R);             /* R^2 */
	sm2_z256_modp_mont_mul(res_z, H, in1_z);     /* Z3 = H*Z1*Z2 */

	sm2_z256_modp_mont_sqr(Hsqr, H);             /* H^2 */
	sm2_z256_modp_mont_mul(res_z, res_z, in2_z); /* Z3 = H*Z1*Z2 */

	sm2_z256_modp_mont_mul(Hcub, Hsqr, H);       /* H^3 */
	sm2_z256_modp_mont_mul(U2, U1, Hsqr);        /* U1*H^2 */

	sm2_z256_modp_dbl(Hsqr, U2);            /* 2*U1*H^2 */

	sm2_z256_modp_sub(res_x, Rsqr, Hsqr);
	sm2_z256_modp_sub(res_x, res_x, Hcub);

	sm2_z256_modp_sub(res_y, U2, res_x);

	sm2_z256_modp_mont_mul(S2, S1, Hcub);
	sm2_z256_modp_mont_mul(res_y, R, res_y);

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
#endif

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

void sm2_z256_point_mul_pre_compute(const SM2_Z256_POINT *P, SM2_Z256_POINT T[16])
{
	memcpy(&T[0], P, sizeof(SM2_Z256_POINT));

	if (sm2_z256_equ(P->Z, SM2_Z256_MODP_MONT_ONE) == 1) {
		const SM2_Z256_AFFINE_POINT *P_ = (const SM2_Z256_AFFINE_POINT *)P;
		sm2_z256_point_dbl(&T[ 1], &T[ 0]);
		sm2_z256_point_add_affine(&T[ 2], &T[ 1], P_);
		sm2_z256_point_dbl(&T[ 3], &T[ 1]);
		sm2_z256_point_add_affine(&T[ 4], &T[ 3], P_);
		sm2_z256_point_dbl(&T[ 5], &T[ 2]);
		sm2_z256_point_add_affine(&T[ 6], &T[ 5], P_);
		sm2_z256_point_dbl(&T[ 7], &T[ 3]);
		sm2_z256_point_add_affine(&T[ 8], &T[ 7], P_);
		sm2_z256_point_dbl(&T[ 9], &T[ 4]);
		sm2_z256_point_add_affine(&T[10], &T[ 9], P_);
		sm2_z256_point_dbl(&T[11], &T[ 5]);
		sm2_z256_point_add_affine(&T[12], &T[11], P_);
		sm2_z256_point_dbl(&T[13], &T[ 6]);
		sm2_z256_point_add_affine(&T[14], &T[13], P_);
		sm2_z256_point_dbl(&T[15], &T[ 7]);
	} else {
		sm2_z256_point_dbl(&T[2-1], &T[1-1]);
		sm2_z256_point_dbl(&T[4-1], &T[2-1]);
		sm2_z256_point_dbl(&T[8-1], &T[4-1]);
		sm2_z256_point_dbl(&T[16-1], &T[8-1]);
		sm2_z256_point_add(&T[3-1], &T[2-1], P);
		sm2_z256_point_dbl(&T[6-1], &T[3-1]);
		sm2_z256_point_dbl(&T[12-1], &T[6-1]);
		sm2_z256_point_add(&T[5-1], &T[3-1], &T[2-1]);
		sm2_z256_point_dbl(&T[10-1], &T[5-1]);
		sm2_z256_point_add(&T[7-1], &T[4-1], &T[3-1]);
		sm2_z256_point_dbl(&T[14-1], &T[7-1]);
		sm2_z256_point_add(&T[9-1], &T[4-1], &T[5-1]);
		sm2_z256_point_add(&T[11-1], &T[6-1], &T[5-1]);
		sm2_z256_point_add(&T[13-1], &T[7-1], &T[6-1]);
		sm2_z256_point_add(&T[15-1], &T[8-1], &T[7-1]);
	}
}

void sm2_z256_point_mul_ex(SM2_Z256_POINT *R, const uint64_t k[4], const SM2_Z256_POINT *T)
{
	int window_size = 5;
	int R_infinity = 1;
	int n = (256 + window_size - 1)/window_size;
	int i;

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

void sm2_z256_point_mul(SM2_Z256_POINT *R, const sm2_z256_t k, const SM2_Z256_POINT *P)
{
	int window_size = 5;
	SM2_Z256_POINT T[16];
	int R_infinity = 1;
	int n = (256 + window_size - 1)/window_size;
	int i;

	sm2_z256_point_mul_pre_compute(P, T);

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

int sm2_z256_point_print(FILE *fp, int fmt, int ind, const char *label, const SM2_Z256_POINT *P)
{
	if (sm2_z256_point_is_at_infinity(P) == 1) {
		format_print(fp, fmt, ind, "%s: point_at_infinity\n", label);
	} else {
		uint8_t bytes[64];
		sm2_z256_point_to_bytes(P, bytes);
		format_bytes(fp, fmt, ind, label, bytes, 64);
	}
	return 1;
}

void sm2_z256_point_copy_affine(SM2_Z256_POINT *R, const SM2_Z256_AFFINE_POINT *P)
{
	memcpy(R, P, sizeof(SM2_Z256_AFFINE_POINT));
	sm2_z256_copy(R->Z, SM2_Z256_MODP_MONT_ONE);
}

#if !defined(ENABLE_SM2_ARM64) && !defined(ENABLE_SM2_AMD64)
void sm2_z256_point_add_affine(SM2_Z256_POINT *r, const SM2_Z256_POINT *a, const SM2_Z256_AFFINE_POINT *b)
{
	sm2_z256_t U2, S2;
	sm2_z256_t Z1sqr;
	sm2_z256_t H, R;
	sm2_z256_t Hsqr;
	sm2_z256_t Rsqr;
	sm2_z256_t Hcub;

	sm2_z256_t res_x;
	sm2_z256_t res_y;
	sm2_z256_t res_z;

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
	sm2_z256_modp_mont_sqr(Z1sqr, in1_z);

	/* U2 = X2*Z1^2 */
	sm2_z256_modp_mont_mul(U2, in2_x, Z1sqr);
	/* H = U2 - U1 */
	sm2_z256_modp_sub(H, U2, in1_x);

	sm2_z256_modp_mont_mul(S2, Z1sqr, in1_z);    /* S2 = Z1^3 */

	sm2_z256_modp_mont_mul(res_z, H, in1_z);     /* Z3 = H*Z1*Z2 */

	sm2_z256_modp_mont_mul(S2, S2, in2_y);       /* S2 = Y2*Z1^3 */
	sm2_z256_modp_sub(R, S2, in1_y);             /* R = S2 - S1 */

	sm2_z256_modp_mont_sqr(Hsqr, H);             /* H^2 */
	sm2_z256_modp_mont_sqr(Rsqr, R);             /* R^2 */
	sm2_z256_modp_mont_mul(Hcub, Hsqr, H);       /* H^3 */

	sm2_z256_modp_mont_mul(U2, in1_x, Hsqr);     /* U1*H^2 */
	sm2_z256_modp_dbl(Hsqr, U2);            /* 2*U1*H^2 */

	sm2_z256_modp_sub(res_x, Rsqr, Hsqr);
	sm2_z256_modp_sub(res_x, res_x, Hcub);
	sm2_z256_modp_sub(H, U2, res_x);

	sm2_z256_modp_mont_mul(S2, in1_y, Hcub);
	sm2_z256_modp_mont_mul(H, H, R);
	sm2_z256_modp_sub(res_y, H, S2);

	sm2_z256_copy_conditional(res_x, in2_x, in1infty);
	sm2_z256_copy_conditional(res_x, in1_x, in2infty);

	sm2_z256_copy_conditional(res_y, in2_y, in1infty);
	sm2_z256_copy_conditional(res_y, in1_y, in2infty);

	sm2_z256_copy_conditional(res_z, SM2_Z256_MODP_MONT_ONE, in1infty);
	sm2_z256_copy_conditional(res_z, in1_z, in2infty);

	memcpy(r->X, res_x, sizeof(res_x));
	memcpy(r->Y, res_y, sizeof(res_y));
	memcpy(r->Z, res_z, sizeof(res_z));
}
#endif

void sm2_z256_point_sub_affine(SM2_Z256_POINT *R,
	const SM2_Z256_POINT *A, const SM2_Z256_AFFINE_POINT *B)
{
	SM2_Z256_AFFINE_POINT neg_B;

	sm2_z256_copy(neg_B.x, B->x);
	sm2_z256_modp_neg(neg_B.y, B->y);

	sm2_z256_point_add_affine(R, A, &neg_B);
}

int sm2_z256_point_affine_print(FILE *fp, int fmt, int ind, const char *label, const SM2_Z256_AFFINE_POINT *P)
{
	sm2_z256_t a;
	uint8_t affine[64];

	sm2_z256_modp_from_mont(a, P->x);
	sm2_z256_to_bytes(a, affine);

	sm2_z256_modp_from_mont(a, P->y);
	sm2_z256_to_bytes(a, affine + 32);

	format_bytes(fp, fmt, ind, label, affine, 64);
	return 1;
}

extern const uint64_t sm2_z256_pre_comp[37][64 * 4 * 2];
static SM2_Z256_AFFINE_POINT (*g_pre_comp)[64] = (SM2_Z256_AFFINE_POINT (*)[64])sm2_z256_pre_comp;

// FIXME: remove if/else
void sm2_z256_point_mul_generator(SM2_Z256_POINT *R, const sm2_z256_t k)
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
		sm2_z256_point_set_infinity(R);
	}
}

// R = t*P + s*G
void sm2_z256_point_mul_sum(SM2_Z256_POINT *R, const uint64_t t[4], const SM2_Z256_POINT *P, const uint64_t s[4])
{
	SM2_Z256_POINT Q;
	sm2_z256_point_mul_generator(R, s);
	sm2_z256_point_mul(&Q, t, P);
	sm2_z256_point_add(R, R, &Q);
}

// point_at_infinity can not be encoded/decoded to/from bytes
int sm2_z256_point_from_bytes(SM2_Z256_POINT *P, const uint8_t in[64])
{
	sm2_z256_from_bytes(P->X, in);
	if (sm2_z256_cmp(P->X, sm2_z256_prime()) >= 0) {
		error_print();
		return -1;
	}
	sm2_z256_from_bytes(P->Y, in + 32);
	if (sm2_z256_cmp(P->Y, sm2_z256_prime()) >= 0) {
		error_print();
		return -1;
	}

	// point_at_infinity
	if (sm2_z256_is_zero(P->X) == 1 && sm2_z256_is_zero(P->Y) == 1) {
		sm2_z256_point_set_infinity(P);
		return 0;
	}

	sm2_z256_modp_to_mont(P->X, P->X);
	sm2_z256_modp_to_mont(P->Y, P->Y);
	sm2_z256_copy(P->Z, SM2_Z256_MODP_MONT_ONE);

	if (sm2_z256_point_is_on_curve(P) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_z256_point_set_xy(SM2_Z256_POINT *R, const sm2_z256_t x, const sm2_z256_t y)
{
	if (sm2_z256_cmp(x, sm2_z256_prime()) >= 0) {
		error_print();
		return -1;
	}
	if (sm2_z256_cmp(y, sm2_z256_prime()) >= 0) {
		error_print();
		return -1;
	}

	sm2_z256_modp_to_mont(x, R->X);
	sm2_z256_modp_to_mont(y, R->Y);
	sm2_z256_copy(R->Z, SM2_Z256_MODP_MONT_ONE);

	if (sm2_z256_point_is_on_curve(R) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_z256_point_from_hex(SM2_Z256_POINT *P, const char *hex)
{
	uint8_t bytes[64];
	size_t len;
	int ret;

	hex_to_bytes(hex, 128, bytes, &len);
	if ((ret = sm2_z256_point_from_bytes(P, bytes)) < 0) {
		error_print();
		return -1;
	}
	return ret;
}

// point_at_infinity should not to_bytes
int sm2_z256_point_to_bytes(const SM2_Z256_POINT *P, uint8_t out[64])
{
	sm2_z256_t x;
	sm2_z256_t y;
	int ret;

	if ((ret = sm2_z256_point_get_xy(P, x, y)) < 0) {
		error_print();
		return -1;
	}
	sm2_z256_to_bytes(x, out);
	sm2_z256_to_bytes(y, out + 32);
	return ret;
}

int sm2_z256_point_equ(const SM2_Z256_POINT *P, const SM2_Z256_POINT *Q)
{
	sm2_z256_t Z1;
	sm2_z256_t Z2;
	sm2_z256_t V1;
	sm2_z256_t V2;

	// X1 * Z2^2 == X2 * Z1^2
	sm2_z256_modp_mont_sqr(Z1, P->Z);
	sm2_z256_modp_mont_sqr(Z2, Q->Z);
	sm2_z256_modp_mont_mul(V1, P->X, Z2);
	sm2_z256_modp_mont_mul(V2, Q->X, Z1);
	if (sm2_z256_cmp(V1, V2) != 0) {
		return 0;
	}

	// Y1 * Z2^3 == Y2 * Z1^3
	sm2_z256_modp_mont_mul(Z1, Z1, P->Z);
	sm2_z256_modp_mont_mul(Z2, Z2, Q->Z);
	sm2_z256_modp_mont_mul(V1, P->Y, Z2);
	sm2_z256_modp_mont_mul(V2, Q->Y, Z1);
	if (sm2_z256_cmp(V1, V2) != 0) {
		return 0;
	}

	return 1;
}

int sm2_z256_point_equ_hex(const SM2_Z256_POINT *P, const char *hex)
{
	uint8_t P_bytes[64];
	uint8_t hex_bytes[64];
	size_t len;

	if (sm2_z256_point_to_bytes(P, P_bytes) < 0) {
		error_print();
		return 0;
	}

	hex_to_bytes(hex, 128, hex_bytes, &len);

	if (memcmp(P_bytes, hex_bytes, 64) != 0) {
		return 0;
	}
	return 1;
}

int sm2_z256_is_odd(const sm2_z256_t a)
{
	return a[0] & 0x01;
}

// return 0 if no point for given x coordinate
int sm2_z256_point_from_x_bytes(SM2_Z256_POINT *P, const uint8_t x_bytes[32], int y_is_odd)
{
	// mont(3), i.e. mont(-b)
	const uint64_t SM2_Z256_MODP_MONT_THREE[4] = {
		0x0000000000000003, 0x00000002fffffffd, 0x0000000000000000, 0x0000000300000000
	};

	sm2_z256_t x;
	sm2_z256_t y;
	sm2_z256_t y_sqr;
	int ret;

	sm2_z256_from_bytes(x, x_bytes);
	if (sm2_z256_cmp(x, SM2_Z256_P) >= 0) {
		error_print();
		return -1;
	}
	sm2_z256_modp_to_mont(x, x);
	sm2_z256_copy(P->X, x);

	// y^2 = x^3 - 3x + b = (x^2 - 3)*x + b
	sm2_z256_modp_mont_sqr(y_sqr, x);
	sm2_z256_modp_sub(y_sqr, y_sqr, SM2_Z256_MODP_MONT_THREE);
	sm2_z256_modp_mont_mul(y_sqr, y_sqr, x);
	sm2_z256_modp_add(y_sqr, y_sqr, SM2_Z256_MODP_MONT_B);

	// y = sqrt(y^2)
	if ((ret = sm2_z256_modp_mont_sqrt(y, y_sqr)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}

	sm2_z256_copy(P->Y , y); // mont(y)

	sm2_z256_modp_from_mont(y, y);
	if (y_is_odd) {
		if (!sm2_z256_is_odd(y)) {
			sm2_z256_modp_neg(P->Y, P->Y);
		}
	} else {
		if (sm2_z256_is_odd(y)) {
			sm2_z256_modp_neg(P->Y, P->Y);
		}
	}

	sm2_z256_copy(P->Z, SM2_Z256_MODP_MONT_ONE);

	return 1;
}

int sm2_z256_point_from_hash(SM2_Z256_POINT *R, const uint8_t *data, size_t datalen, int y_is_odd)
{
	sm2_z256_t x;
	uint8_t x_bytes[32];
	uint8_t dgst[32];
	int ret;

	do {
		// x = sm3(data) mod p
		SM3_CTX sm3_ctx;
		sm3_init(&sm3_ctx);
		sm3_update(&sm3_ctx, data, datalen);
		sm3_finish(&sm3_ctx, dgst);

		sm2_z256_from_bytes(x, dgst);
		if (sm2_z256_cmp(x, SM2_Z256_P) >= 0) {
			sm2_z256_sub(x, x, SM2_Z256_P);
		}
		sm2_z256_to_bytes(x, x_bytes);

		// compute y
		if ((ret = sm2_z256_point_from_x_bytes(R, x_bytes, y_is_odd)) == 1) {
			break;
		}
		if (ret < 0) {
			error_print();
			return -1;
		}

		// data = sm3(data), try again
		data = dgst;
		datalen = sizeof(dgst);

	} while (1);

	return 1;
}

// return -1 given point_at_infinity
int sm2_z256_point_to_compressed_octets(const SM2_Z256_POINT *P, uint8_t out[33])
{
	sm2_z256_t x;
	sm2_z256_t y;

	if (sm2_z256_point_get_xy(P, x, y) != 1) {
		error_print();
		return -1;
	}

	if (sm2_z256_is_odd(y)) {
		out[0] = SM2_point_compressed_y_odd;
	} else {
		out[0] = SM2_point_compressed_y_even;
	}
	sm2_z256_to_bytes(y, out + 1);

	return 1;
}

// return -1 given point_at_infinity
int sm2_z256_point_to_uncompressed_octets(const SM2_Z256_POINT *P, uint8_t out[65])
{
	if (sm2_z256_point_is_at_infinity(P)) {
		error_print();
		return -1;
	}
	out[0] = SM2_point_uncompressed;
	(void)sm2_z256_point_to_bytes(P, out + 1);
	return 1;
}

int sm2_z256_point_from_octets(SM2_Z256_POINT *P, const uint8_t *in, size_t inlen)
{
	switch (*in) {
	case SM2_point_at_infinity:
		if (inlen != 1) {
			error_print();
			return -1;
		}
		sm2_z256_point_set_infinity(P);
		break;
	case SM2_point_compressed_y_even:
		if (inlen != 33) {
			error_print();
			return -1;
		}
		if (sm2_z256_point_from_x_bytes(P, in + 1, 0) != 1) {
			error_print();
			return -1;
		}
		break;
	case SM2_point_compressed_y_odd:
		if (inlen != 33) {
			error_print();
			return -1;
		}
		if (sm2_z256_point_from_x_bytes(P, in + 1, 1) != 1) {
			error_print();
			return -1;
		}
		break;
	case SM2_point_uncompressed:
		if (inlen != 65) {
			error_print();
			return -1;
		}
		sm2_z256_point_from_bytes(P, in + 1);
		if (sm2_z256_point_is_on_curve(P) != 1) {
			error_print();
			return -1;
		}
		break;
	default:
		error_print();
		return -1;
	}

	return 1;
}

int sm2_z256_point_to_der(const SM2_Z256_POINT *P, uint8_t **out, size_t *outlen)
{
	uint8_t octets[65];
	if (!P) {
		return 0;
	}
	if (sm2_z256_point_to_uncompressed_octets(P, octets) != 1) {
		error_print();
		return -1;
	}
	if (asn1_octet_string_to_der(octets, sizeof(octets), out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_z256_point_from_der(SM2_Z256_POINT *P, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_octet_string_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (dlen != 65) {
		error_print();
		return -1;
	}
	if (sm2_z256_point_from_octets(P, d, dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}
