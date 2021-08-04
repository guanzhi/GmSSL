/*
 * Copyright (c) 2014 - 2020 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <gmssl/hex.h>
#include "endian.h"

typedef uint64_t bn_t[8];
typedef bn_t fp_t;
typedef bn_t fn_t;
typedef uint64_t barrett_bn_t[9];
typedef fp_t fp2_t[2];
typedef fp2_t fp4_t[2];
typedef fp4_t fp12_t[3];


static const bn_t ZERO  = {0,0,0,0,0,0,0,0};
static const bn_t ONE   = {1,0,0,0,0,0,0,0};
static const bn_t TWO   = {2,0,0,0,0,0,0,0};
static const bn_t FIVE  = {5,0,0,0,0,0,0,0};

// p =  b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457d
// n =  b640000002a3a6f1d603ab4ff58ec74449f2934b18ea8beee56ee19cd69ecf25
// mu = 2^512 // p = 167980e0beb5759a655f73aebdcd1312af2665f6d1e36081c71188f90d5c22146
static const bn_t SM9_P = {0xe351457d, 0xe56f9b27, 0x1a7aeedb, 0x21f2934b, 0xf58ec745, 0xd603ab4f, 0x02a3a6f1, 0xb6400000};
static const bn_t SM9_P_MINUS_ONE = {0xe351457c, 0xe56f9b27, 0x1a7aeedb, 0x21f2934b, 0xf58ec745, 0xd603ab4f, 0x02a3a6f1, 0xb6400000};
static const bn_t SM9_N = {0xd69ecf25, 0xe56ee19c, 0x18ea8bee, 0x49f2934b, 0xf58ec744, 0xd603ab4f, 0x02a3a6f1, 0xb6400000};
static const bn_t SM9_MU = {0xd5c22146, 0x71188f90, 0x1e36081c, 0xf2665f6d, 0xdcd1312a, 0x55f73aeb, 0xeb5759a6, 0x167980e0b};

typedef struct {
	fp_t X;
	fp_t Y;
	fp_t Z;
} point_t;

// P1.X 0x93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD
// P1.Y 0x21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616
static const point_t _SM9_P1 = {
	{0x7c66dddd, 0xe8c4e481, 0x09dc3280, 0xe1e40869, 0x487d01d6, 0xf5ed0704, 0x62bf718f, 0x93de051d},
	{0x0a3ea616, 0x0c464cd7, 0xfa602435, 0x1c1c00cb, 0x5c395bbc, 0x63106512, 0x4f21e607, 0x21fe8dda},
	{1,0,0,0,0,0,0,0}
};
static const point_t *SM9_P1 = &_SM9_P1;

typedef struct {
	fp2_t X;
	fp2_t Y;
	fp2_t Z;
} twist_point_t;

/*
	X : [0x3722755292130b08d2aab97fd34ec120ee265948d19c17abf9b7213baf82d65bn,
	     0x85aef3d078640c98597b6027b441a01ff1dd2c190f5e93c454806c11d8806141n],
	Y : [0xa7cf28d519be3da65f3170153d278ff247efba98a71a08116215bba5c999a7c7n,
	     0x17509b092e845c1266ba0d262cbee6ed0736a96fa347c8bd856dc76b84ebeb96n],
	Z : [1n, 0n],
*/
static const twist_point_t _SM9_P2 = {
	{{0xAF82D65B, 0xF9B7213B, 0xD19C17AB, 0xEE265948, 0xD34EC120, 0xD2AAB97F, 0x92130B08, 0x37227552},
	 {0xD8806141, 0x54806C11, 0x0F5E93C4, 0xF1DD2C19, 0xB441A01F, 0x597B6027, 0x78640C98, 0x85AEF3D0}},
	{{0xC999A7C7, 0x6215BBA5, 0xA71A0811, 0x47EFBA98, 0x3D278FF2, 0x5F317015, 0x19BE3DA6, 0xA7CF28D5},
	 {0x84EBEB96, 0x856DC76B, 0xA347C8BD, 0x0736A96F, 0x2CBEE6ED, 0x66BA0D26, 0x2E845C12, 0x17509B09}},
	{{1,0,0,0,0,0,0,0}, {0,0,0,0,0,0,0,0}},
};
static const twist_point_t *SM9_P2 = &_SM9_P2;

#define bn_init(r)	memset((r),0,sizeof(bn_t))
#define bn_clean(r)	memset((r),0,sizeof(bn_t))
#define bn_set_zero(r)	memset((r),0,sizeof(bn_t))
#define bn_set_one(r)	memcpy((r),&ONE,sizeof(bn_t))
#define bn_copy(r,a)	memcpy((r),(a),sizeof(bn_t))
#define bn_is_zero(a)	(memcmp((a),&ZERO, sizeof(bn_t)) == 0)
#define bn_is_one(a)	(memcmp((a),&ONE, sizeof(bn_t)) == 0)

static void bn_to_bytes(const bn_t a, uint8_t out[32])
{
	int i;
	for (i = 7; i >= 0; i--) {
		PUTU32(out, (uint32_t)a[i]);
		out += sizeof(uint32_t);
	}
}

static void bn_from_bytes(bn_t r, const uint8_t in[32])
{
	int i;
	for (i = 7; i >= 0; i--) {
		r[i] = GETU32(in);
		in += sizeof(uint32_t);
	}
}

static int bn_from_hex(bn_t r, const char hex[65])
{
	uint8_t buf[32];
	if (hex2bin(hex, 64, buf) < 0) {
		return -1;
	}
	bn_from_bytes(r, buf);
	return 0;
}

static void bn_to_hex(const bn_t a, char hex[65])
{
	int i;
	for (i = 7; i >= 0; i--) {
		(void)sprintf(hex, "%08x", (uint32_t)a[i]);
		hex += 8;
	}
	hex[64] = '0';
}

static void print_bn(const char *prefix, const bn_t a)
{
	char hex[65];
	bn_to_hex(a, hex);
	printf("%s\n%s\n", prefix, hex);
}

static void bn_to_bits(const bn_t a, char bits[256])
{
	int i, j;
	for (i = 7; i >= 0; i--) {
		uint32_t w = a[i];
		for (j = 0; j < 32; j++) {
			*bits++ = (w & 0x80000000) ? '1' : '0';
			w <<= 1;
		}
	}
}

static int bn_cmp(const bn_t a, const bn_t b)
{
	int i;
	for (i = 7; i >= 0; i--) {
		if (a[i] > b[i])
			return 1;
		if (a[i] < b[i])
			return -1;
	}
	return 0;
}

static int bn_equ_hex(const bn_t a, const char *hex)
{
	bn_t b;
	bn_from_hex(b, hex);
	return (bn_cmp(a, b) == 0);
}

static void bn_set_word(bn_t r, uint32_t a)
{
	bn_set_zero(r);
	r[0] = a;
}

static void bn_add(bn_t r, const bn_t a, const bn_t b)
{
	int i;
	r[0] = a[0] + b[0];
	for (i = 1; i < 8; i++) {
		r[i] = a[i] + b[i] + (r[i-1] >> 32);
	}
	for (i = 0; i < 7; i++) {
		r[i] &= 0xffffffff;
	}
}

static void bn_sub(bn_t ret, const bn_t a, const bn_t b)
{
	int i;
	bn_t r;
	r[0] = ((uint64_t)1 << 32) + a[0] - b[0];
	for (i = 1; i < 7; i++) {
		r[i] = 0xffffffff + a[i] - b[i] + (r[i - 1] >> 32);
		r[i - 1] &= 0xffffffff;
	}
	r[i] = a[i] - b[i] + (r[i - 1] >> 32) - 1;
	r[i - 1] &= 0xffffffff;
	bn_copy(ret, r);
}

static void bn_rand_range(bn_t r, const bn_t range)
{
	FILE *fp;
	uint8_t buf[256];

	fp = fopen("/dev/urandom", "rb");
	do {
		fread(buf, 1, 256, fp);
		bn_from_bytes(r, buf);
	} while (bn_cmp(r, range) >= 0);
	fclose(fp);
}

#define fp_init(a)	bn_init(a)
#define fp_clean(a)	bn_clean(a)
#define fp_is_zero(a)	bn_is_zero(a)
#define fp_is_one(a)	bn_is_one(a)
#define fp_set_zero(a)	bn_set_zero(a)
#define fp_set_one(a)	bn_set_one(a)
#define fp_from_hex(a,s) bn_from_hex((a),(s))
#define fp_to_hex(a,s)	bn_to_hex((a),(s))
#define fp_copy(r,a)	bn_copy((r),(a))

static int fp_equ(const fp_t a, const fp_t b)
{
	int i;
	for (i = 0; i < 8; i++) {
		if (a[i] != b[i])
			return 0;
	}
	return 1;
}

static void fp_add(fp_t r, const fp_t a, const fp_t b)
{
	bn_add(r, a, b);
	if (bn_cmp(r, SM9_P) >= 0)
		return bn_sub(r, r, SM9_P);
}

static void fp_sub(fp_t r, const fp_t a, const fp_t b)
{
	if (bn_cmp(a, b) >= 0) {
		bn_sub(r, a, b);
	} else {
		bn_t t;
		bn_sub(t, SM9_P, b);
		bn_add(r, t, a);
	}
}

static void fp_dbl(fp_t r, const fp_t a)
{
	fp_add(r, a, a);
}

static void fp_tri(fp_t r, const fp_t a)
{
	fp_t t;
	fp_dbl(t, a);
	fp_add(r, t, a);
}

static void fp_div2(fp_t r, const fp_t a)
{
	int i;
	bn_copy(r, a);
	if (r[0] & 0x01) {
		bn_add(r, r, SM9_P);
	}
	for (i = 0; i < 7; i++) {
		r[i] = (r[i] >> 1) | ((r[i + 1] & 0x01) << 31);
	}
	r[i] >>= 1;
}

static void fp_neg(fp_t r, const fp_t a)
{
	if (bn_is_zero(a)) {
		bn_copy(r, a);
	} else {
		bn_sub(r, SM9_P, a);
	}
}

static int barrett_bn_cmp(const barrett_bn_t a, const barrett_bn_t b)
{
	int i;
	for (i = 8; i >= 0; i--) {
		if (a[i] > b[i])
			return 1;
		if (a[i] < b[i])
			return -1;
	}
	return 0;
}

static void barrett_bn_add(barrett_bn_t r, const barrett_bn_t a, const barrett_bn_t b)
{
	int i;
	r[0] = a[0] + b[0];
	for (i = 1; i < 9; i++) {
		r[i] = a[i] + b[i] + (r[i-1] >> 32);
	}
	for (i = 0; i < 8; i++) {
		r[i] &= 0xffffffff;
	}
}

static void barrett_bn_sub(barrett_bn_t ret, const barrett_bn_t a, const barrett_bn_t b)
{
	barrett_bn_t r;
	int i;
	r[0] = ((uint64_t)1 << 32) + a[0] - b[0];
	for (i = 1; i < 8; i++) {
		r[i] = 0xffffffff + a[i] - b[i] + (r[i - 1] >> 32);
		r[i - 1] &= 0xffffffff;
	}
	r[i] = a[i] - b[i] + (r[i - 1] >> 32) - 1;
	r[i - 1] &= 0xffffffff;
	for (i = 0; i < 9; i++) {
		ret[i] = r[i];
	}
}

static void fp_mul(fp_t r, const fp_t a, const fp_t b)
{
	uint64_t s[17];
	barrett_bn_t zh, zl, q;
	uint64_t w;
	int i, j;

	/* z = a * b */
	for (i = 0; i < 8; i++) {
		s[i] = 0;
	}
	for (i = 0; i < 8; i++) {
		w = 0;
		for (j = 0; j < 8; j++) {
			w += s[i + j] + a[i] * b[j];
			s[i + j] = w & 0xffffffff;
			w >>= 32;
		}
		s[i + 8] = w;
	}

	/* zl = z mod (2^32)^9 = z[0..8]
	 * zh = z // (2^32)^7 = z[7..15] */
	for (i = 0; i < 9; i++) {
		zl[i] = s[i];
		zh[i] = s[7 + i];
	}

	/* q = zh * mu // (2^32)^9 */
	for (i = 0; i < 9; i++) {
		s[i] = 0;
	}
	for (i = 0; i < 9; i++) {
		w = 0;
		for (j = 0; j < 8; j++) {
			w += s[i + j] + zh[i] * SM9_MU[j];
			s[i + j] = w & 0xffffffff;
			w >>= 32;
		}
		s[i + 8] = w;
	}
	for (i = 0; i < 8; i++) {
		q[i] = s[9 + i];
	}

	/* q = q * n mod (2^32)^9 */
	for (i = 0; i < 8; i++) {
		s[i] = 0;
	}
	for (i = 0; i < 8; i++) {
		w = 0;
		for (j = 0; j < 8; j++) {
			w += s[i + j] + q[i] * SM9_N[j];
			s[i + j] = w & 0xffffffff;
			w >>= 32;
		}
		s[i + 8] = w;
	}
	for (i = 0; i < 9; i++) {
		q[i] = s[i];
	}

	/* r = zl - q (mod (2^32)^9) */

	if (barrett_bn_cmp(zl, q)) {
		barrett_bn_sub(zl, zl, q);
	} else {
		barrett_bn_t c = {0,0,0,0,0,0,0,0,0x100000000};
		barrett_bn_sub(q, c, q);
		barrett_bn_add(zl, q, zl);

	}

	for (i = 0; i < 8; i++) {
		r[i] = zl[i];
	}
	r[7] += zl[8] << 32;

	/* while r >= p do: r = r - n */
	while (bn_cmp(r, SM9_N) >= 0) {
		bn_sub(r, r, SM9_N);
	}
}

static void fp_sqr(fp_t r, const fp_t a)
{
	fp_mul(r, a, a);
}

static void fp_pow(fp_t r, const fp_t a, const bn_t e)
{
	fp_t t;
	uint32_t w;
	int i, j;

	assert(bn_cmp(e, SM9_P_MINUS_ONE) < 0);

	bn_set_one(t);
	for (i = 7; i >= 0; i--) {
		w = (uint32_t)e[i];
		for (j = 0; j < 32; j++) {
			fp_sqr(t, t);
			if (w & 0x80000000)
				fp_mul(t, t, a);
			w <<= 1;
		}
	}
	bn_copy(r, t);
}

static void fp_inv(fp_t r, const fp_t a)
{
	fp_t e;
	bn_sub(e, SM9_P, TWO);
	fp_pow(r, a, e);
}



static void fn_add(fn_t r, const fn_t a, const fn_t b)
{

}

static void fn_sub(fn_t r, const fn_t a, const fn_t b)
{

}

static void fn_neg(fn_t r, const fn_t a)
{
}

static void fn_inv(fn_t r, const fn_t a)
{

}

static const fp2_t FP2_ZERO = {{0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0}};
static const fp2_t FP2_ONE  = {{1,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0}};
static const fp2_t FP2_U    = {{0,0,0,0,0,0,0,0},{1,0,0,0,0,0,0,0}};
static const fp2_t FP2_5U    = {{0,0,0,0,0,0,0,0},{5,0,0,0,0,0,0,0}};



#define fp2_init(a)	memset((a), 0, sizeof(fp2_t))
#define fp2_clean(a)	memset((a), 0, sizeof(fp2_t))
#define fp2_is_zero(a)	(memcmp((a), &FP2_ZERO, sizeof(fp2_t)) == 0)
#define fp2_is_one(a)	(memcmp((a), &FP2_ONE, sizeof(fp2_t)) == 0)
#define fp2_copy(r,a)	memcpy((r), (a), sizeof(fp2_t))
#define fp2_equ(a,b)	(memcmp((a),(b),sizeof(fp2_t)) == 0)

static void fp2_from_hex(fp2_t r, const char hex[65 * 2])
{
	fp_from_hex(r[1], hex);
	fp_from_hex(r[0], hex + 65);
}

static void fp2_to_hex(const fp2_t a, char hex[65 * 2])
{
	fp_to_hex(a[1], hex);
	hex[64] = '\n';
	fp_to_hex(a[0], hex + 65);
}

static void fp2_print(const char *prefix, const fp2_t a)
{
	char hex[65 * 2];
	fp2_to_hex(a, hex);
	printf("%s\n%s\n", prefix, hex);
}

#define fp2_set_zero(a)	memset((a), 0, sizeof(fp2_t))
#define fp2_set_one(a)	memcpy((a), &FP2_ONE, sizeof(fp2_t))

static void fp2_set_fp(fp2_t r, const fp_t a)
{
	fp_copy(r[0], a);
	fp_set_zero(r[1]);
}

#define fp2_set_u(a)	memcpy((a), &FP2_U, sizeof(fp2_t))

static void fp2_set(fp2_t r, const fp_t a0, const fp_t a1)
{
	fp_copy(r[0], a0);
	fp_copy(r[1], a1);
}

static void fp2_add(fp2_t r, const fp2_t a, const fp2_t b)
{
	fp_add(r[0], a[0], b[0]);
	fp_add(r[1], a[1], b[1]);
}

static void fp2_dbl(fp2_t r, const fp2_t a)
{
	fp_dbl(r[0], a[0]);
	fp_dbl(r[1], a[1]);
}

static void fp2_tri(fp2_t r, const fp2_t a)
{
	fp_tri(r[0], a[0]);
	fp_tri(r[1], a[1]);
}

static void fp2_sub(fp2_t r, const fp2_t a, const fp2_t b)
{
	fp_sub(r[0], a[0], b[0]);
	fp_sub(r[1], a[1], b[1]);
}

static void fp2_neg(fp2_t r, const fp2_t a)
{
	fp_neg(r[0], a[0]);
	fp_neg(r[1], a[1]);
}

static void fp2_mul(fp2_t r, const fp2_t a, const fp2_t b)
{
	fp_t r0, r1, t;

	// r0 = a0 * b0 - 2 * a1 * b1
	fp_mul(r0, a[0], b[0]);
	fp_mul(t, a[1], b[1]);
	fp_dbl(t, t);
	fp_sub(r0, r0, t);

	// r1 = a0 * b1 + a1 * b0
	fp_mul(r1, a[0], b[1]);
	fp_mul(t, a[1], b[0]);
	fp_add(r1, r1, t);

	fp_copy(r[0], r0);
	fp_copy(r[1], r1);
}

static void fp2_mul_u(fp2_t r, const fp2_t a, const fp2_t b)
{
	fp_t r0, r1, t;

	// r0 = -2 * (a0 * b1 + a1 * b0)
	fp_mul(r0, a[0], b[1]);
	fp_mul(t,  a[1], b[0]);
	fp_add(r0, r0, t);
	fp_dbl(r0, r0);
	fp_neg(r0, r0);

	// r1 = a0 * b0 - 2 * a1 * b1
	fp_mul(r1, a[0], b[0]);
	fp_mul(t, a[1], b[1]);
	fp_dbl(t, t);
	fp_sub(r1, r1, t);

	fp_copy(r[0], r0);
	fp_copy(r[1], r1);
}

static void fp2_mul_fp(fp2_t r, const fp2_t a, const fp_t k)
{
	fp_mul(r[0], a[0], k);
	fp_mul(r[1], a[1], k);
}

static void fp2_sqr(fp2_t r, const fp2_t a)
{
	fp_t r0, r1, t;

	// a0^2 - 2 * a1^2
	fp_sqr(r0, a[0]);
	fp_sqr(t, a[1]);
	fp_dbl(t, t);
	fp_sub(r0, r0, t);

	// r1 = 2 * a0 * a1
	fp_mul(r1, a[0], a[1]);
	fp_dbl(r1, r1);

	bn_copy(r[0], r0);
	bn_copy(r[1], r1);
}

static void fp2_sqr_u(fp2_t r, const fp2_t a)
{
	fp_t r0, r1, t;

	// r0 = -4 * a0 * a1
	fp_mul(r0, a[0], a[1]);
	fp_dbl(r0, r0);
	fp_dbl(r0, r0);
	fp_neg(r0, r0);

	// r1 = a0^2 - 2 * a1^2
	fp_sqr(r1, a[0]);
	fp_sqr(t, a[1]);
	fp_dbl(t, t);
	fp_sub(r1, r1, t);

	fp_copy(r[0], r0);
	fp_copy(r[1], r1);

}

static void fp2_inv(fp2_t r, const fp2_t a)
{
	if (fp_is_zero(a[0])) {
		// r0 = 0
		fp_set_zero(r[0]);
		// r1 = -(2 * a1)^-1
		fp_dbl(r[1], a[1]);
		fp_inv(r[1], r[1]);
		fp_neg(r[1], r[1]);

	} else if (fp_is_zero(a[1])) {
		/* r1 = 0 */
		fp_set_zero(r[1]);
		/* r0 = a0^-1 */
		fp_inv(r[0], a[0]);

	} else {
		fp_t k, t;

		// k = (a[0]^2 + 2 * a[1]^2)^-1
		fp_sqr(k, a[0]);
		fp_sqr(t, a[1]);
		fp_dbl(t, t);
		fp_add(k, k, t);
		fp_inv(k, k);

		// r[0] = a[0] * k
		fp_mul(r[0], a[0], k);

		// r[1] = -a[1] * k
		fp_mul(r[1], a[1], k);
		fp_neg(r[1], r[1]);
	}
}

static void fp2_div(fp2_t r, const fp2_t a, const fp2_t b)
{
	fp2_t t;
	fp2_inv(t, b);
	fp2_mul(r, a, t);
}

static void fp2_div2(fp2_t r, const fp2_t a)
{
	fp_div2(r[0], a[0]);
	fp_div2(r[1], a[1]);
}

static const fp4_t FP4_ZERO = {{{0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0}}, {{0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0}}};
static const fp4_t FP4_ONE = {{{1,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0}}, {{0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0}}};
static const fp4_t FP4_U = {{{0,0,0,0,0,0,0,0},{1,0,0,0,0,0,0,0}}, {{0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0}}};
static const fp4_t FP4_V = {{{0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0}}, {{1,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0}}};

#define fp4_init(r)	memcpy((r), &FP4_ZERO, sizeof(fp4_t))
#define fp4_clean(r)	memcpy((r), &FP4_ZERO, sizeof(fp4_t))
#define fp4_set_zero(r)	memcpy((r), &FP4_ZERO, sizeof(fp4_t))
#define fp4_set_one(r)	memcpy((r), &FP4_ONE, sizeof(fp4_t))
#define fp4_is_zero(a)	(memcmp((a), &FP4_ZERO, sizeof(fp4_t)) == 0)
#define fp4_is_one(a)	(memcmp((a), &FP4_ONE, sizeof(fp4_t)) == 0)
#define fp4_equ(a,b)	(memcmp((a), (b), sizeof(fp4_t)) == 0)
#define fp4_copy(r,a)	memcpy((r), (a), sizeof(fp4_t))



static void fp4_from_hex(fp4_t r, const char hex[65 * 4])
{
	fp2_from_hex(r[1], hex);
	fp2_from_hex(r[0], hex + 65 * 2);
}

static void fp4_to_hex(const fp4_t a, char hex[65 * 4])
{
	fp2_to_hex(a[1], hex);
	hex[65 + 64] = '\n';
	fp2_to_hex(a[0], hex + 65 * 2);
}

static void fp4_set_fp(fp4_t r, const fp_t a)
{
	fp2_set_fp(r[0], a);
	fp2_set_zero(r[1]);
}

static void fp4_set_fp2(fp4_t r, const fp2_t a)
{
	fp2_copy(r[0], a);
	fp2_set_zero(r[1]);
}

static void fp4_set(fp4_t r, const fp2_t a0, const fp2_t a1)
{
	fp2_copy(r[0], a0);
	fp2_copy(r[1], a1);
}

/*
static void fp4_set_one(fp4_t r)
{
	fp2_set_one(r[0]);
	fp2_set_zero(r[1]);
}
*/

static void fp4_set_u(fp4_t r)
{
	fp2_set_u(r[0]);
	fp2_set_zero(r[1]);
}

static void fp4_set_v(fp4_t r)
{
	fp2_set_zero(r[0]);
	fp2_set_one(r[1]);
}

static void fp4_add(fp4_t r, const fp4_t a, const fp4_t b)
{
	fp2_add(r[0], a[0], b[0]);
	fp2_add(r[1], a[1], b[1]);
}

static void fp4_dbl(fp4_t r, const fp4_t a)
{
	fp2_dbl(r[0], a[0]);
	fp2_dbl(r[1], a[1]);
}

static void fp4_sub(fp4_t r, const fp4_t a, const fp4_t b)
{
	fp2_sub(r[0], a[0], b[0]);
	fp2_sub(r[1], a[1], b[1]);
}

static void fp4_neg(fp4_t r, const fp4_t a)
{
	fp2_neg(r[0], a[0]);
	fp2_neg(r[1], a[1]);
}

static void fp4_mul(fp4_t r, const fp4_t a, const fp4_t b)
{
	fp2_t r0, r1, t;

	fp2_mul(r0, a[0], b[0]);
	fp2_mul_u(t, a[1], b[1]);
	fp2_add(r0, r0, t);

	fp2_mul(r1, a[0], b[1]);
	fp2_mul(t, a[1], b[0]);
	fp2_add(r1, r1, t);

	fp2_copy(r[0], r0);
	fp2_copy(r[1], r1);
}

static void fp4_mul_fp(fp4_t r, const fp4_t a, const fp_t k)
{
	fp2_mul_fp(r[0], a[0], k);
	fp2_mul_fp(r[1], a[1], k);
}

static void fp4_mul_fp2(fp4_t r, const fp4_t a, const fp2_t b0)
{
	fp2_mul(r[0], a[0], b0);
	fp2_mul(r[1], a[1], b0);
}

static void fp4_mul_v(fp4_t r, const fp4_t a, const fp4_t b)
{
	fp2_t r0, r1, t;

	fp2_mul_u(r0, a[0], b[1]);
	fp2_mul_u(t, a[1], b[0]);
	fp2_add(r0, r0, t);

	fp2_mul(r1, a[0], b[0]);
	fp2_mul_u(t, a[1], b[1]);
	fp2_add(r1, r1, t);

	fp2_copy(r[0], r0);
	fp2_copy(r[1], r1);
}

static void fp4_sqr(fp4_t r, const fp4_t a)
{
	fp2_t r0, r1, t;

	fp2_sqr(r0, a[0]);
	fp2_sqr_u(t, a[1]);
	fp2_add(r0, r0, t);

	fp2_mul(r1, a[0], a[1]);
	fp2_dbl(r1, r1);
	fp2_copy(r[0], r0);
	fp2_copy(r[1], r1);
}

static void fp4_sqr_v(fp4_t r, const fp4_t a)
{
	fp2_t r0, r1, t;

	fp2_mul_u(t, a[0], a[1]);
	fp2_dbl(r0, t);

	fp2_sqr(r1, a[0]);
	fp2_sqr_u(t, a[1]);
	fp2_add(r1, r1, t);

	fp2_copy(r[0], r0);
	fp2_copy(r[1], r1);
}

static void fp4_inv(fp4_t r, const fp4_t a)
{
	fp2_t r0, r1, k;

	fp2_sqr_u(k, a[1]);
	fp2_sqr(r0, a[0]);
	fp2_sub(k, k, r0);
	fp2_inv(k, k);

	fp2_mul(r0, a[0], k);
	fp2_neg(r0, r0);

	fp2_mul(r1, a[1], k);

	fp2_copy(r[0], r0);
	fp2_copy(r[1], r1);
}


#define fp12_init(r)		memset((r), 0, sizeof(fp12_t))
#define fp12_clean(r)		memset((r), 0, sizeof(fp12_t))
#define fp12_set_zero(r)	memset((r), 0, sizeof(fp12_t))
#define fp12_copy(r, a)		memcpy((r), (a), sizeof(fp12_t))

static void fp12_set_one(fp12_t r)
{
	fp4_set_one(r[0]);
	fp4_set_zero(r[1]);
	fp4_set_zero(r[2]);
}

static int fp12_is_one(const fp12_t a)
{
	return fp4_is_one(a[0])
		&& fp4_is_zero(a[1])
		&& fp4_is_zero(a[2]);
}

static int fp12_is_zero(const fp12_t a)
{
	return fp4_is_zero(a[0])
		&& fp4_is_zero(a[1])
		&& fp4_is_zero(a[2]);
}

static void fp12_from_hex(fp12_t r, const char hex[65 * 12])
{
	fp4_from_hex(r[2], hex);
	fp4_from_hex(r[1], hex + 65 * 4);
	fp4_from_hex(r[0], hex + 65 * 8);
}

static void fp12_to_hex(const fp12_t a, char hex[65 * 12])
{
	fp4_to_hex(a[2], hex);
	hex[65 * 4 - 1] = '\n';
	fp4_to_hex(a[1], hex + 65 * 4);
	hex[65 * 8 - 1] = '\n';
	fp4_to_hex(a[0], hex + 65 * 8);
}

static void fp12_print(const char *prefix, const fp12_t a)
{
	char hex[65 * 12];
	fp12_to_hex(a, hex);
	printf("%s\n%s\n", prefix, hex);
}

static void fp12_set(fp12_t r, const fp4_t a0, const fp4_t a1, const fp4_t a2)
{
	fp4_copy(r[0], a0);
	fp4_copy(r[1], a1);
	fp4_copy(r[2], a2);
}

static void fp12_set_fp(fp12_t r, const fp_t a)
{
	fp4_set_fp(r[0], a);
	fp4_set_zero(r[1]);
	fp4_set_zero(r[2]);
}

static void fp12_set_fp2(fp12_t r, const fp2_t a)
{
	fp4_set_fp2(r[0], a);
	fp4_set_zero(r[1]);
	fp4_set_zero(r[2]);
}

static void fp12_set_fp4(fp12_t r, const fp4_t a)
{
	fp4_copy(r[0], a);
	fp4_set_zero(r[1]);
	fp4_set_zero(r[2]);
}

static void fp12_set_u(fp12_t r)
{
	fp4_set_u(r[0]);
	fp4_set_zero(r[1]);
	fp4_set_zero(r[2]);
}

static void fp12_set_v(fp12_t r)
{
	fp4_set_v(r[0]);
	fp4_set_zero(r[1]);
	fp4_set_zero(r[2]);
}

static void fp12_set_w(fp12_t r)
{
	fp4_set_zero(r[0]);
	fp4_set_one(r[1]);
	fp4_set_zero(r[2]);
}

static void fp12_set_w_sqr(fp12_t r)
{
	fp4_set_zero(r[0]);
	fp4_set_zero(r[1]);
	fp4_set_one(r[2]);
}

static int fp12_equ(const fp12_t a, const fp12_t b)
{
	return fp4_equ(a[0], b[0])
		&& fp4_equ(a[1], b[1])
		&& fp4_equ(a[2], b[2]);
}

static void fp12_add(fp12_t r, const fp12_t a, const fp12_t b)
{
	fp4_add(r[0], a[0], b[0]);
	fp4_add(r[1], a[1], b[1]);
	fp4_add(r[2], a[2], b[2]);
}

static void fp12_dbl(fp12_t r, const fp12_t a)
{
	fp4_dbl(r[0], a[0]);
	fp4_dbl(r[1], a[1]);
	fp4_dbl(r[2], a[2]);
}

static void fp12_tri(fp12_t r, const fp12_t a)
{
	fp12_t t;
	fp12_dbl(t, a);
	fp12_add(r, t, a);
}

static void fp12_sub(fp12_t r, const fp12_t a, const fp12_t b)
{
	fp4_sub(r[0], a[0], b[0]);
	fp4_sub(r[1], a[1], b[1]);
	fp4_sub(r[2], a[2], b[2]);
}

static void fp12_neg(fp12_t r, const fp12_t a)
{
	fp4_neg(r[0], a[0]);
	fp4_neg(r[1], a[1]);
	fp4_neg(r[2], a[2]);
}

static void fp12_mul(fp12_t r, const fp12_t a, const fp12_t b)
{
	fp4_t r0, r1, r2, t;

	fp4_mul(r0, a[0], b[0]);
	fp4_mul_v(t, a[1], b[2]);
	fp4_add(r0, r0, t);
	fp4_mul_v(t, a[2], b[1]);
	fp4_add(r0, r0, t);

	fp4_mul(r1, a[0], b[1]);
	fp4_mul(t, a[1], b[0]);
	fp4_add(r1, r1, t);
	fp4_mul_v(t, a[2], b[2]);
	fp4_add(r1, r1, t);

	fp4_mul(r2, a[0], b[2]);
	fp4_mul(t, a[1], b[1]);
	fp4_add(r2, r2, t);
	fp4_mul(t, a[2], b[0]);
	fp4_add(r2, r2, t);

	fp4_copy(r[0], r0);
	fp4_copy(r[1], r1);
	fp4_copy(r[2], r2);
}

static void fp12_sqr(fp12_t r, const fp12_t a)
{
	fp4_t r0, r1, r2, t;

	fp4_sqr(r0, a[0]);
	fp4_mul_v(t, a[1], a[2]);
	fp4_dbl(t, t);
	fp4_add(r0, r0, t);

	fp4_mul(r1, a[0], a[1]);
	fp4_dbl(r1, r1);
	fp4_sqr_v(t, a[2]);
	fp4_add(r1, r1, t);

	fp4_mul(r2, a[0], a[2]);
	fp4_dbl(r2, r2);
	fp4_sqr(t, a[1]);
	fp4_add(r2, r2, t);

	fp4_copy(r[0], r0);
	fp4_copy(r[1], r1);
	fp4_copy(r[2], r2);
}

static void fp12_inv(fp12_t r, const fp12_t a)
{
	if (fp4_is_zero(a[2])) {
		fp4_t k, t;

		fp4_sqr(k, a[0]);
		fp4_mul(k, k, a[0]);
		fp4_sqr_v(t, a[1]);
		fp4_mul(t, t, a[1]);
		fp4_add(k, k, t);
		fp4_inv(k, k);

		fp4_sqr(r[2], a[1]);
		fp4_mul(r[2], r[2], k);

		fp4_mul(r[1], a[0], a[1]);
		fp4_mul(r[1], r[1], k);
		fp4_neg(r[1], r[1]);

		fp4_sqr(r[0], a[0]);
		fp4_mul(r[0], r[0], k);

	} else {
		fp4_t t0, t1, t2, t3;

		fp4_sqr(t0, a[1]);
		fp4_mul(t1, a[0], a[2]);
		fp4_sub(t0, t0, t1);

		fp4_mul(t1, a[0], a[1]);
		fp4_sqr_v(t2, a[2]);
		fp4_sub(t1, t1, t2);

		fp4_sqr(t2, a[0]);
		fp4_mul_v(t3, a[1], a[2]);
		fp4_sub(t2, t2, t3);

		fp4_sqr(t3, t1);
		fp4_mul(r[0], t0, t2);
		fp4_sub(t3, t3, r[0]);
		fp4_inv(t3, t3);
		fp4_mul(t3, a[2], t3);

		fp4_mul(r[0], t2, t3);

		fp4_mul(r[1], t1, t3);
		fp4_neg(r[1], r[1]);

		fp4_mul(r[2], t0, t3);
	}
}

static void fp12_pow(fp12_t r, const fp12_t a, const bn_t k)
{
	char kbits[257];
	fp12_t t;
	int i;

	assert(bn_cmp(k, SM9_P_MINUS_ONE) < 0);
	fp12_set_zero(t);

	bn_to_bits(k, kbits);
	fp12_copy(t, a);
	for (i = 1; i < 256; i++) {
		fp12_sqr(t, t);
		if (kbits[i] == '1') {
			fp12_mul(t, t, a);
		}
	}
	fp12_copy(r, t);
}

static void fp2_conjugate(fp2_t r, const fp2_t a)
{
	fp_copy(r[0], a[0]);
	fp_neg (r[1], a[1]);

}

static void fp2_frobenius(fp2_t r, const fp2_t a)
{
	return fp2_conjugate(r, a);
}

// beta   = 0x6c648de5dc0a3f2cf55acc93ee0baf159f9d411806dc5177f5b21fd3da24d011
// alpha1 = 0x3f23ea58e5720bdb843c6cfa9c08674947c5c86e0ddd04eda91d8354377b698b
// alpha2 = 0xf300000002a3a6f2780272354f8b78f4d5fc11967be65334
// alpha3 = 0x6c648de5dc0a3f2cf55acc93ee0baf159f9d411806dc5177f5b21fd3da24d011
// alpha4 = 0xf300000002a3a6f2780272354f8b78f4d5fc11967be65333
// alpha5 = 0x2d40a38cf6983351711e5f99520347cc57d778a9f8ff4c8a4c949c7fa2a96686
static const fp2_t SM9_BETA = {{0xda24d011, 0xf5b21fd3, 0x06dc5177, 0x9f9d4118, 0xee0baf15, 0xf55acc93, 0xdc0a3f2c, 0x6c648de5}, {0}};
static const fp_t SM9_ALPHA1 = {0x377b698b, 0xa91d8354, 0x0ddd04ed, 0x47c5c86e, 0x9c086749, 0x843c6cfa, 0xe5720bdb, 0x3f23ea58};
static const fp_t SM9_ALPHA2 = {0x7be65334, 0xd5fc1196, 0x4f8b78f4, 0x78027235, 0x02a3a6f2, 0xf3000000, 0x0,        0x0       };
static const fp_t SM9_ALPHA3 = {0xda24d011, 0xf5b21fd3, 0x06dc5177, 0x9f9d4118, 0xee0baf15, 0xf55acc93, 0xdc0a3f2c, 0x6c648de5};
static const fp_t SM9_ALPHA4 = {0x7be65333, 0xd5fc1196, 0x4f8b78f4, 0x78027235, 0x02a3a6f2, 0xf3000000, 0x0,        0x0       };
static const fp_t SM9_ALPHA5 = {0xa2a96686, 0x4c949c7f, 0xf8ff4c8a, 0x57d778a9, 0x520347cc, 0x711e5f99, 0xf6983351, 0x2d40a38c};


static void fp4_frobenius(fp4_t r, const fp4_t a)
{
	fp2_conjugate(r[0], a[0]);
	fp2_conjugate(r[1], a[1]);
	fp2_mul(r[1], r[1], SM9_BETA);
}

static void fp4_conjugate(fp4_t r, const fp4_t a)
{
	fp2_copy(r[0], a[0]);
	fp2_neg(r[1], a[1]);
}

static void fp4_frobenius2(fp4_t r, const fp4_t a)
{
	return fp4_conjugate(r, a);
}

static void fp4_frobenius3(fp4_t r, const fp4_t a)
{
	fp2_conjugate(r[0], a[0]);
	fp2_conjugate(r[1], a[1]);
	fp2_mul(r[1], r[1], SM9_BETA);
	fp2_neg(r[1], r[1]);
}

static void fp12_frobenius(fp12_t r, const fp12_t x)
{
	const fp2_t *xa = x[0];
	const fp2_t *xb = x[1];
	const fp2_t *xc = x[2];
	fp4_t ra;
	fp4_t rb;
	fp4_t rc;

	fp2_conjugate(ra[0], xa[0]);
	fp2_conjugate(ra[1], xa[1]);
	fp2_mul_fp(ra[1], ra[1], SM9_ALPHA3);

	fp2_conjugate(rb[0], xb[0]);
	fp2_mul_fp(rb[0], rb[0], SM9_ALPHA1);
	fp2_conjugate(rb[1], xb[1]);
	fp2_mul_fp(rb[1], rb[1], SM9_ALPHA4);

	fp2_conjugate(rc[0], xc[0]);
	fp2_mul_fp(rc[0], rc[0], SM9_ALPHA2);
	fp2_conjugate(rc[1], xc[1]);
	fp2_mul_fp(rc[1], rc[1], SM9_ALPHA5);

	fp12_set(r, ra, rb, rc);
}

static void fp12_frobenius2(fp12_t r, const fp12_t x)
{
	fp4_t a;
	fp4_t b;
	fp4_t c;

	fp4_conjugate(a, x[0]);
	fp4_conjugate(b, x[1]);
	fp4_mul_fp(b, b, SM9_ALPHA2);
	fp4_conjugate(c, x[2]);
	fp4_mul_fp(c, c, SM9_ALPHA4);

	fp4_copy(r[0], a);
	fp4_copy(r[1], b);
	fp4_copy(r[2], c);
}

static void fp12_frobenius3(fp12_t r, const fp12_t x)
{
	const fp2_t *xa = x[0];
	const fp2_t *xb = x[1];
	const fp2_t *xc = x[2];
	fp4_t ra;
	fp4_t rb;
	fp4_t rc;

	fp2_conjugate(ra[0], xa[0]);
	fp2_conjugate(ra[1], xa[1]);
	fp2_mul(ra[1], ra[1], SM9_BETA);
	fp2_neg(ra[1], ra[1]);

	fp2_conjugate(rb[0], xb[0]);
	fp2_mul(rb[0], rb[0], SM9_BETA);
	fp2_conjugate(rb[1], xb[1]);

	fp2_conjugate(rc[0], xc[0]);
	fp2_neg(rc[0], rc[0]);
	fp2_conjugate(rc[1], xc[1]);
	fp2_mul(rc[1], rc[1], SM9_BETA);

	fp4_copy(r[0], ra);
	fp4_copy(r[1], rb);
	fp4_copy(r[2], rc);
}

static void fp12_frobenius6(fp12_t r, const fp12_t x)
{
	fp4_t a;
	fp4_t b;
	fp4_t c;

	fp4_copy(a, x[0]);
	fp4_copy(b, x[1]);
	fp4_copy(c, x[2]);

	fp4_conjugate(a, a);
	fp4_conjugate(b, b);
	fp4_neg(b, b);
	fp4_conjugate(c, c);

	fp4_copy(r[0], a);
	fp4_copy(r[1], b);
	fp4_copy(r[2], c);
}


static void point_init(point_t *R)
{
	fp_set_zero(R->X);
	fp_set_zero(R->Y);
	fp_set_one(R->Z);
}

static void point_from_hex(point_t *R, const char hex[65 * 2])
{
	bn_from_hex(R->X, hex);
	bn_from_hex(R->Y, hex + 65);
	bn_set_one(R->Z);
}

#define point_copy(R, P)	memcpy((R), (P), sizeof(point_t))

static int point_is_at_infinity(const point_t *P) {
	return fp_is_zero(P->X);
}

static void point_set_infinity(point_t *R) {
	fp_set_one(R->X);
	fp_set_one(R->Y);
	fp_set_zero(R->Z);
}

static void point_get_xy(const point_t *P, fp_t x, fp_t y)
{
	fp_t z_inv;

	assert(!fp_is_zero(P->Z));

	if (fp_is_one(P->Z)) {
		fp_copy(x, P->X);
		fp_copy(y, P->Y);
	}

	fp_inv(z_inv, P->Z);
	if (y)
		fp_mul(y, P->Y, z_inv);
	fp_sqr(z_inv, z_inv);
	fp_mul(x, P->X, z_inv);
	if (y)
		fp_mul(y, y, z_inv);
}

static int point_equ(const point_t *P, const point_t *Q)
{
	fp_t t1, t2, t3, t4;
	fp_sqr(t1, P->Z);
	fp_sqr(t2, Q->Z);
	fp_mul(t3, P->X, t2);
	fp_mul(t4, Q->X, t1);
	if (!fp_equ(t3, t4)) {
		return 0;
	}
	fp_mul(t1, t1, P->Z);
	fp_mul(t2, t2, Q->Z);
	fp_mul(t3, P->Y, t2);
	fp_mul(t4, Q->Y, t1);
	return fp_equ(t3, t4);
}

static int point_is_on_curve(const point_t *P)
{
	fp_t t0, t1, t2;
	if (fp_is_one(P->Z)) {
		fp_sqr(t0, P->Y);
		fp_sqr(t1, P->X);
		fp_mul(t1, t1, P->X);
		fp_add(t1, t1, FIVE);
	} else {
		fp_sqr(t0, P->X);
		fp_mul(t0, t0, P->X);
		fp_sqr(t1, P->Z);
		fp_sqr(t2, t1);
		fp_mul(t1, t1, t2);
		fp_mul(t1, t1, FIVE);
		fp_add(t1, t0, t1);
		fp_sqr(t0, P->Y);
	}
	return fp_equ(t0, t1);
}

static void point_dbl(point_t *R, const point_t *P)
{
	const uint64_t *X1 = P->X;
	const uint64_t *Y1 = P->Y;
	const uint64_t *Z1 = P->Z;
	fp_t X3, Y3, Z3, T1, T2, T3;

	if (point_is_at_infinity(P)) {
		point_copy(R, P);
		return;
	}

	fp_sqr(T2, X1);
	fp_tri(T2, T2);
	fp_dbl(Y3, Y1);
	fp_mul(Z3, Y3, Z1);
	fp_sqr(Y3, Y3);
	fp_mul(T3, Y3, X1);
	fp_sqr(Y3, Y3);
	fp_div2(Y3, Y3);
	fp_sqr(X3, T2);
	fp_dbl(T1, T3);
	fp_sub(X3, X3, T1);
	fp_sub(T1, T3, X3);
	fp_mul(T1, T1, T2);
	fp_sub(Y3, T1, Y3);

	fp_copy(R->X, X3);
	fp_copy(R->Y, Y3);
	fp_copy(R->Z, Z3);
}

static void point_add(point_t *R, const point_t *P, const point_t *Q)
{
	const uint64_t *X1 = P->X;
	const uint64_t *Y1 = P->Y;
	const uint64_t *Z1 = P->Z;
	const uint64_t *x2 = Q->X;
	const uint64_t *y2 = Q->Y;
	fp_t X3, Y3, Z3, T1, T2, T3, T4;

	if (point_is_at_infinity(Q)) {
		point_copy(R, P);
		return;
	}
	if (point_is_at_infinity(P)) {
		point_copy(R, Q);
		return;
	}

	fp_sqr(T1, Z1);
	fp_mul(T2, T1, Z1);
	fp_mul(T1, T1, x2);
	fp_mul(T2, T2, y2);
	fp_sub(T1, T1, X1);
	fp_sub(T2, T2, Y1);

	if (fp_is_zero(T1)) {
		if (fp_is_zero(T2)) {
			point_dbl(R, Q);
			return;
		} else {
			point_set_infinity(R);
			return;
		}
	}

	fp_mul(Z3, Z1, T1);
	fp_sqr(T3, T1);
	fp_mul(T4, T3, T1);
	fp_mul(T3, T3, X1);
	fp_dbl(T1, T3);
	fp_sqr(X3, T2);
	fp_sub(X3, X3, T1);
	fp_sub(X3, X3, T4);
	fp_sub(T3, T3, X3);
	fp_mul(T3, T3, T2);
	fp_mul(T4, T4, Y1);
	fp_sub(Y3, T3, T4);

	fp_copy(R->X, X3);
	fp_copy(R->Y, Y3);
	fp_copy(R->Z, Z3);
}

static void point_neg(point_t *R, const point_t *P)
{
	fp_copy(R->X, P->X);
	fp_neg(R->Y, P->Y);
	fp_copy(R->Z, P->Z);
}

static void point_sub(point_t *R, const point_t *P, const point_t *Q)
{
	point_t _T, *T = &_T;
	point_neg(T, Q);
	point_add(R, P, T);
}

static void point_mul(point_t *R, const bn_t k, const point_t *P)
{
	char kbits[257];
	point_t _Q, *Q = &_Q;
	int i;

	bn_to_bits(k, kbits);
	for (i = 0; i < 256; i++) {
		point_dbl(Q, Q);
		if (kbits[i] == '1') {
			point_add(Q, Q, P);
		}
	}
	point_copy(R, Q);
}

static void point_mul_generator(point_t *R, const bn_t k)
{
	point_mul(R, k, SM9_P1);
}


static void twist_point_from_hex(twist_point_t *R, const char hex[65 * 4])
{
	fp2_from_hex(R->X, hex);
	fp2_from_hex(R->Y, hex + 65 * 2);
	fp2_set_one(R->Z);
}

#define twist_point_copy(R, P)	memcpy((R), (P), sizeof(twist_point_t))

static int twist_point_is_at_infinity(const twist_point_t *P)
{
	return fp2_is_zero(P->Z);
}

static void twist_point_set_infinity(twist_point_t *R)
{
	fp2_set_one(R->X);
	fp2_set_one(R->Y);
	fp2_set_zero(R->Z);
}

static void twist_point_get_xy(const twist_point_t *P, fp2_t x, fp2_t y)
{
	fp2_t z_inv;

	assert(!fp2_is_zero(P->Z));

	if (fp2_is_one(P->Z)) {
		fp2_copy(x, P->X);
		fp2_copy(y, P->Y);
	}

	fp2_inv(z_inv, P->Z);
	if (y)
		fp2_mul(y, P->Y, z_inv);
	fp2_sqr(z_inv, z_inv);
	fp2_mul(x, P->X, z_inv);
	if (y)
		fp2_mul(y, y, z_inv);
}







static int twist_point_equ(const twist_point_t *P, const twist_point_t *Q)
{
	fp2_t t1, t2, t3, t4;

	fp2_sqr(t1, P->Z);
	fp2_sqr(t2, Q->Z);
	fp2_mul(t3, P->X, t2);
	fp2_mul(t4, Q->X, t1);
	if (!fp2_equ(t3, t4)) {
		return 0;
	}
	fp2_mul(t1, t1, P->Z);
	fp2_mul(t2, t2, Q->Z);
	fp2_mul(t3, P->Y, t2);
	fp2_mul(t4, Q->Y, t1);
	return fp2_equ(t3, t4);
}

static int twist_point_is_on_curve(const twist_point_t *P)
{
	fp2_t t0, t1, t2;

	if (fp2_is_one(P->Z)) {
		fp2_sqr(t0, P->Y);
		fp2_sqr(t1, P->X);
		fp2_mul(t1, t1, P->X);
		fp2_add(t1, t1, FP2_5U);

	} else {
		fp2_sqr(t0, P->X);
		fp2_mul(t0, t0, P->X);
		fp2_sqr(t1, P->Z);
		fp2_sqr(t2, t1);
		fp2_mul(t1, t1, t2);
		fp2_mul(t1, t1, FP2_5U);
		fp2_add(t1, t0, t1);
		fp2_sqr(t0, P->Y);
	}

	return fp2_equ(t0, t1);
}

static void twist_point_neg(twist_point_t *R, const twist_point_t *P)
{
	fp2_copy(R->X, P->X);
	fp2_neg(R->Y, P->Y);
	fp2_copy(R->Z, P->Z);
}

static void twist_point_dbl(twist_point_t *R, const twist_point_t *P)
{
	const fp_t *X1 = P->X;
	const fp_t *Y1 = P->Y;
	const fp_t *Z1 = P->Z;
	fp2_t X3, Y3, Z3, T1, T2, T3;

	if (twist_point_is_at_infinity(P)) {
		twist_point_copy(R, P);
		return;
	}
	fp2_sqr(T2, X1);
	fp2_tri(T2, T2);
	fp2_dbl(Y3, Y1);
	fp2_mul(Z3, Y3, Z1);
	fp2_sqr(Y3, Y3);
	fp2_mul(T3, Y3, X1);
	fp2_sqr(Y3, Y3);
	fp2_div2(Y3, Y3);
	fp2_sqr(X3, T2);
	fp2_dbl(T1, T3);
	fp2_sub(X3, X3, T1);
	fp2_sub(T1, T3, X3);
	fp2_mul(T1, T1, T2);
	fp2_sub(Y3, T1, Y3);

	fp2_copy(R->X, X3);
	fp2_copy(R->Y, Y3);
	fp2_copy(R->Z, Z3);
}

static void twist_point_add(twist_point_t *R, const twist_point_t *P, const twist_point_t *Q)
{
	const fp_t *X1 = P->X;
	const fp_t *Y1 = P->Y;
	const fp_t *Z1 = P->Z;
	const fp_t *x2 = Q->X;
	const fp_t *y2 = Q->Y;
	fp2_t X3, Y3, Z3, T1, T2, T3, T4;

	if (twist_point_is_at_infinity(Q)) {
		twist_point_copy(R, P);
		return;
	}
	if (twist_point_is_at_infinity(P)) {
		twist_point_copy(R, Q);
		return;
	}

	fp2_sqr(T1, Z1);
	fp2_mul(T2, T1, Z1);
	fp2_mul(T1, T1, x2);
	fp2_mul(T2, T2, y2);
	fp2_sub(T1, T1, X1);
	fp2_sub(T2, T2, Y1);
	if (fp2_is_zero(T1)) {
		if (fp2_is_zero(T2)) {
			twist_point_dbl(R, Q);
			return;
		} else {
			twist_point_set_infinity(R);
			return;
		}
	}
	fp2_mul(Z3, Z1, T1);
	fp2_sqr(T3, T1);
	fp2_mul(T4, T3, T1);
	fp2_mul(T3, T3, X1);
	fp2_dbl(T1, T3);
	fp2_sqr(X3, T2);
	fp2_sub(X3, X3, T1);
	fp2_sub(X3, X3, T4);
	fp2_sub(T3, T3, X3);
	fp2_mul(T3, T3, T2);
	fp2_mul(T4, T4, Y1);
	fp2_sub(Y3, T3, T4);

	fp2_copy(R->X, X3);
	fp2_copy(R->Y, Y3);
	fp2_copy(R->Z, Z3);
}

static void twist_point_sub(twist_point_t *R, const twist_point_t *P, const twist_point_t *Q)
{
	twist_point_t _T, *T = &_T;
	twist_point_neg(T, Q);
	twist_point_add(R, P, T);
}

static void twist_point_add_full(twist_point_t *R, const twist_point_t *P, const twist_point_t *Q)
{
	const fp_t *X1 = P->X;
	const fp_t *Y1 = P->Y;
	const fp_t *Z1 = P->Z;
	const fp_t *X2 = Q->X;
	const fp_t *Y2 = Q->Y;
	const fp_t *Z2 = Q->Z;
	fp2_t T1, T2, T3, T4, T5, T6, T7, T8;

	if (twist_point_is_at_infinity(Q)) {
		twist_point_copy(R, P);
		return;
	}
	if (twist_point_is_at_infinity(P)) {
		twist_point_copy(R, Q);
		return;
	}

	fp2_sqr(T1, Z1);
	fp2_sqr(T2, Z2);
	fp2_mul(T3, X2, T1);
	fp2_mul(T4, X1, T2);
	fp2_add(T5, T3, T4);
	fp2_sub(T3, T3, T4);
	fp2_mul(T1, T1, Z1);
	fp2_mul(T1, T1, Y2);
	fp2_mul(T2, T2, Z2);
	fp2_mul(T2, T2, Y1);
	fp2_add(T6, T1, T2);
	fp2_sub(T1, T1, T2);

	if (fp2_is_zero(T1) && fp2_is_zero(T3)) {
		return twist_point_dbl(R, P);
	}
	if (fp2_is_zero(T1) && fp2_is_zero(T6)) {
		return twist_point_set_infinity(R);
	}

	fp2_sqr(T6, T1);
	fp2_mul(T7, T3, Z1);
	fp2_mul(T7, T7, Z2);
	fp2_sqr(T8, T3);
	fp2_mul(T5, T5, T8);
	fp2_mul(T3, T3, T8);
	fp2_mul(T4, T4, T8);
	fp2_sub(T6, T6, T5);
	fp2_sub(T4, T4, T6);
	fp2_mul(T1, T1, T4);
	fp2_mul(T2, T2, T3);
	fp2_sub(T1, T1, T2);

	fp2_copy(R->X, T6);
	fp2_copy(R->Y, T1);
	fp2_copy(R->Z, T7);
}

static void twist_point_mul(twist_point_t *R, const bn_t k, const twist_point_t *P)
{
	twist_point_t _Q, *Q = &_Q;
	char kbits[256];
	int i;

	bn_to_bits(k, kbits);
	for (i = 0; i < 256; i++) {
		twist_point_dbl(Q, Q);
		if (kbits[i] == '1') {
			twist_point_add(Q, Q, P);
		}
	}
	twist_point_copy(R, Q);
}

static void twist_point_mul_G(twist_point_t *R, const bn_t k)
{
	twist_point_mul(R, k, SM9_P2);
}

static void eval_g_tangent(fp12_t num, fp12_t den, const twist_point_t *P, const point_t *Q)
{
	const fp_t *XP = P->X;
	const fp_t *YP = P->Y;
	const fp_t *ZP = P->Z;
	const uint64_t *xQ = Q->X;
	const uint64_t *yQ = Q->Y;

	fp_t *a0 = num[0][0];
	fp_t *a1 = num[0][1];
	fp_t *a4 = num[2][0];
	fp_t *b1 = den[0][1];

	fp2_t t0;
	fp2_t t1;
	fp2_t t2;


	fp12_set_zero(num);
	fp12_set_zero(den);

	fp2_sqr(t0, ZP);
	fp2_mul(t1, t0, ZP);
	fp2_mul(b1, t1, YP);

	fp2_mul_fp(t2, b1, yQ);
	fp2_neg(a1, t2);

	fp2_sqr(t1, XP);
	fp2_mul(t0, t0, t1);
	fp2_mul_fp(t0, t0, xQ);
	fp2_tri(t0, t0);
	fp2_div2(a4, t0);

	fp2_mul(t1, t1, XP);
	fp2_tri(t1, t1);
	fp2_div2(t1, t1);
	fp2_sqr(t0, YP);
	fp2_sub(a0, t0, t1);
}

static void eval_g_line(fp12_t num, fp12_t den, const twist_point_t *T, const twist_point_t *P, const point_t *Q)
{
	const fp_t *XT = T->X;
	const fp_t *YT = T->Y;
	const fp_t *ZT = T->Z;
	const fp_t *XP = P->X;
	const fp_t *YP = P->Y;
	const fp_t *ZP = P->Z;
	const uint64_t *xQ = Q->X;
	const uint64_t *yQ = Q->Y;

	fp_t *a0 = num[0][0];
	fp_t *a1 = num[0][1];
	fp_t *a4 = num[2][0];
	fp_t *b1 = den[0][1];

	fp2_t T0, T1, T2, T3, T4;


	fp12_set_zero(num);
	fp12_set_zero(den);

	fp2_sqr(T0, ZP);
	fp2_mul(T1, T0, XT);
	fp2_mul(T0, T0, ZP);
	fp2_sqr(T2, ZT);
	fp2_mul(T3, T2, XP);
	fp2_mul(T2, T2, ZT);
	fp2_mul(T2, T2, YP);
	fp2_sub(T1, T1, T3);
	fp2_mul(T1, T1, ZT);
	fp2_mul(T1, T1, ZP);
	fp2_mul(T4, T1, T0);
	fp2_copy(b1, T4);
	fp2_mul(T1, T1, YP);
	fp2_mul(T3, T0, YT);
	fp2_sub(T3, T3, T2);
	fp2_mul(T0, T0, T3);
	fp2_mul_fp(T0, T0, xQ);
	fp2_copy(a4, T0);
	fp2_mul(T3, T3, XP);
	fp2_mul(T3, T3, ZP);
	fp2_sub(T1, T1, T3);
	fp2_copy(a0, T1);
	fp2_mul_fp(T2, T4, yQ);
	fp2_neg(T2, T2);
	fp2_copy(a1, T2);
}

static void twist_point_pi1(twist_point_t *R, const twist_point_t *P)
{
	//const c = 0x3f23ea58e5720bdb843c6cfa9c08674947c5c86e0ddd04eda91d8354377b698bn;
	const fp_t c = {
		0x377b698b, 0xa91d8354, 0x0ddd04ed, 0x47c5c86e,
		0x9c086749, 0x843c6cfa, 0xe5720bdb, 0x3f23ea58,
	};
	fp2_conjugate(R->X, P->X);
	fp2_conjugate(R->Y, P->Y);
	fp2_conjugate(R->Z, P->Z);
	fp2_mul_fp(R->Z, R->Z, c);

}

static void twist_point_pi2(twist_point_t *R, const twist_point_t *P)
{
	//c = 0xf300000002a3a6f2780272354f8b78f4d5fc11967be65334
	const fp_t c = {
		0x7be65334, 0xd5fc1196, 0x4f8b78f4, 0x78027235,
		0x02a3a6f2, 0xf3000000, 0, 0,
	};
	fp2_copy(R->X, P->X);
	fp2_copy(R->Y, P->Y);
	fp2_mul_fp(R->Z, P->Z, c);
}

static void twist_point_neg_pi2(twist_point_t *R, const twist_point_t *P)
{
	// c = 0xf300000002a3a6f2780272354f8b78f4d5fc11967be65334
	const fp_t c = {
		0x7be65334, 0xd5fc1196, 0x4f8b78f4, 0x78027235,
		0x02a3a6f2, 0xf3000000, 0, 0,
	};
	fp2_copy(R->X, P->X);
	fp2_neg(R->Y, P->Y);
	fp2_mul_fp(R->Z, P->Z, c);
}


static void final_exponent_hard_part(fp12_t r, const fp12_t f)
{
	// a2 = 0xd8000000019062ed0000b98b0cb27659
	// a3 = 0x2400000000215d941
	const bn_t a2 = {0xcb27659, 0x0000b98b, 0x019062ed, 0xd8000000, 0, 0, 0, 0};
	const bn_t a3 = {0x215d941, 0x40000000, 0x2, 0, 0, 0, 0, 0};
	const bn_t nine = {9,0,0,0,0,0,0,0};
	fp12_t t0, t1, t2, t3;

	fp12_pow(t0, f, a3);
	fp12_inv(t0, t0);
	fp12_frobenius(t1, t0);
	fp12_mul(t1, t0, t1);

	fp12_mul(t0, t0, t1);
	fp12_frobenius(t2, f);
	fp12_mul(t3, t2, f);
	fp12_pow(t3, t3, nine);

	fp12_mul(t0, t0, t3);
	fp12_sqr(t3, f);
	fp12_sqr(t3, t3);
	fp12_mul(t0, t0, t3);
	fp12_sqr(t2, t2);
	fp12_mul(t2, t2, t1);
	fp12_frobenius2(t1, f);
	fp12_mul(t1, t1, t2);

	fp12_pow(t2, t1, a2);
	fp12_mul(t0, t2, t0);
	fp12_frobenius3(t1, f);
	fp12_mul(t1, t1, t0);

	fp12_copy(r, t1);
}

static void final_exponent(fp12_t r, const fp12_t f)
{
	fp12_t t0;
	fp12_t t1;

	fp12_frobenius6(t0, f);
	fp12_inv(t1, f);
	fp12_mul(t0, t0, t1);
	fp12_frobenius2(t1, t0);
	fp12_mul(t0, t0, t1);
	final_exponent_hard_part(t0, t0);

	fp12_copy(r, t0);
}

static void sm9_pairing(fp12_t r, const twist_point_t *Q, const point_t *P) {
	const char *abits = "00100000000000000000000000000000000000010000101011101100100111110";

	twist_point_t _T, *T = &_T;
	twist_point_t _Q1, *Q1 = &_Q1;
	twist_point_t _Q2, *Q2 = &_Q2;

	fp12_t f_num;
	fp12_t f_den;
	fp12_t g_num;
	fp12_t g_den;
	int i;

	twist_point_copy(T, Q);

	fp12_set_one(f_num);
	fp12_set_one(f_den);

	for (i = 0; i < strlen(abits); i++) {

		fp12_sqr(f_num, f_num);
		fp12_sqr(f_den, f_den);
		eval_g_tangent(g_num, g_den, T, P);
		fp12_mul(f_num, f_num, g_num);
		fp12_mul(f_den, f_den, g_den);

		twist_point_dbl(T, T);

		if (abits[i] == '1') {
			eval_g_line(g_num, g_den, T, Q, P);
			fp12_mul(f_num, f_num, g_num);
			fp12_mul(f_den, f_den, g_den);
			twist_point_add(T, T, Q);
		}
	}

	twist_point_pi1(Q1, Q);
	twist_point_neg_pi2(Q2, Q);

	eval_g_line(g_num, g_den, T, Q1, P);
	fp12_mul(f_num, f_num, g_num);
	fp12_mul(f_den, f_den, g_den);
	twist_point_add_full(T, T, Q1);

	eval_g_line(g_num, g_den, T, Q2, P);
	fp12_mul(f_num, f_num, g_num);
	fp12_mul(f_den, f_den, g_den);
	twist_point_add_full(T, T, Q2);

	fp12_inv(f_den, f_den);
	fp12_mul(r, f_num, f_den);

	final_exponent(r, r);
}

#if 0
static void pairing_test() {

	let r = fp12_new();
	const char g[] =
		"aab9f06a4eeba4323a7833db202e4e35639d93fa3305af73f0f071d7d284fcfb\n",
		"84b87422330d7936eaba1109fa5a7a7181ee16f2438b0aeb2f38fd5f7554e57a\n",
		"4c744e69c4a2e1c8ed72f796d151a17ce2325b943260fc460b9f73cb57c9014b\n",
		"b3129a75d31d17194675a1bc56947920898fbf390a5bf5d931ce6cbb3340f66d\n",
		"93634f44fa13af76169f3cc8fbea880adaff8475d5fd28a75deb83c44362b439\n",
		"1604a3fcfa9783e667ce9fcb1062c2a5c6685c316dda62de0548baa6ba30038b\n",
		"5a1ae172102efd95df7338dbc577c66d8d6c15e0a0158c7507228efb078f42a6\n",
		"67e0e0c2eed7a6993dce28fe9aa2ef56834307860839677f96685f2b44d0911f\n",
		"a01f2c8bee81769609462c69c96aa923fd863e209d3ce26dd889b55e2e3873db\n",
		"38bffe40a22d529a0c66124b2c308dac9229912656f62b4facfced408e02380f\n",
		"28b3404a61908f5d6198815c99af1990c8af38655930058c28c21bb539ce0000\n",
		"4e378fb5561cd0668f906b731ac58fee25738edf09cadc7a29c0abc0177aea6d\n";


	sm9_pairing(r, SM9_Ppubs, SM9_P1);
	console.log("test pairing: ", fp12_equ(r, fp12_from_hex(g)));
}

#endif
