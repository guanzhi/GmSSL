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
#include <assert.h>
#include <gmssl/sm2.h>
#include <gmssl/error.h>
#include "endian.h"


typedef uint64_t bignum_t[8];

typedef struct {
	bignum_t X;
	bignum_t Y;
	bignum_t Z;
} point_t;


static const bignum_t SM2_P = {
	0xffffffff, 0xffffffff, 0x00000000, 0xffffffff,
	0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe,
};

static const bignum_t SM2_B = {
	0x4d940e93, 0xddbcbd41, 0x15ab8f92, 0xf39789f5,
	0xcf6509a7, 0x4d5a9e4b, 0x9d9f5e34, 0x28e9fa9e,
};

static const point_t _SM2_G = {
	{
	0x334c74c7, 0x715a4589, 0xf2660be1, 0x8fe30bbf,
	0x6a39c994, 0x5f990446, 0x1f198119, 0x32c4ae2c,
	},
	{
	0x2139f0a0, 0x02df32e5, 0xc62a4740, 0xd0a9877c,
	0x6b692153, 0x59bdcee3, 0xf4f6779c, 0xbc3736a2,
	},
	{
	1, 0, 0, 0, 0, 0, 0, 0,
	},
};
static const point_t *SM2_G = &_SM2_G;

static const bignum_t SM2_N = {
	0x39d54123, 0x53bbf409, 0x21c6052b, 0x7203df6b,
	0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe,
};

// u = (p - 1)/4, u + 1 = (p + 1)/4
static const bignum_t SM2_U_PLUS_ONE = {
	0x00000000, 0x40000000, 0xc0000000, 0xffffffff,
	0xffffffff, 0xffffffff, 0xbfffffff, 0x3fffffff,
};

static const bignum_t ONE = {1,0,0,0,0,0,0,0};
static const bignum_t TWO = {2,0,0,0,0,0,0,0};
static const bignum_t THREE = {3,0,0,0,0,0,0,0};

#define bn_init(r) memset((r), 0, sizeof(bignum_t))
#define bn_set_zero(r) memset((r), 0, sizeof(bignum_t))
#define bn_copy(r, a) memcpy((r), (a), sizeof(bignum_t))
#define bn_clean(r) memset((r), 0, sizeof(bignum_t))

static int bn_check(const bignum_t a)
{
	int err = 0;
	int i;
	for (i = 0; i < 8; i++) {
		if (a[i] > 0xffffffff) {
			fprintf(stderr, "%s %d: error\n", __FILE__, __LINE__);
			err++;
		}
	}
	if (err)
		return -1;
	else	return 1;
}

static int bn_is_zero(const bignum_t a)
{
	int i;
	for (i = 0; i < 8; i++) {
		if (a[i] != 0)
			return 0;
	}
	return 1;
}

static int bn_is_one(const bignum_t a)
{
	int i;
	if (a[0] != 1)
		return 0;
	for (i = 1; i < 8; i++) {
		if (a[i] != 0)
			return 0;
	}
	return 1;
}

static void bn_to_bytes(const bignum_t a, uint8_t out[32])
{
	int i;
	uint8_t *p = out;

	/*
	fprintf(stderr, "bn_to_bytes:\n");
	for (i = 0; i < 8; i++) {
		fprintf(stderr, "%016lx ", a[i]);
	}
	fprintf(stderr, "\n");
	*/

	for (i = 7; i >= 0; i--) {
		uint32_t ai = (uint32_t)a[i];
		PUTU32(out, ai);
		out += sizeof(uint32_t);
	}

	/*
	for (i = 0; i < 32; i++) {
		fprintf(stderr, "%02X ", p[i]);
	}
	*/

}

static void bn_from_bytes(bignum_t r, const uint8_t in[32])
{
	int i;
	for (i = 7; i >= 0; i--) {
		r[i] = GETU32(in);
		in += sizeof(uint32_t);
	}
}

static int hexchar2int(char c)
{
	if      ('0' <= c && c <= '9') return c - '0';
	else if ('a' <= c && c <= 'f') return c - 'a' + 10;
	else if ('A' <= c && c <= 'F') return c - 'A' + 10;
	else return -1;
}

static int hex2bin(const char *in, size_t inlen, uint8_t *out)
{
	int c;
	if (inlen % 2)
		return -1;

	while (inlen) {
		if ((c = hexchar2int(*in++)) < 0)
			return -1;
		*out = (uint8_t)c << 4;
		if ((c = hexchar2int(*in++)) < 0)
			return -1;
		*out |= (uint8_t)c;
		inlen -= 2;
		out++;
	}
	return 1;
}

static void bn_to_hex(const bignum_t a, char hex[64])
{
	int i;
	for (i = 7; i >= 0; i--) {
		int len;
		len = sprintf(hex, "%08x", (uint32_t)a[i]);
		assert(len == 8);
		hex += 8;
	}
}

static int bn_from_hex(bignum_t r, const char hex[64])
{
	uint8_t buf[32];
	if (hex2bin(hex, 64, buf) < 0)
		return -1;
	bn_from_bytes(r, buf);
	return 1;
}

static int bn_print(FILE *fp, const bignum_t a, int format, int indent)
{
	int ret = 0, i;
	for (i = 7; i >= 0; i--) {
		if (a[i] >= ((uint64_t)1 << 32)) {
			printf("bn_print check failed\n");
		}
		ret += fprintf(fp, "%08x", (uint32_t)a[i]);
	}
	ret += fprintf(fp, "\n");
	return ret;
}
#define print_bn(a) bn_print(stdout,a,0,0)

static void bn_to_bits(const bignum_t a, char bits[256])
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

static int bn_cmp(const bignum_t a, const bignum_t b)
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

static int bn_equ_hex(const bignum_t a, const char *hex)
{
	char buf[65] = {0};
	char *p = buf;
	int i;

	for (i = 7; i >= 0; i--) {
		sprintf(p, "%08x", (uint32_t)a[i]);
		p += 8;
	}
	return (strcmp(buf, hex) == 0);
}

static int bn_is_odd(const bignum_t a)
{
	return a[0] & 0x01;
}

static void bn_set_word(bignum_t r, uint32_t a)
{
	int i;
	r[0] = a;
	for (i = 1; i < 8; i++) {
		r[i] = 0;
	}
}
#define bn_set_one(r) bn_set_word((r), 1)

static void bn_add(bignum_t r, const bignum_t a, const bignum_t b)
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

static void bn_sub(bignum_t ret, const bignum_t a, const bignum_t b)
{
	int i;
	bignum_t r;
	r[0] = ((uint64_t)1 << 32) + a[0] - b[0];
	for (i = 1; i < 7; i++) {
		r[i] = 0xffffffff + a[i] - b[i] + (r[i - 1] >> 32);
		r[i - 1] &= 0xffffffff;
	}
	r[i] = a[i] - b[i] + (r[i - 1] >> 32) - 1;
	r[i - 1] &= 0xffffffff;
	bn_copy(ret, r);
}

static void bn_rand_range(bignum_t r, const bignum_t range)
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

static void fp_add(bignum_t r, const bignum_t a, const bignum_t b)
{
	bn_add(r, a, b);
	if (bn_cmp(r, SM2_P) >= 0) {
		bn_sub(r, r, SM2_P);
	}
}

static void fp_sub(bignum_t r, const bignum_t a, const bignum_t b)
{
	if (bn_cmp(a, b) >= 0) {
		bn_sub(r, a, b);
	} else {
		bignum_t t;
		bn_sub(t, SM2_P, b);
		bn_add(r, t, a);
	}
}

static void fp_dbl(bignum_t r, const bignum_t a)
{
	fp_add(r, a, a);
}

static void fp_tri(bignum_t r, const bignum_t a)
{
	bignum_t t;
	fp_dbl(t, a);
	fp_add(r, t, a);
}

static void fp_div2(bignum_t r, const bignum_t a)
{
	int i;
	bn_copy(r, a);
	if (r[0] & 0x01) {
		bn_add(r, r, SM2_P);
	}
	for (i = 0; i < 7; i++) {
		r[i] = (r[i] >> 1) | ((r[i + 1] & 0x01) << 31);
	}
	r[i] >>= 1;
}

static void fp_neg(bignum_t r, const bignum_t a)
{
	if (bn_is_zero(a)) {
		bn_copy(r, a);
	} else {
		bn_sub(r, SM2_P, a);
	}
}

static void fp_mul(bignum_t r, const bignum_t a, const bignum_t b)
{
	int i, j;
	uint64_t s[16] = {0};
	bignum_t d = {0};
	uint64_t u;

	// s = a * b
	for (i = 0; i < 8; i++) {
		u = 0;
		for (j = 0; j < 8; j++) {
			u = s[i + j] + a[i] * b[j] + u;
			s[i + j] = u & 0xffffffff;
			u >>= 32;
		}
		s[i + 8] = u;
	}

	r[0] = s[0] + s[ 8] + s[ 9] + s[10] + s[11] + s[12] + ((s[13] + s[14] + s[15]) << 1);
	r[1] = s[1] + s[ 9] + s[10] + s[11] + s[12] + s[13] + ((s[14] + s[15]) << 1);
	r[2] = s[2];
	r[3] = s[3] + s[ 8] + s[11] + s[12] + s[14] + s[15] + (s[13] << 1);
	r[4] = s[4] + s[ 9] + s[12] + s[13] + s[15] + (s[14] << 1);
	r[5] = s[5] + s[10] + s[13] + s[14] + (s[15] << 1);
	r[6] = s[6] + s[11] + s[14] + s[15];
	r[7] = s[7] + s[ 8] + s[ 9] + s[10] + s[11] + s[15] + ((s[12] + s[13] + s[14] + s[15]) << 1);

	for (i = 1; i < 8; i++) {
		r[i] += r[i - 1] >> 32;
		r[i - 1] &= 0xffffffff;
	}

	d[2] = s[8] + s[9] + s[13] + s[14];
	d[3] = d[2] >> 32;
	d[2] &= 0xffffffff;
	bn_sub(r, r, d);

	// max times ?
	while (bn_cmp(r, SM2_P) >= 0) {
		bn_sub(r, r, SM2_P);
	}
}

static void fp_sqr(bignum_t r, const bignum_t a)
{
	fp_mul(r, a, a);
}

static void fp_exp(bignum_t r, const bignum_t a, const bignum_t e)
{
	bignum_t t;
	uint32_t w;
	int i, j;

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

static void fp_inv(bignum_t r, const bignum_t a)
{
	bignum_t a1;
	bignum_t a2;
	bignum_t a3;
	bignum_t a4;
	bignum_t a5;
	int i;

	fp_sqr(a1, a);
	fp_mul(a2, a1, a);
	fp_sqr(a3, a2);
	fp_sqr(a3, a3);
	fp_mul(a3, a3, a2);
	fp_sqr(a4, a3);
	fp_sqr(a4, a4);
	fp_sqr(a4, a4);
	fp_sqr(a4, a4);
	fp_mul(a4, a4, a3);
	fp_sqr(a5, a4);
	for (i = 1; i < 8; i++)
		fp_sqr(a5, a5);
	fp_mul(a5, a5, a4);
	for (i = 0; i < 8; i++)
		fp_sqr(a5, a5);
	fp_mul(a5, a5, a4);
	for (i = 0; i < 4; i++)
		fp_sqr(a5, a5);
	fp_mul(a5, a5, a3);
	fp_sqr(a5, a5);
	fp_sqr(a5, a5);
	fp_mul(a5, a5, a2);
	fp_sqr(a5, a5);
	fp_mul(a5, a5, a);
	fp_sqr(a4, a5);
	fp_mul(a3, a4, a1);
	fp_sqr(a5, a4);
	for (i = 1; i< 31; i++)
		fp_sqr(a5, a5);
	fp_mul(a4, a5, a4);
	fp_sqr(a4, a4);
	fp_mul(a4, a4, a);
	fp_mul(a3, a4, a2);
	for (i = 0; i < 33; i++)
		fp_sqr(a5, a5);
	fp_mul(a2, a5, a3);
	fp_mul(a3, a2, a3);
	for (i = 0; i < 32; i++)
		fp_sqr(a5, a5);
	fp_mul(a2, a5, a3);
	fp_mul(a3, a2, a3);
	fp_mul(a4, a2, a4);
	for (i = 0; i < 32; i++)
		fp_sqr(a5, a5);
	fp_mul(a2, a5, a3);
	fp_mul(a3, a2, a3);
	fp_mul(a4, a2, a4);
	for (i = 0; i < 32; i++)
		fp_sqr(a5, a5);
	fp_mul(a2, a5, a3);
	fp_mul(a3, a2, a3);
	fp_mul(a4, a2, a4);
	for (i = 0; i < 32; i++)
		fp_sqr(a5, a5);
	fp_mul(a2, a5, a3);
	fp_mul(a3, a2, a3);
	fp_mul(a4, a2, a4);
	for (i = 0; i < 32; i++)
		fp_sqr(a5, a5);
	fp_mul(r, a4, a5);

	bn_clean(a1);
	bn_clean(a2);
	bn_clean(a3);
	bn_clean(a4);
	bn_clean(a5);
}


static void fn_add(bignum_t r, const bignum_t a, const bignum_t b)
{
	bn_add(r, a, b);
	if (bn_cmp(r, SM2_N) >= 0) {
		bn_sub(r, r, SM2_N);
	}
}

static void fn_sub(bignum_t r, const bignum_t a, const bignum_t b)
{
	if (bn_cmp(a, b) >= 0) {
		bn_sub(r, a, b);
	} else {
		bignum_t t;
		bn_add(t, a, SM2_N);
		bn_sub(r, t, b);
	}
}

static void fn_neg(bignum_t r, const bignum_t a)
{
	if (bn_is_zero(a)) {
		bn_copy(r, a);
	} else {
		bn_sub(r, SM2_N, a);
	}
}

/* bn288 only used in barrett reduction */
static int bn288_cmp(const uint64_t a[9], const uint64_t b[9])
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

static void bn288_add(uint64_t r[9], const uint64_t a[9], const uint64_t b[9])
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

static void bn288_sub(uint64_t ret[9], const uint64_t a[9], const uint64_t b[9])
{
	int i;
	uint64_t r[9];

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

static void fn_mul(bignum_t r, const bignum_t a, const bignum_t b)
{
	static const uint64_t mu[8] = {
		0xf15149a0, 0x12ac6361, 0xfa323c01, 0x8dfc2096,
		1, 1, 1, 0x100000001,
	};

	uint64_t s[17];
	uint64_t zh[9];
	uint64_t zl[9];
	uint64_t q[9];
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
	//printf("zl = "); for (i = 8; i >= 0; i--) printf("%08x", (uint32_t)zl[i]); printf("\n");
	//printf("zh = "); for (i = 8; i >= 0; i--) printf("%08x", (uint32_t)zh[i]); printf("\n");

	/* q = zh * mu // (2^32)^9 */
	for (i = 0; i < 9; i++) {
		s[i] = 0;
	}
	for (i = 0; i < 9; i++) {
		w = 0;
		for (j = 0; j < 8; j++) {
			w += s[i + j] + zh[i] * mu[j];
			s[i + j] = w & 0xffffffff;
			w >>= 32;
		}
		s[i + 8] = w;
	}
	for (i = 0; i < 8; i++) {
		q[i] = s[9 + i];
	}
	//printf("q  = "); for (i = 7; i >= 0; i--) printf("%08x", (uint32_t)q[i]); printf("\n");


	/* q = q * n mod (2^32)^9 */
	for (i = 0; i < 8; i++) {
		s[i] = 0;
	}
	for (i = 0; i < 8; i++) {
		w = 0;
		for (j = 0; j < 8; j++) {
			w += s[i + j] + q[i] * SM2_N[j];
			s[i + j] = w & 0xffffffff;
			w >>= 32;
		}
		s[i + 8] = w;
	}
	for (i = 0; i < 9; i++) {
		q[i] = s[i];
	}
	//printf("qn = "); for (i = 8; i >= 0; i--) printf("%08x", (uint32_t)q[i]); printf("\n");

	/* r = zl - q (mod (2^32)^9) */

	if (bn288_cmp(zl, q)) {
		bn288_sub(zl, zl, q);
	} else {
		uint64_t c[9] = {0,0,0,0,0,0,0,0,0x100000000};
		bn288_sub(q, c, q);
		bn288_add(zl, q, zl);
		printf("******\n");
		printf("******\n");
		printf("******\n");
		printf("******\n");
		printf("******\n");

	}

	//printf("r  = "); for (i = 8; i >= 0; i--) printf("%08x", (uint32_t)zl[i]); printf("\n");

	for (i = 0; i < 8; i++) {
		r[i] = zl[i];
	}
	r[7] += zl[8] << 32;

	/* while r >= p do: r = r - n */
	while (bn_cmp(r, SM2_N) >= 0) {
		bn_sub(r, r, SM2_N);
		//printf("r = r -n  = "); for (i = 8; i >= 0; i--) printf("%08x", (uint32_t)zl[i]); printf("\n");
	}
}

static void fn_sqr(bignum_t r, const bignum_t a)
{
	fn_mul(r, a, a);
}

static void fn_exp(bignum_t r, const bignum_t a, const bignum_t e)
{
	bignum_t t;
	uint32_t w;
	int i, j;

	bn_set_one(t);
	for (i = 7; i >= 0; i--) {
		w = (uint32_t)e[i];
		for (j = 0; j < 32; j++) {
			fn_sqr(t, t);
			if (w & 0x80000000) {
				fn_mul(t, t, a);
			}
			w <<= 1;
		}
	}

	bn_copy(r, t);
}

static void fn_inv(bignum_t r, const bignum_t a)
{
	bignum_t e;
	bn_sub(e, SM2_N, TWO);
	fn_exp(r, a, e);
}

static void fn_rand(bignum_t r)
{
	bn_rand_range(r, SM2_N);
}

#define hex_fp_add_x_y "eefbe4cf140ff8b5b956d329d5a2eae8608c933cb89053217439786e54866567"
#define hex_fp_sub_x_y "768d77882a23097d05db3562fed0a840bf3984422c3bc4a26e7b12a412128426"
#define hex_fp_sub_y_x "89728876d5dcf682fa24ca9d012f57bf40c67bbcd3c43b5e9184ed5beded7bd9"
#define hex_fp_neg_x   "cd3b51d2e0e67ee6a066fbb995c6366b701cf43f0d99f41f8ea5ba76ccb38b38"
#define hex_fp_mul_x_y "edd7e745bdc4630ccfa1da1057033a525346dbf202f082f3c431349991ace76a"
#define hex_fp_squ_x   "f4e2cca0bcfd67fba8531eebff519e4cb3d47f9fe8c5eff5151f4c497ec99fbf"
#define hex_fp_exp_x_y "8cafd11b1a0d2072b82911ba87e0d376103a1be5986fce91d8d297b758f68146"
#define hex_fp_inv_x   "053b878fb82e213c17e554b9a574b7bd31775222704b7fd9c7d6f8441026cd80"

#define hex_fn_add_x_y "eefbe4cf140ff8b5b956d329d5a2eae8608c933cb89053217439786e54866567"
#define hex_fn_sub_x_y "768d77882a23097d05db3562fed0a840313d63ae4e01c9ccc23706ad4be7c54a"
#define hex_fn_sub_y_x "89728876d5dcf682fa24ca9d012f57bf40c67bbcd3c43b5e9184ed5beded7bd9"
#define hex_fn_neg_x   "cd3b51d2e0e67ee6a066fbb995c6366ae220d3ab2f5ff949e261ae800688cc5c"
#define hex_fn_mul_x_y "cf7296d5cbf0b64bb5e9a11b294962e9c779b41c038e9c8d815234a0df9d6623"
#define hex_fn_sqr_x   "82d3d1b296d3a3803888b7ffc78f23eca824e7ec8d7ddaf231ffb0d256a19da2"
#define hex_fn_exp_x_y "0cf4df7e76d7d49ff23b94853a98aba1e36e9ca0358acbf23a3bbda406f46df3"
#define hex_fn_inv_x   "96340ec8b80f44e9b345a706bdb5c9e3ab8a6474a5cb4e0d4645dbaecf1cf03d"
#define hex_v          "d3da0ef661be97360e1b32f834e6ca5673b1984b22bb420133da05e56ccd59fb"
#define hex_fn_mul_x_v "0375c61e1ed13e460f4b5d462dc5b2c846f36c7b481cd4bed8f7dd55908a6afd"

#define hex_t \
	"2fbadf57b52dc19e8470bf201cb182e0a4f7fa5e28d356b15da173132b94b325"

static int bn_test(void)
{
	bignum_t r;
	bignum_t x;
	bignum_t y;
	bn_copy(x, SM2_G->X);
	bn_copy(y, SM2_G->Y);
	int ok, i = 1;

	char hex[65];

	bignum_t v = {
		0x6ccd59fb, 0x33da05e5, 0x22bb4201, 0x73b1984b,
		0x34e6ca56, 0x0e1b32f8, 0x61be9736, 0xd3da0ef6,
	};

	bignum_t t;

	bn_from_hex(r, hex_v);
	print_bn(r);

	// fp tests
	fp_add(r, x, y);
	ok = bn_equ_hex(r, hex_fp_add_x_y);
	printf("sm2 bn test %d %s\n", i++, ok ? "ok" : "failed");

	fp_sub(r, x, y);
	ok = bn_equ_hex(r, hex_fp_sub_x_y);
	printf("sm2 bn test %d %s\n", i++, ok ? "ok" : "failed");

	fp_mul(r, x, y);
	ok = bn_equ_hex(r, hex_fp_mul_x_y);
	printf("sm2 bn test %d %s\n", i++, ok ? "ok" : "failed");

	fp_exp(r, x, y);
	ok = bn_equ_hex(r, hex_fp_exp_x_y);
	printf("sm2 bn test %d %s\n", i++, ok ? "ok" : "failed");

	fp_inv(r, x);
	ok = bn_equ_hex(r, hex_fp_inv_x);
	printf("sm2 bn test %d %s\n", i++, ok ? "ok" : "failed");

	fp_neg(r, x);
	ok = bn_equ_hex(r, hex_fp_neg_x);
	printf("sm2 bn test %d %s\n", i++, ok ? "ok" : "failed");

	// fn tests
	fn_add(r, x, y);
	ok = bn_equ_hex(r, hex_fn_add_x_y);
	printf("sm2 bn test %d %s\n", i++, ok ? "ok" : "failed");

	fn_sub(r, x, y);
	ok = bn_equ_hex(r, hex_fn_sub_x_y);
	printf("sm2 bn test %d %s\n", i++, ok ? "ok" : "failed");

	fn_sub(r, y, x);
	ok = bn_equ_hex(r, hex_fn_sub_y_x);
	printf("sm2 bn test %d %s\n", i++, ok ? "ok" : "failed");

	fn_neg(r, x);
	ok = bn_equ_hex(r, hex_fn_neg_x);
	printf("sm2 bn test %d %s\n", i++, ok ? "ok" : "failed");

	fn_mul(r, x, y);
	ok = bn_equ_hex(r, hex_fn_mul_x_y);
	printf("sm2 bn test %d %s\n", i++, ok ? "ok" : "failed");

	fn_mul(r, x, v);
	ok = bn_equ_hex(r, hex_fn_mul_x_v);
	printf("sm2 bn test %d %s\n", i++, ok ? "ok" : "failed");

	fn_sqr(r, x);
	ok = bn_equ_hex(r, hex_fn_sqr_x);
	printf("sm2 bn test %d %s\n", i++, ok ? "ok" : "failed");

	fn_exp(r, x, y);
	ok = bn_equ_hex(r, hex_fn_exp_x_y);
	printf("sm2 bn test %d %s\n", i++, ok ? "ok" : "failed");

	fn_inv(r, x);
	ok = bn_equ_hex(r, hex_fn_inv_x);
	printf("sm2 bn test %d %s\n", i++, ok ? "ok" : "failed");

	bignum_t tv = {
		0x2b94b325, 0x5da17313, 0x28d356b1, 0xa4f7fa5e,
		0x1cb182e0, 0x8470bf20, 0xb52dc19e, 0x2fbadf57,
	};
	bn_from_hex(t, hex_t);
	ok = (bn_cmp(t, tv) == 0);

	bn_to_hex(t, hex);
	bn_check(t);

	printf("end\n");
	return 0;
}

static void point_init(point_t *R)
{
	memset(R, 0, sizeof(point_t));
	R->X[0] = 1;
	R->Y[0] = 1;
}
#define point_set_infinity(R) point_init(R)

static int point_is_at_infinity(const point_t *P)
{
	return bn_is_zero(P->Z);
}

#define point_copy(R, P) memcpy((R), (P), sizeof(point_t))

static void point_set_xy(point_t *R, const bignum_t x, const bignum_t y)
{
	bn_copy(R->X, x);
	bn_copy(R->Y, y);
	bn_set_one(R->Z);
}

static void point_get_xy(const point_t *P, bignum_t x, bignum_t y)
{
	bignum_t z_inv;

	if (bn_is_one(P->Z)) {
		bn_copy(x, P->X);
		bn_copy(y, P->Y);
	} else {
		fp_inv(z_inv, P->Z);
		if (y)
			fp_mul(y, P->Y, z_inv);
		fp_sqr(z_inv, z_inv);
		fp_mul(x, P->X, z_inv);
		if (y)
			fp_mul(y, y, z_inv);
	}
}

static int point_print(FILE *fp, const point_t *P, int format, int indent)
{
	int len = 0;
	bignum_t x;
	bignum_t y;
	point_get_xy(P, x, y);
	len += bn_print(fp, x, format, indent);
	len += bn_print(fp, y, format, indent);

	return len;
}

#define print_point(P) point_print(stdout,P,0,0)

static int point_is_on_curve(const point_t *P)
{
	bignum_t t0;
	bignum_t t1;
	bignum_t t2;

	if (bn_is_one(P->Z)) {
		fp_sqr(t0, P->Y);
		fp_add(t0, t0, P->X);
		fp_add(t0, t0, P->X);
		fp_add(t0, t0, P->X);
		fp_sqr(t1, P->X);
		fp_mul(t1, t1, P->X);
		fp_add(t1, t1, SM2_B);
	} else {
		fp_sqr(t0, P->Y);
		fp_sqr(t1, P->Z);
		fp_sqr(t2, t1);
		fp_mul(t1, t1, t2);
		fp_mul(t1, t1, SM2_B);
		fp_mul(t2, t2, P->X);
		fp_add(t0, t0, t2);
		fp_add(t0, t0, t2);
		fp_add(t0, t0, t2);
		fp_sqr(t2, P->X);
		fp_mul(t2, t2, P->X);
		fp_add(t1, t1, t2);
	}

	return (bn_cmp(t0, t1) == 0);
}

static void point_neg(point_t *R, const point_t *P)
{
	bn_copy(R->X, P->X);
	fp_neg(R->Y, P->Y);
	bn_copy(R->Z, P->Z);
}

static void point_dbl(point_t *R, const point_t *P)
{
	const uint64_t *X1 = P->X;
	const uint64_t *Y1 = P->Y;
	const uint64_t *Z1 = P->Z;
	bignum_t T1;
	bignum_t T2;
	bignum_t T3;
	bignum_t X3;
	bignum_t Y3;
	bignum_t Z3;
				//printf("X1 = "); print_bn(X1);
				//printf("Y1 = "); print_bn(Y1);
				//printf("Z1 = "); print_bn(Z1);

	if (point_is_at_infinity(P)) {
		point_copy(R, P);
		return;
	}

	fp_sqr(T1, Z1);		//printf("T1 = Z1^2    = "); print_bn(T1);
	fp_sub(T2, X1, T1);	//printf("T2 = X1 - T1 = "); print_bn(T2);
	fp_add(T1, X1, T1);	//printf("T1 = X1 + T1 = "); print_bn(T1);
	fp_mul(T2, T2, T1);	//printf("T2 = T2 * T1 = "); print_bn(T2);
	fp_tri(T2, T2);		//printf("T2 =  3 * T2 = "); print_bn(T2);
	fp_dbl(Y3, Y1);		//printf("Y3 =  2 * Y1 = "); print_bn(Y3);
	fp_mul(Z3, Y3, Z1);	//printf("Z3 = Y3 * Z1 = "); print_bn(Z3);
	fp_sqr(Y3, Y3);		//printf("Y3 = Y3^2    = "); print_bn(Y3);
	fp_mul(T3, Y3, X1);	//printf("T3 = Y3 * X1 = "); print_bn(T3);
	fp_sqr(Y3, Y3);		//printf("Y3 = Y3^2    = "); print_bn(Y3);
	fp_div2(Y3, Y3);	//printf("Y3 = Y3/2    = "); print_bn(Y3);
	fp_sqr(X3, T2);		//printf("X3 = T2^2    = "); print_bn(X3);
	fp_dbl(T1, T3);		//printf("T1 =  2 * T1 = "); print_bn(T1);
	fp_sub(X3, X3, T1);	//printf("X3 = X3 - T1 = "); print_bn(X3);
	fp_sub(T1, T3, X3);	//printf("T1 = T3 - X3 = "); print_bn(T1);
	fp_mul(T1, T1, T2);	//printf("T1 = T1 * T2 = "); print_bn(T1);
	fp_sub(Y3, T1, Y3);	//printf("Y3 = T1 - Y3 = "); print_bn(Y3);

	bn_copy(R->X, X3);
	bn_copy(R->Y, Y3);
	bn_copy(R->Z, Z3);

				//printf("X3 = "); print_bn(R->X);
				//printf("Y3 = "); print_bn(R->Y);
				//printf("Z3 = "); print_bn(R->Z);

}

// FIXME: Q must be affine coordinate
// change API!			
static void point_add(point_t *R, const point_t *P, const point_t *Q)
{
	const uint64_t *X1 = P->X;
	const uint64_t *Y1 = P->Y;
	const uint64_t *Z1 = P->Z;
	const uint64_t *x2 = Q->X;
	const uint64_t *y2 = Q->Y;
	bignum_t T1;
	bignum_t T2;
	bignum_t T3;
	bignum_t T4;
	bignum_t X3;
	bignum_t Y3;
	bignum_t Z3;

	if (point_is_at_infinity(Q)) {
		point_copy(R, P);
		return;
	}

	if (point_is_at_infinity(P)) {
		point_copy(R, Q);
		return;
	}

	assert(bn_is_one(Q->Z));

	fp_sqr(T1, Z1);
	fp_mul(T2, T1, Z1);
	fp_mul(T1, T1, x2);
	fp_mul(T2, T2, y2);
	fp_sub(T1, T1, X1);
	fp_sub(T2, T2, Y1);
	if (bn_is_zero(T1)) {
		if (bn_is_zero(T2)) {
			point_t _Q, *Q = &_Q;
			point_set_xy(Q, x2, y2);

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

	bn_copy(R->X, X3);
	bn_copy(R->Y, Y3);
	bn_copy(R->Z, Z3);
}

static void point_sub(point_t *R, const point_t *P, const point_t *Q)
{
	point_t _T, *T = &_T;
	point_neg(T, Q);
	point_add(R, P, T);
}

static void point_mul(point_t *R, const bignum_t k, const point_t *P)
{
	char bits[257] = {0};
	point_t _Q, *Q = &_Q;
	point_t _T, *T = &_T;
	int i;

	// FIXME: point_add need affine, so we can not use point_add
	if (!bn_is_one(P->Z)) {
		bignum_t x;
		bignum_t y;
		point_get_xy(P, x, y);
		point_set_xy(T, x, y);
		P = T;
	}

	point_set_infinity(Q);
	bn_to_bits(k, bits);
	for (i = 0; i < 256; i++) {
		point_dbl(Q, Q);
		if (bits[i] == '1') {
			point_add(Q, Q, P);
		}
	}
	point_copy(R, Q);
}

static void point_to_bytes(const point_t *P, uint8_t out[64])
{
	bignum_t x;
	bignum_t y;
	point_get_xy(P, x, y);
	bn_to_bytes(x, out);
	bn_to_bytes(y, out + 32);
}

static void point_from_bytes(point_t *P, const uint8_t in[64])
{
	bn_from_bytes(P->X, in);
	bn_from_bytes(P->Y, in + 32);
	bn_set_word(P->Z, 1);
	/* should we check if point_is_on_curve */
}

static void point_mul_generator(point_t *R, const bignum_t k)
{
	point_mul(R, k, SM2_G);
}

/* R = t * P + s * G */
static void point_mul_sum(point_t *R, const bignum_t t, const point_t *P, const bignum_t s)
{
	point_t _sG, *sG = &_sG;
	bignum_t x;
	bignum_t y;

	/* T = s * G */
	point_mul_generator(sG, s);

	// R = t * P
	point_mul(R, t, P);
	point_get_xy(R, x, y);
	point_set_xy(R, x, y);

	// R = R + T
	point_add(R, sG, R);
}

static void point_from_hex(point_t *P, const char hex[64 * 2])
{
	bn_from_hex(P->X, hex);
	bn_from_hex(P->Y, hex + 64);
	bn_set_one(P->Z);
}

static int point_equ_hex(const point_t *P, const char hex[128])
{
	bignum_t x;
	bignum_t y;
	point_t _T, *T = &_T;

	point_get_xy(P, x, y);
	point_from_hex(T, hex);

	return (bn_cmp(x, T->X) == 0) && (bn_cmp(y, T->Y) == 0);
}

#define hex_G \
	"32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7" \
	"bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0"
#define hex_2G \
	"56cefd60d7c87c000d58ef57fa73ba4d9c0dfa08c08a7331495c2e1da3f2bd52" \
	"31b7e7e6cc8189f668535ce0f8eaf1bd6de84c182f6c8e716f780d3a970a23c3"
#define hex_3G \
	"a97f7cd4b3c993b4be2daa8cdb41e24ca13f6bd945302244e26918f1d0509ebf" \
	"530b5dd88c688ef5ccc5cec08a72150f7c400ee5cd045292aaacdd037458f6e6"
#define hex_negG \
	"32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7" \
	"43c8c95c0b098863a642311c9496deac2f56788239d5b8c0fd20cd1adec60f5f"
#define hex_10G \
	"d3f94862519621c121666061f65c3e32b2d0d065cd219e3284a04814db522756" \
	"4b9030cf676f6a742ebd57d146dca428f6b743f64d1482d147d46fb2bab82a14"
#define hex_bG \
	"528470bc74a6ebc663c06fc4cfa1b630d1e9d4a80c0a127b47f73c324c46c0ba" \
	"832cf9c5a15b997e60962b4cf6e2c9cee488faaec98d20599d323d4cabfc1bf4"

#define hex_P \
	"504cfe2fae749d645e99fbb5b25995cc6fed70196007b039bdc44706bdabc0d9" \
	"b80a8018eda5f55ddc4b870d7784b7b84e53af02f575ab53ed8a99a3bbe2abc2"
#define hex_2P \
	"a53d20e89312b5243f66aec12ef6471f5911941d86302d5d8337cb70937d65ae" \
	"96953c46815e4259363256ddd6c77fcc33787aeafc6a57beec5833f476dd69e0"

#define hex_tP \
	"02deff2c5b3656ca3f7c7ca9d710ca1d69860c75a9c7ec284b96b8adc50b2936" \
	"b74bcba937e9267fce4ccc069a6681f5b04dcedd9e2794c6a25ddc7856df7145"


static int point_test(void)
{
	point_t _P, *P = &_P;
	point_t _G, *G = &_G;
	bignum_t k;
	int err = 0, i = 1, ok;

	uint8_t buf[64];

	printf("point_test\n");

	point_copy(G, SM2_G);
	ok = point_equ_hex(G, hex_G);
	printf("sm2 point test %d %s\n", i++, ok ? "ok" : "failed"); err += ok ^ 1;

	ok = point_is_on_curve(G);
	printf("sm2 point test %d %s\n", i++, ok ? "ok" : "failed"); err += ok ^ 1;

	point_dbl(P, G);
	ok = point_equ_hex(P, hex_2G);
	printf("sm2 point test %d %s\n", i++, ok ? "ok" : "failed"); err += ok ^ 1;

	point_add(P, P, G);
	ok = point_equ_hex(P, hex_3G);
	printf("sm2 point test %d %s\n", i++, ok ? "ok" : "failed"); err += ok ^ 1;

	point_sub(P, P, G);
	ok = point_equ_hex(P, hex_2G);
	printf("sm2 point test %d %s\n", i++, ok ? "ok" : "failed"); err += ok ^ 1;

	point_neg(P, G);
	ok = point_equ_hex(P, hex_negG);
	printf("sm2 point test %d %s\n", i++, ok ? "ok" : "failed"); err += ok ^ 1;

	bn_set_word(k, 10);
	point_mul(P, k, G);
	ok = point_equ_hex(P, hex_10G);
	printf("sm2 point test %d %s\n", i++, ok ? "ok" : "failed"); err += ok ^ 1;

	point_mul_generator(P, SM2_B);
	ok = point_equ_hex(P, hex_bG);
	printf("sm2 point test %d %s\n", i++, ok ? "ok" : "failed"); err += ok ^ 1;

	point_to_bytes(P, buf);
	point_from_hex(P, hex_P);

	return err;
}

int sm2_algo_selftest(void)
{
	point_test();
	return 0;
}

int sm2_keygen(SM2_KEY *key)
{
	bignum_t x;
	bignum_t y;
	point_t _P, *P = &_P;

	if (!key) {
		return -1;
	}

	do {
		bn_rand_range(x, SM2_N);
	} while (bn_is_zero(x));
	bn_to_bytes(x, key->private_key);

	point_mul_generator(P, x);
	point_get_xy(P, x, y);
	bn_to_bytes(x, key->public_key.x);
	bn_to_bytes(y, key->public_key.y);
	return 1;
}

int sm2_point_is_on_curve(const SM2_POINT *P)
{
	point_t T;
	point_from_bytes(&T, (const uint8_t *)P);
	return point_is_on_curve(&T);
}

int sm2_point_from_x(SM2_POINT *P, const uint8_t x[32], int y)
{
	bignum_t _x, _y, _g, _z;
	bn_from_bytes(_x, x);

	// g = x^3 - 3x + b = (x^2 - 3)*x + b
	fp_sqr(_g, _x);
	fp_sub(_g, _g, THREE);
	fp_mul(_g, _g, _x);
	fp_add(_g, _g, SM2_B);

	// y = g^(u + 1) mod p, u = (p - 3)/4
	fp_exp(_y, _g, SM2_U_PLUS_ONE);

	// z = y^2 mod p
	fp_sqr(_z, _y);
	if (bn_cmp(_z, _g)) {
		error_print();
		return -1;
	}
	
	if ((y == 0x02 && bn_is_odd(_y)) || (y == 0x03) && !bn_is_odd(_y)) {
		fp_neg(_y, _y);
	}

	bn_to_bytes(_x, P->x);
	bn_to_bytes(_y, P->y);

	bn_clean(_x);
	bn_clean(_y);
	bn_clean(_g);
	bn_clean(_z);

	if (!sm2_point_is_on_curve(P)) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_point_from_xy(SM2_POINT *P, const uint8_t x[32], const uint8_t y[32])
{
	memcpy(P->x, x, 32);
	memcpy(P->y, y, 32);
	return sm2_point_is_on_curve(P);
}

int sm2_point_mul(SM2_POINT *R, const uint8_t k[32], const SM2_POINT *P)
{
	bignum_t _k;
	point_t _P;

	bn_from_bytes(_k, k);
	point_from_bytes(&_P, (uint8_t *)P);
	point_mul(&_P, _k, &_P);
	point_to_bytes(&_P, (uint8_t *)R);

	bn_clean(_k);
	return 1;
}

int sm2_point_mul_generator(SM2_POINT *R, const uint8_t k[32])
{
	bignum_t _k;
	point_t _R;

	bn_from_bytes(_k, k);
	point_mul_generator(&_R, _k);
	point_to_bytes(&_R, (uint8_t *)R);

	bn_clean(_k);
	return 1;
}

int sm2_point_mul_sum(SM2_POINT *R, const uint8_t k[32], const SM2_POINT *P, const uint8_t s[32])
{
	bignum_t _k;
	point_t _P;
	bignum_t _s;

	bn_from_bytes(_k, k);
	point_from_bytes(&_P, (uint8_t *)P);
	bn_from_bytes(_s, s);
	point_mul_sum(&_P, _k, &_P, _s);
	point_to_bytes(&_P, (uint8_t *)R);

	bn_clean(_k);
	bn_clean(_s);
	return 1;
}

#define hex_d   "5aebdfd947543b713bc0df2c65baaecc5dadd2cab39c6971402daf92c263fad2"
#define hex_e   "c0881c19beec741b9af27cc26493dcc33b05d481bfeab2f3ce9cc056e6ff8400"
#define hex_k   "981325ee1ab171e9d2cffb317181a02957b18a34bca610a6d2f8afcdeb53f6b8"
#define hex_x1  "17d2dfe83f23cce8499bca983950d59f0fd56c4c671dd63c04b27e4e94cfd767"
#define hex_r   "d85afc01fe104103e48e475a9de4b2624adb40ce2708892fd34f3ea57bcf5b67"
#define hex_rd  "a70ba64f9c30e05095f39fe26675114e3f157b2c35191bf6ff06246452f82eb3"
#define hex_di  "3ecfdb51c24b0eecb2d4238d1da8c013b8b575cef14ef43e2ddb7bce740ce9cf"
#define hex_krd "f1077f9d7e8091993cdc5b4f0b0c8eda8a9fee73a952f9db27ae7f72d2310928"
#define hex_s   "006bac5b8057ca829534dfde72a0d7883444a3b9bfe9bcdfb383fb90ed7d9486"

int sm2_do_sign(const SM2_KEY *key, const uint8_t dgst[32], SM2_SIGNATURE *sig)
{
	point_t _P, *P = &_P;
	bignum_t d;
	bignum_t e;
	bignum_t k;
	bignum_t x;
	bignum_t r;
	bignum_t s;

	if (!key || !dgst || !sig) {
		return -1;
	}

	bn_from_bytes(d, key->private_key);

	// e = H(M)
	bn_from_bytes(e, dgst);		//print_bn("e", e);

retry:

	// rand k in [1, n - 1]
	do {
		fn_rand(k);
	} while (bn_is_zero(k));
					//print_bn("k", k);

	// (x, y) = kG
	point_mul_generator(P, k);
	point_get_xy(P, x, NULL);	//print_bn("x", x);


	// r = e + x (mod n)
	fn_add(r, e, x);		//print_bn("r = e + x (mod n)", r);

	/* if r == 0 or r + k == n re-generate k */
	if (bn_is_zero(r)) {
		goto retry;
	}
	bn_add(x, r, k);
	if (bn_cmp(x, SM2_N) == 0) {
		goto retry;
	}

	/* s = ((1 + d)^-1 * (k - r * d)) mod n */

	fn_mul(e, r, d);		//print_bn("r*d", e);
	fn_sub(k, k, e);		//print_bn("k-r*d", k);
	fn_add(e, ONE, d);		//print_bn("1 +d", e);
	fn_inv(e, e);			//printf("(1+d)^-1", e);
	fn_mul(s, e, k);		//print_bn("s = ((1 + d)^-1 * (k - r * d)) mod n", s);

	bn_clean(d);
	bn_clean(k);
	bn_to_bytes(r, sig->r);		//print_bn("r", r);
	bn_to_bytes(s, sig->s);		//print_bn("s", s);
	return 1;
}

int sm2_do_verify(const SM2_KEY *key, const uint8_t dgst[32], const SM2_SIGNATURE *sig)
{
	point_t _P, *P = &_P;
	point_t _R, *R = &_R;
	bignum_t r;
	bignum_t s;
	bignum_t e;
	bignum_t x;
	bignum_t t;

	if (!key || !dgst || !sig) {
		error_print();
		return -1;
	}

	// parse signature values
	bn_from_bytes(r, sig->r);	//print_bn("r", r);
	bn_from_bytes(s, sig->s);	//print_bn("s", s);
	if (bn_is_zero(r)
		|| bn_cmp(r, SM2_N) >= 0
		|| bn_is_zero(s)
		|| bn_cmp(s, SM2_N) >= 0) {
		error_print();
		return -1;
	}

	// parse public key
	point_from_bytes(P, (const uint8_t *)&key->public_key);
					//print_point("P", P);

	// t = r + s (mod n)
	// check t != 0
	fn_add(t, r, s);		//print_bn("t = r + s (mod n)", t);
	if (bn_is_zero(t)) {
		error_print();
		return -1;
	}

	// Q = s * G + t * P
	point_mul_sum(R, t, P, s);
	point_get_xy(R, x, NULL);	//print_bn("x", x);

	// e  = H(M)
	// r' = e + x (mod n)
	bn_from_bytes(e, dgst);		//print_bn("e = H(M)", e);
	fn_add(e, e, x);		//print_bn("e + x (mod n)", e);

	// check if r == r'
	if (bn_cmp(e, r) == 0) {
		return 1;
	} else {
		error_print(); // 此处不应该打印错误，因为验证失败是预期的返回结果之一
		return 0;
	}
}

int sm2_point_from_signature(SM2_POINT *point, const SM2_SIGNATURE *sig)
{
	return -1;
}

int sm2_kdf(const uint8_t *in, size_t inlen, size_t outlen, uint8_t *out)
{
	SM3_CTX ctx;
	uint8_t counter_be[4];
	uint8_t dgst[SM3_DIGEST_SIZE];
	uint32_t counter = 1;
	size_t len;

	/*
	size_t i; fprintf(stderr, "kdf input : ");
	for (i = 0; i < inlen; i++) fprintf(stderr, "%02x", in[i]); fprintf(stderr, "\n");
	*/

	while (outlen) {
		PUTU32(counter_be, counter);
		counter++;

		sm3_init(&ctx);
		sm3_update(&ctx, in, inlen);
		sm3_update(&ctx, counter_be, sizeof(counter_be));
		sm3_finish(&ctx, dgst);

		len = outlen < SM3_DIGEST_SIZE ? outlen : SM3_DIGEST_SIZE;
		memcpy(out, dgst, len);
		out += len;
		outlen -= len;
	}

	memset(&ctx, 0, sizeof(SM3_CTX));
	memset(dgst, 0, sizeof(dgst));
	return 1;
}

// `sm2_do_encrypt` does not check validity of `key`
int sm2_do_encrypt(const SM2_KEY *key, const uint8_t *in, size_t inlen, SM2_CIPHERTEXT *out)
{
	bignum_t k;
	point_t _P, *P = &_P;
	SM3_CTX sm3_ctx;
	uint8_t buf[64];
	int i;

	if (!key || !in || !inlen || !out) {
		return -1;
	}

	// rand k in [1, n - 1]
	do {
		bn_rand_range(k, SM2_N);
	} while (bn_is_zero(k));

	// C1 = k * G = (x1, y1)
	point_mul_generator(P, k);
	point_to_bytes(P, (uint8_t *)&out->point);


	// Q = k * P = (x2, y2)
	point_from_bytes(P, (uint8_t *)&key->public_key);

	point_mul(P, k, P);

	point_to_bytes(P, buf);


	// t = KDF(x2 || y2, klen)
	sm2_kdf(buf, sizeof(buf), inlen, out->ciphertext);


	// C2 = M xor t
	for (i = 0; i < inlen; i++) {
		out->ciphertext[i] ^= in[i];
	}
	out->ciphertext_size = (uint32_t)inlen;

	// C3 = Hash(x2 || m || y2)
	sm3_init(&sm3_ctx);
	sm3_update(&sm3_ctx, buf, 32);
	sm3_update(&sm3_ctx, in, inlen);
	sm3_update(&sm3_ctx, buf + 32, 32);
	sm3_finish(&sm3_ctx, out->hash);

	return 1;
}

int sm2_do_decrypt(const SM2_KEY *key, const SM2_CIPHERTEXT *in, uint8_t *out, size_t *outlen)
{
	uint32_t inlen;
	bignum_t d;
	point_t _P, *P = &_P;
	SM3_CTX sm3_ctx;
	uint8_t buf[64];
	uint8_t hash[32];
	int i;

	// FIXME: check SM2_CIPHERTEXT format

	// check C1
	point_from_bytes(P, (uint8_t *)&in->point);
	//point_print(stdout, P, 0, 2);

	/*
	if (!point_is_on_curve(P)) {
		fprintf(stderr, "%s %d: invalid ciphertext\n", __FILE__, __LINE__);
		return -1;
	}
	*/

	// d * C1 = (x2, y2)
	bn_from_bytes(d, key->private_key);
	point_mul(P, d, P);
	bn_clean(d);
	point_to_bytes(P, buf);

	// t = KDF(x2 || y2, klen)
	if ((inlen = in->ciphertext_size) <= 0) {
		fprintf(stderr, "%s %d: invalid ciphertext\n", __FILE__, __LINE__);
		return -1;
	}

	sm2_kdf(buf, sizeof(buf), inlen, out);

	// M = C2 xor t
	for (i = 0; i < inlen; i++) {
		out[i] ^= in->ciphertext[i];
	}
	*outlen = inlen;

	// u = Hash(x2 || M || y2)
	sm3_init(&sm3_ctx);
	sm3_update(&sm3_ctx, buf, 32);
	sm3_update(&sm3_ctx, out, inlen);
	sm3_update(&sm3_ctx, buf + 32, 32);
	sm3_finish(&sm3_ctx, hash);

	// check if u == C3
	if (memcmp(in->hash, hash, sizeof(hash)) != 0) {
		fprintf(stderr, "%s %d: invalid ciphertext\n", __FILE__, __LINE__);
		return -1;
	}

	return 1;
}

int sm2_ecdh(const SM2_KEY *key, const SM2_POINT *peer_public, SM2_POINT *out)
{
	bignum_t d;
	point_t _P, *P = &_P;

	bn_from_bytes(d, key->private_key);
	point_from_bytes(P, (uint8_t *)peer_public);
	if (!point_is_on_curve(P)) {
		error_print();
		return -1;
	}
	point_mul(P, d, P);
	point_to_bytes(P, (uint8_t *)out);
	return 1;
}
