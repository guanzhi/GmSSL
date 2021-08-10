/* 
 *   Copyright 2014-2021 The GmSSL Project Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

/* GF(2^128) defined by f(x) = x^128 + x^7 + x^2 + x + 1
 * A + B mod f(x) = a xor b
 * A * 2 mod f(x)
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/hex.h>
#include <gmssl/gf128.h>
#include "endian.h"

gf128_t gf128_zero(void)
{
	uint8_t zero[16] = {0};
	return gf128_from_bytes(zero);
}

gf128_t gf128_from_hex(const char *s)
{
	uint8_t bin[16];
	hex2bin(s, strlen(s), bin);
	return gf128_from_bytes(bin);
}

int gf128_equ_hex(gf128_t a, const char *s)
{
	uint8_t bin1[16];
	uint8_t bin2[16];
	hex2bin(s, strlen(s), bin1);
	gf128_to_bytes(a, bin2);
	return memcmp(bin1, bin2, sizeof(bin1)) == 0;
}

// FIXME: 这个函数不支持struct				
void gf128_print_bits(gf128_t a)
{
	int i;
	for (i = 0; i < 128; i++) {
		printf("%d", (int)(a % 2)); //FIXME
		a >>= 1;
	}
	printf("\n");
}

void gf128_print(const char *s, gf128_t a)
{
	uint8_t be[16];
	int i;

	printf("%s", s);
	gf128_to_bytes(a, be);
	for (i = 0; i < 16; i++) {
		printf("%02X", be[i]);
	}
	printf("\n");
}

#ifdef GMSSL_HAVE_UINT128
gf128_t gf128_mul(gf128_t a, gf128_t b)
{
	const gf128_t mask = (gf128_t)1 << 127;

	gf128_t r = 0;
	int i;

	for (i = 0; i < 128; i++) {
		// r = r * 2
		if (r & mask)
			r = (r << 1) ^ 0x87;
		else	r <<= 1;

		// if b[127-i] == 1, r = r + a
		if (b & mask)
			r ^= a;
		b <<= 1;
	}
	return r;
}

gf128_t gf128_add(gf128_t a, gf128_t b)
{
	return a ^ b;
}

gf128_t gf128_mul2(gf128_t a)
{
	if (a & ((gf128_t)1 << 127))
		return (a << 1) ^ 0x87;
	else	return (a << 1);
}

gf128_t gf128_reverse(gf128_t a)
{
	gf128_t r = 0;
	int i;

	for (i = 0; i < 128; i++) {
		r = (r << 1) | (a & 1);
		a >>= 1;
	}
	return r;
}

gf128_t gf128_from_bytes(const uint8_t p[16])
{
	uint64_t hi = GETU64(p);
	uint64_t lo = GETU64(p + 8);
	gf128_t r = (gf128_t)hi << 64 | lo;
	r = gf128_reverse(r);
	return r;
}

void gf128_to_bytes(gf128_t a, uint8_t p[16])
{
	a = gf128_reverse(a);
	uint64_t hi = a >> 64;
	uint64_t lo = a;
	PUTU64(p, hi);
	PUTU64(p + 8, lo);
}


#else
gf128_t gf128_from_bytes(const uint8_t p[16])
{
	gf128_t r;
	r.hi = GETU64(p);
	r.lo = GETU64(p + 8);
	return r;
}

void gf128_to_bytes(gf128_t a, uint8_t p[16])
{
	PUTU64(p, a.hi);
	PUTU64(p + 8, a.lo);
}

gf128_t gf128_add(gf128_t a, gf128_t b)
{
	gf128_t r;
	r.hi = a.hi ^ b.hi;
	r.lo = a.lo ^ b.lo;
	return r;
}

gf128_t gf128_mul(gf128_t a, gf128_t b)
{
	gf128_t r = {0, 0};
	uint64_t mask = (uint64_t)1 << 63;
	int i;

	for (i = 0; i < 64; i++) {
		if (r.hi & mask) {
			r.hi = r.hi << 1 | r.lo >> 63;
			r.lo = (r.lo << 1);
			r.lo ^= 0x87;
		} else {
			r.hi = r.hi << 1 | r.lo >> 63;
			r.lo = r.lo << 1;
		}

		if (b.hi & mask) {
			r.hi ^= a.hi;
			r.lo ^= a.lo;
		}

		b.hi <<= 1;
	}
	for (i = 0; i < 64; i++) {
		if (r.hi & mask) {
			r.hi = r.hi << 1 | r.lo >> 63;
			r.lo = (r.lo << 1) ^ 0x87;
		} else {
			r.hi = r.hi << 1 | r.lo >> 63;
			r.lo = r.lo << 1;
		}

		if (b.lo & mask) {
			r.hi ^= a.hi;
			r.lo ^= a.lo;
		}

		b.lo <<= 1;
	}

	return r;
}

gf128_t gf128_mul2(gf128_t a)
{
	gf128_t r;

	if (a.hi & ((uint64_t)1 << 63)) {
		r.hi = a.hi << 1 | a.lo >> 63;
		r.lo = a.lo << 1;
		r.lo ^= 0x87;
	} else {
		r.hi = a.hi << 1 | a.lo >> 63;
		r.lo = a.lo << 1;
	}

	return r;
}
#endif
