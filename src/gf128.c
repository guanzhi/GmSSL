/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
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
#include <gmssl/endian.h>
#include <gmssl/error.h>


gf128_t gf128_zero(void)
{
	uint8_t zero[16] = {0};
	return gf128_from_bytes(zero);
}

gf128_t gf128_from_hex(const char *s)
{
	uint8_t bin[16];
	size_t len;
	hex_to_bytes(s, strlen(s), bin, &len);
	return gf128_from_bytes(bin);
}

int gf128_equ_hex(gf128_t a, const char *s)
{
	uint8_t bin1[16];
	uint8_t bin2[16];
	size_t len;
	hex_to_bytes(s, strlen(s), bin1, &len);
	gf128_to_bytes(a, bin2);
	return memcmp(bin1, bin2, sizeof(bin1)) == 0;
}

void gf128_print_bits(gf128_t a)
{
	int i;
	for (i = 0; i < 64; i++) {
		printf("%d", (int)(a.hi % 2));
		a.hi >>= 1;
	}
	for (i = 0; i < 64; i++) {
		printf("%d", (int)(a.lo % 2));
		a.lo >>= 1;
	}
	printf("\n");
}

int gf128_print(FILE *fp, int fmt, int ind, const char *label, gf128_t a)
{
	uint8_t be[16];
	int i;

	printf("%s: ", label);
	gf128_to_bytes(a, be);
	for (i = 0; i < 16; i++) {
		printf("%02x", be[i]);
	}
	printf("\n");
	return 1;
}

static uint64_t reverse_bits(uint64_t a)
{
	uint64_t r = 0;
	int i;

	for (i = 0; i < 63; i++) {
		r |= a & 1;
		r <<= 1;
		a >>= 1;
	}
	r |= a & 1;
	return r;
}

gf128_t gf128_from_bytes(const uint8_t p[16])
{
	gf128_t r;

	r.lo = GETU64(p);
	r.hi = GETU64(p + 8);

	r.lo = reverse_bits(r.lo);
	r.hi = reverse_bits(r.hi);
	return r;
}

void gf128_to_bytes(gf128_t a, uint8_t p[16])
{
	a.lo = reverse_bits(a.lo);
	a.hi = reverse_bits(a.hi);
	PUTU64(p, a.lo);
	PUTU64(p + 8, a.hi);
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
