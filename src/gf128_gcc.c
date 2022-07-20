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
