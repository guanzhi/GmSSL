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
#include <gmssl/endian.h>


void bn_set_word(uint32_t *r, uint32_t a, size_t k)
{
	r[0] = a;
	while (k-- > 1) {
		r[k] = 0;
	}
}

void bn_copy(uint32_t *r, const uint32_t *a, size_t k)
{
	while (k-- > 0) {
		r[k] = a[k];
	}
}

int bn_cmp(const uint32_t *a, const uint32_t *b, size_t k)
{
	while (k-- > 0) {
		if (a[k] > b[k]) return 1;
		else if (a[k] < b[k]) return -1;
	}
	return 0;
}

int bn_is_zero(const uint32_t *a, size_t k)
{
	while (k-- > 0) {
		if (a[k]) {
			return 0;
		}
	}
	return 1;
}

int bn_is_one(const uint32_t *a, size_t k)
{
	if (a[0] != 1) {
		return 0;
	}
	while (k-- > 1) {
		if (a[k]) {
			return 0;
		}
	}
	return 1;
}

int bn_add(uint32_t *r, const uint32_t *a, const uint32_t *b, size_t k)
{
	uint64_t w = 0;
	size_t i;
	for (i = 0; i < k; i++) {
		w += (uint64_t)a[i] + (uint64_t)b[i];
		r[i] = w & 0xffffffff;
		w >>= 32;
	}
	return (int)w;
}

int bn_sub(uint32_t *r, const uint32_t *a, const uint32_t *b, size_t k)
{
	int64_t w = 0;
	size_t i;
	for (i = 0; i < k; i++) {
		w += (int64_t)a[i] - (int64_t)b[i];
		r[i] = w & 0xffffffff;
		w >>= 32;
	}
	return (int)w;
}

void bn_mul(uint32_t *r, const uint32_t *a, const uint32_t *b, size_t k)
{
	uint64_t w;
	size_t i, j;
	for (i = 0; i < k; i++) {
		r[i] = 0;
	}
	for (i = 0; i < k; i++) {
		w = 0;
		for (j = 0; j < k; j++) {
			w += (uint64_t)r[i + j] + (uint64_t)a[i] * (uint64_t)b[j];
			r[i + j] = w & 0xffffffff;
			w >>= 32;
		}
		r[i + k] = w;
	}
}

void bn_mul_lo(uint32_t *r, const uint32_t *a, const uint32_t *b, size_t k)
{
	uint64_t w;
	size_t i, j;
	for (i = 0; i < k; i++) {
		r[i] = 0;
	}
	for (i = 0; i < k; i++) {
		w = 0;
		for (j = 0; j < k - i; j++) {
			w += (uint64_t)r[i + j] + (uint64_t)a[i] * (uint64_t)b[j];
			r[i + j] = w & 0xffffffff;
			w >>= 32;
		}
	}
}

void bn_to_bytes(const uint32_t *a, size_t k, uint8_t *out)
{
	while (k-- > 0) {
		PUTU32(out, a[k]);
		out += 4;
	}
}

void bn_from_bytes(uint32_t *a, size_t k, const uint8_t *in)
{
	while (k-- > 0) {
		a[k] = GETU32(in);
		in += 4;
	}
}

int bn_print(FILE *fp, int fmt, int ind, const char *label, const uint32_t *a, size_t k)
{
	fprintf(fp, "%s: ", label);

	int i;
	for (i = 0; i < k; i++) {
		fprintf(fp, "0x%08x, ", a[i]);
	}
	fprintf(fp, "\n");

	while (k-- > 0) {
		fprintf(fp, "%08x", a[k]);
	}
	fprintf(fp, "\n");
	return 1;
}

void bn_mod_add(uint32_t *r, const uint32_t *a, const uint32_t *b, const uint32_t *p, size_t k)
{
	int carry;
	carry = bn_add(r, a, b, k);

	if (carry) {
		bn_sub(r, r, p, k);
	} else if (bn_cmp(r, p, k) >= 0) {
		bn_sub(r, r, p, k);
	}
}

void bn_mod_sub(uint32_t *r, const uint32_t *a, const uint32_t *b, const uint32_t *p, size_t k)
{
	if (bn_cmp(a, b, k) >= 0) {
		bn_sub(r, a, b, k);
	} else {
		bn_sub(r, b, a, k);
		bn_sub(r, p, r, k);
	}
}

void bn_mod_neg(uint32_t *r, const uint32_t *a, const uint32_t *p, size_t k)
{
	bn_sub(r, p, a, k);
}

void bn_barrett_mod_mul(uint32_t *r, // uint32_t r[k] = a * b mod p
	const uint32_t *a, // uint32_t a[k]
	const uint32_t *b, // uint32_t b[k]
	const uint32_t *p, // uint32_t p[k]
	const uint32_t *u, // uint32_t u[k + 1] = floor((2^32)^(2*k) / p)
	uint32_t *tmp, // uint32_t tmp[6*k + 4]
	size_t k)
{
	uint32_t *p_; // uint32_t p_[k + 1];
	uint32_t *z;  // uint32_t z[2 * k];
	uint32_t *q;  // uint32_t q[2 * (k + 1)];
	uint32_t *t_; // uint32_t t_[k + 1];
	size_t i;

	p_ = tmp; tmp += k + 1;
	z  = tmp; tmp += 2 * k;
	q  = tmp; tmp += 2 * (k + 1);
	t_ = tmp; tmp += k + 1;

	for (i = 0; i < k; i++) {
		p_[i] = p[i];
	}
	p_[k] = 0;

	bn_mul(z, a, b, k);
	bn_mul(q, z + k - 1, u,	k + 1);
	bn_mul_lo(t_, q + k + 1, p_, k + 1);
	bn_sub(t_, z, t_, k + 1);

	// reduce at most twice
	if (bn_cmp(t_, p_, k + 1) >= 0) {
		bn_sub(t_, t_, p_, k + 1);
	}
	if (bn_cmp(t_, p_, k) >= 0) {
		bn_sub(t_, t_, p_, k);
	}
	bn_copy(r, t_, k);
}

void bn_barrett_mod_sqr(uint32_t *r, const uint32_t *a, const uint32_t *p,
	const uint32_t *u, // uint32_t u[k + 1]
	uint32_t *tmp, // uint32_t tmp[6*k + 4]
	size_t k)
{
	bn_barrett_mod_mul(r, a, a, p, u, tmp, k);
}

void bn_barrett_mod_exp(uint32_t *r, const uint32_t *a, const uint32_t *e, const uint32_t *p,
	const uint32_t *u, //
	uint32_t *tmp, // uint32_t tmp[7*k + 4]
	size_t k)
{
	uint32_t *t; // uint32_t t[k];
	uint32_t w;
	int i, j;

	// t = 1
	t = tmp; tmp += k;
	bn_set_word(t, 1, k);

	for (i = k - 1; i >= 0; i--) {
		w = e[i];
		for (j = 0; j < 32; j++) {
			bn_barrett_mod_sqr(t, t, p, u, tmp, k);
			if (w & 0x80000000) {
				bn_barrett_mod_mul(t, t, a, p, u, tmp, k);
			}
			w <<= 1;
		}
	}

	bn_copy(r, t, k);
}

// FIXME: 如果 a = 0 (mod p) 会发生什么			
void bn_barrett_mod_inv(uint32_t *r, const uint32_t *a, const uint32_t *p, const uint32_t *u,
	uint32_t *tmp, // uint32_t tmp[8*k + 4]
	size_t k)
{
	uint32_t *e; // uint32_t e[k];

	// e = p - 2
	e = tmp; tmp += k;
	bn_set_word(e, 2, k);
	bn_sub(e, p, e, k);

	// a^-1 = a^(p - 2) (mod p)
	bn_barrett_mod_exp(r, a, e, p, u, tmp, k);
}

// mont(aR, bR) = aR * bR * R^-1 = abR (mod p)
void bn_mont_mod_mul(uint32_t *r, const uint32_t *a, const uint32_t *b, const uint32_t *p,
	const uint32_t *p_inv_neg,
	uint32_t *tmp, // uint32_t tmp[5 * k]
	size_t k)
{
	uint32_t *z; // uint32_t z[k * 2];
	uint32_t *c; // uint32_t c[k * 2];
	uint32_t *t; // uint32_t t[k];

	z = tmp; tmp += 2 * k;
	c = tmp; tmp += 2 * k;
	t = tmp; tmp += k;

	bn_mul(z, a, b, k);
	bn_mul_lo(t, z, p_inv_neg, k);
	bn_mul(c, t, p, k);
	bn_add(c, c, z, k * 2);
	if (bn_cmp(c + k, p, k) >= 0) {
		bn_sub(c + k, c + k, p, k);
	}

	bn_copy(r, c + k, k);
}

void bn_mont_mod_sqr(uint32_t *r, const uint32_t *a, const uint32_t *p,
	const uint32_t *p_inv_neg,
	uint32_t *tmp, // uint32_t tmp[5 * k]
	size_t k)
{
	bn_mont_mod_mul(r, a, a, p, p_inv_neg, tmp, k);
}

void bn_mont_mod_exp(
	uint32_t *r,
	const uint32_t *a,
	const uint32_t *e,
	const uint32_t *p,
	const uint32_t *p_inv_neg,
	uint32_t *tmp, // uint32_t tmp[6 * k];
	size_t k)
{
	uint32_t *t; // uint32_t t[k];
	uint32_t w;
	int i, j;

	// t = 1
	t = tmp; tmp += k;
	bn_set_word(t, 1, k);

	for (i = k - 1; i >= 0; i--) {
		w = e[i];
		for (j = 0; j < 32; j++) {
			bn_mont_mod_sqr(t, t, p, p_inv_neg, tmp, k);
			if (w & 0x80000000) {
				bn_mont_mod_mul(t, t, a, p, p_inv_neg, tmp, k);
			}
			w <<= 1;
		}
	}

	bn_copy(r, t, k);
}

// FIXME: 如果 a = 0 (mod p) 会发生什么			
void bn_mont_mod_inv(uint32_t *r, const uint32_t *a, const uint32_t *p,
	const uint32_t *p_inv_neg,
	uint32_t *tmp, // uint32_t tmp[7 * k];
	size_t k)
{
	uint32_t *e; // uint32_t e[k];

	// e = p - 2
	e = tmp; tmp += k;
	bn_set_word(e, 2, k);
	bn_sub(e, p, e, k);

	// a^-1 = a^(p - 2) (mod p)
	bn_mont_mod_exp(r, a, e, p, p_inv_neg, tmp, k);
}

// mont(a, R^2) = a * R^2 * R^-1 = a * R mod p
void bn_mont_set(uint32_t *r,
	const uint32_t *a,
	const uint32_t *R_sqr,
	const uint32_t *p,
	const uint32_t *p_inv_neg,
	uint32_t *tmp, // uint32_t tmp[5 * k]
	size_t k)
{
	bn_mont_mod_mul(r, a, R_sqr, p, p_inv_neg, tmp, k);
}

// mont(aR, 1) = aR * 1 * R^-1 = a (mod p)
void bn_mont_get(uint32_t *r,
	const uint32_t *a,
	const uint32_t *p,
	const uint32_t *p_inv_neg,
	uint32_t *tmp, // uint32_t tmp[5 * k]
	size_t k)
{
	uint32_t one[k];
	bn_set_word(one, 1, k);
	bn_mont_mod_mul(r, a, one, p, p_inv_neg, tmp, k);
}

