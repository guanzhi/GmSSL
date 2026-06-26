/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#include <gmssl/sm4.h>
#include <string.h>
#include <gmssl/endian.h>
#include <gmssl/error.h>


static const uint32_t sm4_ff1_radix10_mod[] = {
	1,
	10,
	100,
	1000,
	10000,
	100000,
	1000000,
	10000000,
	100000000,
	1000000000,
};

static const size_t sm4_ff1_radix10_b[] = {
	0, 1, 1, 2, 2, 3, 3, 3, 4, 4,
};

int sm4_ff1_init(SM4_KEY *key, const uint8_t raw_key[SM4_KEY_SIZE])
{
	if (!key || !raw_key) {
		error_print();
		return -1;
	}
	sm4_set_encrypt_key(key, raw_key);
	return 1;
}

static int sm4_ff1_digits_to_num(const char *digits, size_t ndigits, uint32_t *num)
{
	uint32_t value = 0;
	size_t i;

	if (!digits || !num || ndigits > SM4_FF1_MAX_DIGITS/2) {
		error_print();
		return -1;
	}
	for (i = 0; i < ndigits; i++) {
		if (digits[i] < '0' || digits[i] > '9') {
			error_print();
			return -1;
		}
		value = value * 10 + (uint32_t)(digits[i] - '0');
	}
	*num = value;
	return 1;
}

static int sm4_ff1_num_to_digits(uint32_t num, size_t ndigits, char *digits)
{
	if (!digits || ndigits > SM4_FF1_MAX_DIGITS/2 || num >= sm4_ff1_radix10_mod[ndigits]) {
		error_print();
		return -1;
	}
	while (ndigits) {
		digits[--ndigits] = (char)('0' + num % 10);
		num /= 10;
	}
	return 1;
}

static int sm4_ff1_check_args(const SM4_KEY *key, const char *in, size_t inlen,
	const uint8_t *tweak, size_t tweaklen, char *out)
{
	size_t i;

	if (!key || !in || !out || (!tweak && tweaklen)) {
		error_print();
		return -1;
	}
	if (inlen < SM4_FF1_MIN_DIGITS || inlen > SM4_FF1_MAX_DIGITS) {
		error_print();
		return -1;
	}
	if (tweaklen < SM4_FF1_MIN_TWEAK_SIZE || tweaklen > SM4_FF1_MAX_TWEAK_SIZE) {
		error_print();
		return -1;
	}
	for (i = 0; i < inlen; i++) {
		if (in[i] < '0' || in[i] > '9') {
			error_print();
			return -1;
		}
	}
	return 1;
}

static int sm4_ff1_init_pblock(const SM4_KEY *key, uint8_t pblock[16],
	size_t u, size_t n, size_t tweaklen)
{
	static const uint8_t sm4_ff1_radix10_pblock[16] = {
		0x01, 0x02, 0x01, 0x00, 0x00, 0x0a, 0x0a, 0xff,
		0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff,
	};

	memcpy(pblock, sm4_ff1_radix10_pblock, 16);
	pblock[7] = (uint8_t)u;
	PUTU32(pblock + 8, (uint32_t)n);
	PUTU32(pblock + 12, (uint32_t)tweaklen);

	sm4_encrypt(key, pblock, pblock);
	return 1;
}

static int sm4_ff1_round(const SM4_KEY *key, const uint8_t pblock[16],
	const uint8_t *tweak, size_t tweaklen, size_t bsize, int round, uint32_t num, uint64_t *y)
{
	uint8_t qblock[32] = {0};
	uint8_t block[16];
	size_t padlen;
	size_t offset;
	size_t qlen;
	size_t i;

	if (!key || !pblock || (!tweak && tweaklen) || !bsize || bsize > sizeof(uint32_t)
		|| !y || round < 0 || round > 0xff) {
		error_print();
		return -1;
	}

	/* Keep a full zero padding block when tweak || round || NUM(B) is block-aligned. */
	padlen = 16 - (tweaklen + 1 + bsize) % 16;
	qlen = tweaklen + padlen + 1 + bsize;
	if (!qlen || qlen > sizeof(qblock) || qlen % 16) {
		error_print();
		return -1;
	}
	if (tweaklen) {
		memcpy(qblock, tweak, tweaklen);
	}
	offset = tweaklen + padlen;
	qblock[offset++] = (uint8_t)round;
	for (i = 0; i < bsize; i++) {
		qblock[offset + bsize - 1 - i] = (uint8_t)(num >> (8 * i));
	}

	for (i = 0; i < sizeof(block); i++) {
		block[i] = pblock[i] ^ qblock[i];
	}
	sm4_encrypt(key, block, block);
	for (offset = 16; offset < qlen; offset += 16) {
		for (i = 0; i < sizeof(block); i++) {
			block[i] ^= qblock[offset + i];
		}
		sm4_encrypt(key, block, block);
	}

	*y = GETU64(block);
	return 1;
}

int sm4_ff1_encrypt(const SM4_KEY *key, const char *in, size_t inlen,
	const uint8_t *tweak, size_t tweaklen, char *out)
{
	size_t u;
	size_t v;
	uint32_t a;
	uint32_t b;
	size_t alen;
	size_t blen;
	uint64_t y;
	uint32_t ymod;
	uint32_t c;
	uint8_t pblock[16];
	size_t bsize;
	int i;

	if (sm4_ff1_check_args(key, in, inlen, tweak, tweaklen, out) != 1) {
		error_print();
		return -1;
	}

	u = inlen / 2;
	v = inlen - u;

	if (sm4_ff1_digits_to_num(in, u, &a) != 1
		|| sm4_ff1_digits_to_num(in + u, v, &b) != 1
		|| sm4_ff1_init_pblock(key, pblock, u, inlen, tweaklen) != 1) {
		error_print();
		return -1;
	}
	alen = u;
	blen = v;
	bsize = sm4_ff1_radix10_b[v];

	for (i = 0; i < SM4_FF1_NUM_ROUNDS; i++) {
		size_t m = (i & 1) ? v : u;

		if (sm4_ff1_round(key, pblock, tweak, tweaklen, bsize, i, b, &y) != 1) {
			error_print();
			return -1;
		}
		ymod = (uint32_t)(y % sm4_ff1_radix10_mod[m]);
		c = (a + ymod) % sm4_ff1_radix10_mod[m];
		a = b;
		alen = blen;
		b = c;
		blen = m;
	}

	if (alen != u || blen != v) {
		error_print();
		return -1;
	}
	if (sm4_ff1_num_to_digits(a, alen, out) != 1
		|| sm4_ff1_num_to_digits(b, blen, out + alen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm4_ff1_decrypt(const SM4_KEY *key, const char *in, size_t inlen,
	const uint8_t *tweak, size_t tweaklen, char *out)
{
	size_t u;
	size_t v;
	uint32_t a;
	uint32_t b;
	size_t alen;
	size_t blen;
	uint64_t y;
	uint32_t ymod;
	uint32_t c;
	uint8_t pblock[16];
	size_t bsize;
	int i;

	if (sm4_ff1_check_args(key, in, inlen, tweak, tweaklen, out) != 1) {
		error_print();
		return -1;
	}

	u = inlen / 2;
	v = inlen - u;

	if (sm4_ff1_digits_to_num(in, u, &a) != 1
		|| sm4_ff1_digits_to_num(in + u, v, &b) != 1
		|| sm4_ff1_init_pblock(key, pblock, u, inlen, tweaklen) != 1) {
		error_print();
		return -1;
	}
	alen = u;
	blen = v;
	bsize = sm4_ff1_radix10_b[v];

	for (i = SM4_FF1_NUM_ROUNDS - 1; i >= 0; i--) {
		size_t m = (i & 1) ? v : u;

		c = b;
		b = a;
		blen = alen;

		if (sm4_ff1_round(key, pblock, tweak, tweaklen, bsize, i, b, &y) != 1) {
			error_print();
			return -1;
		}
		ymod = (uint32_t)(y % sm4_ff1_radix10_mod[m]);
		a = c;
		a = (a >= ymod) ? a - ymod : a + sm4_ff1_radix10_mod[m] - ymod;
		alen = m;
	}

	if (alen != u || blen != v) {
		error_print();
		return -1;
	}
	if (sm4_ff1_num_to_digits(a, alen, out) != 1
		|| sm4_ff1_num_to_digits(b, blen, out + alen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}
