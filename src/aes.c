/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/aes.h>
#include <gmssl/endian.h>
#include <gmssl/mem.h>
#include <gmssl/ghash.h>
#include <gmssl/error.h>


static const uint8_t S[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

static const uint8_t S_inv[256] = {
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
};

static const uint8_t Rcon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
};

static uint32_t sub_word(uint32_t A)
{
	return	((uint32_t)S[(A >> 24) & 0xff] << 24) |
		((uint32_t)S[(A >> 16) & 0xff] << 16) |
		((uint32_t)S[(A >>  8) & 0xff] <<  8) |
		S[A & 0xff];
}

/* (a0,a1,a2,a3) => (a1,a2,a3,a0) */
static uint32_t rot_word(uint32_t A)
{
	return ROL32(A, 8);
}

int aes_set_encrypt_key(AES_KEY *aes_key, const uint8_t *key, size_t keylen)
{
	/* Nk: num user key words
	 * AES-128	Nk = 4		W[44]
	 * AES-192	Nk = 6		W[52]
	 * AES-256	Nk = 8		W[60]
	 */
	uint32_t *W = (uint32_t *)aes_key->rk;
	size_t Nk = keylen/sizeof(uint32_t);
	size_t i;

	switch (keylen) {
	case AES128_KEY_SIZE:
		aes_key->rounds = 10;
		break;
	case AES192_KEY_SIZE:
		aes_key->rounds = 12;
		break;
	case AES256_KEY_SIZE:
		aes_key->rounds = 14;
		break;
	default:
		return -1;
	}

	for (i = 0; i < Nk; i++) {
		W[i] = GETU32(key + sizeof(uint32_t) * i);
	}
	for (; i < 4 * (aes_key->rounds + 1); i++) {
		uint32_t T = W[i - 1];
		if (i % Nk == 0) {
			T = rot_word(T);
			T = sub_word(T);
			T ^= ((uint32_t)Rcon[i/Nk] << 24);

		} else if (Nk == 8 && i % 8 == 4) {
			T = sub_word(T);
		}
		W[i] = W[i - Nk] ^ T;
	}

	return 1;
}

int aes_set_decrypt_key(AES_KEY *aes_key, const uint8_t *key, size_t keylen)
{
	AES_KEY enc_key;
	size_t i;

	if (aes_set_encrypt_key(&enc_key, key, keylen) != 1) {
		gmssl_secure_clear(&enc_key, sizeof(enc_key));
		return -1;
	}

	for (i = 0; i <= enc_key.rounds; i++) {
		aes_key->rk[4*i    ] = enc_key.rk[4*(enc_key.rounds - i)];
		aes_key->rk[4*i + 1] = enc_key.rk[4*(enc_key.rounds - i) + 1];
		aes_key->rk[4*i + 2] = enc_key.rk[4*(enc_key.rounds - i) + 2];
		aes_key->rk[4*i + 3] = enc_key.rk[4*(enc_key.rounds - i) + 3];
	}
	aes_key->rounds = enc_key.rounds;
	gmssl_secure_clear(&enc_key, sizeof(enc_key));
	return 1;
}

/*
 * |S00 S01 S02 S03|     |           |
 * |S10 S11 S12 S13| xor |W0 W1 W2 W3|
 * |S20 S21 S22 S23|     |           |
 * |S30 S31 S32 S33|     |           |
 */
static void add_round_key(uint8_t state[4][4], const uint32_t *W)
{
	int i;
	for (i = 0; i < 4; i++) {
		state[0][i] ^= (W[i] >> 24) & 0xff;
		state[1][i] ^= (W[i] >> 16) & 0xff;
		state[2][i] ^= (W[i] >>  8) & 0xff;
		state[3][i] ^= (W[i]      ) & 0xff;
	}
}

static void sub_bytes(uint8_t state[4][4])
{
	int i, j;
	for (i = 0; i < 4; i++) {
		for (j = 0; j < 4; j++) {
			state[i][j] = S[state[i][j]];
		}
	}
}

static void inv_sub_bytes(uint8_t state[4][4])
{
	int i, j;
	for (i = 0; i < 4; i++) {
		for (j = 0; j < 4; j++) {
			state[i][j] = S_inv[state[i][j]];
		}
	}
}

/*
 * |S00 S01 S02 S03| <<<0     |S00 S01 S02 S03|
 * |S10 S11 S12 S13| <<<1 =>  |S11 S12 S13 S10|
 * |S20 S21 S22 S23| <<<2     |S22 S23 S20 S21|
 * |S30 S31 S32 S33| <<<3     |S33 S30 S31 S32|
 */
static void shift_rows(uint8_t state[4][4])
{
	uint8_t tmp;

	tmp = state[1][0];
	state[1][0] = state[1][1];
	state[1][1] = state[1][2];
	state[1][2] = state[1][3];
	state[1][3] = tmp;

	tmp = state[2][0];
	state[2][0] = state[2][2];
	state[2][2] = tmp;
	tmp = state[2][1];
	state[2][1] = state[2][3];
	state[2][3] = tmp;

	tmp = state[3][3];
	state[3][3] = state[3][2];
	state[3][2] = state[3][1];
	state[3][1] = state[3][0];
	state[3][0] = tmp;
}


/*
 * |S00 S01 S02 S03| >>>0     |S00 S01 S02 S03|
 * |S10 S11 S12 S13| >>>1 =>  |S13 S10 S11 S12|
 * |S20 S21 S22 S23| >>>2     |S22 S23 S20 S21|
 * |S30 S31 S32 S33| >>>3     |S31 S32 S33 S30|
 */
static void inv_shift_rows(uint8_t state[4][4])
{
	uint8_t tmp;

	tmp = state[1][3];
	state[1][3] = state[1][2];
	state[1][2] = state[1][1];
	state[1][1] = state[1][0];
	state[1][0] = tmp;

	tmp = state[2][0];
	state[2][0] = state[2][2];
	state[2][2] = tmp;
	tmp = state[2][1];
	state[2][1] = state[2][3];
	state[2][3] = tmp;

	tmp = state[3][0];
	state[3][0] = state[3][1];
	state[3][1] = state[3][2];
	state[3][2] = state[3][3];
	state[3][3] = tmp;
}

/*
 * GF(2^8) defSed by f(x) = x^8 + x^4 + x^3 + x + 1
 * x^8 == x^4 + x^3 + x + 1 = 0001,1011 = 0x1b
 * if A[7] == 0 then 2 * A = (A << 1)
 *              else 2 * A = (A << 1) xor A
 */
#define x1(a) (a)

static uint8_t x2(uint8_t a) {
	return (a >> 7) ? ((a << 1) ^ 0x1b) : (a << 1);
}

static uint8_t x3(uint8_t a) {
	return x2(a) ^ x1(a);
}

static uint8_t x9(uint8_t a) {
	return x2(x2(x2(a))) ^ x1(a);
}

/* 0x0b = 11 = 8 + 2 + 1 */
static uint8_t xb(uint8_t a) {
	return x2(x2(x2(a))) ^ x2(a) ^ x1(a);
}

/* 0x0d = 13 = 8 + 4 + 1 */
static uint8_t xd(uint8_t a) {
	return x2(x2(x2(a))) ^ x2(x2(a)) ^ x1(a);
}

/* 0x0e = 14 = 8 + 4 + 2 */
static uint8_t xe(uint8_t a) {
	return x2(x2(x2(a))) ^ x2(x2(a)) ^ x2(a);
}

/*
 * |2  3  1  1| |S00 S01 S02 S03|
 * |1  2  3  1| |S10 S11 S12 S13|
 * |1  1  2  3|*|S20 S21 S22 S23|
 * |3  1  1  2| |S30 S31 S32 S33|
 */
static void mix_columns(uint8_t S[4][4])
{
	uint8_t tmp0, tmp1, tmp2, tmp3;
	int i;

	/* i-th column */
	for (i = 0; i < 4; i++) {
		tmp0 = x2(S[0][i]) ^ x3(S[1][i]) ^ x1(S[2][i]) ^ x1(S[3][i]);
		tmp1 = x1(S[0][i]) ^ x2(S[1][i]) ^ x3(S[2][i]) ^ x1(S[3][i]);
		tmp2 = x1(S[0][i]) ^ x1(S[1][i]) ^ x2(S[2][i]) ^ x3(S[3][i]);
		tmp3 = x3(S[0][i]) ^ x1(S[1][i]) ^ x1(S[2][i]) ^ x2(S[3][i]);
		S[0][i] = tmp0;
		S[1][i] = tmp1;
		S[2][i] = tmp2;
		S[3][i] = tmp3;
	}

}

/*
 * |0E 0B 0D 09| |02 03 01 01|   |1  0  0  0|
 * |09 0E 0B 0D|*|01 02 03 01| = |0  1  0  0|
 * |0D 09 0E 0B| |01 01 02 03|   |0  0  1  0|
 * |0B 0D 09 0E| |03 01 01 02|   |0  0  0  1|
 *
 */
static void inv_mix_columns(uint8_t S[4][4])
{
	uint8_t tmp0, tmp1, tmp2, tmp3;
	int i;

	/* i-th column */
	for (i = 0; i < 4; i++) {
		tmp0 = xe(S[0][i]) ^ xb(S[1][i]) ^ xd(S[2][i]) ^ x9(S[3][i]);
		tmp1 = x9(S[0][i]) ^ xe(S[1][i]) ^ xb(S[2][i]) ^ xd(S[3][i]);
		tmp2 = xd(S[0][i]) ^ x9(S[1][i]) ^ xe(S[2][i]) ^ xb(S[3][i]);
		tmp3 = xb(S[0][i]) ^ xd(S[1][i]) ^ x9(S[2][i]) ^ xe(S[3][i]);
		S[0][i] = tmp0;
		S[1][i] = tmp1;
		S[2][i] = tmp2;
		S[3][i] = tmp3;
	}
}

void aes_encrypt(const AES_KEY *key, const uint8_t in[16], uint8_t out[16])
{
	uint8_t state[4][4];
	size_t i;

	/* fill state columns */
	for (i = 0; i < 4; i++) {
		state[0][i] = *in++;
		state[1][i] = *in++;
		state[2][i] = *in++;
		state[3][i] = *in++;
	}

	/* Sitial add round key */
	add_round_key(state, key->rk);

	/* first n-1 rounds */
	for (i = 1; i < key->rounds; i++) {
		sub_bytes(state);
		shift_rows(state);
		mix_columns(state);
		add_round_key(state, key->rk + 4*i);
	}

	/* last round withtmp mix columns */
	sub_bytes(state);
	shift_rows(state);
	add_round_key(state, key->rk + 4*i);

	/* tmpput state columns */
	for (i = 0; i < 4; i++) {
		*out++ = state[0][i];
		*out++ = state[1][i];
		*out++ = state[2][i];
		*out++ = state[3][i];
	}

	gmssl_secure_clear(state, sizeof(state));
}

void aes_decrypt(const AES_KEY *aes_key, const uint8_t in[16], uint8_t out[16])
{
	uint8_t state[4][4];
	size_t i;

	/* fill state columns */
	for (i = 0; i < 4; i++) {
		state[0][i] = *in++;
		state[1][i] = *in++;
		state[2][i] = *in++;
		state[3][i] = *in++;
	}

	/* Sitial add round key */
	add_round_key(state, aes_key->rk);

	/* first n-1 rounds */
	for (i = 1; i < aes_key->rounds; i++) {
		inv_shift_rows(state);
		inv_sub_bytes(state);
		add_round_key(state, aes_key->rk + 4*i);
		inv_mix_columns(state);
	}

	/* last round withtmp mix columns */
	inv_shift_rows(state);
	inv_sub_bytes(state);
	add_round_key(state, aes_key->rk + 4*i);

	/* tmpput state columns */
	for (i = 0; i < 4; i++) {
		*out++ = state[0][i];
		*out++ = state[1][i];
		*out++ = state[2][i];
		*out++ = state[3][i];
	}

	gmssl_secure_clear(state, sizeof(state));
}

void aes_cbc_encrypt_blocks(const AES_KEY *key, const uint8_t iv[16],
	const uint8_t *in, size_t nblocks, uint8_t *out)
{
	while (nblocks--) {
		gmssl_memxor(out, in, iv, 16);
		aes_encrypt(key, out, out);
		iv = out;
		in += 16;
		out += 16;
	}
}

void aes_cbc_decrypt_blocks(const AES_KEY *key, const uint8_t iv[16],
	const uint8_t *in, size_t nblocks, uint8_t *out)
{
	while (nblocks--) {
		aes_decrypt(key, in, out);
		memxor(out, iv, 16);
		iv = in;
		in += 16;
		out += 16;
	}
}

int aes_cbc_padding_encrypt(const AES_KEY *key, const uint8_t iv[16],
	const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen)
{
	uint8_t block[16];
	size_t rem = inlen % 16;
	int padding = 16 - inlen % 16;

	if (in) {
		memcpy(block, in + inlen - rem, rem);
	}
	memset(block + rem, padding, padding);
	if (inlen/16) {
		aes_cbc_encrypt_blocks(key, iv, in, inlen/16, out);
		out += inlen - rem;
		iv = out - 16;
	}
	aes_cbc_encrypt_blocks(key, iv, block, 1, out);
	*outlen = inlen - rem + 16;
	return 1;
}

int aes_cbc_padding_decrypt(const AES_KEY *key, const uint8_t iv[16],
	const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen)
{
	uint8_t block[16];
	size_t len = sizeof(block);
	int padding;
	int i;

	if (inlen == 0) {
		error_print();
		return 0;
	}
	if (inlen%16 != 0 || inlen < 16) {
		error_print();
		return -1;
	}
	if (inlen > 16) {
		aes_cbc_decrypt_blocks(key, iv, in, inlen/16 - 1, out);
		iv = in + inlen - 32;
	}
	aes_cbc_decrypt_blocks(key, iv, in + inlen - 16, 1, block);
	padding = block[15];
	if (padding < 1 || padding > 16) {
		error_print();
		return -1;
	}
	for (i = 16 - padding; i < 16; i++) {
		if (block[i] != padding) {
			error_print();
			return -1;
		}
	}

	len -= padding;
	memcpy(out + inlen - 16, block, len);
	*outlen = inlen - padding;
	return 1;
}

static void ctr128_incr(uint8_t a[16])
{
	int i;
	for (i = 15; i >= 0; i--) {
		a[i]++;
		if (a[i]) break;
	}
}

void aes_ctr_encrypt(const AES_KEY *key, uint8_t ctr[16], const uint8_t *in, size_t inlen, uint8_t *out)
{
	uint8_t block[16];
	size_t len;

	while (inlen) {
		len = inlen < 16 ? inlen : 16;
		aes_encrypt(key, ctr, block);
		gmssl_memxor(out, in, block, len);
		ctr128_incr(ctr);
		in += len;
		out += len;
		inlen -= len;
	}
}

static void ctr32_incr(uint8_t a[16])
{
	int i;
	for (i = 15; i >= 12; i--) {
		a[i]++;
		if (a[i]) break;
	}
}

static void aes_ctr32_encrypt(const AES_KEY *key, uint8_t ctr[16], const uint8_t *in, size_t inlen, uint8_t *out)
{
	uint8_t block[16];
	size_t len;

	while (inlen) {
		len = inlen < 16 ? inlen : 16;
		aes_encrypt(key, ctr, block);
		gmssl_memxor(out, in, block, len);
		ctr32_incr(ctr);
		in += len;
		out += len;
		inlen -= len;
	}
	gmssl_secure_clear(block, sizeof(block));
}

int aes_gcm_encrypt(const AES_KEY *key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	uint8_t *out, size_t taglen, uint8_t *tag)
{
	const uint8_t *pin = in;
	uint8_t *pout = out;
	size_t left = inlen;
	uint8_t H[16] = {0};
	uint8_t Y[16];
	uint8_t T[16];

	if (taglen > AES_GCM_MAX_TAG_SIZE) {
		error_print();
		return -1;
	}

	aes_encrypt(key, H, H);

	if (ivlen == 12) {
		memcpy(Y, iv, 12);
		Y[12] = Y[13] = Y[14] = 0;
		Y[15] = 1;
	} else {
		ghash(H, NULL, 0, iv, ivlen, Y);
	}

	aes_encrypt(key, Y, T);

	ctr32_incr(Y);
	aes_ctr32_encrypt(key, Y, in, inlen, out);

	ghash(H, aad, aadlen, out, inlen, H);
	gmssl_memxor(tag, T, H, taglen);

	gmssl_secure_clear(H, sizeof(H));
	gmssl_secure_clear(Y, sizeof(Y));
	gmssl_secure_clear(T, sizeof(T));
	return 1;
}

int aes_gcm_decrypt(const AES_KEY *key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	const uint8_t *tag, size_t taglen, uint8_t *out)
{
	const uint8_t *pin = in;
	uint8_t *pout = out;
	size_t left = inlen;
	uint8_t H[16] = {0};
	uint8_t Y[16];
	uint8_t T[16];

	if (taglen > AES_GCM_MAX_TAG_SIZE) {
		error_print();
		return -1;
	}

	aes_encrypt(key, H, H);

	if (ivlen == 12) {
		memcpy(Y, iv, 12);
		Y[12] = Y[13] = Y[14] = 0;
		Y[15] = 1;
	} else {
		ghash(H, NULL, 0, iv, ivlen, Y);
	}

	ghash(H, aad, aadlen, in, inlen, H);
	aes_encrypt(key, Y, T);
	gmssl_memxor(T, T, H, taglen);
	if (gmssl_secure_memcmp(T, tag, taglen) != 0) {
		gmssl_secure_clear(H, sizeof(H));
		gmssl_secure_clear(Y, sizeof(Y));
		gmssl_secure_clear(T, sizeof(T));
		error_print();
		return -1;
	}

	ctr32_incr(Y);
	aes_ctr32_encrypt(key, Y, in, inlen, out);

	gmssl_secure_clear(H, sizeof(H));
	gmssl_secure_clear(Y, sizeof(Y));
	gmssl_secure_clear(T, sizeof(T));
	return 1;
}

#ifdef ENABLE_AES_CCM
static void length_to_bytes(size_t len, size_t nbytes, uint8_t *out)
{
	uint8_t *p = out + nbytes - 1;
	while (nbytes--) {
		*p-- = len & 0xff;
		len >>= 8;
	}
}

static void ctr_n_incr(uint8_t a[16], size_t n)
{
	size_t i;
	for (i = 15; i >= 16 - n; i--) {
		a[i]++;
		if (a[i]) break;
	}
}

static void aes_ctr_n_encrypt(const AES_KEY *key, uint8_t ctr[16], size_t n, const uint8_t *in, size_t inlen, uint8_t *out)
{
	uint8_t block[16];
	size_t len;

	while (inlen) {
		len = inlen < 16 ? inlen : 16;
		aes_encrypt(key, ctr, block);
		gmssl_memxor(out, in, block, len);
		ctr_n_incr(ctr, n);
		in += len;
		out += len;
		inlen -= len;
	}
}

typedef struct {
	AES_KEY key;
	uint8_t iv[16];
	size_t ivlen;
} AES_CBC_MAC_CTX;

static int aes_cbc_mac_update(AES_CBC_MAC_CTX *ctx, const uint8_t *data, size_t datalen)
{
	if (!ctx || (!data && datalen)) {
		error_print();
		return -1;
	}
	if (ctx->ivlen >= 16) {
		error_print();
		return -1;
	}
	if (!data || !datalen) {
		return 1;
	}
	while (datalen) {
		size_t ivleft = 16 - ctx->ivlen;
		size_t len = datalen < ivleft ? datalen : ivleft;
		gmssl_memxor(ctx->iv + ctx->ivlen, ctx->iv + ctx->ivlen, data, len);
		ctx->ivlen += len;
		if (ctx->ivlen >= 16) {
			aes_encrypt(&ctx->key, ctx->iv, ctx->iv);
			ctx->ivlen = 0;
		}
		data += len;
		datalen -= len;
	}
	return 1;
}

static int aes_cbc_mac_finish(AES_CBC_MAC_CTX *ctx, uint8_t mac[16])
{
	if (!ctx || !mac) {
		error_print();
		return -1;
	}
	if (ctx->ivlen >= 16) {
		error_print();
		return -1;
	}
	if (ctx->ivlen) {
		aes_encrypt(&ctx->key, ctx->iv, ctx->iv);
		ctx->ivlen = 0;
	}
	memcpy(mac, ctx->iv, 16);
	return 1;
}

int aes_ccm_encrypt(const AES_KEY *key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	uint8_t *out, size_t taglen, uint8_t *tag)
{
	AES_CBC_MAC_CTX mac_ctx;
	const uint8_t zeros[16] = {0};
	uint8_t block[16] = {0};
	uint8_t ctr[16] = {0};
	uint8_t mac[16];
	size_t inlen_size;

	if (!key || !iv || (!aad && aadlen) || (!in && inlen) || !out || !tag) {
		error_print();
		return -1;
	}
	if (ivlen < 7 || ivlen > 13) {
		error_print();
		return -1;
	}
	if (taglen < 4 || taglen > 16 || taglen & 1) {
		error_print();
		return -1;
	}

	inlen_size = 15 - ivlen;
	// WARNING: (size_t)1 << n or (int)1 << n overflows on some systems when n == 32.
	if (inlen_size < 8 && (uint64_t)inlen >= ((uint64_t)1 << (inlen_size * 8))) {
		error_print();
		return -1;
	}

	memset(&mac_ctx, 0, sizeof(mac_ctx));
	mac_ctx.key = *key;

	block[0] |= ((aadlen > 0) & 0x1) << 6;
	block[0] |= (((taglen - 2)/2) & 0x7) << 3;
	block[0] |= (inlen_size - 1) & 0x7;
	memcpy(block + 1, iv, ivlen);
	length_to_bytes(inlen, inlen_size, block + 1 + ivlen);
	aes_cbc_mac_update(&mac_ctx, block, 16);

	if (aad && aadlen) {
		size_t alen;

		if (aadlen < ((1<<16) - (1<<8))) {
			length_to_bytes(aadlen, 2, block);
			alen = 2;
		} else if ((uint64_t)aadlen < ((uint64_t)1<<32)) {
			block[0] = 0xff;
			block[1] = 0xfe;
			length_to_bytes(aadlen, 4, block + 2);
			alen = 6;
		} else {
			block[0] = 0xff;
			block[1] = 0xff;
			length_to_bytes(aadlen, 8, block + 2);
			alen = 10;
		}
		aes_cbc_mac_update(&mac_ctx, block, alen);
		aes_cbc_mac_update(&mac_ctx, aad, aadlen);
		if ((alen + aadlen) % 16) {
			aes_cbc_mac_update(&mac_ctx, zeros, 16 - (alen + aadlen)%16);
		}
	}

	ctr[0] = 0;
	ctr[0] |= (inlen_size - 1) & 0x7;
	memcpy(ctr + 1, iv, ivlen);
	memset(ctr + 1 + ivlen, 0, 15 - ivlen);
	aes_encrypt(key, ctr, block);

	ctr[15] = 1;
	aes_ctr_n_encrypt(key, ctr, 15 - ivlen, in, inlen, out);

	aes_cbc_mac_update(&mac_ctx, in, inlen);
	if (inlen % 16) {
		aes_cbc_mac_update(&mac_ctx, zeros, 16 - inlen % 16);
	}
	aes_cbc_mac_finish(&mac_ctx, mac);
	gmssl_memxor(tag, mac, block, taglen);

	gmssl_secure_clear(&mac_ctx, sizeof(mac_ctx));
	return 1;
}

int aes_ccm_decrypt(const AES_KEY *key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	const uint8_t *tag, size_t taglen, uint8_t *out)
{
	AES_CBC_MAC_CTX mac_ctx;
	const uint8_t zeros[16] = {0};
	uint8_t block[16] = {0};
	uint8_t ctr[16] = {0};
	uint8_t mac[16];
	size_t inlen_size;

	if (!key || !iv || (!aad && aadlen) || (!in && inlen) || !tag || !out) {
		error_print();
		return -1;
	}
	if (ivlen < 7 || ivlen > 13) {
		error_print();
		return -1;
	}
	if (taglen < 4 || taglen > 16 || taglen & 1) {
		error_print();
		return -1;
	}

	inlen_size = 15 - ivlen;
	// WARNING: (size_t)1 << n or (int)1 << n overflows on some systems when n == 32.
	if (inlen_size < 8 && (uint64_t)inlen >= ((uint64_t)1 << (inlen_size * 8))) {
		error_print();
		return -1;
	}

	memset(&mac_ctx, 0, sizeof(mac_ctx));
	mac_ctx.key = *key;

	block[0] |= ((aadlen > 0) & 0x1) << 6;
	block[0] |= (((taglen - 2)/2) & 0x7) << 3;
	block[0] |= (inlen_size - 1) & 0x7;
	memcpy(block + 1, iv, ivlen);
	length_to_bytes(inlen, inlen_size, block + 1 + ivlen);
	aes_cbc_mac_update(&mac_ctx, block, 16);

	if (aad && aadlen) {
		size_t alen;

		if (aadlen < ((1<<16) - (1<<8))) {
			length_to_bytes(aadlen, 2, block);
			alen = 2;
		} else if ((uint64_t)aadlen < ((uint64_t)1<<32)) {
			block[0] = 0xff;
			block[1] = 0xfe;
			length_to_bytes(aadlen, 4, block + 2);
			alen = 6;
		} else {
			block[0] = 0xff;
			block[1] = 0xff;
			length_to_bytes(aadlen, 8, block + 2);
			alen = 10;
		}
		aes_cbc_mac_update(&mac_ctx, block, alen);
		aes_cbc_mac_update(&mac_ctx, aad, aadlen);
		if ((alen + aadlen) % 16) {
			aes_cbc_mac_update(&mac_ctx, zeros, 16 - (alen + aadlen)%16);
		}
	}

	ctr[0] = 0;
	ctr[0] |= (inlen_size - 1) & 0x7;
	memcpy(ctr + 1, iv, ivlen);
	memset(ctr + 1 + ivlen, 0, 15 - ivlen);
	aes_encrypt(key, ctr, block);

	ctr[15] = 1;
	aes_ctr_n_encrypt(key, ctr, 15 - ivlen, in, inlen, out);

	aes_cbc_mac_update(&mac_ctx, out, inlen);
	if (inlen % 16) {
		aes_cbc_mac_update(&mac_ctx, zeros, 16 - inlen % 16);
	}
	aes_cbc_mac_finish(&mac_ctx, mac);

	gmssl_memxor(mac, mac, block, taglen);
	if (gmssl_secure_memcmp(mac, tag, taglen) != 0) {
		error_print();
		gmssl_secure_clear(&mac_ctx, sizeof(mac_ctx));
		return -1;
	}

	gmssl_secure_clear(&mac_ctx, sizeof(mac_ctx));
	return 1;
}
#endif
