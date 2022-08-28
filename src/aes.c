/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
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
	return	S[(A >> 24) & 0xff] << 24 |
		S[(A >> 16) & 0xff] << 16 |
		S[(A >>  8) & 0xff] <<  8 |
		S[A & 0xff];
}

/* (a0,a1,a2,a3) => (a1,a2,a3,a0) */
static uint32_t rot_word(uint32_t A)
{
	return ROL32(A, 8);
}

#ifdef CRYPTO_INFO
static void print_rk(const AES_KEY *aes_key)
{
	size_t i;
	for (i = 0; i <= aes_key->rounds; i++) {
		printf("%08x ", aes_key->rk[4 * i]);
		printf("%08x ", aes_key->rk[4 * i + 1]);
		printf("%08x ", aes_key->rk[4 * i + 2]);
		printf("%08x\n", aes_key->rk[4 * i + 3]);
	}
	printf("\n");
}
#endif

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
		return 0;
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

#ifdef CRYPTO_INFO
	print_rk(aes_key);
#endif

	return 1;
}

int aes_set_decrypt_key(AES_KEY *aes_key, const uint8_t *key, size_t keylen)
{
	int ret = 0;
	AES_KEY enc_key;
	size_t i;

	if (!aes_set_encrypt_key(&enc_key, key, keylen)) {
		goto end;
	}

	for (i = 0; i <= enc_key.rounds; i++) {
		aes_key->rk[4*i    ] = enc_key.rk[4*(enc_key.rounds - i)];
		aes_key->rk[4*i + 1] = enc_key.rk[4*(enc_key.rounds - i) + 1];
		aes_key->rk[4*i + 2] = enc_key.rk[4*(enc_key.rounds - i) + 2];
		aes_key->rk[4*i + 3] = enc_key.rk[4*(enc_key.rounds - i) + 3];
	}
	aes_key->rounds = enc_key.rounds;
	ret = 1;

#ifdef CRYPTO_INFO
	print_rk(aes_key);
#endif

end:
	memset(&enc_key, 0, sizeof(AES_KEY));
	return ret;
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
	uint8_t tmp[4][4];

	tmp[0][0] = state[0][0];
	tmp[0][1] = state[0][1];
	tmp[0][2] = state[0][2];
	tmp[0][3] = state[0][3];

	tmp[1][0] = state[1][1];
	tmp[1][1] = state[1][2];
	tmp[1][2] = state[1][3];
	tmp[1][3] = state[1][0];

	tmp[2][0] = state[2][2];
	tmp[2][1] = state[2][3];
	tmp[2][2] = state[2][0];
	tmp[2][3] = state[2][1];

	tmp[3][0] = state[3][3];
	tmp[3][1] = state[3][0];
	tmp[3][2] = state[3][1];
	tmp[3][3] = state[3][2];

	memcpy(state, tmp, sizeof(tmp));
	memset(tmp, 0, sizeof(tmp));
}


/*
 * |S00 S01 S02 S03| >>>0     |S00 S01 S02 S03|
 * |S10 S11 S12 S13| >>>1 =>  |S13 S10 S11 S12|
 * |S20 S21 S22 S23| >>>2     |S22 S23 S20 S21|
 * |S30 S31 S32 S33| >>>3     |S31 S32 S33 S30|
 */
static void inv_shift_rows(uint8_t state[4][4])
{
	uint8_t tmp[4][4];

	tmp[0][0] = state[0][0];
	tmp[0][1] = state[0][1];
	tmp[0][2] = state[0][2];
	tmp[0][3] = state[0][3];

	tmp[1][0] = state[1][3];
	tmp[1][1] = state[1][0];
	tmp[1][2] = state[1][1];
	tmp[1][3] = state[1][2];

	tmp[2][0] = state[2][2];
	tmp[2][1] = state[2][3];
	tmp[2][2] = state[2][0];
	tmp[2][3] = state[2][1];

	tmp[3][0] = state[3][1];
	tmp[3][1] = state[3][2];
	tmp[3][2] = state[3][3];
	tmp[3][3] = state[3][0];

	memcpy(state, tmp, sizeof(tmp));
	memset(tmp, 0, sizeof(tmp));
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
	uint8_t tmp[4][4];
	int i;

	/* i-th column */
	for (i = 0; i < 4; i++) {
		tmp[0][i] = x2(S[0][i]) ^ x3(S[1][i]) ^ x1(S[2][i]) ^ x1(S[3][i]);
		tmp[1][i] = x1(S[0][i]) ^ x2(S[1][i]) ^ x3(S[2][i]) ^ x1(S[3][i]);
		tmp[2][i] = x1(S[0][i]) ^ x1(S[1][i]) ^ x2(S[2][i]) ^ x3(S[3][i]);
		tmp[3][i] = x3(S[0][i]) ^ x1(S[1][i]) ^ x1(S[2][i]) ^ x2(S[3][i]);
	}

	memcpy(S, tmp, sizeof(tmp));
	memset(tmp, 0, sizeof(tmp));
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
	uint8_t tmp[4][4];
	int i;

	/* i-th column */
	for (i = 0; i < 4; i++) {
		tmp[0][i] = xe(S[0][i]) ^ xb(S[1][i]) ^ xd(S[2][i]) ^ x9(S[3][i]);
		tmp[1][i] = x9(S[0][i]) ^ xe(S[1][i]) ^ xb(S[2][i]) ^ xd(S[3][i]);
		tmp[2][i] = xd(S[0][i]) ^ x9(S[1][i]) ^ xe(S[2][i]) ^ xb(S[3][i]);
		tmp[3][i] = xb(S[0][i]) ^ xd(S[1][i]) ^ x9(S[2][i]) ^ xe(S[3][i]);
	}

	memcpy(S, tmp, sizeof(tmp));
	memset(tmp, 0, sizeof(tmp));
}

#ifdef CRYPTO_INFO
static void print_state(const uint8_t S[4][4])
{
	int i;
	for (i = 0; i < 4; i++) {
		printf("%02x %02x %02x %02x\n", S[i][0], S[i][1], S[i][2], S[i][3]);
	}
	printf("\n");
}
#endif

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

	memset(state, 0, sizeof(state));
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

	memset(state, 0, sizeof(state));
}
