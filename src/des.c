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
#include <gmssl/des.h>
#include <gmssl/endian.h>


/* permuted choice 1 for key schedule, 64 bits to 56 bits */
static unsigned char PC1[56] = {
	57, 49, 41, 33, 25, 17,  9,
	 1, 58, 50, 42, 34, 26, 18,
	10,  2, 59, 51, 43, 35, 27,
	19, 11,  3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,
	 7, 62, 54, 46, 38, 30, 22,
	14,  6, 61, 53, 45, 37, 29,
	21, 13,  5, 28, 20, 12,  4,
};

/* permuted choice 2 for key schedule, 48 bits to 48 bits */
static unsigned char PC2[48] = {
	14, 17, 11, 24,  1,  5,
	 3, 28, 15,  6, 21, 10,
	23, 19, 12,  4, 26,  8,
	16,  7, 27, 20, 13,  2,
	41, 52, 31, 37, 47, 55,
	30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53,
	46, 42, 50, 36, 29, 32,
};

/* rotations for every round of key schedule */
static unsigned char S[16] = {
	1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1,
};

/* initial permutation, 64 bits to 64 bits */
static unsigned char IP[64] = {
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6,
	64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17,  9, 1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7,
};

/* inverse initial permutation, 64 bits to 64 bits */
static unsigned char IP_inv[64] = {
	40, 8, 48, 16, 56, 24, 64, 32,
	39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30,
	37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28,
	35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26,
	33, 1, 41,  9, 49, 17, 57, 25,
};

/* expansion permutation, 32 bits to 48 bits */
static unsigned char E[48] = {
	32,  1,  2,  3,  4,  5,
	4,   5,  6,  7,  8,  9,
	8,   9, 10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32,  1,
};

/* eight s-box, 6 bits to 4 bits */
static unsigned char S1[64] = {
	14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
	 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
	 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
	15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13,
};

static unsigned char S2[64] = {
	15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
	 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
	 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
	13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9,
};

static unsigned char S3[64] = {
	10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
	13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
	13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
	 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12,
};

static unsigned char S4[64] = {
	 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
	13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
	10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
	 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14,
};

static unsigned char S5[64] = {
	 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
	14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
	 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
	11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3,
};

static unsigned char S6[64] = {
	12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
	10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
	 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
	 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13,
};

static unsigned char S7[64] = {
	 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
	13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
	 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
	 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12,
};

static unsigned char S8[64] = {
	13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
	 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
	 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
	 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11,
};

/* permutation, 32 bits to 32 bits */
static unsigned char P[32] = {
	16, 7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5, 18, 31, 10,
	 2, 8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6, 22, 11,  4, 25,
};


static uint64_t permute(const unsigned char *table, size_t n, uint64_t A)
{
	uint64_t R = 0;
	for (size_t i = 0; i < n; i++) {
		R |= (A >> (n - table[i])) & 0x01;
	}
	return R;
}

static uint32_t substitution(const uint64_t A)
{
	return	(((uint32_t)S1[(A >> 42) & 0x3f]) << 28) |
		(((uint32_t)S2[(A >> 36) & 0x3f]) << 24) |
		(((uint32_t)S3[(A >> 30) & 0x3f]) << 20) |
		(((uint32_t)S4[(A >> 24) & 0x3f]) << 16) |
		(((uint32_t)S5[(A >> 18) & 0x3f]) << 12) |
		(((uint32_t)S6[(A >> 12) & 0x3f]) <<  8) |
		(((uint32_t)S7[(A >>  6) & 0x3f]) <<  4) |
		(((uint32_t)S8[(A      ) & 0x3f])      );
}

//#define ROL32(A,Si)	(((A)<<(Si))|((A)>>(32-(Si))))

void des_set_encrypt_key(DES_KEY *key, const unsigned char user_key[8])
{
	uint64_t K;
	uint32_t L, R;
	int i;

	K = GETU64(user_key);
	K = permute(PC1, sizeof(PC1), K);
	L = (K >> 28) & 0xffffffff;
	R = K & 0x0fffffff;

	for (i = 0; i < 16; i++) {
		L = ROL32(L, S[i]);
		R = ROL32(R, S[i]);
		K = ((uint64_t)L << 28) | R;
		key->rk[i] = permute(PC2, sizeof(PC2), K);
	}
}

void des_set_decrypt_key(DES_KEY *key, const unsigned char user_key[8])
{
	// TODO
}

void des_encrypt(DES_KEY *key, const unsigned char in[DES_BLOCK_SIZE],
	unsigned char out[DES_BLOCK_SIZE])
{
	uint64_t T;
	uint32_t L, R;
	int i;

	T = GETU64(in);

	/* initial permutation */
	T = permute(IP, sizeof(IP), T);

	L = T >> 32;
	R = T & 0xffffffff;

	for (i = 0; i < 16; i++) {

		/* compute F_{Ki}(R) */
		T = permute(E, sizeof(E), R);
		T ^= key->rk[i];
		T = substitution(T);
		T = permute(P, sizeof(P), T);

		T ^= L;

		L = R;
		R = T & 0xffffffff;
	}

	T = ((uint64_t)L << 32) | R;

	/* inverse initial permutation */
	T = permute(IP_inv, sizeof(IP_inv), T);

	PUTU64(out, T);
}
