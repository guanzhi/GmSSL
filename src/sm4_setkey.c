/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <gmssl/sm4.h>
#include <gmssl/endian.h>
#include "sm4_lcl.h"

static uint32_t FK[4] = {
	0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc,
};

static uint32_t CK[32] = {
	0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
	0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
	0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
	0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
	0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
	0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
	0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
	0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
};

#define L32_(x)					\
	((x) ^ 					\
	ROL32((x), 13) ^			\
	ROL32((x), 23))

#define ENC_ROUND(x0, x1, x2, x3, x4, i)	\
	x4 = x1 ^ x2 ^ x3 ^ *(CK + i);		\
	x4 = S32(x4);				\
	x4 = x0 ^ L32_(x4);			\
	*(rk + i) = x4

#define DEC_ROUND(x0, x1, x2, x3, x4, i)	\
	x4 = x1 ^ x2 ^ x3 ^ *(CK + i);		\
	x4 = S32(x4);				\
	x4 = x0 ^ L32_(x4);			\
	*(rk + 31 - i) = x4

void sm4_set_encrypt_key(SM4_KEY *key, const uint8_t user_key[16])
{
	uint32_t *rk = key->rk;
	uint32_t x0, x1, x2, x3, x4;

	x0 = GETU32(user_key     ) ^ FK[0];
	x1 = GETU32(user_key  + 4) ^ FK[1];
	x2 = GETU32(user_key  + 8) ^ FK[2];
	x3 = GETU32(user_key + 12) ^ FK[3];

#define ROUND ENC_ROUND
	ROUNDS(x0, x1, x2, x3, x4);
#undef ROUND

	x0 = x1 = x2 = x3 = x4 = 0;
}

void sm4_set_decrypt_key(SM4_KEY *key, const uint8_t user_key[16])
{
	uint32_t *rk = key->rk;
	uint32_t x0, x1, x2, x3, x4;

	x0 = GETU32(user_key     ) ^ FK[0];
	x1 = GETU32(user_key  + 4) ^ FK[1];
	x2 = GETU32(user_key  + 8) ^ FK[2];
	x3 = GETU32(user_key + 12) ^ FK[3];

#define ROUND DEC_ROUND
	ROUNDS(x0, x1, x2, x3, x4);
#undef ROUND

	x0 = x1 = x2 = x3 = x4 = 0;
}
