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


#define L32(x)							\
	((x) ^							\
	ROL32((x),  2) ^					\
	ROL32((x), 10) ^					\
	ROL32((x), 18) ^					\
	ROL32((x), 24))

#define ROUND_SBOX(x0, x1, x2, x3, x4, i)			\
	x4 = x1 ^ x2 ^ x3 ^ *(rk + i);				\
	x4 = S32(x4);						\
	x4 = x0 ^ L32(x4)

#define ROUND_TBOX(x0, x1, x2, x3, x4, i)			\
	x4 = x1 ^ x2 ^ x3 ^ *(rk + i);				\
	t0 = ROL32(SM4_T[(uint8_t)x4], 8);			\
	x4 >>= 8;						\
	x0 ^= t0;						\
	t0 = ROL32(SM4_T[(uint8_t)x4], 16);			\
	x4 >>= 8;						\
	x0 ^= t0;						\
	t0 = ROL32(SM4_T[(uint8_t)x4], 24);			\
	x4 >>= 8;						\
	x0 ^= t0;						\
	t1 = SM4_T[x4];					\
	x4 = x0 ^ t1

#define ROUND ROUND_TBOX


void sm4_encrypt(const SM4_KEY *key, const unsigned char in[16], unsigned char out[16])
{
	const uint32_t *rk = key->rk;
	uint32_t x0, x1, x2, x3, x4;
	uint32_t t0, t1;

	x0 = GETU32(in     );
	x1 = GETU32(in +  4);
	x2 = GETU32(in +  8);
	x3 = GETU32(in + 12);
	ROUNDS(x0, x1, x2, x3, x4);
	PUTU32(out     , x0);
	PUTU32(out +  4, x4);
	PUTU32(out +  8, x3);
	PUTU32(out + 12, x2);
}

/* caller make sure counter not overflow */
void sm4_ctr32_encrypt_blocks(const unsigned char *in, unsigned char *out,
	size_t blocks, const SM4_KEY *key, const unsigned char iv[16])
{
	const uint32_t *rk = key->rk;
	unsigned int c0 = GETU32(iv     );
	unsigned int c1 = GETU32(iv +  4);
	unsigned int c2 = GETU32(iv +  8);
	unsigned int c3 = GETU32(iv + 12);
	uint32_t x0, x1, x2, x3, x4;
	uint32_t t0, t1;

	while (blocks--) {
		x0 = c0;
		x1 = c1;
		x2 = c2;
		x3 = c3;
		ROUNDS(x0, x1, x2, x3, x4);
		PUTU32(out     , GETU32(in     ) ^ x0);
		PUTU32(out +  4, GETU32(in +  4) ^ x4);
		PUTU32(out +  8, GETU32(in +  8) ^ x3);
		PUTU32(out + 12, GETU32(in + 12) ^ x2);
		in += 16;
		out += 16;
		c3++;
	}
}
