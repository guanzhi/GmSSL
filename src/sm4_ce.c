/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <arm_neon.h>
#include <gmssl/sm4.h>


static const uint32_t FK[4] = {
	0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc,
};

static const uint32_t CK[32] = {
	0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
	0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
	0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
	0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
	0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
	0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
	0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
	0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
};

void sm4_set_encrypt_key(SM4_KEY *sm4_key, const uint8_t key[16])
{
	uint32x4_t rk;
	uint32x4_t fk;

	rk = vrev32q_u8(vld1q_u8(key));
	rk = veorq_u32(rk, vld1q_u32(FK));

	rk = vsm4ekeyq_u32(rk, vld1q_u32(CK));
	vst1q_u32(sm4_key->rk, rk);
	rk = vsm4ekeyq_u32(rk, vld1q_u32(CK + 4));
	vst1q_u32(sm4_key->rk + 4, rk);
	rk = vsm4ekeyq_u32(rk, vld1q_u32(CK + 8));
	vst1q_u32(sm4_key->rk + 8, rk);
	rk = vsm4ekeyq_u32(rk, vld1q_u32(CK + 12));
	vst1q_u32(sm4_key->rk + 12, rk);
	rk = vsm4ekeyq_u32(rk, vld1q_u32(CK + 16));
	vst1q_u32(sm4_key->rk + 16, rk);
	rk = vsm4ekeyq_u32(rk, vld1q_u32(CK + 20));
	vst1q_u32(sm4_key->rk + 20, rk);
	rk = vsm4ekeyq_u32(rk, vld1q_u32(CK + 24));
	vst1q_u32(sm4_key->rk + 24, rk);
	rk = vsm4ekeyq_u32(rk, vld1q_u32(CK + 28));
	vst1q_u32(sm4_key->rk + 28, rk);
}

void sm4_encrypt(const SM4_KEY *key, const unsigned char in[16], unsigned char out[16])
{
	uint32x4_t x4, rk;

	x4 = vld1q_u8(in);
	x4 = vrev32q_u8(x4);

	rk = vld1q_u32(key->rk);
	x4 = vsm4eq_u32(x4, rk);
	rk = vld1q_u32(key->rk + 4);
	x4 = vsm4eq_u32(x4, rk);
	rk = vld1q_u32(key->rk + 8);
	x4 = vsm4eq_u32(x4, rk);
	rk = vld1q_u32(key->rk + 12);
	x4 = vsm4eq_u32(x4, rk);
	rk = vld1q_u32(key->rk + 16);
	x4 = vsm4eq_u32(x4, rk);
	rk = vld1q_u32(key->rk + 20);
	x4 = vsm4eq_u32(x4, rk);
	rk = vld1q_u32(key->rk + 24);
	x4 = vsm4eq_u32(x4, rk);
	rk = vld1q_u32(key->rk + 28);
	x4 = vsm4eq_u32(x4, rk);

	x4 = vrev64q_u32(x4);
	x4 = vextq_u32(x4, x4, 2);
	x4 = vrev32q_u8(x4);

	vst1q_u8(out, x4);
}
