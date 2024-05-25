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
#include <gmssl/mem.h>


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

	rk = (uint32x4_t)vrev32q_u8(vld1q_u8(key));
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

void sm4_set_decrypt_key(SM4_KEY *sm4_key, const uint8_t key[16])
{
	SM4_KEY enc_key;
	int i;

	sm4_set_encrypt_key(&enc_key, key);
	for (i = 0; i < 32; i++) {
		sm4_key->rk[i] = enc_key.rk[31 - i];
	}
	gmssl_secure_clear(&enc_key, sizeof(SM4_KEY));
}

void sm4_encrypt(const SM4_KEY *key, const unsigned char in[16], unsigned char out[16])
{
	uint32x4_t x4, rk;

	x4 = (uint32x4_t)vrev32q_u8(vld1q_u8(in));

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

	vst1q_u8(out, vrev32q_u8((uint8x16_t)x4));
}

void sm4_encrypt_blocks(const SM4_KEY *key, const uint8_t *in, size_t nblocks, uint8_t *out)
{
	uint32x4_t x4, rk;

	while (nblocks--) {

		x4 = (uint32x4_t)vrev32q_u8(vld1q_u8(in));

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

		vst1q_u8(out, vrev32q_u8((uint8x16_t)x4));

		in += 16;
		out += 16;
	}
}

void sm4_cbc_encrypt_blocks(const SM4_KEY *key, uint8_t iv[16],
	const uint8_t *in, size_t nblocks, uint8_t *out)
{
	const uint8_t *piv = iv;

	while (nblocks--) {
		size_t i;
		for (i = 0; i < 16; i++) {
			out[i] = in[i] ^ piv[i];
		}
		sm4_encrypt(key, out, out);
		piv = out;
		in += 16;
		out += 16;
	}

	memcpy(iv, piv, 16);
}

void sm4_cbc_decrypt_blocks(const SM4_KEY *key, uint8_t iv[16],
	const uint8_t *in, size_t nblocks, uint8_t *out)
{
	const uint8_t *piv = iv;

	while (nblocks--) {
		size_t i;
		sm4_encrypt(key, in, out);
		for (i = 0; i < 16; i++) {
			out[i] ^= piv[i];
		}
		piv = in;
		in += 16;
		out += 16;
	}

	memcpy(iv, piv, 16);
}

static void ctr_incr(uint8_t a[16]) {
	int i;
	for (i = 15; i >= 0; i--) {
		a[i]++;
		if (a[i]) break;
	}
}

void sm4_ctr_encrypt_blocks(const SM4_KEY *key, uint8_t ctr[16], const uint8_t *in, size_t nblocks, uint8_t *out)
{
	uint8_t block[16];
	int i;

	while (nblocks--) {
		sm4_encrypt(key, ctr, block);
		ctr_incr(ctr);
		for (i = 0; i < 16; i++) {
			out[i] = in[i] ^ block[i];
		}
		in += 16;
		out += 16;
	}
}

// inc32() in nist-sp800-38d
static void ctr32_incr(uint8_t a[16]) {
	int i;
	for (i = 15; i >= 12; i--) {
		a[i]++;
		if (a[i]) break;
	}
}

void sm4_ctr32_encrypt_blocks(const SM4_KEY *key, uint8_t ctr[16], const uint8_t *in, size_t nblocks, uint8_t *out)
{
	uint8_t block[16];
	int i;

	while (nblocks--) {
		sm4_encrypt(key, ctr, block);
		ctr32_incr(ctr);
		for (i = 0; i < 16; i++) {
			out[i] = in[i] ^ block[i];
		}
		in += 16;
		out += 16;
	}
}
