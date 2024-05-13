/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <gmssl/sm4.h>
#include <gmssl/endian.h>
#include <arm_neon.h>


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

const uint8_t S[256] = {
	0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7,
	0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
	0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3,
	0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
	0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a,
	0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
	0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95,
	0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
	0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
	0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
	0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b,
	0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
	0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2,
	0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
	0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
	0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
	0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5,
	0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
	0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55,
	0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
	0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
	0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
	0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f,
	0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
	0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f,
	0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
	0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
	0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
	0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e,
	0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
	0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20,
	0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
};


#define L32(X)					\
	((X) ^					\
	ROL32((X),  2) ^			\
	ROL32((X), 10) ^			\
	ROL32((X), 18) ^			\
	ROL32((X), 24))

#define L32_(X)					\
	((X) ^ 					\
	ROL32((X), 13) ^			\
	ROL32((X), 23))

#define S32(A)					\
	((S[((A) >> 24)       ] << 24) |	\
	 (S[((A) >> 16) & 0xff] << 16) |	\
	 (S[((A) >>  8) & 0xff] <<  8) |	\
	 (S[((A))       & 0xff]))


void sm4_set_encrypt_key(SM4_KEY *key, const uint8_t user_key[16])
{
	uint32_t X0, X1, X2, X3, X4;
	int i;

	X0 = GETU32(user_key     ) ^ FK[0];
	X1 = GETU32(user_key  + 4) ^ FK[1];
	X2 = GETU32(user_key  + 8) ^ FK[2];
	X3 = GETU32(user_key + 12) ^ FK[3];

	for (i = 0; i < 32; i++) {

		X4 = X1 ^ X2 ^ X3 ^ CK[i];
		X4 = S32(X4);
		X4 = X0 ^ L32_(X4);

		key->rk[i] = X4;

		X0 = X1;
		X1 = X2;
		X2 = X3;
		X3 = X4;
	}
}

void sm4_set_decrypt_key(SM4_KEY *key, const uint8_t user_key[16])
{
	uint32_t X0, X1, X2, X3, X4;
	int i;

	X0 = GETU32(user_key     ) ^ FK[0];
	X1 = GETU32(user_key  + 4) ^ FK[1];
	X2 = GETU32(user_key  + 8) ^ FK[2];
	X3 = GETU32(user_key + 12) ^ FK[3];

	for (i = 0; i < 32; i++) {

		X4 = X1 ^ X2 ^ X3 ^ CK[i];
		X4 = S32(X4);
		X4 = X0 ^ L32_(X4);

		key->rk[31 - i] = X4;

		X0 = X1;
		X1 = X2;
		X2 = X3;
		X3 = X4;
	}
}

// const time sbox with neon tbl/tbx
void sm4_encrypt(const SM4_KEY *key, const unsigned char in[16], unsigned char out[16])
{
	uint8x16x4_t S0 = vld1q_u8_x4(S);
	uint8x16x4_t S1 = vld1q_u8_x4(S + 64);
	uint8x16x4_t S2 = vld1q_u8_x4(S + 128);
	uint8x16x4_t S3 = vld1q_u8_x4(S + 192);
	uint8x16_t vx;
	uint8x16_t vt;
	uint32_t X0, X1, X2, X3, X4;
	int i;

	X0 = GETU32(in     );
	X1 = GETU32(in +  4);
	X2 = GETU32(in +  8);
	X3 = GETU32(in + 12);

	for (i = 0; i < 32; i++) {

		X4 = X1 ^ X2 ^ X3 ^ key->rk[i];

		// const time X4 = S32(X4)
		vx = vdupq_n_u32(X4);
		vt = vqtbl4q_u8(S0, vx);
		vt = vqtbx4q_u8(vt, S1, veorq_u8(vx, vdupq_n_u8(0x40)));
		vt = vqtbx4q_u8(vt, S2, veorq_u8(vx, vdupq_n_u8(0x80)));
		vx = vqtbx4q_u8(vt, S3, veorq_u8(vx, vdupq_n_u8(0xc0)));
		X4 = vgetq_lane_u32(vx, 0);

		X4 = X0 ^ L32(X4);
		X0 = X1;
		X1 = X2;
		X2 = X3;
		X3 = X4;
	}

	PUTU32(out     , X3);
	PUTU32(out +  4, X2);
	PUTU32(out +  8, X1);
	PUTU32(out + 12, X0);
}

void sm4_encrypt_blocks(const SM4_KEY *key, const uint8_t *in, size_t nblocks, uint8_t *out)
{
	while (nblocks--) {
		sm4_encrypt(key, in, out);
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

#define vrolq_n_u32(words, nbits) \
	vorrq_u32(vshlq_n_u32((words), (nbits)), vshrq_n_u32((words), 32 - (nbits)))

void sm4_ctr32_encrypt_4blocks(const SM4_KEY *key, uint8_t iv[16], const uint8_t *in, size_t n4blks, uint8_t *out)
{
	uint8x16x4_t S0 = vld1q_u8_x4(S);
	uint8x16x4_t S1 = vld1q_u8_x4(S + 64);
	uint8x16x4_t S2 = vld1q_u8_x4(S + 128);
	uint8x16x4_t S3 = vld1q_u8_x4(S + 192);

	const uint32_t incr[4] = { 0, 1, 2, 3 };
	uint32_t __attribute__((aligned(16))) buf[16];
	uint8_t *cipher = (uint8_t *)buf;
	uint32_t n;
	uint32x4_t ctr;
	uint32x4_t ctr0, ctr1, ctr2, ctr3;
	uint32x4_t vi = vld1q_u32(incr);
	uint32x4_t fours = vdupq_n_u32(4);
	uint32x4_t x0, x1, x2, x3, x4;
	uint32x4_t rk, xt;
	uint32x4x2_t x02, x13, x01, x23;
	int i;

	// compute low ctr32
	n = GETU32(iv + 12);
	n += (uint32_t)(4 * n4blks);

	memcpy(buf, iv, 16);
	ctr = vld1q_u32(buf);
	ctr = vrev32q_u8(ctr);

	ctr0 = vdupq_n_u32(vgetq_lane_u32(ctr, 0));
	ctr1 = vdupq_n_u32(vgetq_lane_u32(ctr, 1));
	ctr2 = vdupq_n_u32(vgetq_lane_u32(ctr, 2));
	ctr3 = vdupq_n_u32(vgetq_lane_u32(ctr, 3));

	ctr3 = vaddq_u32(ctr3, vi);

	while (n4blks--) {

		x0 = ctr0;
		x1 = ctr1;
		x2 = ctr2;
		x3 = ctr3;

		for (i = 0; i < 32; i++) {

			// X4 = X1 ^ X2 ^ X3 ^ RK[i]
			rk = vdupq_n_u32(key->rk[i]);
			x4 = veorq_u32(veorq_u32(x1, x2), veorq_u32(x3, rk));

			// X4 = SBOX(X4)
			xt = vqtbl4q_u8(S0, x4);
			xt = vqtbx4q_u8(xt, S1, veorq_u8(x4, vdupq_n_u8(0x40)));
			xt = vqtbx4q_u8(xt, S2, veorq_u8(x4, vdupq_n_u8(0x80)));
			x4 = vqtbx4q_u8(xt, S3, veorq_u8(x4, vdupq_n_u8(0xc0)));

			// X4 = L(X4)
			xt = veorq_u32(x4, vrolq_n_u32(x4,  2));
			xt = veorq_u32(xt, vrolq_n_u32(x4, 10));
			xt = veorq_u32(xt, vrolq_n_u32(x4, 18));
			x4 = veorq_u32(xt, vrolq_n_u32(x4, 24));

			// X0, X1, X2, X3 = X1, X2, X3, X0^X4
			x4 = veorq_u32(x0, x4);
			x0 = x1;
			x1 = x2;
			x2 = x3;
			x3 = x4;
		}

		// output x3,x2,x1,x0
		x02 = vzipq_u32(x3, x1);
		x13 = vzipq_u32(x2, x0);
		x01 = vzipq_u32(x02.val[0], x13.val[0]);
		x23 = vzipq_u32(x02.val[1], x13.val[1]);

		x0 = vrev32q_u8(x01.val[0]);
		vst1q_u32(buf, x0);

		x1 = vrev32q_u8(x01.val[1]);
		vst1q_u32(buf + 4, x1);

		x2 = vrev32q_u8(x23.val[0]);
		vst1q_u32(buf + 8, x2);

		x3 = vrev32q_u8(x23.val[1]);
		vst1q_u32(buf + 12, x3);

		// xor with plaintext
		for (i = 0; i < 16*4; i++) {
			out[i] = in[i] ^ cipher[i];
		}

		// update ctr
		ctr3 = vaddq_u32(ctr3, fours);

		in += 64;
		out += 64;
	}

	// update iv
	PUTU32(iv + 12, n);
}

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

	if (nblocks >= 4) {
		sm4_ctr32_encrypt_4blocks(key, ctr, in, nblocks/4, out);
		in += 64 * (nblocks/4);
		out += 64 * (nblocks/4);
		nblocks %= 4;
	}

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
