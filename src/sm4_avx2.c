/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdint.h>
#include <gmssl/sm4.h>
#include <gmssl/endian.h>
#include <immintrin.h>


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

void sm4_encrypt(const SM4_KEY *key, const uint8_t in[16], uint8_t out[16])
{
	uint32_t X0, X1, X2, X3, X4;
	int i;

	X0 = GETU32(in     );
	X1 = GETU32(in +  4);
	X2 = GETU32(in +  8);
	X3 = GETU32(in + 12);

	for (i = 0; i < 32; i++) {

		X4 = X1 ^ X2 ^ X3 ^ key->rk[i];
		X4 = S32(X4);
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



#define GET_BLKS(x0, x1, x2, x3, in)					\
	t0 = _mm256_i32gather_epi32((int *)(in+4*0), vindex_4i, 4);	\
	t1 = _mm256_i32gather_epi32((int *)(in+4*1), vindex_4i, 4);	\
	t2 = _mm256_i32gather_epi32((int *)(in+4*2), vindex_4i, 4);	\
	t3 = _mm256_i32gather_epi32((int *)(in+4*3), vindex_4i, 4);	\
	x0 = _mm256_shuffle_epi8(t0, vindex_swap);			\
	x1 = _mm256_shuffle_epi8(t1, vindex_swap);			\
	x2 = _mm256_shuffle_epi8(t2, vindex_swap);			\
	x3 = _mm256_shuffle_epi8(t3, vindex_swap)

#define PUT_BLKS(out, x0, x1, x2, x3)					\
	t0 = _mm256_shuffle_epi8(x0, vindex_swap);			\
	t1 = _mm256_shuffle_epi8(x1, vindex_swap);			\
	t2 = _mm256_shuffle_epi8(x2, vindex_swap);			\
	t3 = _mm256_shuffle_epi8(x3, vindex_swap);			\
	_mm256_storeu_si256((__m256i *)(out+32*0), t0);			\
	_mm256_storeu_si256((__m256i *)(out+32*1), t1);			\
	_mm256_storeu_si256((__m256i *)(out+32*2), t2);			\
	_mm256_storeu_si256((__m256i *)(out+32*3), t3);			\
	x0 = _mm256_i32gather_epi32((int *)(out+8*0), vindex_read, 4);	\
	x1 = _mm256_i32gather_epi32((int *)(out+8*1), vindex_read, 4);	\
	x2 = _mm256_i32gather_epi32((int *)(out+8*2), vindex_read, 4);	\
	x3 = _mm256_i32gather_epi32((int *)(out+8*3), vindex_read, 4);	\
	_mm256_storeu_si256((__m256i *)(out+32*0), x0);			\
	_mm256_storeu_si256((__m256i *)(out+32*1), x1);			\
	_mm256_storeu_si256((__m256i *)(out+32*2), x2);			\
	_mm256_storeu_si256((__m256i *)(out+32*3), x3)


#define _mm256_rotl_epi32(a, i)						\
	_mm256_xor_si256(_mm256_slli_epi32(a, i), _mm256_srli_epi32(a, 32 - i))


#define ROUND(i, x0, x1, x2, x3, x4)					\
	t0 = _mm256_set1_epi32(*(rk + i));				\
	t1 = _mm256_xor_si256(x1, x2);					\
	t2 = _mm256_xor_si256(x3, t0);					\
	x4 = _mm256_xor_si256(t1, t2);					\
	t0 = _mm256_and_si256(x4, vindex_mask);				\
	t0 = _mm256_i32gather_epi32((int *)SM4_T, t0, 4);		\
	t0 = _mm256_rotl_epi32(t0, 8);					\
	x4 = _mm256_srli_epi32(x4, 8);					\
	x0 = _mm256_xor_si256(x0, t0);					\
	t0 = _mm256_and_si256(x4, vindex_mask);				\
	t0 = _mm256_i32gather_epi32((int *)SM4_T, t0, 4);		\
	t0 = _mm256_rotl_epi32(t0, 16);					\
	x4 = _mm256_srli_epi32(x4, 8);					\
	x0 = _mm256_xor_si256(x0, t0);					\
	t0 = _mm256_and_si256(x4, vindex_mask);				\
	t0 = _mm256_i32gather_epi32((int *)SM4_T, t0, 4);		\
	t0 = _mm256_rotl_epi32(t0, 24);					\
	x4 = _mm256_srli_epi32(x4, 8);					\
	x0 = _mm256_xor_si256(x0, t0);					\
	t1 = _mm256_i32gather_epi32((int *)SM4_T, x4, 4);		\
	x4 = _mm256_xor_si256(x0, t1)


// T0[i] = L32(S[i] << 24)
const uint32_t SM4_T[256] = {
	0x8ed55b5b, 0xd0924242, 0x4deaa7a7, 0x06fdfbfb,
	0xfccf3333, 0x65e28787, 0xc93df4f4, 0x6bb5dede,
	0x4e165858, 0x6eb4dada, 0x44145050, 0xcac10b0b,
	0x8828a0a0, 0x17f8efef, 0x9c2cb0b0, 0x11051414,
	0x872bacac, 0xfb669d9d, 0xf2986a6a, 0xae77d9d9,
	0x822aa8a8, 0x46bcfafa, 0x14041010, 0xcfc00f0f,
	0x02a8aaaa, 0x54451111, 0x5f134c4c, 0xbe269898,
	0x6d482525, 0x9e841a1a, 0x1e061818, 0xfd9b6666,
	0xec9e7272, 0x4a430909, 0x10514141, 0x24f7d3d3,
	0xd5934646, 0x53ecbfbf, 0xf89a6262, 0x927be9e9,
	0xff33cccc, 0x04555151, 0x270b2c2c, 0x4f420d0d,
	0x59eeb7b7, 0xf3cc3f3f, 0x1caeb2b2, 0xea638989,
	0x74e79393, 0x7fb1cece, 0x6c1c7070, 0x0daba6a6,
	0xedca2727, 0x28082020, 0x48eba3a3, 0xc1975656,
	0x80820202, 0xa3dc7f7f, 0xc4965252, 0x12f9ebeb,
	0xa174d5d5, 0xb38d3e3e, 0xc33ffcfc, 0x3ea49a9a,
	0x5b461d1d, 0x1b071c1c, 0x3ba59e9e, 0x0cfff3f3,
	0x3ff0cfcf, 0xbf72cdcd, 0x4b175c5c, 0x52b8eaea,
	0x8f810e0e, 0x3d586565, 0xcc3cf0f0, 0x7d196464,
	0x7ee59b9b, 0x91871616, 0x734e3d3d, 0x08aaa2a2,
	0xc869a1a1, 0xc76aadad, 0x85830606, 0x7ab0caca,
	0xb570c5c5, 0xf4659191, 0xb2d96b6b, 0xa7892e2e,
	0x18fbe3e3, 0x47e8afaf, 0x330f3c3c, 0x674a2d2d,
	0xb071c1c1, 0x0e575959, 0xe99f7676, 0xe135d4d4,
	0x661e7878, 0xb4249090, 0x360e3838, 0x265f7979,
	0xef628d8d, 0x38596161, 0x95d24747, 0x2aa08a8a,
	0xb1259494, 0xaa228888, 0x8c7df1f1, 0xd73becec,
	0x05010404, 0xa5218484, 0x9879e1e1, 0x9b851e1e,
	0x84d75353, 0x00000000, 0x5e471919, 0x0b565d5d,
	0xe39d7e7e, 0x9fd04f4f, 0xbb279c9c, 0x1a534949,
	0x7c4d3131, 0xee36d8d8, 0x0a020808, 0x7be49f9f,
	0x20a28282, 0xd4c71313, 0xe8cb2323, 0xe69c7a7a,
	0x42e9abab, 0x43bdfefe, 0xa2882a2a, 0x9ad14b4b,
	0x40410101, 0xdbc41f1f, 0xd838e0e0, 0x61b7d6d6,
	0x2fa18e8e, 0x2bf4dfdf, 0x3af1cbcb, 0xf6cd3b3b,
	0x1dfae7e7, 0xe5608585, 0x41155454, 0x25a38686,
	0x60e38383, 0x16acbaba, 0x295c7575, 0x34a69292,
	0xf7996e6e, 0xe434d0d0, 0x721a6868, 0x01545555,
	0x19afb6b6, 0xdf914e4e, 0xfa32c8c8, 0xf030c0c0,
	0x21f6d7d7, 0xbc8e3232, 0x75b3c6c6, 0x6fe08f8f,
	0x691d7474, 0x2ef5dbdb, 0x6ae18b8b, 0x962eb8b8,
	0x8a800a0a, 0xfe679999, 0xe2c92b2b, 0xe0618181,
	0xc0c30303, 0x8d29a4a4, 0xaf238c8c, 0x07a9aeae,
	0x390d3434, 0x1f524d4d, 0x764f3939, 0xd36ebdbd,
	0x81d65757, 0xb7d86f6f, 0xeb37dcdc, 0x51441515,
	0xa6dd7b7b, 0x09fef7f7, 0xb68c3a3a, 0x932fbcbc,
	0x0f030c0c, 0x03fcffff, 0xc26ba9a9, 0xba73c9c9,
	0xd96cb5b5, 0xdc6db1b1, 0x375a6d6d, 0x15504545,
	0xb98f3636, 0x771b6c6c, 0x13adbebe, 0xda904a4a,
	0x57b9eeee, 0xa9de7777, 0x4cbef2f2, 0x837efdfd,
	0x55114444, 0xbdda6767, 0x2c5d7171, 0x45400505,
	0x631f7c7c, 0x50104040, 0x325b6969, 0xb8db6363,
	0x220a2828, 0xc5c20707, 0xf531c4c4, 0xa88a2222,
	0x31a79696, 0xf9ce3737, 0x977aeded, 0x49bff6f6,
	0x992db4b4, 0xa475d1d1, 0x90d34343, 0x5a124848,
	0x58bae2e2, 0x71e69797, 0x64b6d2d2, 0x70b2c2c2,
	0xad8b2626, 0xcd68a5a5, 0xcb955e5e, 0x624b2929,
	0x3c0c3030, 0xce945a5a, 0xab76dddd, 0x867ff9f9,
	0xf1649595, 0x5dbbe6e6, 0x35f2c7c7, 0x2d092424,
	0xd1c61717, 0xd66fb9b9, 0xdec51b1b, 0x94861212,
	0x78186060, 0x30f3c3c3, 0x897cf5f5, 0x5cefb3b3,
	0xd23ae8e8, 0xacdf7373, 0x794c3535, 0xa0208080,
	0x9d78e5e5, 0x56edbbbb, 0x235e7d7d, 0xc63ef8f8,
	0x8bd45f5f, 0xe7c82f2f, 0xdd39e4e4, 0x68492121,
};


void sm4_encrypt_blocks(const SM4_KEY *key, const uint8_t *in, size_t nblocks, uint8_t *out)
{
	const int *rk = (int *)key->rk;
	__m256i x0, x1, x2, x3, x4;
	__m256i t0, t1, t2, t3;

	__m256i vindex_4i = _mm256_setr_epi32(0,4,8,12,16,20,24,28);
	__m256i vindex_mask = _mm256_set1_epi32(0xff);
	__m256i vindex_read = _mm256_setr_epi32(0,8,16,24,1,9,17,25);
	__m256i vindex_swap = _mm256_setr_epi8(
		3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12,
		3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12
	);

	while (nblocks >= 8) {

		GET_BLKS(x0, x1, x2, x3, in);

		ROUND( 0, x0, x1, x2, x3, x4);
		ROUND( 1, x1, x2, x3, x4, x0);
		ROUND( 2, x2, x3, x4, x0, x1);
		ROUND( 3, x3, x4, x0, x1, x2);
		ROUND( 4, x4, x0, x1, x2, x3);
		ROUND( 5, x0, x1, x2, x3, x4);
		ROUND( 6, x1, x2, x3, x4, x0);
		ROUND( 7, x2, x3, x4, x0, x1);
		ROUND( 8, x3, x4, x0, x1, x2);
		ROUND( 9, x4, x0, x1, x2, x3);
		ROUND(10, x0, x1, x2, x3, x4);
		ROUND(11, x1, x2, x3, x4, x0);
		ROUND(12, x2, x3, x4, x0, x1);
		ROUND(13, x3, x4, x0, x1, x2);
		ROUND(14, x4, x0, x1, x2, x3);
		ROUND(15, x0, x1, x2, x3, x4);
		ROUND(16, x1, x2, x3, x4, x0);
		ROUND(17, x2, x3, x4, x0, x1);
		ROUND(18, x3, x4, x0, x1, x2);
		ROUND(19, x4, x0, x1, x2, x3);
		ROUND(20, x0, x1, x2, x3, x4);
		ROUND(21, x1, x2, x3, x4, x0);
		ROUND(22, x2, x3, x4, x0, x1);
		ROUND(23, x3, x4, x0, x1, x2);
		ROUND(24, x4, x0, x1, x2, x3);
		ROUND(25, x0, x1, x2, x3, x4);
		ROUND(26, x1, x2, x3, x4, x0);
		ROUND(27, x2, x3, x4, x0, x1);
		ROUND(28, x3, x4, x0, x1, x2);
		ROUND(29, x4, x0, x1, x2, x3);
		ROUND(30, x0, x1, x2, x3, x4);
		ROUND(31, x1, x2, x3, x4, x0);

		PUT_BLKS(out, x0, x4, x3, x2);

		in += 128;
		out += 128;
		nblocks -= 8;
	}

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
	const int *rk = (int *)key->rk;
	__m256i x0, x1, x2, x3, x4;
	__m256i t0, t1, t2, t3;
	__m256i vindex_4i = _mm256_setr_epi32(0,4,8,12,16,20,24,28);
	__m256i vindex_mask = _mm256_set1_epi32(0xff);
	__m256i vindex_read = _mm256_setr_epi32(0,8,16,24,1,9,17,25);
	__m256i vindex_swap = _mm256_setr_epi8(
		3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12,
		3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12
	);
	__m256i incr = _mm256_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7);
	int c0 = (int)GETU32(ctr     );
	int c1 = (int)GETU32(ctr +  4);
	int c2 = (int)GETU32(ctr +  8);
	int c3 = (int)GETU32(ctr + 12);

	while (nblocks >= 8) {
		x0 = _mm256_set1_epi32(c0);
		x1 = _mm256_set1_epi32(c1);
		x2 = _mm256_set1_epi32(c2);
		x3 = _mm256_set1_epi32(c3);
		x3 = _mm256_add_epi32(x3, incr);

		ROUND( 0, x0, x1, x2, x3, x4);
		ROUND( 1, x1, x2, x3, x4, x0);
		ROUND( 2, x2, x3, x4, x0, x1);
		ROUND( 3, x3, x4, x0, x1, x2);
		ROUND( 4, x4, x0, x1, x2, x3);
		ROUND( 5, x0, x1, x2, x3, x4);
		ROUND( 6, x1, x2, x3, x4, x0);
		ROUND( 7, x2, x3, x4, x0, x1);
		ROUND( 8, x3, x4, x0, x1, x2);
		ROUND( 9, x4, x0, x1, x2, x3);
		ROUND(10, x0, x1, x2, x3, x4);
		ROUND(11, x1, x2, x3, x4, x0);
		ROUND(12, x2, x3, x4, x0, x1);
		ROUND(13, x3, x4, x0, x1, x2);
		ROUND(14, x4, x0, x1, x2, x3);
		ROUND(15, x0, x1, x2, x3, x4);
		ROUND(16, x1, x2, x3, x4, x0);
		ROUND(17, x2, x3, x4, x0, x1);
		ROUND(18, x3, x4, x0, x1, x2);
		ROUND(19, x4, x0, x1, x2, x3);
		ROUND(20, x0, x1, x2, x3, x4);
		ROUND(21, x1, x2, x3, x4, x0);
		ROUND(22, x2, x3, x4, x0, x1);
		ROUND(23, x3, x4, x0, x1, x2);
		ROUND(24, x4, x0, x1, x2, x3);
		ROUND(25, x0, x1, x2, x3, x4);
		ROUND(26, x1, x2, x3, x4, x0);
		ROUND(27, x2, x3, x4, x0, x1);
		ROUND(28, x3, x4, x0, x1, x2);
		ROUND(29, x4, x0, x1, x2, x3);
		ROUND(30, x0, x1, x2, x3, x4);
		ROUND(31, x1, x2, x3, x4, x0);

		GET_BLKS(t0, t1, t2, t3, in);

		x0 = _mm256_xor_si256(x0, t0);
		x4 = _mm256_xor_si256(x4, t1);
		x3 = _mm256_xor_si256(x3, t2);
		x2 = _mm256_xor_si256(x2, t3);

		PUT_BLKS(out, x0, x4, x3, x2);

		c3 += 8;
		in += 128;
		out += 128;

		nblocks -= 8;
	}

	PUTU32(ctr + 12, c3);

	while (nblocks--) {
		uint8_t block[16];
		int i;

		sm4_encrypt(key, ctr, block);
		ctr32_incr(ctr);

		for (i = 0; i < 16; i++) {
			out[i] = in[i] ^ block[i];
		}
		in += 16;
		out += 16;
	}
}

/*
int main(void)
{
	const uint8_t key[16] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	};
	const uint8_t plaintext[16 * 8] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	};
	const uint8_t ciphertext[16 * 8] = {
		0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
		0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46,
		0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
		0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46,
		0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
		0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46,
		0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
		0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46,
		0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
		0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46,
		0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
		0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46,
		0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
		0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46,
		0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
		0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46,
	};

	SM4_KEY sm4_key;
	unsigned char buf[16 * 8];
	int i;

	sm4_set_encrypt_key(&sm4_key, key);

	sm4_encrypt_blocks(&sm4_key, plaintext, 8, buf);

	if (memcmp(buf, ciphertext, 16) != 0) {
		fprintf(stderr, "sm4 encrypt not pass!\n");
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}
*/
