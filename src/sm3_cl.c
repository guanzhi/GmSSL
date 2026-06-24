/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#include "cl.h"


static const char *sm3_cl_src = KERNEL(

__constant uint K[64] = {
	0x79cc4519U, 0xf3988a32U, 0xe7311465U, 0xce6228cbU,
	0x9cc45197U, 0x3988a32fU, 0x7311465eU, 0xe6228cbcU,
	0xcc451979U, 0x988a32f3U, 0x311465e7U, 0x6228cbceU,
	0xc451979cU, 0x88a32f39U, 0x11465e73U, 0x228cbce6U,
	0x9d8a7a87U, 0x3b14f50fU, 0x7629ea1eU, 0xec53d43cU,
	0xd8a7a879U, 0xb14f50f3U, 0x629ea1e7U, 0xc53d43ceU,
	0x8a7a879dU, 0x14f50f3bU, 0x29ea1e76U, 0x53d43cecU,
	0xa7a879d8U, 0x4f50f3b1U, 0x9ea1e762U, 0x3d43cec5U,
	0x7a879d8aU, 0xf50f3b14U, 0xea1e7629U, 0xd43cec53U,
	0xa879d8a7U, 0x50f3b14fU, 0xa1e7629eU, 0x43cec53dU,
	0x879d8a7aU, 0x0f3b14f5U, 0x1e7629eaU, 0x3cec53d4U,
	0x79d8a7a8U, 0xf3b14f50U, 0xe7629ea1U, 0xcec53d43U,
	0x9d8a7a87U, 0x3b14f50fU, 0x7629ea1eU, 0xec53d43cU,
	0xd8a7a879U, 0xb14f50f3U, 0x629ea1e7U, 0xc53d43ceU,
	0x8a7a879dU, 0x14f50f3bU, 0x29ea1e76U, 0x53d43cecU,
	0xa7a879d8U, 0x4f50f3b1U, 0x9ea1e762U, 0x3d43cec5U,
};

uint rotl32(uint x, uint n)
{
	return (x << n) | (x >> (32 - n));
}

uint P0(uint x)
{
	return x ^ rotl32(x, 9) ^ rotl32(x, 17);
}

uint P1(uint x)
{
	return x ^ rotl32(x, 15) ^ rotl32(x, 23);
}

uint FF(uint x, uint y, uint z, uint j)
{
	return j < 16 ? (x ^ y ^ z) : ((x & y) | (x & z) | (y & z));
}

uint GG(uint x, uint y, uint z, uint j)
{
	return j < 16 ? (x ^ y ^ z) : (((y ^ z) & x) ^ z);
}

uint load_be32(__global const uchar *p)
{
	return ((uint)p[0] << 24) | ((uint)p[1] << 16) | ((uint)p[2] << 8) | (uint)p[3];
}

uint load_be32_private(__private const uchar *p)
{
	return ((uint)p[0] << 24) | ((uint)p[1] << 16) | ((uint)p[2] << 8) | (uint)p[3];
}

void store_be32(__private uchar *p, uint x)
{
	p[0] = (uchar)(x >> 24);
	p[1] = (uchar)(x >> 16);
	p[2] = (uchar)(x >> 8);
	p[3] = (uchar)x;
}

void set_be32(__private uchar *p, uint x)
{
	p[0] = (uchar)(x >> 24);
	p[1] = (uchar)(x >> 16);
	p[2] = (uchar)(x >> 8);
	p[3] = (uchar)x;
}

void copy32_from_global(__private uchar dst[32], __global const uchar *src)
{
	uint i;
	for (i = 0; i < 32; i++) {
		dst[i] = src[i];
	}
}

void copy32(__private uchar dst[32], __private const uchar src[32])
{
	uint i;
	for (i = 0; i < 32; i++) {
		dst[i] = src[i];
	}
}

void sm3_compress_words(__private uint dgst[8], __private uint W[68])
{
	uint A = dgst[0];
	uint B = dgst[1];
	uint C = dgst[2];
	uint D = dgst[3];
	uint E = dgst[4];
	uint F = dgst[5];
	uint G = dgst[6];
	uint H = dgst[7];
	uint SS1, SS2, TT1, TT2;
	uint j;

	for (j = 16; j < 68; j++) {
		W[j] = P1(W[j - 16] ^ W[j - 9] ^ rotl32(W[j - 3], 15))
			^ rotl32(W[j - 13], 7) ^ W[j - 6];
	}

	for (j = 0; j < 64; j++) {
		SS1 = rotl32(rotl32(A, 12) + E + K[j], 7);
		SS2 = SS1 ^ rotl32(A, 12);
		TT1 = FF(A, B, C, j) + D + SS2 + (W[j] ^ W[j + 4]);
		TT2 = GG(E, F, G, j) + H + SS1 + W[j];
		D = C;
		C = rotl32(B, 9);
		B = A;
		A = TT1;
		H = G;
		G = rotl32(F, 19);
		F = E;
		E = P0(TT2);
	}

	dgst[0] ^= A;
	dgst[1] ^= B;
	dgst[2] ^= C;
	dgst[3] ^= D;
	dgst[4] ^= E;
	dgst[5] ^= F;
	dgst[6] ^= G;
	dgst[7] ^= H;
}

void sm3_init_state(__private uint dgst[8])
{
	dgst[0] = 0x7380166fU;
	dgst[1] = 0x4914b2b9U;
	dgst[2] = 0x172442d7U;
	dgst[3] = 0xda8a0600U;
	dgst[4] = 0xa96f30bcU;
	dgst[5] = 0x163138aaU;
	dgst[6] = 0xe38dee4dU;
	dgst[7] = 0xb0fb0e4eU;
}

void sm3_compress_blocks(__private uint dgst[8], __private uchar block[64])
{
	uint W[68];
	uint i;
	for (i = 0; i < 16; i++) {
		W[i] = load_be32_private(block + 4*i);
	}
	sm3_compress_words(dgst, W);
}

void sm3_update_byte(__private uint dgst[8], __private uchar block[64],
	__private uint *num, __private ulong *nblocks, uchar b)
{
	block[*num] = b;
	*num += 1;
	if (*num == 64) {
		sm3_compress_blocks(dgst, block);
		*nblocks += 1;
		*num = 0;
	}
}

void sm3_finish_ctx(__private uint dgst[8], __private uchar block[64],
	uint num, ulong nblocks, __private uchar out[32])
{
	ulong bits;
	ulong len = nblocks * 64 + num;
	uint i;

	block[num++] = 0x80;
	if (num > 56) {
		while (num < 64) {
			block[num++] = 0;
		}
		sm3_compress_blocks(dgst, block);
		num = 0;
	}
	while (num < 56) {
		block[num++] = 0;
	}
	bits = len * 8;
	for (i = 0; i < 8; i++) {
		block[56 + i] = (uchar)(bits >> (56 - 8*i));
	}
	sm3_compress_blocks(dgst, block);
	for (i = 0; i < 8; i++) {
		store_be32(out + 4*i, dgst[i]);
	}
}

);

const char *sm3_cl_source(void)
{
	return sm3_cl_src;
}
