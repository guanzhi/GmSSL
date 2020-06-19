/* ====================================================================
 * Copyright (c) 2015 - 2019 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include <stdlib.h>
#include <string.h>
#include <openssl/zuc.h>
#include "modes_lcl.h"

static const ZUC_UINT15 KD[16] = {
	0x44D7,0x26BC,0x626B,0x135E,0x5789,0x35E2,0x7135,0x09AF,
	0x4D78,0x2F13,0x6BC4,0x1AF1,0x5E26,0x3C4D,0x789A,0x47AC,
};

static const uint8_t S0[256] = {
	0x3e,0x72,0x5b,0x47,0xca,0xe0,0x00,0x33,0x04,0xd1,0x54,0x98,0x09,0xb9,0x6d,0xcb,
	0x7b,0x1b,0xf9,0x32,0xaf,0x9d,0x6a,0xa5,0xb8,0x2d,0xfc,0x1d,0x08,0x53,0x03,0x90,
	0x4d,0x4e,0x84,0x99,0xe4,0xce,0xd9,0x91,0xdd,0xb6,0x85,0x48,0x8b,0x29,0x6e,0xac,
	0xcd,0xc1,0xf8,0x1e,0x73,0x43,0x69,0xc6,0xb5,0xbd,0xfd,0x39,0x63,0x20,0xd4,0x38,
	0x76,0x7d,0xb2,0xa7,0xcf,0xed,0x57,0xc5,0xf3,0x2c,0xbb,0x14,0x21,0x06,0x55,0x9b,
	0xe3,0xef,0x5e,0x31,0x4f,0x7f,0x5a,0xa4,0x0d,0x82,0x51,0x49,0x5f,0xba,0x58,0x1c,
	0x4a,0x16,0xd5,0x17,0xa8,0x92,0x24,0x1f,0x8c,0xff,0xd8,0xae,0x2e,0x01,0xd3,0xad,
	0x3b,0x4b,0xda,0x46,0xeb,0xc9,0xde,0x9a,0x8f,0x87,0xd7,0x3a,0x80,0x6f,0x2f,0xc8,
	0xb1,0xb4,0x37,0xf7,0x0a,0x22,0x13,0x28,0x7c,0xcc,0x3c,0x89,0xc7,0xc3,0x96,0x56,
	0x07,0xbf,0x7e,0xf0,0x0b,0x2b,0x97,0x52,0x35,0x41,0x79,0x61,0xa6,0x4c,0x10,0xfe,
	0xbc,0x26,0x95,0x88,0x8a,0xb0,0xa3,0xfb,0xc0,0x18,0x94,0xf2,0xe1,0xe5,0xe9,0x5d,
	0xd0,0xdc,0x11,0x66,0x64,0x5c,0xec,0x59,0x42,0x75,0x12,0xf5,0x74,0x9c,0xaa,0x23,
	0x0e,0x86,0xab,0xbe,0x2a,0x02,0xe7,0x67,0xe6,0x44,0xa2,0x6c,0xc2,0x93,0x9f,0xf1,
	0xf6,0xfa,0x36,0xd2,0x50,0x68,0x9e,0x62,0x71,0x15,0x3d,0xd6,0x40,0xc4,0xe2,0x0f,
	0x8e,0x83,0x77,0x6b,0x25,0x05,0x3f,0x0c,0x30,0xea,0x70,0xb7,0xa1,0xe8,0xa9,0x65,
	0x8d,0x27,0x1a,0xdb,0x81,0xb3,0xa0,0xf4,0x45,0x7a,0x19,0xdf,0xee,0x78,0x34,0x60,
};

static const uint8_t S1[256] = {
	0x55,0xc2,0x63,0x71,0x3b,0xc8,0x47,0x86,0x9f,0x3c,0xda,0x5b,0x29,0xaa,0xfd,0x77,
	0x8c,0xc5,0x94,0x0c,0xa6,0x1a,0x13,0x00,0xe3,0xa8,0x16,0x72,0x40,0xf9,0xf8,0x42,
	0x44,0x26,0x68,0x96,0x81,0xd9,0x45,0x3e,0x10,0x76,0xc6,0xa7,0x8b,0x39,0x43,0xe1,
	0x3a,0xb5,0x56,0x2a,0xc0,0x6d,0xb3,0x05,0x22,0x66,0xbf,0xdc,0x0b,0xfa,0x62,0x48,
	0xdd,0x20,0x11,0x06,0x36,0xc9,0xc1,0xcf,0xf6,0x27,0x52,0xbb,0x69,0xf5,0xd4,0x87,
	0x7f,0x84,0x4c,0xd2,0x9c,0x57,0xa4,0xbc,0x4f,0x9a,0xdf,0xfe,0xd6,0x8d,0x7a,0xeb,
	0x2b,0x53,0xd8,0x5c,0xa1,0x14,0x17,0xfb,0x23,0xd5,0x7d,0x30,0x67,0x73,0x08,0x09,
	0xee,0xb7,0x70,0x3f,0x61,0xb2,0x19,0x8e,0x4e,0xe5,0x4b,0x93,0x8f,0x5d,0xdb,0xa9,
	0xad,0xf1,0xae,0x2e,0xcb,0x0d,0xfc,0xf4,0x2d,0x46,0x6e,0x1d,0x97,0xe8,0xd1,0xe9,
	0x4d,0x37,0xa5,0x75,0x5e,0x83,0x9e,0xab,0x82,0x9d,0xb9,0x1c,0xe0,0xcd,0x49,0x89,
	0x01,0xb6,0xbd,0x58,0x24,0xa2,0x5f,0x38,0x78,0x99,0x15,0x90,0x50,0xb8,0x95,0xe4,
	0xd0,0x91,0xc7,0xce,0xed,0x0f,0xb4,0x6f,0xa0,0xcc,0xf0,0x02,0x4a,0x79,0xc3,0xde,
	0xa3,0xef,0xea,0x51,0xe6,0x6b,0x18,0xec,0x1b,0x2c,0x80,0xf7,0x74,0xe7,0xff,0x21,
	0x5a,0x6a,0x54,0x1e,0x41,0x31,0x92,0x35,0xc4,0x33,0x07,0x0a,0xba,0x7e,0x0e,0x34,
	0x88,0xb1,0x98,0x7c,0xf3,0x3d,0x60,0x6c,0x7b,0xca,0xd3,0x1f,0x32,0x65,0x04,0x28,
	0x64,0xbe,0x85,0x9b,0x2f,0x59,0x8a,0xd7,0xb0,0x25,0xac,0xaf,0x12,0x03,0xe2,0xf2,
};


#define ADD31(a,b)	a += (b); a = (a & 0x7fffffff) + (a >> 31)
#define ROT31(a,k)	((((a) << (k)) | ((a) >> (31 - (k)))) & 0x7FFFFFFF)
#define ROT32(a,k)	(((a) << (k)) | ((a) >> (32 - (k))))

#define L1(X)			\
	((X) ^			\
	ROT32((X),  2) ^	\
	ROT32((X), 10) ^	\
	ROT32((X), 18) ^	\
	ROT32((X), 24))

#define L2(X)			\
	((X) ^			\
	ROT32((X),  8) ^	\
	ROT32((X), 14) ^	\
	ROT32((X), 22) ^	\
	ROT32((X), 30))

#define LFSRWithInitialisationMode(u)			\
	V = LFSR[0];					\
	ADD31(V, ROT31(LFSR[0], 8));			\
	ADD31(V, ROT31(LFSR[4], 20));			\
	ADD31(V, ROT31(LFSR[10], 21));			\
	ADD31(V, ROT31(LFSR[13], 17));			\
	ADD31(V, ROT31(LFSR[15], 15));			\
	ADD31(V, (u));					\
	{int j; for (j=0; j<15;j++) LFSR[j]=LFSR[j+1];}	\
	LFSR[15] = V

#define LFSRWithWorkMode()			\
	{					\
	int j;					\
	uint64_t a = LFSR[0];			\
	a += ((uint64_t)LFSR[0]) << 8;		\
	a += ((uint64_t)LFSR[4]) << 20;		\
	a += ((uint64_t)LFSR[10]) << 21;	\
	a += ((uint64_t)LFSR[13]) << 17;	\
	a += ((uint64_t)LFSR[15]) << 15;	\
	a = (a & 0x7fffffff) + (a >> 31);	\
	V = (a & 0x7fffffff) + (a >> 31);	\
	for (j = 0; j < 15; j++)		\
		LFSR[j] = LFSR[j+1];		\
	LFSR[15] = V;				\
	}

#define BitReconstruction2(X1,X2)					\
	X1 = ((LFSR[11] & 0xFFFF) << 16) | (LFSR[9] >> 15);		\
	X2 = ((LFSR[7] & 0xFFFF) << 16) | (LFSR[5] >> 15)

#define BitReconstruction3(X0,X1,X2)					\
	X0 = ((LFSR[15] & 0x7FFF8000) << 1) | (LFSR[14] & 0xFFFF);	\
	BitReconstruction2(X1,X2)

#define BitReconstruction4(X0,X1,X2,X3)					\
	BitReconstruction3(X0,X1,X2);					\
	X3 = ((LFSR[2] & 0xFFFF) << 16) | (LFSR[0] >> 15)


#define MAKEU31(k,d,iv) 				\
	(((uint32_t)(k) << 23) |			\
	 ((uint32_t)(d) <<  8) |			\
	  (uint32_t)(iv))

#define MAKEU32(a, b, c, d)				\
	(((uint32_t)(a) << 24) |			\
	 ((uint32_t)(b) << 16) | 			\
	 ((uint32_t)(c) <<  8) |			\
	 ((uint32_t)(d)))

#define F_(X1,X2)					\
	W1 = R1 + X1;					\
	W2 = R2 ^ X2;					\
	U = L1((W1 << 16) | (W2 >> 16));		\
	V = L2((W2 << 16) | (W1 >> 16));		\
	R1 = MAKEU32(	S0[U >> 24],			\
			S1[(U >> 16) & 0xFF],		\
			S0[(U >> 8) & 0xFF],		\
			S1[U & 0xFF]);			\
	R2 = MAKEU32(	S0[V >> 24],			\
			S1[(V >> 16) & 0xFF],		\
			S0[(V >> 8) & 0xFF],		\
			S1[V & 0xFF])

#define F(X0,X1,X2)					\
	(X0 ^ R1) + R2;					\
	F_(X1, X2)

void ZUC_set_key(ZUC_KEY *key, const unsigned char *user_key, const unsigned char *iv)
{
	ZUC_UINT31 *LFSR = key->LFSR;
	uint32_t R1, R2;
	uint32_t X0, X1, X2;
	uint32_t W, W1, W2, U, V;
	int i;

	for (i = 0; i < 16; i++) {
		LFSR[i] = MAKEU31(user_key[i], KD[i], iv[i]);
	}

	R1 = 0;
	R2 = 0;

	for (i = 0; i < 32; i++) {
		BitReconstruction3(X0, X1, X2);
		W = F(X0, X1, X2);
		LFSRWithInitialisationMode(W >> 1);
	}

	BitReconstruction2(X1, X2);
	F_(X1, X2);
	LFSRWithWorkMode();

	key->R1 = R1;
	key->R2 = R2;
}

uint32_t ZUC_generate_keyword(ZUC_KEY *key)
{
	ZUC_UINT31 *LFSR = key->LFSR;
	uint32_t R1 = key->R1;
	uint32_t R2 = key->R2;
	uint32_t X0, X1, X2, X3;
	uint32_t W1, W2, U, V;
	uint32_t Z;

	BitReconstruction4(X0, X1, X2, X3);
	Z = X3 ^ F(X0, X1, X2);
	LFSRWithWorkMode();

	key->R1 = R1;
	key->R2 = R2;

	return Z;
}

void ZUC_generate_keystream(ZUC_KEY *key, size_t nwords, uint32_t *keystream)
{
	ZUC_UINT31 *LFSR = key->LFSR;
	uint32_t R1 = key->R1;
	uint32_t R2 = key->R2;
	uint32_t X0, X1, X2, X3;
	uint32_t W1, W2, U, V;
	size_t i;

	for (i = 0; i < nwords; i ++) {
		BitReconstruction4(X0, X1, X2, X3);
		keystream[i] = X3 ^ F(X0, X1, X2);
		LFSRWithWorkMode();
	}

	key->R1 = R1;
	key->R2 = R2;
}

void ZUC_MAC_init(ZUC_MAC_CTX *ctx, const unsigned char key[16], const unsigned char iv[16])
{
	memset(ctx, 0, sizeof(*ctx));
	ZUC_set_key((ZUC_KEY *)ctx, key, iv);
	ctx->K0 = ZUC_generate_keyword((ZUC_KEY *)ctx);
}

void ZUC_MAC_update(ZUC_MAC_CTX *ctx, const unsigned char *data, size_t len)
{
	ZUC_UINT32 T = ctx->T;
	ZUC_UINT32 K0 = ctx->K0;
	ZUC_UINT32 K1, M;
	ZUC_UINT31 *LFSR = ctx->LFSR;
	ZUC_UINT32 R1 = ctx->R1;
	ZUC_UINT32 R2 = ctx->R2;
	ZUC_UINT32 X0, X1, X2, X3;
	ZUC_UINT32 W1, W2, U, V;
	size_t i;

	if (!data || !len) {
		return;
	}

	if (ctx->buflen) {
		size_t num = sizeof(ctx->buf) - ctx->buflen;
		if (len < num) {
			memcpy(ctx->buf + ctx->buflen, data, len);
			ctx->buflen += len;
			return;
		}

		memcpy(ctx->buf + ctx->buflen, data, num);
		M = GETU32(ctx->buf);
		ctx->buflen = 0;

		BitReconstruction4(X0, X1, X2, X3);
		K1 = X3 ^ F(X0, X1, X2);
		LFSRWithWorkMode();

		for (i = 0; i < 32; i++) {
			if (M & 0x80000000) {
				T ^= K0;
			}
			M <<= 1;
			K0 = (K0 << 1) | (K1 >> 31);
			K1 <<= 1;
		}

		data += num;
		len -= num;
	}

	while (len >= 4) {
		M = GETU32(data);

		BitReconstruction4(X0, X1, X2, X3);
		K1 = X3 ^ F(X0, X1, X2);
		LFSRWithWorkMode();

		for (i = 0; i < 32; i++) {
			if (M & 0x80000000) {
				T ^= K0;
			}
			M <<= 1;
			K0 = (K0 << 1) | (K1 >> 31);
			K1 <<= 1;
		}

		data += 4;
		len -= 4;
	}

	if (len) {
		memcpy(ctx->buf, data, len);
		ctx->buflen = len;
	}
	ctx->R1 = R1;
	ctx->R2 = R2;
	ctx->K0 = K0;
	ctx->T = T;
}

void ZUC_MAC_final(ZUC_MAC_CTX *ctx, const unsigned char *data, size_t nbits, unsigned char mac[4])
{
	ZUC_UINT32 T = ctx->T;
	ZUC_UINT32 K0 = ctx->K0;
	ZUC_UINT32 K1, M;
	ZUC_UINT31 *LFSR = ctx->LFSR;
	ZUC_UINT32 R1 = ctx->R1;
	ZUC_UINT32 R2 = ctx->R2;
	ZUC_UINT32 X0, X1, X2, X3;
	ZUC_UINT32 W1, W2, U, V;
	size_t i;


	if (!data)
		nbits = 0;

	if (nbits >= 8) {
		ZUC_MAC_update(ctx, data, nbits/8);
		data += nbits/8;
		nbits %= 8;
	}

	T = ctx->T;
	K0 = ctx->K0;
	LFSR = ctx->LFSR;
	R1 = ctx->R1;
	R2 = ctx->R2;


	if (nbits)
		ctx->buf[ctx->buflen] = *data;

	if (ctx->buflen || nbits) {
		M = GETU32(ctx->buf);
		BitReconstruction4(X0, X1, X2, X3);
		K1 = X3 ^ F(X0, X1, X2);
		LFSRWithWorkMode();

		for (i = 0; i < ctx->buflen * 8 + nbits; i++) {
			if (M & 0x80000000) {
				T ^= K0;
			}
			M <<= 1;
			K0 = (K0 << 1) | (K1 >> 31);
			K1 <<= 1;
		}
	}

	T ^= K0;

	BitReconstruction4(X0, X1, X2, X3);
	K1 = X3 ^ F(X0, X1, X2);
	LFSRWithWorkMode();
	T ^= K1;

	ctx->T = T;
	PUTU32(mac, T);
}

typedef unsigned char ZUC_UINT7;

static const ZUC_UINT7 ZUC256_D[][16] = {
	{0x22,0x2F,0x24,0x2A,0x6D,0x40,0x40,0x40,
	 0x40,0x40,0x40,0x40,0x40,0x52,0x10,0x30},
	{0x22,0x2F,0x25,0x2A,0x6D,0x40,0x40,0x40,
	 0x40,0x40,0x40,0x40,0x40,0x52,0x10,0x30},
	{0x23,0x2F,0x24,0x2A,0x6D,0x40,0x40,0x40,
	 0x40,0x40,0x40,0x40,0x40,0x52,0x10,0x30},
	{0x23,0x2F,0x25,0x2A,0x6D,0x40,0x40,0x40,
	 0x40,0x40,0x40,0x40,0x40,0x52,0x10,0x30},
};

#define ZUC256_MAKEU31(a,b,c,d)				\
	(((uint32_t)(a) << 23) |			\
	 ((uint32_t)(b) << 16) |			\
	 ((uint32_t)(c) <<  8) |			\
	  (uint32_t)(d))


static void zuc256_set_mac_key(ZUC_KEY *key, const unsigned char K[32],
	const unsigned char IV[23], int macbits)
{
	ZUC_UINT31 *LFSR = key->LFSR;
	uint32_t R1, R2;
	uint32_t X0, X1, X2;
	uint32_t W, W1, W2, U, V;
	const ZUC_UINT7 *D;
	int i;

	ZUC_UINT6 IV17 = IV[17] >> 2;
	ZUC_UINT6 IV18 = ((IV[17] & 0x3) << 4) | (IV[18] >> 4);
	ZUC_UINT6 IV19 = ((IV[18] & 0xf) << 2) | (IV[19] >> 6);
	ZUC_UINT6 IV20 = IV[19] & 0x3f;
	ZUC_UINT6 IV21 = IV[20] >> 2;
	ZUC_UINT6 IV22 = ((IV[20] & 0x3) << 4) | (IV[21] >> 4);
	ZUC_UINT6 IV23 = ((IV[21] & 0xf) << 2) | (IV[22] >> 6);
	ZUC_UINT6 IV24 = IV[22] & 0x3f;

	D = macbits/32 < 3 ? ZUC256_D[macbits/32] : ZUC256_D[3];
	LFSR[0] = ZUC256_MAKEU31(K[0], D[0], K[21], K[16]);
	LFSR[1] = ZUC256_MAKEU31(K[1], D[1], K[22], K[17]);
	LFSR[2] = ZUC256_MAKEU31(K[2], D[2], K[23], K[18]);
	LFSR[3] = ZUC256_MAKEU31(K[3], D[3], K[24], K[19]);
	LFSR[4] = ZUC256_MAKEU31(K[4], D[4], K[25], K[20]);
	LFSR[5] = ZUC256_MAKEU31(IV[0], (D[5] | IV17), K[5], K[26]);
	LFSR[6] = ZUC256_MAKEU31(IV[1], (D[6] | IV18), K[6], K[27]);
	LFSR[7] = ZUC256_MAKEU31(IV[10], (D[7] | IV19), K[7], IV[2]);
	LFSR[8] = ZUC256_MAKEU31(K[8], (D[8] | IV20), IV[3], IV[11]);
	LFSR[9] = ZUC256_MAKEU31(K[9], (D[9] | IV21), IV[12], IV[4]);
	LFSR[10] = ZUC256_MAKEU31(IV[5], (D[10] | IV22), K[10], K[28]);
	LFSR[11] = ZUC256_MAKEU31(K[11], (D[11] | IV23), IV[6], IV[13]);
	LFSR[12] = ZUC256_MAKEU31(K[12], (D[12] | IV24), IV[7], IV[14]);
	LFSR[13] = ZUC256_MAKEU31(K[13], D[13], IV[15], IV[8]);
	LFSR[14] = ZUC256_MAKEU31(K[14], (D[14] | (K[31] >> 4)), IV[16], IV[9]);
	LFSR[15] = ZUC256_MAKEU31(K[15], (D[15] | (K[31] & 0x0F)), K[30], K[29]);

	R1 = 0;
	R2 = 0;

	for (i = 0; i < 32; i++) {
		BitReconstruction3(X0, X1, X2);
		W = F(X0, X1, X2);
		LFSRWithInitialisationMode(W >> 1);
	}

	BitReconstruction2(X1, X2);
	F_(X1, X2);
	LFSRWithWorkMode();

	key->R1 = R1;
	key->R2 = R2;
}

void ZUC256_set_key(ZUC_KEY *key, const unsigned char K[32],
	const unsigned char IV[23])
{
	zuc256_set_mac_key(key, K, IV, 0);
}

void ZUC256_MAC_init(ZUC256_MAC_CTX *ctx, const unsigned char key[32],
	const unsigned char iv[23], int macbits)
{
	if (macbits < 32)
		macbits = 32;
	else if (macbits > 64)
		macbits = 128;
	memset(ctx, 0, sizeof(*ctx));
	zuc256_set_mac_key((ZUC256_KEY *)ctx, key, iv, macbits);
	ZUC256_generate_keystream((ZUC256_KEY *)ctx, macbits/32, ctx->T);
	ZUC256_generate_keystream((ZUC256_KEY *)ctx, macbits/32, ctx->K0);
	ctx->macbits = (macbits/32) * 32;
}

void ZUC256_MAC_update(ZUC256_MAC_CTX *ctx, const unsigned char *data, size_t len)
{
	ZUC_UINT32 K1, M;
	size_t n = ctx->macbits / 32;
	size_t i, j;

	if (!data || !len) {
		return;
	}

	if (ctx->buflen) {
		size_t num = sizeof(ctx->buf) - ctx->buflen;
		if (len < num) {
			memcpy(ctx->buf + ctx->buflen, data, len);
			ctx->buflen += len;
			return;
		}

		memcpy(ctx->buf + ctx->buflen, data, num);
		M = GETU32(ctx->buf);
		ctx->buflen = 0;

		K1 = ZUC256_generate_keyword((ZUC256_KEY *)ctx);

		for (i = 0; i < 32; i++) {
			if (M & 0x80000000) {
				for (j = 0; j < n; j++) {
					ctx->T[j] ^= ctx->K0[j];
				}
			}
			M <<= 1;
			for (j = 0; j < n - 1; j++) {
				ctx->K0[j] = (ctx->K0[j] << 1) | (ctx->K0[j + 1] >> 31);
			}
			ctx->K0[j] = (ctx->K0[j] << 1) | (K1 >> 31);
			K1 <<= 1;
		}

		data += num;
		len -= num;
	}

	while (len >= 4) {
		M = GETU32(data);
		K1 = ZUC256_generate_keyword((ZUC256_KEY *)ctx);

		for (i = 0; i < 32; i++) {
			if (M & 0x80000000) {
				for (j = 0; j < n; j++) {
					ctx->T[j] ^= ctx->K0[j];
				}
			}
			M <<= 1;
			for (j = 0; j < n - 1; j++) {
				ctx->K0[j] = (ctx->K0[j] << 1) | (ctx->K0[j + 1] >> 31);
			}
			ctx->K0[j] = (ctx->K0[j] << 1) | (K1 >> 31);
			K1 <<= 1;
		}

		data += 4;
		len -= 4;
	}

	if (len) {
		memcpy(ctx->buf, data, len);
		ctx->buflen = len;
	}
}

void ZUC256_MAC_final(ZUC256_MAC_CTX *ctx, const unsigned char *data, size_t nbits, unsigned char *mac)
{
	ZUC_UINT32 K1, M;
	size_t n = ctx->macbits/32;
	size_t i, j;


	if (!data)
		nbits = 0;

	if (nbits >= 8) {
		ZUC256_MAC_update(ctx, data, nbits/8);
		data += nbits/8;
		nbits %= 8;
	}

	if (nbits)
		ctx->buf[ctx->buflen] = *data;

	if (ctx->buflen || nbits) {
		M = GETU32(ctx->buf);
		K1 = ZUC256_generate_keyword((ZUC256_KEY *)ctx);


		for (i = 0; i < ctx->buflen * 8 + nbits; i++) {
			if (M & 0x80000000) {
				for (j = 0; j < n; j++) {
					ctx->T[j] ^= ctx->K0[j];
				}
			}
			M <<= 1;
			for (j = 0; j < n - 1; j++) {
				ctx->K0[j] = (ctx->K0[j] << 1) | (ctx->K0[j + 1] >> 31);
			}
			ctx->K0[j] = (ctx->K0[j] << 1) | (K1 >> 31);
			K1 <<= 1;
		}
	}

	for (j = 0; j < n; j++) {
		ctx->T[j] ^= ctx->K0[j];
		PUTU32(mac, ctx->T[j]);
		mac += 4;
	}
}
