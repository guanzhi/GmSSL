/* ====================================================================
 * Copyright (c) 2015 - 2018 The GmSSL Project.  All rights reserved.
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

/* code from ZUC 3GPP Specifications, version 1.6
 */

#include <stdio.h>
#include <stdlib.h>
#include "zuc_spec.h"

/* the state registers of LFSR */
u32 LFSR_S0;
u32 LFSR_S1;
u32 LFSR_S2;
u32 LFSR_S3;
u32 LFSR_S4;
u32 LFSR_S5;
u32 LFSR_S6;
u32 LFSR_S7;
u32 LFSR_S8;
u32 LFSR_S9;
u32 LFSR_S10;
u32 LFSR_S11;
u32 LFSR_S12;
u32 LFSR_S13;
u32 LFSR_S14;
u32 LFSR_S15;

/* the registers of F */
u32 F_R1;
u32 F_R2;

/* the outputs of BitReorganization */
u32 BRC_X0;
u32 BRC_X1;
u32 BRC_X2;
u32 BRC_X3;

/* the s-boxes */
u8 S0[256] = {
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
	0x8d,0x27,0x1a,0xdb,0x81,0xb3,0xa0,0xf4,0x45,0x7a,0x19,0xdf,0xee,0x78,0x34,0x60
};

u8 S1[256] = {
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
	0x64,0xbe,0x85,0x9b,0x2f,0x59,0x8a,0xd7,0xb0,0x25,0xac,0xaf,0x12,0x03,0xe2,0xf2
};

/* the constants D */
u32 EK_d[16] = {
	0x44D7, 0x26BC, 0x626B, 0x135E, 0x5789, 0x35E2, 0x7135, 0x09AF,
	0x4D78, 0x2F13, 0x6BC4, 0x1AF1, 0x5E26, 0x3C4D, 0x789A, 0x47AC
};

/* c = a + b mod (2^31 – 1) */
u32 AddM(u32 a, u32 b)
{
	u32 c = a + b;
	return (c & 0x7FFFFFFF) + (c >> 31);
}

/* LFSR with initialization mode */
#define MulByPow2(x, k) ((((x) << k) | ((x) >> (31 - k))) & 0x7FFFFFFF)

void LFSRWithInitialisationMode(u32 u)
{
	u32 f, v;
	f = LFSR_S0;
	v = MulByPow2(LFSR_S0, 8);
	f = AddM(f, v);
	v = MulByPow2(LFSR_S4, 20);
	f = AddM(f, v);
	v = MulByPow2(LFSR_S10, 21);
	f = AddM(f, v);
	v = MulByPow2(LFSR_S13, 17);
	f = AddM(f, v);
	v = MulByPow2(LFSR_S15, 15);
	f = AddM(f, v);
	f = AddM(f, u);
	/* update the state */
	LFSR_S0 = LFSR_S1;
	LFSR_S1 = LFSR_S2;
	LFSR_S2 = LFSR_S3;
	LFSR_S3 = LFSR_S4;
	LFSR_S4 = LFSR_S5;
	LFSR_S5 = LFSR_S6;
	LFSR_S6 = LFSR_S7;
	LFSR_S7 = LFSR_S8;
	LFSR_S8 = LFSR_S9;
	LFSR_S9 = LFSR_S10;
	LFSR_S10 = LFSR_S11;
	LFSR_S11 = LFSR_S12;
	LFSR_S12 = LFSR_S13;
	LFSR_S13 = LFSR_S14;
	LFSR_S14 = LFSR_S15;
	LFSR_S15 = f;
}

/* LFSR with work mode */
void LFSRWithWorkMode(void)
{
	u32 f, v;
	f = LFSR_S0;
	v = MulByPow2(LFSR_S0, 8);
	f = AddM(f, v);
	v = MulByPow2(LFSR_S4, 20);
	f = AddM(f, v);
	v = MulByPow2(LFSR_S10, 21);
	f = AddM(f, v);
	v = MulByPow2(LFSR_S13, 17);
	f = AddM(f, v);
	v = MulByPow2(LFSR_S15, 15);
	f = AddM(f, v);
	/* update the state */
	LFSR_S0 = LFSR_S1;
	LFSR_S1 = LFSR_S2;
	LFSR_S2 = LFSR_S3;
	LFSR_S3 = LFSR_S4;
	LFSR_S4 = LFSR_S5;
	LFSR_S5 = LFSR_S6;
	LFSR_S6 = LFSR_S7;
	LFSR_S7 = LFSR_S8;
	LFSR_S8 = LFSR_S9;
	LFSR_S9 = LFSR_S10;
	LFSR_S10 = LFSR_S11;
	LFSR_S11 = LFSR_S12;
	LFSR_S12 = LFSR_S13;
	LFSR_S13 = LFSR_S14;
	LFSR_S14 = LFSR_S15;
	LFSR_S15 = f;
}

/* BitReorganization */
void BitReorganization(void)
{
	BRC_X0 = ((LFSR_S15 & 0x7FFF8000) << 1) | (LFSR_S14 & 0xFFFF);
	BRC_X1 = ((LFSR_S11 & 0xFFFF) << 16) | (LFSR_S9 >> 15);
	BRC_X2 = ((LFSR_S7 & 0xFFFF) << 16) | (LFSR_S5 >> 15);
	BRC_X3 = ((LFSR_S2 & 0xFFFF) << 16) | (LFSR_S0 >> 15);
}

#define ROT(a, k) (((a) << k) | ((a) >> (32 - k)))

/* L1 */
u32 L1(u32 X)
{
	return (X ^ ROT(X, 2) ^ ROT(X, 10) ^ ROT(X, 18) ^ ROT(X, 24));
}

/* L2 */
u32 L2(u32 X)
{
	return (X ^ ROT(X, 8) ^ ROT(X, 14) ^ ROT(X, 22) ^ ROT(X, 30));
}

#define MAKEU32(a, b, c, d) \
	(((u32)(a) << 24) | ((u32)(b) << 16) | ((u32)(c) << 8) | ((u32)(d)))

/* F */
u32 F()
{
	u32 W, W1, W2, u, v;
	W = (BRC_X0 ^ F_R1) + F_R2;
	W1 = F_R1 + BRC_X1;
	W2 = F_R2 ^ BRC_X2;
	u = L1((W1 << 16) | (W2 >> 16));
	v = L2((W2 << 16) | (W1 >> 16));
	F_R1 = MAKEU32(S0[u >> 24], S1[(u >> 16) & 0xFF],
			S0[(u >> 8) & 0xFF], S1[u & 0xFF]);
	F_R2 = MAKEU32(S0[v >> 24], S1[(v >> 16) & 0xFF],
			S0[(v >> 8) & 0xFF], S1[v & 0xFF]);
	return W;
}

#define MAKEU31(a, b, c) (((u32)(a) << 23) | ((u32)(b) << 8) | (u32)(c))

/* initialize */
void Initialization(u8* k, u8* iv)
{
	u32 w, nCount;

	/* expand key */
	LFSR_S0 = MAKEU31(k[0], EK_d[0], iv[0]);
	LFSR_S1 = MAKEU31(k[1], EK_d[1], iv[1]);
	LFSR_S2 = MAKEU31(k[2], EK_d[2], iv[2]);
	LFSR_S3 = MAKEU31(k[3], EK_d[3], iv[3]);
	LFSR_S4 = MAKEU31(k[4], EK_d[4], iv[4]);
	LFSR_S5 = MAKEU31(k[5], EK_d[5], iv[5]);
	LFSR_S6 = MAKEU31(k[6], EK_d[6], iv[6]);
	LFSR_S7 = MAKEU31(k[7], EK_d[7], iv[7]);
	LFSR_S8 = MAKEU31(k[8], EK_d[8], iv[8]);
	LFSR_S9 = MAKEU31(k[9], EK_d[9], iv[9]);
	LFSR_S10 = MAKEU31(k[10], EK_d[10], iv[10]);
	LFSR_S11 = MAKEU31(k[11], EK_d[11], iv[11]);
	LFSR_S12 = MAKEU31(k[12], EK_d[12], iv[12]);
	LFSR_S13 = MAKEU31(k[13], EK_d[13], iv[13]);
	LFSR_S14 = MAKEU31(k[14], EK_d[14], iv[14]);
	LFSR_S15 = MAKEU31(k[15], EK_d[15], iv[15]);

	/* set F_R1 and F_R2 to zero */
	F_R1 = 0;
	F_R2 = 0;
	nCount = 32;
	while (nCount > 0)
	{
		BitReorganization();
		w = F();
		LFSRWithInitialisationMode(w >> 1);
		nCount --;
	}
}

void GenerateKeystream(u32* pKeystream, int KeystreamLen)
{
	int i;

	{
		BitReorganization();
		F(); /* discard the output of F */
		LFSRWithWorkMode();
	}

	for (i = 0; i < KeystreamLen; i ++)
	{
		BitReorganization();
		pKeystream[i] = F() ^ BRC_X3;
		LFSRWithWorkMode();
	}
}

/* The ZUC algorithm, see ref. [3]*/
void ZUC(u8* k, u8* iv, u32* ks, int len)
{
	/* The initialization of ZUC, see page 17 of ref. [3]*/
	Initialization(k, iv);
	/* The procedure of generating keystream of ZUC, see page 18 of ref. [3]*/
	GenerateKeystream(ks, len);
}

void EEA3(u8* CK, u32 COUNT, u32 BEARER, u32 DIRECTION, u32 LENGTH, u32* M, u32* C)
{
	u32 *z, L, i;
	u8 IV[16];

	L = (LENGTH+31)/32;
	z = (u32 *) malloc(L*sizeof(u32));
	IV[0] = (COUNT>>24) & 0xFF;
	IV[1] = (COUNT>>16) & 0xFF;
	IV[2] = (COUNT>>8) & 0xFF;
	IV[3] = COUNT & 0xFF;

	IV[4] = ((BEARER << 3) | ((DIRECTION&1)<<2)) & 0xFC;
	IV[5] = 0;
	IV[6] = 0;
	IV[7] = 0;

	IV[8] = IV[0];
	IV[9] = IV[1];
	IV[10] = IV[2];
	IV[11] = IV[3];

	IV[12] = IV[4];
	IV[13] = IV[5];
	IV[14] = IV[6];
	IV[15] = IV[7];

	ZUC(CK, IV, z, L);
	for (i=0; i<L; i++) {
		C[i] = M[i] ^ z[i];
	}
	free(z);
}

u32 GET_WORD(u32 * DATA, u32 i)
{
	u32 WORD, ti;
	ti = i % 32;

	if (ti == 0) {
		WORD = DATA[i/32];
	}
	else {
		WORD = (DATA[i/32]<<ti) | (DATA[i/32+1]>>(32-ti));
	}
	return WORD;
}

u8 GET_BIT(u32 * DATA, u32 i)
{
	return (DATA[i/32] & (1<<(31-(i%32)))) ? 1 : 0;
}

void EIA3(u8* IK, u32 COUNT, u32 DIRECTION, u32 BEARER, u32 LENGTH, u32* M, u32* MAC)
{
	u32 *z, N, L, T, i;
	u8 IV[16];

	IV[0] = (COUNT>>24) & 0xFF;
	IV[1] = (COUNT>>16) & 0xFF;
	IV[2] = (COUNT>>8) & 0xFF;
	IV[3] = COUNT & 0xFF;

	IV[4] = (BEARER << 3) & 0xF8;
	IV[5] = IV[6] = IV[7] = 0;

	IV[8] = ((COUNT>>24) & 0xFF) ^ ((DIRECTION&1)<<7);
	IV[9] = (COUNT>>16) & 0xFF;
	IV[10] = (COUNT>>8) & 0xFF;
	IV[11] = COUNT & 0xFF;

	IV[12] = IV[4];
	IV[13] = IV[5];
	IV[14] = IV[6] ^ ((DIRECTION&1)<<7);
	IV[15] = IV[7];

	N = LENGTH + 64;
	L = (N + 31) / 32;
	z = (u32 *) malloc(L*sizeof(u32));
	ZUC(IK, IV, z, L);

	T = 0;
	for (i = 0; i < LENGTH; i++) {
		if (GET_BIT(M,i)) {
			T ^= GET_WORD(z,i);
		}
	}
	T ^= GET_WORD(z,LENGTH);

	*MAC = T ^ z[L-1];
	free(z);
}
