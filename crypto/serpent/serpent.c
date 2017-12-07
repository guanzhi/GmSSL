/* ====================================================================
 * Copyright (c) 2014 - 2017 The GmSSL Project.  All rights reserved.
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
/**
Copyright © 2015 Odzhan
Copyright © 2008 Daniel Otte
All Rights Reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:
1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.
3. The name of the author may not be used to endorse or promote products
derived from this software without specific prior written permission.
THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE. */

#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/serpent.h>
#include "serpent_locl.h"

static void serpent_whiten(serpent_blk *dst, serpent_key_t *src, int idx) {
	uint8_t i;
	serpent_blk *p = (serpent_blk*)&src->x[idx];

	for (i = 0; i<SERPENT_BLOCK_SIZE / 4; i++) {
		dst->w[i] ^= p->w[i];
	}
}

static void permute(serpent_blk *out, serpent_blk *in, int type)
{
	uint8_t cy;
	uint8_t n, m;

	for (n = 0; n<SERPENT_BLOCK_SIZE / 4; n++) {
		out->w[n] = 0;
	}

	if (type == SERPENT_IP)
	{
		for (n = 0; n<16; n++) {
			for (m = 0; m<8; m++) {
				cy = in->w[m % 4] & 1;
				in->w[m % 4] >>= 1;
				out->b[n] = (cy << 7) | (out->b[n] >> 1);
			}
		}
	}
	else {
		for (n = 0; n<4; n++) {
			for (m = 0; m<32; m++) {
				cy = in->w[n] & 1;
				in->w[n] >>= 1;
				out->w[m % 4] = (cy << 31) | (out->w[m % 4] >> 1);
			}
		}
	}
}

#define HI_NIBBLE(b) (((b) >> 4) & 0x0F)
#define LO_NIBBLE(b) ((b) & 0x0F)

static uint32_t serpent_gen_w(uint32_t *b, uint32_t i) {
	uint32_t ret;
	ret = b[0] ^ b[3] ^ b[5] ^ b[7] ^ GOLDEN_RATIO ^ i;
	return ROTL32(ret, 11);
}

static void serpent_subbytes(serpent_blk *blk, uint32_t box_idx, int type)
{
	serpent_blk tmp_blk, sb;
	uint8_t *sbp;
	uint8_t i, t;

	uint8_t sbox[8][8] =
	{ { 0x83, 0x1F, 0x6A, 0xB5, 0xDE, 0x24, 0x07, 0xC9 },
	{ 0xCF, 0x72, 0x09, 0xA5, 0xB1, 0x8E, 0xD6, 0x43 },
	{ 0x68, 0x97, 0xC3, 0xFA, 0x1D, 0x4E, 0xB0, 0x25 },
	{ 0xF0, 0x8B, 0x9C, 0x36, 0x1D, 0x42, 0x7A, 0xE5 },
	{ 0xF1, 0x38, 0x0C, 0x6B, 0x52, 0xA4, 0xE9, 0xD7 },
	{ 0x5F, 0xB2, 0xA4, 0xC9, 0x30, 0x8E, 0x6D, 0x17 },
	{ 0x27, 0x5C, 0x48, 0xB6, 0x9E, 0xF1, 0x3D, 0x0A },
	{ 0xD1, 0x0F, 0x8E, 0xB2, 0x47, 0xAC, 0x39, 0x65 }
	};

	uint8_t sbox_inv[8][8] =
	{ { 0x3D, 0x0B, 0x6A, 0xC5, 0xE1, 0x74, 0x9F, 0x28 },
	{ 0x85, 0xE2, 0x6F, 0x3C, 0x4B, 0x97, 0xD1, 0x0A },
	{ 0x9C, 0x4F, 0xEB, 0x21, 0x30, 0xD6, 0x85, 0x7A },
	{ 0x90, 0x7A, 0xEB, 0xD6, 0x53, 0x2C, 0x84, 0x1F },
	{ 0x05, 0x38, 0x9A, 0xE7, 0xC2, 0x6B, 0xF4, 0x1D },
	{ 0xF8, 0x92, 0x14, 0xED, 0x6B, 0x35, 0xC7, 0x0A },
	{ 0xAF, 0xD1, 0x35, 0x06, 0x94, 0x7E, 0xC2, 0xB8 },
	{ 0x03, 0xD6, 0xE9, 0x8F, 0xC5, 0x7B, 0x1A, 0x24 }
	};

	box_idx &= 7;

	if (type == SERPENT_ENCRYPT) {
		sbp = (uint8_t*)&sbox[box_idx][0];
	}
	else {
		sbp = (uint8_t*)&sbox_inv[box_idx][0];
	}

	for (i = 0; i<16; i += 2) {
		t = sbp[i / 2];
		sb.b[i + 0] = LO_NIBBLE(t);
		sb.b[i + 1] = HI_NIBBLE(t);
	}

	permute(&tmp_blk, blk, SERPENT_IP);

	for (i = 0; i<SERPENT_BLOCK_SIZE; i++) {
		t = tmp_blk.b[i];
		tmp_blk.b[i] = (sb.b[HI_NIBBLE(t)] << 4) | sb.b[LO_NIBBLE(t)];
	}
	permute(blk, &tmp_blk, SERPENT_FP);
}

static void serpent_lt(serpent_blk* x, int enc)
{
	uint32_t x0, x1, x2, x3;

	/* load */
	x0 = x->w[0];
	x1 = x->w[1];
	x2 = x->w[2];
	x3 = x->w[3];

	if (enc == SERPENT_DECRYPT) {
		x2 = ROTL32(x2, 10);
		x0 = ROTR32(x0, 5);
		x2 ^= x3 ^ (x1 << 7);
		x0 ^= x1 ^ x3;
		x3 = ROTR32(x3, 7);
		x1 = ROTR32(x1, 1);
		x3 ^= x2 ^ (x0 << 3);
		x1 ^= x0 ^ x2;
		x2 = ROTR32(x2, 3);
		x0 = ROTR32(x0, 13);
	}
	else {
		x0 = ROTL32(x0, 13);
		x2 = ROTL32(x2, 3);
		x1 ^= x0 ^ x2;
		x3 ^= x2 ^ (x0 << 3);
		x1 = ROTL32(x1, 1);
		x3 = ROTL32(x3, 7);
		x0 ^= x1 ^ x3;
		x2 ^= x3 ^ (x1 << 7);
		x0 = ROTL32(x0, 5);
	    x2 = ROTR32(x2, 10);
	}
	x->w[0] = x0;
	x->w[1] = x1;
	x->w[2] = x2;
	x->w[3] = x3;
}

void serpent_set_encrypt_key(serpent_key_t *key, const unsigned char *user_key)
{
	union {
		uint8_t b[32];
		uint32_t w[8];
	} s_ws;

	uint32_t i, j;

	/* copy key input to local buffer */
	memcpy(&s_ws.b[0], user_key, SERPENT_KEY256);

	/* expand the key */
	for (i = 0; i <= SERPENT_ROUNDS; i++) {
		for (j = 0; j<4; j++) {
			key->x[i][j] = serpent_gen_w(s_ws.w, i * 4 + j);
			memmove(&s_ws.b, &s_ws.b[4], 7 * 4);
			s_ws.w[7] = key->x[i][j];
		}
		serpent_subbytes((serpent_blk*)&key->x[i], 3 - i, SERPENT_ENCRYPT);
	}
}

void serpent_set_decrypt_key(serpent_key_t *key, const unsigned char *user_key)
{
    	union {
		uint8_t b[32];
		uint32_t w[8];
	} s_ws;

	uint32_t i, j;

	/* copy key input to local buffer */
	memcpy(&s_ws.b[0], user_key, SERPENT_KEY256);

	/* expand the key */
	for (i = 0; i <= SERPENT_ROUNDS; i++) {
		for (j = 0; j<4; j++) {
			key->x[i][j] = serpent_gen_w(s_ws.w, i * 4 + j);
			memmove(&s_ws.b, &s_ws.b[4], 7 * 4);
			s_ws.w[7] = key->x[i][j];
		}
		serpent_subbytes((serpent_blk*)&key->x[i], 3 - i, SERPENT_ENCRYPT);
	}
}

void serpent_encrypt(const void *in, void *out, serpent_key_t *key)
{
	int8_t i;
	serpent_blk *_out = out;
    	memcpy(out, in, SERPENT_BLOCK_SIZE);

	i = 0;
	for (;;) {
		/* xor with subkey */
		serpent_whiten(_out, key, i);
		/* apply sbox */
		serpent_subbytes(_out, i, SERPENT_ENCRYPT);
		if (++i == SERPENT_ROUNDS) 
            break;
		/* linear transformation */
		serpent_lt(_out, SERPENT_ENCRYPT);
	}
	serpent_whiten(_out, key, i);
}

void serpent_decrypt(const void *in, void *out, serpent_key_t *key)
{
	int8_t i;
	serpent_blk *_out = out;
    	memcpy(out, in, SERPENT_BLOCK_SIZE);


	i = SERPENT_ROUNDS;
	serpent_whiten(_out, key, i);
	for (;;) {
		--i;
		/* apply sbox */
		serpent_subbytes(_out, i, SERPENT_DECRYPT);
		/* xor with subkey */
		serpent_whiten(_out, key, i);
		if (i == 0) 
            break;
		/* linear transformation */
		serpent_lt(_out, SERPENT_DECRYPT);
	}
}
