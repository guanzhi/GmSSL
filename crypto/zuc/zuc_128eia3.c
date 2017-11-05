/* ====================================================================
 * Copyright (c) 2015 - 2016 The GmSSL Project.  All rights reserved.
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

#include <openssl/zuc.h>
#include "zuc_lcl.h"

void eea3_init(eea3_ctx_t *ctx, const unsigned char *user_key,
	uint32_t count, uint32_t bearer, int direction)
{
	unsigned char iv[16] = {0};
	iv[0] = iv[8]  = (count >> 24) & 0xff;
	iv[1] = iv[9]  = (count >> 16) & 0xff;
	iv[2] = iv[10] = (count >>  8) & 0xff;
	iv[3] = iv[11] =  count        & 0xff;
	iv[4] = iv[12] = ((bearer << 3) | ((direction & 1) << 2)) & 0xfc;

	zuc_ctx_init(ctx->zuc_ctx, user_key, iv);
}

void eea3_encrypt(eea3_ctx_t *ctx, size_t len, const unsigned char *in, unsigned char *out);



void eea3(const unsigned char *key, uint32_t count, uint32_t bearer, int direction,
	size_t len, const unsigned char *in, unsigned char *out);



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

void EIA3(u8* IK, u32 count, u32 DIRECTION, u32 BEARER, u32 LENGTH, u32* M, u32* MAC)
{
	u32 *z, N, L, T, i;
	u8 iv[16];

	iv[0] = (count>>24) & 0xFF;
	iv[1] = (count>>16) & 0xFF;
	iv[2] = (count>>8) & 0xFF;
	iv[3] = count & 0xFF;

	iv[4] = (BEARER << 3) & 0xF8;
	iv[5] = iv[6] = iv[7] = 0;

	iv[8] = ((count>>24) & 0xFF) ^ ((DIRECTION&1)<<7);
	iv[9] = (count>>16) & 0xFF;
	iv[10] = (count>>8) & 0xFF;
	iv[11] = count & 0xFF;

	iv[12] = iv[4];
	iv[13] = iv[5];
	iv[14] = iv[6] ^ ((DIRECTION&1)<<7);
	iv[15] = iv[7];

	N = LENGTH + 64;
	L = (N + 31) / 32;
	z = (u32 *) malloc(L*sizeof(u32));
	ZUC(IK, iv, z, L);

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
