/*
 * Copyright (c) 2014 - 2020 The GmSSL Project.  All rights reserved.
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
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/chacha20.h>
#include "endian.h"

void chacha20_set_key(CHACHA20_STATE *state,
	const unsigned char key[CHACHA20_KEY_SIZE],
	const unsigned char nonce[CHACHA20_NONCE_SIZE],
	uint32_t counter)
{
	state->d[ 0] = 0x61707865;
	state->d[ 1] = 0x3320646e;
	state->d[ 2] = 0x79622d32;
	state->d[ 3] = 0x6b206574;
	state->d[ 4] = GETU32_LE(key     );
	state->d[ 5] = GETU32_LE(key +  4);
	state->d[ 6] = GETU32_LE(key +  8);
	state->d[ 7] = GETU32_LE(key + 12);
	state->d[ 8] = GETU32_LE(key + 16);
	state->d[ 9] = GETU32_LE(key + 20);
	state->d[10] = GETU32_LE(key + 24);
	state->d[11] = GETU32_LE(key + 28);
	state->d[12] = counter;
	state->d[13] = GETU32_LE(nonce);
	state->d[14] = GETU32_LE(nonce + 4);
	state->d[15] = GETU32_LE(nonce + 8);
}

/* quarter round */
#define QR(A, B, C, D) \
	A += B; D ^= A; D = ROL32(D, 16); \
	C += D; B ^= C; B = ROL32(B, 12); \
	A += B; D ^= A; D = ROL32(D,  8); \
	C += D; B ^= C; B = ROL32(B,  7)

/* double round on state 4x4 matrix:
 * four column rounds and and four diagonal rounds
 *
 *   0   1   2   3
 *   4   5   6   7
 *   8   9  10  11
 *  12  13  14  15
 *
 */
#define DR(S) \
	QR(S[0], S[4], S[ 8], S[12]);  \
	QR(S[1], S[5], S[ 9], S[13]);  \
	QR(S[2], S[6], S[10], S[14]);  \
	QR(S[3], S[7], S[11], S[15]);  \
	QR(S[0], S[5], S[10], S[15]);  \
	QR(S[1], S[6], S[11], S[12]);  \
	QR(S[2], S[7], S[ 8], S[13]);  \
	QR(S[3], S[4], S[ 9], S[14])

void chacha20_generate_keystream(CHACHA20_STATE *state, unsigned int counts, unsigned char *out)
{
	uint32_t working_state[16];
	int i;

	while (counts-- > 0) {
		memcpy(working_state, state->d, sizeof(working_state));
		for (i = 0; i < 10; i++) {
			DR(working_state);
		}
		for (i = 0; i < 16; i++) {
			working_state[i] += state->d[i];
			PUTU32_LE(out, working_state[i]);
			out += sizeof(uint32_t);
		}
		state->d[12]++;
	}
}
