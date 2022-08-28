/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/chacha20.h>
#include <gmssl/endian.h>


void chacha20_init(CHACHA20_STATE *state,
	const uint8_t key[CHACHA20_KEY_SIZE],
	const uint8_t nonce[CHACHA20_NONCE_SIZE],
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

void chacha20_generate_keystream(CHACHA20_STATE *state, size_t counts, uint8_t *out)
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
