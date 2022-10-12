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
#include <gmssl/rc4.h>

void rc4_init(RC4_STATE *state, const uint8_t *key, size_t keylen)
{
	int i, j;
	uint8_t *s = state->d;
	uint8_t k[256] = {0};
	uint8_t temp;

	if (keylen > sizeof(k)) {
		keylen = sizeof(k);
	}

	/* expand key */
	for (i = 0; i < (int)keylen; i++) {
		k[i] = key[i];
	}
	for (; i < 256; i++) {
		k[i] = key[i % keylen];
	}

	/* init state */
	for (i = 0; i < 256; i++) {
		s[i] = i;
	}

	/* shuffle state with key */
	j = 0;
	for (i = 0; i < 256; i++) {
		j = (j + s[i] + k[i]) % 256;

		/* swap(s[i], s[j]) */
		temp = s[j];
		s[j] = s[i];
		s[i] = temp;
	}

	/* clean expanded temp key */
	memset(k, 0, sizeof(k));
}

void rc4_generate_keystream(RC4_STATE *state, size_t outlen, uint8_t *out)
{
	int i = 0, j = 0;
	uint8_t *s = state->d;
	int oi;
	int temp;

	while (outlen > 0) {
		i = (i + 1) % 256;
		j = (j + s[i]) % 256;

		/* swap(s[i], s[j]) */
		temp = s[j];
		s[j] = s[i];
		s[i] = temp;

		oi = (s[i] + s[j]) % 256;
		*out++ = s[oi];

		outlen--;
	}
}

uint8_t rc4_generate_keybyte(RC4_STATE *state)
{
	uint8_t out[1];
	rc4_generate_keystream(state, 1, out);
	return out[0];
}
