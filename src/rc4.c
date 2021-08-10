/* 
 *   Copyright 2014-2021 The GmSSL Project Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/rc4.h>

void rc4_set_key(RC4_STATE *state, const unsigned char *key, size_t keylen)
{
	int i, j;
	unsigned char *s = state->d;
	unsigned char k[256];
	unsigned char temp;

	/* expand key */
	for (i = 0; i < keylen; i++) {
		k[i] = key[i];
	}
	for (i = keylen; i < 256; i++) {
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

void rc4_generate_keystream(RC4_STATE *state, size_t outlen, unsigned char *out)
{
	int i = 0, j = 0;
	unsigned char *s = state->d;
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

unsigned char rc4_generate_keybyte(RC4_STATE *state)
{
	unsigned char out[1];
	rc4_generate_keystream(state, 1, out);
	return out[0];
}
