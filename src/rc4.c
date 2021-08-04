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
