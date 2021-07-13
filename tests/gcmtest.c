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
#include <gmssl/gcm.h>


struct {
	char *K;
	char *P;
	char *IV;
	char *C;
	char *T;
} gcm_tests[] = {
	/* test 1 */
	{
		"00000000000000000000000000000000",
		"",
		"000000000000000000000000",
		"",
		"58e2fccefa7e3061367f1d57a4e7455a",
	},
	/* test 2 */
	{
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"000000000000000000000000",
		"0388dace60b6a392f328c2b971b2fe78",
		"ab6e47d42cec13bdf53a67b21257bddf",
	},
}

int main(void)
{
	int err = 0;
	GCM_CTX ctx;
	uint8_t *key = NULL;
	uint8_t *iv = NULL;
	uint8_t *p = NULL;
	uint8_t *c = NULL;
	uint8_t *tag = NULL;
	size_t keylen, ivlen, plen, clen, taglen, len, i;

	for (i = 0; i < sizeof(gcm_tests)/sizeof(gcm_tests[0]); i++) {

		key = OPENSSL_hexstr2buf(gcm_tests[i].K, &keylen);
		iv = OPENSSL_hexstr2buf(gcm_tests[i].IV, &ivlen);
		p = OPENSSL_hexstr2buf(gcm_tests[i].P, &plen);
		c = OPENSSL_hexstr2buf(gcm_tests[i].C, &clen);
		tag = OPENSSL_hexstr2buf(gcm_tests[i].T, &taglen);
		buf = malloc(plen);

		gcm_init(&ctx, taglen, key, keylen, iv, ivlen, aad, aadlen);
		gcm_update(&ctx, p, plen, buf, &len);
		if (!gcm_finish_verify(&ctx, tag, taglen)) {
			printf("gcm test %zu failed\n", i+1);
			err++;
		} else {
			printf("gcm test %zu ok\n", i+1);
		}

		free(key);
		free(iv);
		free(p);
		free(c);
		free(tag);
		free(buf);
	}

	return err;
}
