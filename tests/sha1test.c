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
#include <stdint.h>
#include <gmssl/sha1.h>
#include <gmssl/hex.h>


static char *teststr[] = {
	"abc",
	"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	"a",
	"0123456701234567012345670123456701234567012345670123456701234567",
};

static size_t testcnt[] = {
	1,
	1,
	1000000,
	10,
};

static char *dgsthex[] = {
	"A9993E364706816ABA3E25717850C26C9CD0D89D",
	"84983E441C3BD26EBAAE4AA1F95129E5E54670F1",
	"34AA973CD4C4DAA4F61EEB2BDBAD27316534016F",
	"DEA356A2CDDD90C7A7ECEDC5EBB563934F460452",
};

int main(void)
{
	int err = 0;
	SHA1_CTX ctx;
	uint8_t dgst[20];
	uint8_t dgstbuf[20];
	size_t dgstlen;
	size_t i, j;

	for (i = 0; i < sizeof(teststr)/sizeof(teststr[0]); i++) {
		hex_to_bytes(dgsthex[i], strlen(dgsthex[i]), dgstbuf, &dgstlen);

		sha1_init(&ctx);
		for (j = 0; j < testcnt[i]; j++) {
			sha1_update(&ctx, (uint8_t *)teststr[i], strlen(teststr[i]));
		}
		sha1_finish(&ctx, dgst);

		if (memcmp(dgstbuf, dgst, sizeof(dgst)) != 0) {
			printf("sha1 test %lu failed\n", i+1);
			printf("%s\n", dgsthex[i]);
			for (j = 0; j < sizeof(dgst); j++) {
				printf("%02X", dgst[j]);
			}
			printf("\n");
			err++;
		} else {
			printf("sha1 test %lu ok\n", i+1);
		}
	}

	return err;
}
