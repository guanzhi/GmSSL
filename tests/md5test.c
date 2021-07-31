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
#include <gmssl/md5.h>
#include <gmssl/hex.h>


static char *teststr[] = {
	"",
	"a",
	"abc",
	"message digest",
	"abcdefghijklmnopqrstuvwxyz",
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
	"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
};

static char *dgsthex[] = {
	"d41d8cd98f00b204e9800998ecf8427e",
	"0cc175b9c0f1b6a831c399e269772661",
	"900150983cd24fb0d6963f7d28e17f72",
	"f96b697d7cb7938d525a2f31aaf161d0",
	"c3fcd3d76192e4007dfb496cca67e13b",
	"d174ab98d277d9f5a5611c2c9f419d9f",
	"57edf4a22be3c955ac49da2e2107b67a",
};

int main(int argc, char **argv)
{
	int err = 0;
	char *p;
	uint8_t dgst[16];
	uint8_t dgstbuf[16];
	size_t dgstbuflen;
	size_t i;

	for (i = 0; i < sizeof(teststr)/sizeof(teststr[0]); i++) {
		hex_to_bytes(dgsthex[i], strlen(dgsthex[i]), dgstbuf, &dgstbuflen);
		md5_digest((uint8_t *)teststr[i], strlen(teststr[i]), dgst);

		if (memcmp(dgstbuf, dgst, sizeof(dgst)) != 0) {
			int n;
			printf("error calculating MD5 on %s\n", teststr[i]);
			printf(" digest(corret) = ");
			for (n = 0; n < sizeof(dgst); n++) {
				printf("%02X", dgst[n]);
			}
			printf("\n");
			printf(" digest(error)  = %s\n", dgsthex[i]);
			err++;
		} else {
			printf("md5 test %lu ok\n", i+1);
		}
	}

	return err;
}
