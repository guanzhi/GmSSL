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
			printf("sha1 test %zu failed\n", i+1);
			printf("%s\n", dgsthex[i]);
			for (j = 0; j < sizeof(dgst); j++) {
				printf("%02X", dgst[j]);
			}
			printf("\n");
			err++;
		} else {
			printf("sha1 test %zu ok\n", i+1);
		}
	}

	return err;
}
