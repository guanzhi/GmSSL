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
			printf("md5 test %zu ok\n", i+1);
		}
	}

	return err;
}
