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
#include <gmssl/hex.h>
#include <gmssl/sha2.h>


#define TEST1	"abc"
#define TEST2	"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
#define TEST3	"a"
#define TEST4	"0123456701234567012345670123456701234567012345670123456701234567"
#define TEST5	"\x19"
#define TEST6	"\xe3\xd7\x25\x70\xdc\xdd\x78\x7c\xe3\x88\x7a\xb2\xcd\x68\x46\x52"
#define TEST7	"\x83\x26\x75\x4e\x22\x77\x37\x2f\x4f\xc1\x2b\x20\x52\x7a\xfe\xf0" \
		"\x4d\x8a\x05\x69\x71\xb1\x1a\xd5\x71\x23\xa7\xc1\x37\x76\x00\x00" \
		"\xd7\xbe\xf6\xf3\xc1\xf7\xa9\x08\x3a\xa3\x9d\x81\x0d\xb3\x10\x77" \
		"\x7d\xab\x8b\x1e\x7f\x02\xb8\x4a\x26\xc7\x73\x32\x5f\x8b\x23\x74" \
		"\xde\x7a\x4b\x5a\x58\xcb\x5c\x5c\xf3\x5b\xce\xe6\xfb\x94\x6e\x5b" \
		"\xd6\x94\xfa\x59\x3a\x8b\xeb\x3f\x9d\x65\x92\xec\xed\xaa\x66\xca" \
		"\x82\xa2\x9d\x0c\x51\xbc\xf9\x33\x62\x30\xe5\xd7\x84\xe4\xc0\xa4" \
		"\x3f\x8d\x79\xa3\x0a\x16\x5c\xba\xbe\x45\x2b\x77\x4b\x9c\x71\x09" \
		"\xa9\x7d\x13\x8f\x12\x92\x28\x96\x6f\x6c\x0a\xdc\x10\x6a\xad\x5a" \
		"\x9f\xdd\x30\x82\x57\x69\xb2\xc6\x71\xaf\x67\x59\xdf\x28\xeb\x39" \
		"\x3d\x54\xd6"

#define DGST1	"BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
#define DGST2	"248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1"
#define DGST3	"CDC76E5C9914FB9281A1C7E284D73E67F1809A48A497200E046D39CCC7112CD0"
#define DGST4	"594847328451BDFA85056225462CC1D867D877FB388DF0CE35F25AB5562BFBB5"
#define DGST5	"68AA2E2EE5DFF96E3355E6C7EE373E3D6A4E17F75F9518D843709C0C9BC3E3D4"
#define DGST6	"175EE69B02BA9B58E2B0A5FD13819CEA573F3940A94F825128CF4209BEABB4E8"
#define DGST7	"97DBCA7DF46D62C8A422C941DD7E835B8AD3361763F7E9B2D95F4F0DA6E1CCBC"

struct {
	char *data;
	size_t length;
	size_t count;
	char *dgsthex;
} tests[7] = {
	{TEST1, sizeof(TEST1) - 1, 1,       DGST1},
	{TEST2, sizeof(TEST2) - 1, 1,       DGST2},
	{TEST3, sizeof(TEST3) - 1, 1000000, DGST3},
	{TEST4, sizeof(TEST4) - 1, 10,      DGST4},
	{TEST5, sizeof(TEST5) - 1, 1,       DGST5},
	{TEST6, sizeof(TEST6) - 1, 1,       DGST6},
	{TEST7, sizeof(TEST7) - 1, 1,       DGST7},
};

int main(int argc, char **argv)
{
	int err = 0;
	SHA256_CTX ctx;
	uint8_t dgst[SHA256_DIGEST_SIZE];
	uint8_t dgstbuf[SHA256_DIGEST_SIZE];
	size_t dgstlen;
	size_t i, j;

	for (i = 0; i < 7; i++) {
		hex_to_bytes(tests[i].dgsthex, strlen(tests[i].dgsthex), dgstbuf, &dgstlen);

		sha256_init(&ctx);
		for (j = 0; j < tests[i].count; j++) {
			sha256_update(&ctx, (uint8_t *)tests[i].data, tests[i].length);
		}
		sha256_finish(&ctx, dgst);

		if (memcmp(dgstbuf, dgst, sizeof(dgst)) != 0) {
			printf("sha256 test %zu failed\n", i+1);
			printf("%s\n", tests[i].dgsthex);
			for (j = 0; j < sizeof(dgst); j++) {
				printf("%02X", dgst[j]);
			}
			printf("\n");
			err++;
		} else {
			printf("sha256 test %zu ok\n", i+1);
		}
	}

	return err;
}
