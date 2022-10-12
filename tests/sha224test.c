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
#define TEST5	"\x07"
#define TEST6	"\x18\x80\x40\x05\xdd\x4f\xbd\x15\x56\x29\x9d\x6f\x9d\x93\xdf\x62"
#define TEST7	\
  "\x55\xb2\x10\x07\x9c\x61\xb5\x3a\xdd\x52\x06\x22\xd1\xac\x97\xd5" \
  "\xcd\xbe\x8c\xb3\x3a\xa0\xae\x34\x45\x17\xbe\xe4\xd7\xba\x09\xab" \
  "\xc8\x53\x3c\x52\x50\x88\x7a\x43\xbe\xbb\xac\x90\x6c\x2e\x18\x37" \
  "\xf2\x6b\x36\xa5\x9a\xe3\xbe\x78\x14\xd5\x06\x89\x6b\x71\x8b\x2a" \
  "\x38\x3e\xcd\xac\x16\xb9\x61\x25\x55\x3f\x41\x6f\xf3\x2c\x66\x74" \
  "\xc7\x45\x99\xa9\x00\x53\x86\xd9\xce\x11\x12\x24\x5f\x48\xee\x47" \
  "\x0d\x39\x6c\x1e\xd6\x3b\x92\x67\x0c\xa5\x6e\xc8\x4d\xee\xa8\x14" \
  "\xb6\x13\x5e\xca\x54\x39\x2b\xde\xdb\x94\x89\xbc\x9b\x87\x5a\x8b" \
  "\xaf\x0d\xc1\xae\x78\x57\x36\x91\x4a\xb7\xda\xa2\x64\xbc\x07\x9d" \
  "\x26\x9f\x2c\x0d\x7e\xdd\xd8\x10\xa4\x26\x14\x5a\x07\x76\xf6\x7c" \
  "\x87\x82\x73"


#define DGST1	"23097D223405D8228642A477BDA255B32AADBCE4BDA0B3F7E36C9DA7"
#define DGST2	"75388B16512776CC5DBA5DA1FD890150B0C6455CB4F58B1952522525"
#define DGST3	"20794655980C91D8BBB4C1EA97618A4BF03F42581948B2EE4EE7AD67"
#define DGST4	"567F69F168CD7844E65259CE658FE7AADFA25216E68ECA0EB7AB8262"
#define DGST5	"00ECD5F138422B8AD74C9799FD826C531BAD2FCABC7450BEE2AA8C2A"
#define DGST6	"DF90D78AA78821C99B40BA4C966921ACCD8FFB1E98AC388E56191DB1"
#define DGST7	"0B31894EC8937AD9B91BDFBCBA294D9ADEFAA18E09305E9F20D5C3A4"

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
	SHA224_CTX ctx;
	uint8_t dgst[SHA224_DIGEST_SIZE];
	uint8_t dgstbuf[SHA224_DIGEST_SIZE];
	size_t dgstlen;
	size_t i, j;

	for (i = 0; i < 7; i++) {
		hex_to_bytes(tests[i].dgsthex, strlen(tests[i].dgsthex), dgstbuf, &dgstlen);

		sha224_init(&ctx);
		for (j = 0; j < tests[i].count; j++) {
			sha224_update(&ctx, (uint8_t *)tests[i].data, tests[i].length);
		}
		sha224_finish(&ctx, dgst);

		if (memcmp(dgstbuf, dgst, sizeof(dgst)) != 0) {
			printf("sha224 test %zu failed\n", i+1);
			printf("%s\n", tests[i].dgsthex);
			for (j = 0; j < sizeof(dgst); j++) {
				printf("%02X", dgst[j]);
			}
			printf("\n");
			err++;
		} else {
			printf("sha224 test %zu ok\n", i+1);
		}
	}

	return err;
}
