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
#define TEST2	"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn" \
		"hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
#define TEST3	"a"
#define TEST4	"0123456701234567012345670123456701234567012345670123456701234567"
#define TEST5	"\xb9"
#define TEST6	"\xa4\x1c\x49\x77\x79\xc0\x37\x5f\xf1\x0a\x7f\x4e\x08\x59\x17\x39"
#define TEST7	"\x39\x96\x69\xe2\x8f\x6b\x9c\x6d\xbc\xbb\x69\x12\xec\x10\xff\xcf" \
		"\x74\x79\x03\x49\xb7\xdc\x8f\xbe\x4a\x8e\x7b\x3b\x56\x21\xdb\x0f" \
		"\x3e\x7d\xc8\x7f\x82\x32\x64\xbb\xe4\x0d\x18\x11\xc9\xea\x20\x61" \
		"\xe1\xc8\x4a\xd1\x0a\x23\xfa\xc1\x72\x7e\x72\x02\xfc\x3f\x50\x42" \
		"\xe6\xbf\x58\xcb\xa8\xa2\x74\x6e\x1f\x64\xf9\xb9\xea\x35\x2c\x71" \
		"\x15\x07\x05\x3c\xf4\xe5\x33\x9d\x52\x86\x5f\x25\xcc\x22\xb5\xe8" \
		"\x77\x84\xa1\x2f\xc9\x61\xd6\x6c\xb6\xe8\x95\x73\x19\x9a\x2c\xe6" \
		"\x56\x5c\xbd\xf1\x3d\xca\x40\x38\x32\xcf\xcb\x0e\x8b\x72\x11\xe8" \
		"\x3a\xf3\x2a\x11\xac\x17\x92\x9f\xf1\xc0\x73\xa5\x1c\xc0\x27\xaa" \
		"\xed\xef\xf8\x5a\xad\x7c\x2b\x7c\x5a\x80\x3e\x24\x04\xd9\x6d\x2a" \
		"\x77\x35\x7b\xda\x1a\x6d\xae\xed\x17\x15\x1c\xb9\xbc\x51\x25\xa4" \
		"\x22\xe9\x41\xde\x0c\xa0\xfc\x50\x11\xc2\x3e\xcf\xfe\xfd\xd0\x96" \
		"\x76\x71\x1c\xf3\xdb\x0a\x34\x40\x72\x0e\x16\x15\xc1\xf2\x2f\xbc" \
		"\x3c\x72\x1d\xe5\x21\xe1\xb9\x9b\xa1\xbd\x55\x77\x40\x86\x42\x14" \
		"\x7e\xd0\x96"

#define DGST1	"CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED8086072BA1E7CC2358BAECA134C825A7"
#define DGST2	"09330C33F71147E83D192FC782CD1B4753111B173B3B05D22FA08086E3B0F712FCC7C71A557E2DB966C3E9FA91746039"
#define DGST3	"9D0E1809716474CB086E834E310A4A1CED149E9C00F248527972CEC5704C2A5B07B8B3DC38ECC4EBAE97DDD87F3D8985"
#define DGST4	"2FC64A4F500DDB6828F6A3430B8DD72A368EB7F3A8322A70BC84275B9C0B3AB00D27A5CC3C2D224AA6B61A0D79FB4596"
#define DGST5	"BC8089A19007C0B14195F4ECC74094FEC64F01F90929282C2FB392881578208AD466828B1C6C283D2722CF0AD1AB6938"
#define DGST6	"C9A68443A005812256B8EC76B00516F0DBB74FAB26D665913F194B6FFB0E91EA9967566B58109CBC675CC208E4C823F7"
#define DGST7	"4F440DB1E6EDD2899FA335F09515AA025EE177A79F4B4AAF38E42B5C4DE660F5DE8FB2A5B2FBD2A3CBFFD20CFF1288C0"


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

int main(void)
{
	int err = 0;
	SHA384_CTX ctx;
	uint8_t dgst[SHA384_DIGEST_SIZE];
	uint8_t dgstbuf[SHA384_DIGEST_SIZE];
	size_t dgstlen;
	size_t i, j;

	for (i = 0; i < 7; i++) {
		hex_to_bytes(tests[i].dgsthex, strlen(tests[i].dgsthex), dgstbuf, &dgstlen);

		sha384_init(&ctx);
		for (j = 0; j < tests[i].count; j++) {
			sha384_update(&ctx, (uint8_t *)tests[i].data, tests[i].length);
		}
		sha384_finish(&ctx, dgst);

		if (memcmp(dgstbuf, dgst, sizeof(dgst)) != 0) {
			printf("sha384 test %zu failed\n", i+1);
			printf("%s\n", tests[i].dgsthex);
			for (j = 0; j < sizeof(dgst); j++) {
				printf("%02x", dgst[j]);
			}
			printf("\n");
			err++;
		} else {
			printf("sha384 test %zu ok\n", i+1);
		}
	}

	return err;
}
