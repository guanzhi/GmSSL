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
#define TEST5	"\xD0"
#define TEST6	"\x8d\x4e\x3c\x0e\x38\x89\x19\x14\x91\x81\x6e\x9d\x98\xbf\xf0\xa0"
#define TEST7	\
  "\xa5\x5f\x20\xc4\x11\xaa\xd1\x32\x80\x7a\x50\x2d\x65\x82\x4e\x31" \
  "\xa2\x30\x54\x32\xaa\x3d\x06\xd3\xe2\x82\xa8\xd8\x4e\x0d\xe1\xde" \
  "\x69\x74\xbf\x49\x54\x69\xfc\x7f\x33\x8f\x80\x54\xd5\x8c\x26\xc4" \
  "\x93\x60\xc3\xe8\x7a\xf5\x65\x23\xac\xf6\xd8\x9d\x03\xe5\x6f\xf2" \
  "\xf8\x68\x00\x2b\xc3\xe4\x31\xed\xc4\x4d\xf2\xf0\x22\x3d\x4b\xb3" \
  "\xb2\x43\x58\x6e\x1a\x7d\x92\x49\x36\x69\x4f\xcb\xba\xf8\x8d\x95" \
  "\x19\xe4\xeb\x50\xa6\x44\xf8\xe4\xf9\x5e\xb0\xea\x95\xbc\x44\x65" \
  "\xc8\x82\x1a\xac\xd2\xfe\x15\xab\x49\x81\x16\x4b\xbb\x6d\xc3\x2f" \
  "\x96\x90\x87\xa1\x45\xb0\xd9\xcc\x9c\x67\xc2\x2b\x76\x32\x99\x41" \
  "\x9c\xc4\x12\x8b\xe9\xa0\x77\xb3\xac\xe6\x34\x06\x4e\x6d\x99\x28" \
  "\x35\x13\xdc\x06\xe7\x51\x5d\x0d\x73\x13\x2e\x9a\x0d\xc6\xd3\xb1" \
  "\xf8\xb2\x46\xf1\xa9\x8a\x3f\xc7\x29\x41\xb1\xe3\xbb\x20\x98\xe8" \
  "\xbf\x16\xf2\x68\xd6\x4f\x0b\x0f\x47\x07\xfe\x1e\xa1\xa1\x79\x1b" \
  "\xa2\xf3\xc0\xc7\x58\xe5\xf5\x51\x86\x3a\x96\xc9\x49\xad\x47\xd7" \
  "\xfb\x40\xd2"

#define DGST1	"DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F"
#define DGST2	"8E959B75DAE313DA8CF4F72814FC143F8F7779C6EB9F7FA17299AEADB6889018501D289E4900F7E4331B99DEC4B5433AC7D329EEB6DD26545E96E55B874BE909"
#define DGST3	"E718483D0CE769644E2E42C7BC15B4638E1F98B13B2044285632A803AFA973EBDE0FF244877EA60A4CB0432CE577C31BEB009C5C2C49AA2E4EADB217AD8CC09B"
#define DGST4	"89D05BA632C699C31231DED4FFC127D5A894DAD412C0E024DB872D1ABD2BA8141A0F85072A9BE1E2AA04CF33C765CB510813A39CD5A84C4ACAA64D3F3FB7BAE9"
#define DGST5	"9992202938E882E73E20F6B69E68A0A7149090423D93C81BAB3F21678D4ACEEEE50E4E8CAFADA4C85A54EA8306826C4AD6E74CECE9631BFA8A549B4AB3FBBA15"
#define DGST6	"CB0B67A4B8712CD73C9AABC0B199E9269B20844AFB75ACBDD1C153C9828924C3DDEDAAFE669C5FDD0BC66F630F6773988213EB1B16F517AD0DE4B2F0C95C90F8"
#define DGST7	"C665BEFB36DA189D78822D10528CBF3B12B3EEF726039909C1A16A270D48719377966B957A878E720584779A62825C18DA26415E49A7176A894E7510FD1451F5"


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
	SHA512_CTX ctx;
	uint8_t dgst[SHA512_DIGEST_SIZE];
	uint8_t dgstbuf[SHA512_DIGEST_SIZE];
	size_t dgstlen;
	size_t i, j;

	for (i = 0; i < 7; i++) {
		hex_to_bytes(tests[i].dgsthex, strlen(tests[i].dgsthex), dgstbuf, &dgstlen);

		sha512_init(&ctx);
		for (j = 0; j < tests[i].count; j++) {
			sha512_update(&ctx, (uint8_t *)tests[i].data, tests[i].length);
		}
		sha512_finish(&ctx, dgst);

		if (memcmp(dgstbuf, dgst, sizeof(dgst)) != 0) {
			printf("sha512 test %zu failed\n", i+1);
			printf("%s\n", tests[i].dgsthex);
			for (j = 0; j < sizeof(dgst); j++) {
				printf("%02x", dgst[j]);
			}
			printf("\n");
			err++;
		} else {
			printf("sha512 test %zu ok\n", i+1);
		}
	}

	return err;
}
