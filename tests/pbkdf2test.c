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
#include <gmssl/hex.h>
#include <gmssl/pbkdf2.h>



struct {
	char *pass;
	char *salt;
	int iter;
	int dklen;
	char *dk;
} pbkdf2_hmac_sha1_tests[] = {

	// rfc 6070 test vectors for pbkdf2-hmac-sha1
	{
		"password",
		"salt",
		1,
		20,
		"0c60c80f961f0e71f3a9b524af6012062fe037a6",
	},
	{
		"password",
		"salt",
		2,
		20,
		"ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957",
	},
	{
		"password",
		"salt",
		4096,
		20,
		"4b007901b765489abead49d926f721d065a429c1",
	},
	{
		"password",
		"salt",
		16777216,
		20,
		"eefe3d61cd4da4e4e9945b3d6ba2158c2634e984",
	},
	{
		"passwordPASSWORDpassword",
		"saltSALTsaltSALTsaltSALTsaltSALTsalt",
		4096,
		25,
		"3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038",
	},
};


void test(void)
{
	HMAC_CTX ctx;
	uint8_t iter[4] = {0, 0, 0, 1};
	uint8_t mac[20];
	size_t len;
	int i;

	hmac_init(&ctx, DIGEST_sha1(), (uint8_t *)"password", 8);
	hmac_update(&ctx, (uint8_t *)"salt", 4);
	hmac_update(&ctx, iter, 4);
	hmac_finish(&ctx, mac, &len);

	for (i = 1; i < 4096; i++) {
		uint8_t buf[20];
		memset(&ctx, 0, sizeof(HMAC_CTX));
		hmac_init(&ctx, DIGEST_sha1(), (uint8_t *)"password", 8);
		hmac_update(&ctx, mac, len);
		hmac_finish(&ctx, buf, &len);
		int j;
		for (j = 0; j < len; j++) {
			mac[j] ^= buf[j];
		}
	}


	for (i = 0; i < len; i++) {
		printf("%02x", mac[i]);
	}
	printf("\n");
}

int main(void)
{
	int i;
	uint8_t key[64];
	uint8_t buf[64];
	size_t len;

	for (i = 0; i < sizeof(pbkdf2_hmac_sha1_tests)/sizeof(pbkdf2_hmac_sha1_tests[0]); i++) {
		hex2bin(pbkdf2_hmac_sha1_tests[i].dk, strlen(pbkdf2_hmac_sha1_tests[i].dk), buf);

		pbkdf2_genkey(DIGEST_sha1(),
			pbkdf2_hmac_sha1_tests[i].pass, strlen(pbkdf2_hmac_sha1_tests[i].pass),
			(uint8_t *)pbkdf2_hmac_sha1_tests[i].salt, strlen(pbkdf2_hmac_sha1_tests[i].salt),
			pbkdf2_hmac_sha1_tests[i].iter, pbkdf2_hmac_sha1_tests[i].dklen, key);

		if (memcmp(key, buf, pbkdf2_hmac_sha1_tests[i].dklen) != 0) {
			printf("%d failed\n", i);
		} else {
			printf("%d ok\n", i);
		}
	}

	return 1;
}
