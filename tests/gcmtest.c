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
#include <gmssl/hex.h>
#include <gmssl/error.h>


struct {
	char *H;
	char *A;
	char *C;
	char *T;
} ghash_tests[] = {
	// test 1
	{
		"66e94bd4ef8a2c3b884cfa59ca342b2e",
		"",
		"",
		"00000000000000000000000000000000",
	},
	// test 2
	{
		"66e94bd4ef8a2c3b884cfa59ca342b2e",
		"",
		"0388dace60b6a392f328c2b971b2fe78",
		"f38cbb1ad69223dcc3457ae5b6b0f885",

	},
	// test 3
	{
		"b83b533708bf535d0aa6e52980d53b78",
		"",
		"42831ec2217774244b7221b784d0d49c"
		"e3aa212f2c02a4e035c17e2329aca12e"
		"21d514b25466931c7d8f6a5aac84aa05"
		"1ba30b396a0aac973d58e091473f5985",
		"7f1b32b81b820d02614f8895ac1d4eac",
	},
	// test 4
	{
		"b83b533708bf535d0aa6e52980d53b78",
		"feedfacedeadbeeffeedfacedeadbeef"
		"abaddad2",
		"42831ec2217774244b7221b784d0d49c"
		"e3aa212f2c02a4e035c17e2329aca12e"
		"21d514b25466931c7d8f6a5aac84aa05"
		"1ba30b396a0aac973d58e091",
		"698e57f70e6ecc7fd9463b7260a9ae5f",
	},
	// test 5
	{
		"b83b533708bf535d0aa6e52980d53b78",
		"feedfacedeadbeeffeedfacedeadbeef"
		"abaddad2",
		"61353b4c2806934a777ff51fa22a4755"
		"699b2a714fcdc6f83766e5f97b6c7423"
		"73806900e49f24b22b097544d4896b42"
		"4989b5e1ebac0f07c23f4598",
		"df586bb4c249b92cb6922877e444d37b",
	},
	// test 6
	{
		"b83b533708bf535d0aa6e52980d53b78",
		"feedfacedeadbeeffeedfacedeadbeef"
		"abaddad2",
		"8ce24998625615b603a033aca13fb894"
		"be9112a5c3a211a8ba262a3cca7e2ca7"
		"01e4a9a4fba43c90ccdcb281d48c7c6f"
		"d62875d2aca417034c34aee5",
		"1c5afe9760d3932f3c9a878aac3dc3de",
	},
};

int test_ghash(void)
{
	uint8_t H[16];
	uint8_t A[32];
	uint8_t C[64];
	uint8_t T[16];
	uint8_t out[16];
	size_t Hlen, Alen, Clen, Tlen;
	int i;

	printf("%s\n", __FUNCTION__);

	for (i = 0; i < sizeof(ghash_tests)/sizeof(ghash_tests[0]); i++) {
		hex_to_bytes(ghash_tests[i].H, strlen(ghash_tests[i].H), H, &Hlen);
		hex_to_bytes(ghash_tests[i].A, strlen(ghash_tests[i].A), A, &Alen);
		hex_to_bytes(ghash_tests[i].C, strlen(ghash_tests[i].C), C, &Clen);
		hex_to_bytes(ghash_tests[i].T, strlen(ghash_tests[i].T), T, &Tlen);
		ghash(H, A, Alen, C, Clen, out);

		printf("  test %d %s\n", i + 1, memcmp(out ,T, Tlen) == 0 ? "ok" : "error");
		/*
		format_print(stdout, 0, 2, "H = %s\n", ghash_tests[i].H);
		format_print(stdout, 0, 2, "A = %s\n", ghash_tests[i].A);
		format_print(stdout, 0, 2, "C = %s\n", ghash_tests[i].C);
		format_bytes(stdout, 0, 2, "GHASH(H,A,C) = ", out, 16);
		format_print(stdout, 0, 2, "             = %s\n\n", ghash_tests[i].T);
		*/
	}
	return 1;
}


int main(void)
{
	test_ghash();
	return 1;
}
