/* ====================================================================
 * Copyright (c) 2014 - 2017 The GmSSL Project.  All rights reserved.
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
 * ====================================================================
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../e_os.h"

#ifdef OPENSSL_NO_SPECK
int main(int argc, char **argv)
{
	printf("No SPECK support\n");
	return 0;
}
#else
# include <openssl/e_os2.h>
# include <openssl/speck.h>
# include <openssl/evp.h>

int main(int argc, char** argv)
{
	int sum = 0;
	uint16_t key16[4] = { 0x0100, 0x0908, 0x1110, 0x1918 };
	uint16_t plain16[2] = { 0x694c, 0x6574 };
	uint16_t enc16[2] = { 0x42f2, 0xa868 };

	uint32_t key32[4] = { 0x03020100, 0x0b0a0908, 0x13121110, 0x1b1a1918 };
	uint32_t plain32[2] = { 0x7475432d, 0x3b726574 };
	uint32_t enc32[2] = { 0x454e028b, 0x8c6fa548 };

	uint64_t key64[4] = { 0x0706050403020100, 0x0f0e0d0c0b0a0908, 0x1716151413121110, 0x1f1e1d1c1b1a1918 };
	uint64_t plain64[2] = { 0x202e72656e6f6f70, 0x65736f6874206e49 };
	uint64_t enc64[2] = { 0x4eeeb48d9c188f43, 0x4109010405c0f53e };

	uint16_t buffer[2] = { 0 };
	uint16_t exp[SPECK_ROUNDS16];

	uint32_t exp32[SPECK_ROUNDS32];
	uint32_t buffer32[2] = { 0 };

	uint64_t exp64[SPECK_ROUNDS64];
	uint64_t buffer64[2] = { 0 };


	speck_set_encrypt_key16(key16, exp);
	speck_encrypt16(plain16, buffer, exp);
	if (memcmp(buffer, enc16, sizeof(enc16))) {
		fprintf(stderr, "%s %d: speck error\n", __FILE__, __LINE__);
		sum++;
	}
	speck_decrypt16(enc16, buffer, exp);
	if (memcmp(buffer, plain16, sizeof(enc16))) {
		fprintf(stderr, "%s %d: speck error\n", __FILE__, __LINE__);
		sum++;
	}

	speck_set_encrypt_key32(key32, exp32);
	speck_encrypt32(plain32, buffer32, exp32);
	if (memcmp(buffer, enc32, sizeof(enc32))) {
		fprintf(stderr, "%s %d: speck error\n", __FILE__, __LINE__);
		sum++;
	}
	speck_decrypt32(enc32, buffer32, exp32);
	if (memcmp(buffer32, plain32, sizeof(enc32))) {
		fprintf(stderr, "%s %d: speck error\n", __FILE__, __LINE__);
		sum++;
	}

	speck_set_encrypt_key64(key64, exp64);
	speck_encrypt64(plain64, buffer64, exp64);
	if (memcmp(buffer64, enc64, sizeof(enc64))) {
		fprintf(stderr, "%s %d: speck error\n", __FILE__, __LINE__);
		sum++;
	}
	speck_decrypt64(enc64, buffer64, exp64);
	if (memcmp(buffer64, plain64, sizeof(enc64))) {
		fprintf(stderr, "%s %d: speck error\n", __FILE__, __LINE__);
		sum++;
	}

	return sum;
}
#endif
