/* ====================================================================
 * Copyright (c) 2015 The GmSSL Project.  All rights reserved.
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
 *
 */
/*
 * Format-Preserve Encryption
 * implementation of NIST 800-38G FF1 schemes
 *
 * FPE is used to encrypt strings such as credit card numbers and phone numbers
 * the ciphertext is still in valid format, for example:
 *	 FPE_encrypt("13810631266") == "98723498792"
 * the output is still 11 digits
 */


#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <assert.h>
#include <openssl/err.h>
#include <openssl/ffx.h>

static int test()
{
	char buf[100];
	char buf2[100];
	unsigned char key[32] = {0};
	unsigned char tweak[8] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
	FFX_CTX ctx;
	int r;

	ERR_load_crypto_strings();

	if (FFX_init(&ctx, 0, key, sizeof(key) * 8) < 0) {
		ERR_print_errors_fp(stderr);
		fprintf(stderr, "%s: %d\n", __FILE__, __LINE__);
		return -1;
	}

	char *in = "99999999999999999";
	r = FFX_encrypt(&ctx, in, strlen(in), tweak, sizeof(tweak), buf);

	if (r < 0) {
		printf("failed\n");
		return -1;
	}

	printf("%s\n", buf);
	printf("\n");

	r = FFX_decrypt(&ctx, buf, strlen(buf), tweak, sizeof(tweak), buf2);
	printf("%s\n", buf2);

	return 0;
}


/*
 * 7992739871, checksum = 3
 */

int luhn_test()
{
	char *digits = "7992739871";
	int r = FFX_compute_luhn(digits, strlen(digits));
	printf("%c", r);
	return 0;
}

int main(int argc, char **argv)
{
	return 0;
}

