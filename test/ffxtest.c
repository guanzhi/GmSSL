/* ====================================================================
 * Copyright (c) 2014 - 2016 The GmSSL Project.  All rights reserved.
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

#ifdef OPENSSL_NO_FFX
int main(int argc, char **argv)
{
	printf("No FFX support\n");
	return 0;
}
#else
# include <openssl/err.h>
# include <openssl/evp.h>
# include <openssl/ffx.h>

static int test_ffx(int verbose)
{
	int ret = 0;
	FFX_CTX *ctx = NULL;
	char *in = "99999999999999999";
	const EVP_CIPHER *cipher[] = {
		EVP_sms4_ecb(),
		EVP_aes_128_ecb(),
		EVP_aes_256_ecb(),
	};
	unsigned char key[32] = {0};
	unsigned char tweak[8] = {
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
	};
	char buf1[100];
	char buf2[100];
	int i;

	if (!(ctx = FFX_CTX_new())) {
		ERR_print_errors_fp(stderr);
		return 0;
	}

	for (i = 0; i < OSSL_NELEM(cipher); i++) {

		memset(buf1, 0, sizeof(buf1));
		memset(buf2, 0, sizeof(buf2));

		if (!FFX_init(ctx, cipher[i], key, 0)) {
			ERR_print_errors_fp(stderr);
			goto end;
		}
		if (!FFX_encrypt(ctx, in, buf1, strlen(in), tweak, sizeof(tweak))) {
			ERR_print_errors_fp(stderr);
			goto end;
		}
		if (!FFX_decrypt(ctx, buf1, buf2, strlen(in), tweak, sizeof(tweak))) {
			ERR_print_errors_fp(stderr);
			goto end;
		}
		if (strcmp(in, buf2) != 0) {
			printf("error ffx-%s\n", EVP_CIPHER_name(cipher[i]));
			printf("encrypt/decrypt not match\n");
		} else {
			printf("test %d ok\n", i + 1);
		}

		if (verbose) {
			printf("ffx-%s-encrypt(\"%s\") = \"%s\"\n",
				EVP_CIPHER_name(cipher[i]), in, buf1);
		}
	}

	ret = 1;
end:
	FFX_CTX_free(ctx);
	return ret;
}

char *digits[] = {
	"7992739871",
};

int luhn_checksums[] = {
	'3',
};

int test_luhn(int verbose)
{
	int i;
	int checksum;

	for (i = 0; i < OSSL_NELEM(digits); i++) {
		checksum = FFX_compute_luhn(digits[i], strlen(digits[i]));
		if (checksum != luhn_checksums[i]) {
			printf("error calculating Luhn checksum on %s\n", digits[i]);
			printf("got %c instead of %c\n", checksum, luhn_checksums[i]);
		} else {
			printf("test %d ok\n", i+1);
		}
	}

	return 1;
}

int main(int argc, char **argv)
{
	int err = 0;
	if (!test_ffx(1)) {
		err = 1;
	}
	if (!test_luhn(1)) {
		err = 1;
	}
	return err;
}
#endif
