/* ====================================================================
 * Copyright (c) 2014 - 2018 The GmSSL Project.  All rights reserved.
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
/*
 * Alert:
 * This is a only a demo of the FFX format-preserving encryption algorithm,
 * the encryption key should not be read from command line argumnents, and
 * the key and tweak should be binary (full 8-bit per char).
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libgen.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ffx.h>
#include <openssl/is_gmssl.h>

int main(int argc, char **argv)
{
	int ret = -1;
	char *prog = basename(argv[0]);
	FFX_CTX *ctx = NULL;
	unsigned char key[32] = {0};
	char out[FFX_MAX_DIGITS + 1] = {0};

	if (argc != 4) {
		printf("usage: %s <digits> <key> <tweak>\n", prog);
		return -1;
	}
	if (strlen(argv[1]) < FFX_MIN_DIGITS || strlen(argv[1]) > FFX_MAX_DIGITS) {
		fprintf(stderr, "%s: invalid digits length, should be %d to %d\n",
			prog, FFX_MIN_DIGITS, FFX_MAX_DIGITS);
		return -1;
	}
	if (strlen(argv[2]) < FFX_MIN_TWEAKLEN || strlen(argv[2]) > FFX_MAX_TWEAKLEN) {
		fprintf(stderr, "%s: invalid tweak length, should be %d to %d\n",
			prog, FFX_MIN_TWEAKLEN, FFX_MAX_TWEAKLEN);
		return -1;
	}
	strncpy((char *)key, argv[2], sizeof(key));

	if (!(ctx = FFX_CTX_new())) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!FFX_init(ctx, EVP_sms4_ecb(), key, 0)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	if (!FFX_decrypt(ctx, argv[1], out, strlen(argv[1]),
		(unsigned char *)argv[3], strlen(argv[3]))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	printf("%s\n", out);

	ret = 0;

end:
	FFX_CTX_free(ctx);
	return ret;
}
