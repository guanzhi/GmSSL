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
 * This SM3 demo use the abstract EVP API
 */

#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/is_gmssl.h>

int main(int argc, char **argv)
{
	int ret = -1;
	FILE *fp = stdin;
	unsigned char buf[1024];
	size_t len;
	const EVP_MD *md = EVP_sm3();
	EVP_MD_CTX *mdctx = NULL;
	unsigned char dgst[EVP_MAX_MD_SIZE];
	unsigned int dgstlen, i;

	/* hash a file when argv[1] exist, or from stdin */
	if (argc == 2) {
		if (!(fp = fopen(argv[1], "r"))) {
			fprintf(stderr, "open file %s failed\n", argv[1]);
			return -1;
		}
	}

	/* get the SM3 EVP_MD object by name */
	if (!(md = EVP_get_digestbyname("sm3"))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	/* create message digest (MD) context */
	if (!(mdctx = EVP_MD_CTX_new())) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	/* set digest method, i.e. sm3 */
	if (!EVP_DigestInit(mdctx, md)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	/* update data to be digested */
	while ((len = fread(buf, 1, sizeof(buf), fp))) {
		if (!EVP_DigestUpdate(mdctx, buf, len)) {
			ERR_print_errors_fp(stderr);
			goto end;
		}
	}

	/* get the digest/hash value */
	if (!EVP_DigestFinal(mdctx, dgst, &dgstlen)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	for (i = 0; i < dgstlen; i++) {
		printf("%02X", dgst[i]);
	}
	printf("\n");
	ret = 0;

end:
	fclose(fp);
	EVP_MD_CTX_free(mdctx);
	return ret;
}
