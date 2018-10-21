/* ====================================================================
 * Copyright (c) 2018 The GmSSL Project.  All rights reserved.
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
#include <libgen.h>
#include <openssl/cpk.h>
#include <openssl/pem.h>
#include <openssl/sm2.h>
#include <openssl/is_gmssl.h>

int main(int argc, char **argv)
{
	int ret = -1;
	char *prog = basename(argv[0]);
	EVP_MD_CTX *md_ctx = NULL;
	EVP_PKEY_CTX *pctx;
	EVP_PKEY *sk = NULL;
	unsigned char magic[] = "~CPK signature appended~";
	unsigned char sig[128] = {0};
	size_t sigsize = sizeof(sig);
	unsigned int idlen, siglen, totallen;
	BIO *in_bio = NULL;
	BIO *sk_bio = NULL;
	BIO *out_bio = NULL;
	unsigned char buf[1024];
	int len;

	if (argc != 5) {
		printf("usage: %s <file> <id> <sk-file> <signed-file>\n", prog);
		return 0;
	}

	if (strlen(argv[2]) > 64) {
		fprintf(stderr, "%s: signer's id too long\n", prog);
		goto end;
	}

	if (!(in_bio = BIO_new_file(argv[1], "r"))
		|| !(sk_bio = BIO_new_file(argv[3], "r"))
		|| !(out_bio = BIO_new_file(argv[4], "w"))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!(sk = PEM_read_bio_PrivateKey(sk_bio, NULL, NULL, NULL))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!(md_ctx = EVP_MD_CTX_new())) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	if (!EVP_DigestSignInit(md_ctx, &pctx, EVP_sm3(), NULL, sk)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	if (!EVP_PKEY_CTX_set_ec_scheme(pctx, NID_sm_scheme)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	while ((len = BIO_read(in_bio, buf, sizeof(buf))) > 0) {
		if (!EVP_DigestSignUpdate(md_ctx, buf, len)) {
			ERR_print_errors_fp(stderr);
			goto end;
		}
		if (len != BIO_write(out_bio, buf, len)) {
			ERR_print_errors_fp(stderr);
			goto end;
		}
	}
	if (!EVP_DigestSignFinal(md_ctx, sig, &sigsize)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	idlen = strlen(argv[2]);
	siglen = (unsigned int)sigsize;
	totallen = sizeof(idlen) + idlen + sizeof(siglen) + siglen;

	if (BIO_write(out_bio, &idlen, sizeof(idlen)) != sizeof(idlen)
		|| BIO_write(out_bio, argv[2], strlen(argv[2])) != strlen(argv[2])
		|| BIO_write(out_bio, &siglen, sizeof(siglen)) != sizeof(siglen)
		|| BIO_write(out_bio, sig, siglen) != siglen
		|| BIO_write(out_bio, &totallen, sizeof(totallen)) != sizeof(totallen)
		|| BIO_write(out_bio, magic, sizeof(magic)) != sizeof(magic)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	ret = 0;

end:
	EVP_MD_CTX_free(md_ctx);
	EVP_PKEY_free(sk);
	BIO_free(in_bio);
	BIO_free(sk_bio);
	BIO_free(out_bio);
	return ret;
}
