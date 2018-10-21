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
	FILE *fp = NULL;
	BIO *bio = NULL;
	BIO *bio_mpk = NULL;
	CPK_PUBLIC_PARAMS *mpk = NULL;
	EVP_PKEY *pk = NULL;
	EVP_MD_CTX *md_ctx = NULL;
	EVP_PKEY_CTX *pctx;
	unsigned char magicstr[] = "~CPK signature appended~";
	unsigned char magic[sizeof(magicstr)] = {0};
	unsigned char id[128] = {0};
	unsigned char sig[128];
	unsigned int idlen, siglen, totallen;
	int datalen;

	if (argc != 3) {
		printf("usage: %s <signed-file> <mpk-file>\n", prog);
		return 0;
	}

	if (!(fp = fopen(argv[1], "r"))) {
		fprintf(stderr, "%s: open file failed\n", prog);
		goto end;
	}

	if (fseek(fp, -(sizeof(magic) + sizeof(unsigned int)), SEEK_END) != 0) {
		fprintf(stderr, "%s: parse file error\n", prog);
		goto end;
	}
	if ((datalen = ftell(fp)) <= 0) {
		fprintf(stderr, "%s: parse file error\n", prog);
		goto end;
	}

	if (fread(&totallen, sizeof(unsigned int), 1, fp) != sizeof(unsigned char)) {
		fprintf(stderr, "%s: parse file error\n", prog);
		goto end;
	}
	datalen -= totallen;

	if (fread(magic, 1, sizeof(magic), fp) != sizeof(magic)) {
		fprintf(stderr, "%s: parse file error\n", prog);
		goto end;
	}

	if (memcmp(magic, magicstr, sizeof(magic)) != 0) {
		fprintf(stderr, "%s: file is not signed\n", prog);
		goto end;
	}

	if (fseek(fp, datalen, SEEK_SET) != 0) {
		fprintf(stderr, "%s: parse file error\n", prog);
		goto end;
	}

	if (fread(&idlen, 1, 4, fp) != 4) {
		fprintf(stderr, "%s: parse file error\n", prog);
		goto end;
	}

	if (fread(id, 1, idlen, fp) != idlen) {
		fprintf(stderr, "%s: parse file error\n", prog);
		goto end;
	}

	if (fread(&siglen, 1, sizeof(unsigned int), fp) != sizeof(unsigned int)) {
		fprintf(stderr, "%s: parse file error\n", prog);
		goto end;
	}
	if (fread(sig, 1, siglen, fp) != siglen) {
		fprintf(stderr, "%s: parse file error\n", prog);
		goto end;
	}

	fclose(fp);
	fp = NULL;

	if (!(bio = BIO_new_file(argv[1], "r"))
		|| !(bio_mpk = BIO_new_file(argv[2], "r"))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!(mpk = d2i_CPK_PUBLIC_PARAMS_bio(bio_mpk, NULL))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	if (!(pk = CPK_PUBLIC_PARAMS_extract_public_key(mpk, (char *)id))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!(md_ctx = EVP_MD_CTX_new())) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	if (!EVP_DigestVerifyInit(md_ctx, &pctx, EVP_sm3(), NULL, pk)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	if (!EVP_PKEY_CTX_set_ec_scheme(pctx, NID_sm_scheme)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	while (datalen > 0) {
		unsigned char buf[1024];
		int len;

		len = sizeof(buf) < datalen ? sizeof(buf) : datalen;

		if (len != BIO_read(bio, buf, len)) {
			ERR_print_errors_fp(stderr);
			goto end;
		}

		if (!EVP_DigestVerifyUpdate(md_ctx, buf, len)) {
			ERR_print_errors_fp(stderr);
			goto end;
		}

		datalen -= len;
	}

	if (1 != EVP_DigestVerifyFinal(md_ctx, sig, siglen)) {
			ERR_print_errors_fp(stderr);
			printf("%s: failed\n", argv[1]);
			goto end;
	}
	printf("%s: success\n", argv[1]);

	ret = 0;
end:
	return ret;
}
