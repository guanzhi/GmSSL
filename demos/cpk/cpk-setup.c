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
#include <openssl/err.h>


int main(int argc, char **argv)
{
	int ret = -1;
	char *prog = basename(argv[0]);
	X509_ALGOR *map = NULL;
	EC_KEY *ec_key = NULL;
	EVP_PKEY *pkey = NULL;
	CPK_MASTER_SECRET *msk = NULL;
	CPK_PUBLIC_PARAMS *mpk = NULL;
	BIO *mpk_bio = NULL;
	BIO *msk_bio = NULL;

	if (argc != 3) {
		printf("usage: %s <mpk-file> <msk-file>\n", prog);
		return 0;
	}

	if (!(msk = CPK_MASTER_SECRET_create("codesign", 0, NID_cpk_map_sha1))
		|| !(mpk = CPK_MASTER_SECRET_extract_public_params(msk))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!(mpk_bio = BIO_new_file(argv[1], "w"))
		|| !(msk_bio = BIO_new_file(argv[2], "w"))
		|| !i2d_CPK_MASTER_SECRET_bio(msk_bio, msk)
		|| !i2d_CPK_PUBLIC_PARAMS_bio(mpk_bio, mpk)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	ret = 0;

end:
	X509_ALGOR_free(map);
	//EC_KEY_free(ec_key);
	EVP_PKEY_free(pkey);
	CPK_MASTER_SECRET_free(msk);
	CPK_PUBLIC_PARAMS_free(mpk);
	BIO_free(msk_bio);
	BIO_free(mpk_bio);
	return ret;
}
