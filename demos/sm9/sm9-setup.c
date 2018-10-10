/* ====================================================================
 * Copyright (c) 2016 - 2018 The GmSSL Project.  All rights reserved.
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
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <openssl/sm9.h>
#include <openssl/err.h>
#include <openssl/objects.h>

int main(int argc, char **argv)
{
	int ret = -1;
	char *prog = basename(argv[0]);
	char *msk_file;
	char *mpk_file;
	SM9MasterSecret *msk = NULL;
	SM9PublicParameters *mpk = NULL;
	FILE *msk_fp = NULL;
	FILE *mpk_fp = NULL;

	if (argc != 4) {
		printf("usage: %s <sm9sign|sm9encrypt> <mpk-file> <msk-file>\n", prog);
		return -1;
	}

	if (!SM9_setup(NID_sm9bn256v1, OBJ_txt2nid(argv[1]), NID_sm9hash1_with_sm3, &mpk, &msk)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!(msk_fp = fopen(argv[3], "w"))
		|| !(mpk_fp = fopen(argv[2], "w"))
		|| !i2d_SM9MasterSecret_fp(msk_fp, msk)
		|| !i2d_SM9PublicParameters_fp(mpk_fp, mpk)) {
		fprintf(stderr, "%s: failed to output files\n", prog);
		goto end;
	}
	printf("generate '%s'\n", argv[2]);
	printf("generate '%s'\n", argv[3]);

	ret = 0;
end:
	SM9MasterSecret_free(msk);
	SM9PublicParameters_free(mpk);
	fclose(msk_fp);
	fclose(mpk_fp);
	return ret;
}
