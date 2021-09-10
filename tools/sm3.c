/*
 * Copyright (c) 2014 - 2021 The GmSSL Project.  All rights reserved.
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
#include <gmssl/sm3.h>
#include <gmssl/sm2.h>
#include <gmssl/error.h>


int main(int argc, char **argv)
{
	char *prog = argv[0];
	char *pubkeyfile = NULL;
	char *infile = NULL;
	char *id = NULL;
	FILE *pubkeyfp = NULL;
	FILE *infp = stdin;
	SM3_CTX sm3_ctx;
	uint8_t dgst[32];
	uint8_t buf[4096];
	ssize_t len;
	int i;

	argc--;
	argv++;

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
help:
			fprintf(stderr, "usage: %s [-pubkey pem [-id str]] [-in file]\n", prog);
			fprintf(stderr, "usage: echo -n \"abc\" | %s\n", prog);
			return -1;

		} else if (!strcmp(*argv, "-pubkey")) {
			if (--argc < 1) goto bad;
			pubkeyfile = *(++argv);

		} else if (!strcmp(*argv, "-id")) {
			if (--argc < 1) goto bad;
			id = *(++argv);

		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);

		} else {
			fprintf(stderr, "%s: illegal option '%s'\n", prog, *argv);
			goto help;
		}

		argc--;
		argv++;
	}

	sm3_init(&sm3_ctx);

	if (pubkeyfile) {
		SM2_KEY sm2_key;
		uint8_t z[32];

		if (!(pubkeyfp = fopen(pubkeyfile, "r"))) {
			error_print();
			return -1;
		}
		if (sm2_public_key_info_from_pem(&sm2_key, pubkeyfp) != 1) {
			error_print();
			return -1;
		}
		if (!id) {
			id = SM2_DEFAULT_ID;
		}

		sm2_compute_z(z, (SM2_POINT *)&sm2_key, id);
		sm3_update(&sm3_ctx, z, sizeof(z));

	} else {
		if (id) {
			fprintf(stderr, "%s: option '-id' must be with '-pubkey'\n", prog);
			goto help;
		}
	}

	if (infile) {
		if (!(infp = fopen(infile, "r"))) {
			error_print();
			return -1;
		}
	}
	while ((len = fread(buf, 1, sizeof(buf), infp)) > 0) {
		sm3_update(&sm3_ctx, buf, len);
	}

	sm3_finish(&sm3_ctx, dgst);
	for (i = 0; i < sizeof(dgst); i++) {
		printf("%02x", dgst[i]);
	}
	printf("\n");

	if (infile) {
		fclose(infp);
	}
	return 0;

bad:
	fprintf(stderr, "%s: '%s' option value required\n", prog, *argv);
	return -1;
}
