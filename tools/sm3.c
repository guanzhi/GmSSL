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
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/error.h>


static const char *options = "[-hex|-bin] [-pubkey pem [-id str]] [-in file] [-out file]";

int sm3_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	int bin = 0;
	char *pubkeyfile = NULL;
	char *infile = NULL;
	char *outfile = NULL;
	char *id = NULL;
	FILE *pubkeyfp = NULL;
	FILE *infp = stdin;
	FILE *outfp = stdout;
	SM3_CTX sm3_ctx;
	uint8_t dgst[32];
	uint8_t buf[4096];
	ssize_t len;
	int i;

	argc--;
	argv++;

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: %s %s\n", prog, options);
			printf("usage: echo -n \"abc\" | %s\n", prog);
			ret = 0;
			goto end;
		} else if (!strcmp(*argv, "-hex")) {
			if (bin) {
				error_print();
				goto end;
			}
			bin = 0;
		} else if (!strcmp(*argv, "-bin")) {
			bin = 1;
		} else if (!strcmp(*argv, "-pubkey")) {
			if (--argc < 1) goto bad;
			pubkeyfile = *(++argv);
			if (!(pubkeyfp = fopen(pubkeyfile, "r"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, pubkeyfile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-id")) {
			if (--argc < 1) goto bad;
			id = *(++argv);
		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);
			if (!(infp = fopen(infile, "r"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, infile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) goto bad;
			outfile = *(++argv);
			if (!(outfp = fopen(outfile, "r"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, outfile, strerror(errno));
				goto end;
			}
		} else {
			fprintf(stderr, "%s: illegal option '%s'\n", prog, *argv);
			goto end;
bad:
			fprintf(stderr, "%s: '%s' option value missing\n", prog, *argv);
			goto end;
		}

		argc--;
		argv++;
	}

	sm3_init(&sm3_ctx);

	if (pubkeyfile) {
		SM2_KEY sm2_key;
		uint8_t z[32];

		if (sm2_public_key_info_from_pem(&sm2_key, pubkeyfp) != 1) {
			fprintf(stderr, "%s: parse public key failed\n", prog);
			goto end;
		}
		if (!id) {
			id = SM2_DEFAULT_ID;
		}

		sm2_compute_z(z, (SM2_POINT *)&sm2_key, id, strlen(id));
		sm3_update(&sm3_ctx, z, sizeof(z));
	} else {
		if (id) {
			fprintf(stderr, "%s: option '-id' must be with '-pubkey'\n", prog);
			goto end;
		}
	}

	while ((len = fread(buf, 1, sizeof(buf), infp)) > 0) {
		sm3_update(&sm3_ctx, buf, len);
	}
	sm3_finish(&sm3_ctx, dgst);

	if (bin) {
		if (fwrite(dgst, 1, sizeof(dgst), outfp) != sizeof(dgst)) {
			fprintf(stderr, "%s: output failure : %s\n", prog, strerror(errno));
			goto end;
		}
	} else {
		for (i = 0; i < sizeof(dgst); i++) {
			fprintf(outfp, "%02x", dgst[i]);
		}
		fprintf(outfp, "\n");
	}
	ret = 0;
end:
	if (pubkeyfp) fclose(pubkeyfp);
	if (infile && infp) fclose(infp);
	if (outfile && outfp) fclose(outfp);
	return ret;
}
