/*
 * Copyright (c) 2020 - 2021 The GmSSL Project.  All rights reserved.
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <gmssl/digest.h>

#define FORMAT_HEX	1
#define FORMAT_BIN	2


void print_usage(FILE *out, const char *prog)
{
	fprintf(out, "Usage: %s command [options] ...\n", prog);
	fprintf(out, "\n");
	fprintf(out, "Commands:\n");
	fprintf(out, "  -help		print the usage message\n");
	fprintf(out, "  -digest algor	print the usage message\n");
	fprintf(out, "  -key hex	set the key in hex\n");
	fprintf(out, "  -hex		generate hex output\n");
	fprintf(out, "  -binary		generate binary output\n");
	fprintf(out, "  -out file	set output filename\n");
}

int main(int argc, char **argv)
{
	int ret = -1;
	char *prog = argv[0];
	int help = 0;
	const DIGEST *digest = NULL;
	int format = FORMAT_HEX;
	char *infile = NULL;
	char *outfile = NULL;
	FILE *in = stdin;
	FILE *out = stdout;

	DIGEST_CTX ctx;
	unsigned char dgst[64];
	unsigned char buf[4096];
	size_t len;
	size_t dgstlen, i;

	argc--;
	argv++;
	while (argc >= 1) {
		if (!strcmp(*argv, "-help")) {
			print_usage(stdout, prog);
			goto end;

		} else if (!strcmp(*argv, "-digest")) {
			if (--argc < 1) goto bad;
			algor = *(++argv);

		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			algor = *(++argv);

		} else if (!strcmp(*argv, "-hex")) {
			format = FORMAT_HEX;

		} else if (!strcmp(*argv, "-binary")) {
			format = FORMAT_BIN;

		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) goto bad;
			outfile = *(++argv);

		} else {
			break;
		}

		argc--;
		argv++;
	}

	if (!algor) {
	}

	if (outfile) {
		if (!(out = fopen(outfile, "wb"))) {
			fprintf(stderr, "%s: can not open %s\n", prog, outfile);
			return 1;
		}
	}

	digest_ctx_init(&ctx);

	if (!argc) {
		if (!digest_init(&ctx, digest)) {
			goto end;
		}
		while ((len = fread(buf, 1, sizeof(buf), stdin)) > 0) {
			if (!digest_update(&ctx, buf, len)) {
				goto end;
			}
		}
		if (!digest_finish(&ctx, dgst, &len)) {
			goto end;
		}

		if (format == FORMAT_BIN) {
			fwrite(dgst, 1, len, out);
		} else {
			for (i = 0; i < len; i++) {
				printf("%02x", dgst[i]);
			}
			printf("\n");
		}

		ret = 0;
		goto end;
	}

	// 多个输出文件，输出文件名和二进制输出有冲突

	while (argc > 0) {
		infile = *argv++;
		if (!(in = fopen(infile, "rb"))) {
			fprintf(stderr, "%s: can not open input file %s\n", prog, infile);
			goto end;
		}

		if (!digest_init(&ctx, digest)) {
			goto end;
		}
		while ((len = fread(buf, 1, sizeof(buf), in)) > 0) {
			if (!digest_update(&ctx, buf, len)) {
				goto end;
			}
		}
		fclose(in);
		if (!digest_finish(&ctx, dgst, &dgstlen)) {
			goto end;
		}

		for (i = 0; i < dgstlen; i++) {
			printf("%02x", dgst[i]);
		}
		printf("    %s\n", infile);
		argc--;
	}
	ret = 0;
	goto end;

bad:
	fprintf(stderr, "%s: commands should not be used together\n", prog);
end:
	digest_ctx_cleanup(&ctx);
	fclose(out);
	return ret;
}
