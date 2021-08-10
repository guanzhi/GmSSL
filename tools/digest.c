/* 
 *   Copyright 2014-2021 The GmSSL Project Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmssl/digest.h>

#define FORMAT_HEX	1
#define FORMAT_BIN	2


void print_usage(FILE *out, const char *prog)
{
	fprintf(out, "Usage: %s command [options] ...\n", prog);
	fprintf(out, "\n");
	fprintf(out, "Commands:\n");
	fprintf(out, "  -help		print the usage message\n");
	fprintf(out, "  -sm3		use SM3\n");
	fprintf(out, "  -md5		use MD5\n");
	fprintf(out, "  -sha1		use SHA-1\n");
	fprintf(out, "  -sha224		use SHA-224\n");
	fprintf(out, "  -sha256		use SHA-256\n");
	fprintf(out, "  -sha384		use SHA-384\n");
	fprintf(out, "  -sha512		use SHA-512\n");
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

		} else if (!strcmp(*argv, "-sm3")) {
			if (digest) goto bad;
			digest = DIGEST_sm3();

		} else if (!strcmp(*argv, "-md5")) {
			if (digest) goto bad;
			digest = DIGEST_md5();

		} else if (!strcmp(*argv, "-sha1")) {
			if (digest) goto bad;
			digest = DIGEST_sha1();

		} else if (!strcmp(*argv, "-sha224")) {
			if (digest) goto bad;
			digest = DIGEST_sha224();

		} else if (!strcmp(*argv, "-sha256")) {
			if (digest) goto bad;
			digest = DIGEST_sha256();

		} else if (!strcmp(*argv, "-sha384")) {
			if (digest) goto bad;
			digest = DIGEST_sha384();

		} else if (!strcmp(*argv, "-sha512")) {
			if (digest) goto bad;
			digest = DIGEST_sha512();

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

	if (!digest) {
		fprintf(stderr, "%s: digest algorithm not speicified\n", prog);
		fprintf(stderr, "usage: %s -[sm2|sha224|sha256|sha384|sha512] ...\n", prog);
		return 1;
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
