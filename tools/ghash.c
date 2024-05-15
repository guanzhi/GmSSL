/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/ghash.h>
#include <gmssl/hex.h>
#include <gmssl/error.h>


static const char *usage = "[-in_str str|-in file] [-hex|-bin] [-out file]";

static const char *help =
"Options\n"
"\n"
"    -h hex                 H value of GHASH, a ciphertext block of encrypted zeros\n"
"    -aad str               Authenticated-only message\n"
"    -aad_hex hex           Authenticated-only data in HEX format\n"
"    -in_str str            To be hashed string\n"
"    -in file | stdin       To be hashed file path\n"
"                           `-in_str` and `-in` should not be used together\n"
"                           If neither `-in` nor `-in_str` specified, read from stdin\n"
"    -hex                   Output hash value as hex string (by default)\n"
"    -bin                   Output hash value as binary\n"
"    -out file | stdout     Output file path. If not specified, output to stdout\n"
"\n"
"Examples\n"
"\n"
"  $ TEXT=`gmssl rand -outlen 20 -hex`\n"
"  $ KEY=`gmssl rand -outlen 16 -hex`\n"
"  $ AAD=\"The AAD Data\"\n"
"  $ gmssl ghash -h $KEY -aad $AAD -in_str $TEXT\n"
"\n";


int ghash_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *hhex = NULL;
	uint8_t *aad = NULL;
	uint8_t *aad_buf = NULL;
	size_t aadlen = 0;
	char *in_str = NULL;
	char *infile = NULL;
	int outformat = 0;
	char *outfile = NULL;
	uint8_t h[16];
	size_t hlen;
	FILE *infp = stdin;
	FILE *outfp = stdout;
	GHASH_CTX ghash_ctx;
	uint8_t dgst[GHASH_SIZE];
	int i;

	argc--;
	argv++;

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: gmssl %s %s\n", prog, usage);
			printf("%s\n", help);
			ret = 0;
			goto end;
		} else if (!strcmp(*argv, "-h")) {
			if (--argc < 1) goto bad;
			hhex = *(++argv);
			if (strlen(hhex) != sizeof(h) * 2) {
				fprintf(stderr, "gmssl %s: invalid H value length\n", prog);
				goto end;
			}
			if (hex_to_bytes(hhex, strlen(hhex), h, &hlen) != 1) {
				fprintf(stderr, "gmssl %s: invalid H hex digits\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-aad")) {
			if (--argc < 1) goto bad;
			if (aad) {
				fprintf(stderr, "gmssl %s: `-aad` or `aad_hex` has been specified\n", prog);
				goto bad;
			}
			aad = (uint8_t *)(*(++argv));
			aadlen = strlen((char *)aad);
		} else if (!strcmp(*argv, "-aad_hex")) {
			if (--argc < 1) goto bad;
			if (aad) {
				fprintf(stderr, "gmssl %s: `-aad` or `aad_hex` has been specified\n", prog);
				goto bad;
			}
			aad = (uint8_t *)(*(++argv));
			if (!(aad_buf = malloc(strlen((char *)aad)/2 + 1))) {
				fprintf(stderr, "gmssl %s: malloc failure\n", prog);
				goto end;
			}
			if (hex_to_bytes((char *)aad, strlen((char *)aad), aad_buf, &aadlen) != 1) {
				fprintf(stderr, "gmssl %s: `-aad_hex` invalid HEX format argument\n", prog);
				goto end;
			}
			aad = aad_buf;
		} else if (!strcmp(*argv, "-in_str")) {
			if (infile) {
				fprintf(stderr, "gmssl %s: `-in` and `-in_str` should not be used together\n", prog);
				goto end;
			}
			if (--argc < 1) goto bad;
			in_str = *(++argv);
		} else if (!strcmp(*argv, "-in")) {
			if (in_str) {
				fprintf(stderr, "gmssl %s: `-in` and `-in_str` should not be used together\n", prog);
				goto end;
			}
			if (--argc < 1) goto bad;
			infile = *(++argv);
			if (!(infp = fopen(infile, "rb"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, infile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-hex")) {
			if (outformat > 0) {
				fprintf(stderr, "gmssl %s: `-hex` and `-bin` should not be used together\n", prog);
				goto end;
			}
			outformat = 1;
		} else if (!strcmp(*argv, "-bin")) {
			if (outformat > 0) {
				fprintf(stderr, "gmssl %s: `-hex` and `-bin` should not be used together\n", prog);
				goto end;
			}
			outformat = 2;
		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) goto bad;
			outfile = *(++argv);
			if (!(outfp = fopen(outfile, "wb"))) {
				fprintf(stderr, "gmssl %s: open '%s' failure : %s\n", prog, outfile, strerror(errno));
				goto end;
			}
		} else {
			fprintf(stderr, "gmssl %s: illegal option '%s'\n", prog, *argv);
			goto end;
bad:
			fprintf(stderr, "gmssl %s: '%s' option value missing\n", prog, *argv);
			goto end;
		}

		argc--;
		argv++;
	}

	ghash_init(&ghash_ctx, h, aad, aadlen);

	if (in_str) {
		ghash_update(&ghash_ctx, (uint8_t *)in_str, strlen(in_str));

	} else {
		uint8_t buf[4096];
		size_t len;
		while ((len = fread(buf, 1, sizeof(buf), infp)) > 0) {
			ghash_update(&ghash_ctx, buf, len);
		}
		memset(buf, 0, sizeof(buf));
	}
	ghash_finish(&ghash_ctx, dgst);
	memset(&ghash_ctx, 0, sizeof(ghash_ctx));

	if (outformat > 1) {
		if (fwrite(dgst, 1, sizeof(dgst), outfp) != sizeof(dgst)) {
			fprintf(stderr, "gmssl %s: output failure : %s\n", prog, strerror(errno));
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
	if (infile && infp) fclose(infp);
	if (outfile && outfp) fclose(outfp);
	return ret;
}
