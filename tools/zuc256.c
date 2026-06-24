/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
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
#include <gmssl/mem.h>
#include <gmssl/zuc.h>
#include <gmssl/hex.h>


static const char *usage = "-key hex -iv hex [-in file] [-out file]";

static const char *help =
"Options\n"
"\n"
"    -key hex            ZUC-256 key in HEX format, 32 bytes\n"
"    -iv hex             ZUC-256 IV in HEX format, 23 bytes\n"
"    -in file | stdin    Input data\n"
"    -out file | stdout  Output data\n"
"\n"
"Examples\n"
"\n"
"    gmssl zuc256 -key 0000000000000000000000000000000000000000000000000000000000000000 \\\n"
"        -iv 0000000000000000000000000000000000000000000000 -in plaintext.bin -out ciphertext.bin\n"
"\n";

int zuc256_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *keyhex = NULL;
	char *ivhex = NULL;
	char *infile = NULL;
	char *outfile = NULL;
	uint8_t key[ZUC256_KEY_SIZE];
	uint8_t iv[ZUC256_IV_SIZE];
	size_t keylen;
	size_t ivlen;
	FILE *infp = stdin;
	FILE *outfp = stdout;
	ZUC_STATE zuc_state;
	uint8_t inbuf[4096];
	uint8_t outbuf[4096];
	size_t inlen;

	argc--;
	argv++;

	if (argc < 1) {
		fprintf(stderr, "usage: gmssl %s %s\n", prog, usage);
		return 1;
	}

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: gmssl %s %s\n", prog, usage);
			printf("%s\n", help);
			ret = 0;
			goto end;
		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			keyhex = *(++argv);
			if (strlen(keyhex) != sizeof(key) * 2) {
				fprintf(stderr, "gmssl %s: key should be 32 bytes\n", prog);
				goto end;
			}
			if (hex_to_bytes(keyhex, strlen(keyhex), key, &keylen) != 1) {
				fprintf(stderr, "gmssl %s: invalid key hex digits\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-iv")) {
			if (--argc < 1) goto bad;
			ivhex = *(++argv);
			if (strlen(ivhex) != sizeof(iv) * 2) {
				fprintf(stderr, "gmssl %s: IV should be 23 bytes\n", prog);
				goto end;
			}
			if (hex_to_bytes(ivhex, strlen(ivhex), iv, &ivlen) != 1) {
				fprintf(stderr, "gmssl %s: invalid IV hex digits\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);
			if (!(infp = fopen(infile, "rb"))) {
				fprintf(stderr, "gmssl %s: open '%s' failure : %s\n", prog, infile, strerror(errno));
				goto end;
			}
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

	if (!keyhex) {
		fprintf(stderr, "gmssl %s: option '-key' required\n", prog);
		goto end;
	}
	if (!ivhex) {
		fprintf(stderr, "gmssl %s: option '-iv' required\n", prog);
		goto end;
	}

	zuc256_init(&zuc_state, key, iv);
	while ((inlen = fread(inbuf, 1, sizeof(inbuf), infp)) > 0) {
		zuc_encrypt(&zuc_state, inbuf, inlen, outbuf);
		if (fwrite(outbuf, 1, inlen, outfp) != inlen) {
			fprintf(stderr, "gmssl %s: output failure : %s\n", prog, strerror(errno));
			goto end;
		}
	}
	if (ferror(infp)) {
		fprintf(stderr, "gmssl %s: read failure : %s\n", prog, strerror(errno));
		goto end;
	}

	ret = 0;

end:
	gmssl_secure_clear(&zuc_state, sizeof(zuc_state));
	gmssl_secure_clear(key, sizeof(key));
	gmssl_secure_clear(iv, sizeof(iv));
	gmssl_secure_clear(inbuf, sizeof(inbuf));
	gmssl_secure_clear(outbuf, sizeof(outbuf));
	if (infile && infp) fclose(infp);
	if (outfile && outfp) fclose(outfp);
	return ret;
}
