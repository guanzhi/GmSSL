/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
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


static const char *options = "-key hex -iv hex [-in file] [-out file]";

int zuc_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *keyhex = NULL;
	char *ivhex = NULL;
	char *infile = NULL;
	char *outfile = NULL;
	uint8_t key[16];
	uint8_t iv[16];
	size_t keylen = sizeof(key);
	size_t ivlen = sizeof(iv);
	FILE *infp = stdin;
	FILE *outfp = stdout;
	ZUC_CTX zuc_ctx;
	uint8_t inbuf[4096];
	size_t inlen;
	uint8_t outbuf[4196];
	size_t outlen;

	argc--;
	argv++;

	if (argc < 1) {
		fprintf(stderr, "usage: %s %s\n", prog, options);
		return 1;
	}

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: %s %s\n", prog, options);
			ret = 0;
			goto end;
		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			keyhex = *(++argv);
			if (strlen(keyhex) != sizeof(key) * 2) {
				fprintf(stderr, "%s: invalid key length\n", prog);
				goto end;
			}
			if (hex_to_bytes(keyhex, strlen(keyhex), key, &keylen) != 1) {
				fprintf(stderr, "%s: invalid HEX digits\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-iv")) {
			if (--argc < 1) goto bad;
			ivhex = *(++argv);
			if (strlen(ivhex) != sizeof(iv) * 2) {
				fprintf(stderr, "%s: invalid IV length\n", prog);
				goto end;
			}
			if (hex_to_bytes(ivhex, strlen(ivhex), iv, &ivlen) != 1) {
				fprintf(stderr, "%s: invalid HEX digits\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);
			if (!(infp = fopen(infile, "rb"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, infile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) goto bad;
			outfile = *(++argv);
			if (!(outfp = fopen(outfile, "wb"))) {
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

	if (!keyhex) {
		fprintf(stderr, "%s: option '-key' missing\n", prog);
		goto end;
	}
	if (!ivhex) {
		fprintf(stderr, "%s: option '-iv' missing\n", prog);
		goto end;
	}

	if (zuc_encrypt_init(&zuc_ctx, key, iv) != 1) {
		fprintf(stderr, "%s: inner error\n", prog);
		goto end;
	}
	while ((inlen = fread(inbuf, 1, sizeof(inbuf), infp)) > 0) {
		if (zuc_encrypt_update(&zuc_ctx, inbuf, inlen, outbuf, &outlen) != 1) {
			fprintf(stderr, "%s: inner error\n", prog);
			goto end;
		}
		if (fwrite(outbuf, 1, outlen, outfp) != outlen) {
			fprintf(stderr, "%s: output failure : %s\n", prog, strerror(errno));
			goto end;
		}
	}
	if (zuc_encrypt_finish(&zuc_ctx, outbuf, &outlen) != 1) {
		fprintf(stderr, "%s: inner error\n", prog);
		goto end;
	}
	if (fwrite(outbuf, 1, outlen, outfp) != outlen) {
		fprintf(stderr, "%s: output failure : %s\n", prog, strerror(errno));
		goto end;
	}
	ret = 0;
end:
	gmssl_secure_clear(&zuc_ctx, sizeof(zuc_ctx));
	gmssl_secure_clear(key, sizeof(key));
	gmssl_secure_clear(iv, sizeof(iv));
	gmssl_secure_clear(inbuf, sizeof(inbuf));
	gmssl_secure_clear(outbuf, sizeof(outbuf));
	if (infile && infp) fclose(infp);
	if (outfile && outfp) fclose(outfp);
	return ret;
}
