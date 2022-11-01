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
#include <stdlib.h>
#include <string.h>
#include <gmssl/mem.h>
#include <gmssl/hex.h>
#include <gmssl/sm3.h>


static const char *options = "-key hex [-in file] [-bin|-hex] [-out file]";

int sm3hmac_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *keyhex = NULL;
	int bin = 0;
	char *infile = NULL;
	char *outfile = NULL;
	uint8_t key[SM3_DIGEST_SIZE];
	size_t keylen;
	FILE *infp = stdin;
	FILE *outfp = stdout;
	uint8_t buf[4096];
	size_t len;
	SM3_HMAC_CTX ctx;
	uint8_t mac[SM3_HMAC_SIZE];
	size_t i;

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
			if (strlen(keyhex) > sizeof(key) * 2) {
				fprintf(stderr, "%s: key should be less than 64 digits (32 bytes)\n", prog);
				goto end;
			}
			if (hex_to_bytes(keyhex, strlen(keyhex), key, &keylen) != 1) {
				fprintf(stderr, "%s: invalid HEX digits\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-hex")) {
			bin = 0;
		} else if (!strcmp(*argv, "-bin")) {
			bin = 1;
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
		fprintf(stderr, "%s: option '-key' required\n", prog);
		goto end;
	}

	sm3_hmac_init(&ctx, key, keylen);
	while ((len = fread(buf, 1, sizeof(buf), infp)) > 0) {
		sm3_hmac_update(&ctx, buf, len);
	}
	sm3_hmac_finish(&ctx, mac);

	if (bin) {
		if (fwrite(mac, 1, sizeof(mac), outfp) != sizeof(mac)) {
			fprintf(stderr, "%s: output failure : %s\n", prog, strerror(errno));
			goto end;
		}
	} else {
		for (i = 0; i < sizeof(mac); i++) {
			fprintf(outfp, "%02x", mac[i]);
		}
		fprintf(outfp, "\n");
	}
	ret = 0;
end:
	gmssl_secure_clear(key, sizeof(key));
	gmssl_secure_clear(&ctx, sizeof(ctx));
	if (infile && infp) fclose(infp);
	if (outfile && outfp) fclose(outfp);
	return ret;
}
