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
#include <gmssl/error.h>
#include <gmssl/xmss.h>


static const char *usage = "-xmss_type type -out file [-pubout file] [-verbose]\n";

static const char *options =
"Options\n"
"    -xmss_type type             XMSS Algorithm Type\n"
"                                 "XMSS_HASH256_10_256_NAME"\n"
"                                 "XMSS_HASH256_16_256_NAME"\n"
"                                 "XMSS_HASH256_20_256_NAME"\n"
"    -out file                   Output private key\n"
"    -pubout file                Output public key\n"
"    -verbose                    Print public key\n"
"\n";

int xmsskeygen_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *xmss_type = NULL;
	int xmss_type_val = 0;
	char *outfile = NULL;
	char *puboutfile = NULL;
	int verbose = 0;
	FILE *outfp = NULL;
	FILE *puboutfp = stdout;
	XMSS_KEY key;
	uint8_t *out = NULL;
	uint8_t *pout;
	size_t outlen;
	uint8_t pubout[XMSS_PUBLIC_KEY_SIZE];
	uint8_t *ppubout;
	size_t puboutlen ;

	memset(&key, 0, sizeof(key));

	argc--;
	argv++;

	if (argc < 1) {
		fprintf(stderr, "usage: gmssl %s %s\n", prog, usage);
		return 1;
	}

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: gmssl %s %s\n", prog, usage);
			printf("%s\n", options);
			ret = 0;
			goto end;
		} else if (!strcmp(*argv, "-xmss_type")) {
			if (--argc < 1) goto bad;
			xmss_type = *(++argv);
			if (!(xmss_type_val = xmss_type_from_name(xmss_type))) {
				fprintf(stderr, "%s: invalid xmss_type `%s`\n", prog, xmss_type);
				goto end;
			}
		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) goto bad;
			outfile = *(++argv);
			if (!(outfp = fopen(outfile, "wb"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, outfile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-pubout")) {
			if (--argc < 1) goto bad;
			puboutfile = *(++argv);
			if (!(puboutfp = fopen(puboutfile, "wb"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, outfile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-verbose")) {
			verbose = 1;
		} else {
			fprintf(stderr, "%s: illegal option '%s'\n", prog, *argv);
			goto end;
bad:
			fprintf(stderr, "%s: `%s` option value missing\n", prog, *argv);
			goto end;
		}

		argc--;
		argv++;
	}

	if (!xmss_type) {
		fprintf(stderr, "%s: `-xmss_type` option required\n", prog);
		goto end;
	}
	if (!outfp) {
		fprintf(stderr, "%s: `-out` option required\n", prog);
		goto end;
	}

	if (xmss_key_generate(&key, xmss_type_val) != 1) {
		error_print();
		return -1;
	}
	if (verbose) {
		xmss_public_key_print(stderr, 0, 0, "xmss_public_key", &key);
	}

	outlen = 0;
	if (xmss_private_key_to_bytes(&key, NULL, &outlen) != 1) {
		error_print();
		goto end;
	}
	if (!(out = malloc(outlen))) {
		error_print();
		goto end;
	}
	pout = out;
	outlen = 0;
	if (xmss_private_key_to_bytes(&key, &pout, &outlen) != 1) {
		error_print();
		goto end;
	}
	if (fwrite(out, 1, outlen, outfp) != outlen) {
		error_print();
		goto end;
	}

	ppubout = pubout;
	puboutlen = 0;
	if (xmss_public_key_to_bytes(&key, &ppubout, &puboutlen) != 1) {
		error_print();
		goto end;
	}
	if (puboutlen != sizeof(pubout)) {
		error_print();
		goto end;
	}
	if (fwrite(pubout, 1, puboutlen, puboutfp) != puboutlen) {
		error_print();
		goto end;
	}

	ret = 0;
end:
	xmss_key_cleanup(&key);
	if (out) {
		gmssl_secure_clear(out, outlen);
		free(out);
	}
	if (outfile && outfp) fclose(outfp);
	if (puboutfile && puboutfp) fclose(puboutfp);
	return ret;
}
