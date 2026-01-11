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
#include <gmssl/sphincs.h>


static const char *usage = "-out file [-pubout file] [-verbose]\n";

static const char *options =
"Options\n"
"    -out file                   Output private key\n"
"    -pubout file                Output public key\n"
"    -verbose                    Print public key\n"
"\n";

int sphincskeygen_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *outfile = NULL;
	char *puboutfile = NULL;
	int verbose = 0;
	FILE *outfp = NULL;
	FILE *puboutfp = stdout;
	SPHINCS_KEY key;
	uint8_t out[SPHINCS_PRIVATE_KEY_SIZE];
	uint8_t *pout = out;
	size_t outlen = 0;
	uint8_t pubout[SPHINCS_PUBLIC_KEY_SIZE];
	uint8_t *ppubout = pubout;
	size_t puboutlen = 0;

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

	if (!outfp) {
		fprintf(stderr, "%s: `-out` option required\n", prog);
		goto end;
	}

	if (sphincs_key_generate(&key) != 1) {
		error_print();
		return -1;
	}
	if (verbose) {
		sphincs_public_key_print(stderr, 0, 0, "sphincs_public_key", &key);
	}

	if (sphincs_private_key_to_bytes(&key, &pout, &outlen) != 1) {
		error_print();
		goto end;
	}
	if (fwrite(out, 1, outlen, outfp) != outlen) {
		error_print();
		goto end;
	}

	if (sphincs_public_key_to_bytes(&key, &ppubout, &puboutlen) != 1) {
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
	sphincs_key_cleanup(&key);
	gmssl_secure_clear(out, sizeof(out));
	if (outfile && outfp) fclose(outfp);
	if (puboutfile && puboutfp) fclose(puboutfp);
	return ret;
}
