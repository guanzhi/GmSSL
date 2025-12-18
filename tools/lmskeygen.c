/*
 *  Copyright 2014-2025 The GmSSL Project. All Rights Reserved.
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
#include <gmssl/lms.h>


static const char *usage = "-lms_type type -out file [-pubout file] [-verbose]\n";

static const char *options =
"Options\n"
"    -lms_type type              LMS Algorithm Type\n"
"                                 "LMS_HASH256_M32_H5_NAME"\n"
"                                 "LMS_HASH256_M32_H10_NAME"\n"
"                                 "LMS_HASH256_M32_H15_NAME"\n"
"                                 "LMS_HASH256_M32_H20_NAME"\n"
"                                 "LMS_HASH256_M32_H25_NAME"\n"
"    -out file                   Output private key\n"
"    -pubout file                Output public key\n"
"    -verbose                    Print public key\n"
"\n";

int lmskeygen_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *lms_type = NULL;
	int lms_type_val = 0;
	char *outfile = NULL;
	char *puboutfile = NULL;
	int verbose = 0;
	FILE *outfp = NULL;
	FILE *puboutfp = stdout;
	LMS_KEY key;
	uint8_t out[LMS_PRIVATE_KEY_SIZE];
	uint8_t pubout[LMS_PUBLIC_KEY_SIZE];
	uint8_t *pout = out;
	uint8_t *ppubout = pubout;
	size_t outlen = 0, puboutlen = 0;

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
		} else if (!strcmp(*argv, "-lms_type")) {
			if (--argc < 1) goto bad;
			lms_type = *(++argv);
			if (!(lms_type_val = lms_type_from_name(lms_type))) {
				fprintf(stderr, "%s: invalid lms_type `%s`\n", prog, lms_type);
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

	if (!lms_type) {
		fprintf(stderr, "%s: `-lms_type` option required\n", prog);
		goto end;
	}
	if (!outfp) {
		fprintf(stderr, "%s: `-out` option required\n", prog);
		goto end;
	}

	if (lms_key_generate(&key, lms_type_val) != 1) {
		error_print();
		return -1;
	}
	if (verbose) {
		lms_public_key_print(stderr, 0, 0, "lms_public_key", &key.public_key);
	}

	if (lms_private_key_to_bytes(&key, &pout, &outlen) != 1) {
		error_print();
		goto end;
	}
	if (fwrite(out, 1, outlen, outfp) != outlen) {
		error_print();
		goto end;
	}

	if (lms_public_key_to_bytes(&key, &ppubout, &puboutlen) != 1) {
		error_print();
		goto end;
	}
	if (fwrite(pubout, 1, puboutlen, puboutfp) != puboutlen) {
		error_print();
		goto end;
	}

	ret = 0;
end:
	lms_key_cleanup(&key);
	gmssl_secure_clear(out, outlen);
	if (outfile && outfp) fclose(outfp);
	if (puboutfile && puboutfp) fclose(puboutfp);
	return ret;
}
