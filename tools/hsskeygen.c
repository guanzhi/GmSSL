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


static const char *usage = "-lms_types types -out file [-pubout file] [-verbose]\n";

static const char *options =
"Options\n"
"    -lms_types types            LMS Algorithm Types, start from level 0, seperate by ':'\n"
"                                 such as "LMS_HASH256_M32_H5_NAME":"LMS_HASH256_M32_H10_NAME"\n"
"                                Supported types:\n"
"                                 "LMS_HASH256_M32_H5_NAME"\n"
"                                 "LMS_HASH256_M32_H10_NAME"\n"
"                                 "LMS_HASH256_M32_H15_NAME"\n"
"                                 "LMS_HASH256_M32_H20_NAME"\n"
"                                 "LMS_HASH256_M32_H25_NAME"\n"
"    -out file                   Output private key\n"
"    -pubout file                Output public key\n"
"    -verbose                    Print public key\n"
"\n";

#define LMS_TYPES_STR_MAX_SIZE	(sizeof("LMS_SM3_M32_H20_NAME") * 5)

int hsskeygen_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *lms_types = NULL;
	char *outfile = NULL;
	char *puboutfile = NULL;
	int verbose = 0;
	char lms_types_str[LMS_TYPES_STR_MAX_SIZE];
	int lms_types_val[5];
	int levels = 0;
	FILE *outfp = NULL;
	FILE *puboutfp = stdout;
	HSS_KEY key;
	uint8_t out[HSS_PRIVATE_KEY_MAX_SIZE];
	uint8_t pubout[HSS_PUBLIC_KEY_SIZE];
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
		} else if (!strcmp(*argv, "-lms_types")) {
			char *tok;
			if (--argc < 1) goto bad;
			lms_types = *(++argv);
			strncpy(lms_types_str, lms_types, sizeof(lms_types_str));

			tok = strtok(lms_types_str, ":");
			while (tok) {
				if (!(lms_types_val[levels] = lms_type_from_name(tok))) {
					fprintf(stderr, "%s: invalid lms_type `%s`\n", prog, tok);
					goto end;
				}
				tok = strtok(NULL, ":");
				levels++;
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

	if (!lms_types) {
		fprintf(stderr, "%s: `-lms_types` option required\n", prog);
		goto end;
	}
	if (!outfp) {
		fprintf(stderr, "%s: `-out` option required\n", prog);
		goto end;
	}

	if (hss_key_generate(&key, lms_types_val, levels) != 1) {
		error_print();
		return -1;
	}
	if (verbose) {
		hss_public_key_print(stderr, 0, 0, "hss_public_key", &key);
	}

	if (hss_private_key_to_bytes(&key, &pout, &outlen) != 1) {
		error_print();
		goto end;
	}
	if (fwrite(out, 1, outlen, outfp) != outlen) {
		error_print();
		goto end;
	}

	if (hss_public_key_to_bytes(&key, &ppubout, &puboutlen) != 1) {
		error_print();
		goto end;
	}
	if (fwrite(pubout, 1, puboutlen, puboutfp) != puboutlen) {
		error_print();
		goto end;
	}

	ret = 0;
end:
	hss_key_cleanup(&key);
	gmssl_secure_clear(out, outlen);
	if (outfile && outfp) fclose(outfp);
	if (puboutfile && puboutfp) fclose(puboutfp);
	return ret;
}
