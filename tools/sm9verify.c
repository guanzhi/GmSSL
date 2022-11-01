/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/sm9.h>
#include <gmssl/error.h>


static const char *options = "[-in file] -pubmaster file -id str -sig file";

int sm9verify_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *infile = NULL;
	char *mpkfile = NULL;
	char *id = NULL;
	char *sigfile = NULL;
	FILE *infp = stdin;
	FILE *mpkfp = NULL;
	FILE *sigfp = NULL;
	SM9_SIGN_MASTER_KEY mpk;
	SM9_SIGN_CTX ctx;
	uint8_t buf[4096];
	size_t len;
	uint8_t sig[SM9_SIGNATURE_SIZE];
	size_t siglen;

	argc--;
	argv++;

	if (argc < 1) {
		fprintf(stderr, "usage: %s %s\n", prog, options);
		return 1;
	}

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			fprintf(stdout, "usage: %s %s\n", prog, options);
			return 0;
		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);
			if (!(infp = fopen(infile, "rb"))) {
				error_print();
				goto end;
			}
		} else if (!strcmp(*argv, "-pubmaster")) {
			if (--argc < 1) goto bad;
			mpkfile = *(++argv);
			if (!(mpkfp = fopen(mpkfile, "rb"))) {
				error_print();
				goto end;
			}
		} else if (!strcmp(*argv, "-id")) {
			if (--argc < 1) goto bad;
			id = *(++argv);
		} else if (!strcmp(*argv, "-sig")) {
			if (--argc < 1) goto bad;
			sigfile = *(++argv);
			if (!(sigfp = fopen(sigfile, "rb"))) {
				error_print();
				goto end;
			}
		} else {
bad:
			fprintf(stderr, "%s: illegal option '%s'\n", prog, *argv);
			return 1;
		}

		argc--;
		argv++;
	}

	if (!mpkfile || !id || !sigfile) {
		error_print();
		goto end;
	}

	if (sm9_sign_master_public_key_from_pem(&mpk, mpkfp) != 1) {
		error_print();
		goto end;
	}

	if ((siglen = fread(sig, 1, sizeof(sig), sigfp)) <= 0) {
		error_print();
		goto end;
	}

	if (sm9_verify_init(&ctx) != 1) {
		error_print();
		goto end;
	}
	while ((len = fread(buf, 1, sizeof(buf), infp)) > 0) {
		if (sm9_verify_update(&ctx, buf, len) != 1) {
			error_print();
			goto end;
		}
	}
	if ((ret = sm9_verify_finish(&ctx, sig, siglen, &mpk, id, strlen(id))) != 1) {
		error_print();
		goto end;
	}
	printf("%s %s\n", prog, ret ? "success" : "failure");

end:
	if (infile && infp) fclose(infp);
	if (mpkfile && mpkfp) fclose(mpkfp);
	if (sigfile && sigfp) fclose(sigfp);
	return ret;
}








