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

static const char *usage = "-pubkey file [-in file] -sig file [-verbose]\n";

static const char *options =
"Options\n"
"    -pubkey file                Input public key file\n"
"    -in file                    Input data file (if not using stdin)\n"
"    -sig file                   Input signature file\n"
"    -verbose                    Print public key and signature\n"
"\n";

int lmsverify_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *pubkeyfile = NULL;
	char *infile = NULL;
	char *sigfile = NULL;
	int verbose = 0;
	FILE *pubkeyfp = NULL;
	FILE *infp = stdin;
	FILE *sigfp = NULL;
	uint8_t pubkeybuf[LMS_PUBLIC_KEY_SIZE];
	size_t pubkeylen = LMS_PUBLIC_KEY_SIZE;
	const uint8_t *cp = pubkeybuf;
	uint8_t sig[LMS_SIGNATURE_MAX_SIZE];
	size_t siglen;
	LMS_KEY key;
	LMS_SIGN_CTX ctx;
	int vr;

	argc--;
	argv++;

	if (argc < 1) {
		fprintf(stderr, "usage: gmssl %s %s\n", prog, usage);
		return 1;
	}

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: %s %s\n", prog, usage);
			printf("%s\n", options);
			ret = 0;
			goto end;
		} else if (!strcmp(*argv, "-pubkey")) {
			if (--argc < 1) goto bad;
			pubkeyfile = *(++argv);
			if (!(pubkeyfp = fopen(pubkeyfile, "rb"))) {
				fprintf(stderr, "%s: open '%s' failure: %s\n", prog, pubkeyfile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);
			if (!(infp = fopen(infile, "rb"))) {
				fprintf(stderr, "%s: open '%s' failure: %s\n", prog, infile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-sig")) {
			if (--argc < 1) goto bad;
			sigfile = *(++argv);
			if (!(sigfp = fopen(sigfile, "rb"))) {
				fprintf(stderr, "%s: open '%s' failure: %s\n", prog, sigfile, strerror(errno));
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

	if (!pubkeyfile) {
		fprintf(stderr, "%s: `-key` option required\n", prog);
		goto end;
	}
	if (!sigfile) {
		fprintf(stderr, "%s: `-sig` option required\n", prog);
		goto end;
	}

	if (fread(pubkeybuf, 1, pubkeylen, pubkeyfp) != pubkeylen) {
		fprintf(stderr, "%s: read public key failure\n", prog);
		goto end;
	}
	if (lms_public_key_from_bytes(&key, &cp, &pubkeylen) != 1) {
		error_print();
		goto end;
	}
	if (verbose) {
		lms_public_key_print(stderr, 0, 0, "lms_public_key", &key.public_key);
	}

	// read signature even if signature not compatible with the public key
	if ((siglen = fread(sig, 1, LMS_SIGNATURE_MAX_SIZE, sigfp)) <= 0) {
		fprintf(stderr, "%s: read signature failure\n", prog);
		goto end;
	}
	if (verbose) {
		lms_signature_print(stderr, 0, 0, "lms_signature", sig, siglen);
	}
	if (lms_verify_init(&ctx, &key, sig, siglen) != 1) {
		error_print();
		goto end;
	}

	while (1) {
		uint8_t buf[1024];
		size_t len = fread(buf, 1, sizeof(buf), infp);
		if (len == 0) {
			break;
		}
		if (lms_verify_update(&ctx, buf, len) != 1) {
			error_print();
			goto end;
		}
	}
	if ((vr = lms_verify_finish(&ctx)) < 0) {
		error_print();
		goto end;
	}
	fprintf(stdout, "verify : %s\n", vr == 1 ? "success" : "failure");
	if (vr == 1) {
		ret = 0;
	}

end:
	if (pubkeyfp) fclose(pubkeyfp);
	if (infp && infp != stdin) fclose(infp);
	if (sigfp) fclose(sigfp);
	return ret;
}
