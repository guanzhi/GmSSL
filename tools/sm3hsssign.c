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
#include <gmssl/sm3_lms.h>

static const char *usage = "-key file [-in file] [-out file] [-verbose]\n";

static const char *options =
"Options\n"
"    -key file                   Input private key file\n"
"    -in file                    Input data file (if not using stdin)\n"
"    -out file                   Output signature file\n"
"    -verbose                    Print public key and signature\n"
"\n";

int sm3hsssign_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *keyfile = NULL;
	char *infile = NULL;
	char *outfile = NULL;
	int verbose = 0;
	FILE *keyfp = NULL;
	FILE *infp = stdin;
	FILE *outfp = stdout;
	uint8_t keybuf[SM3_HSS_PRIVATE_KEY_MAX_SIZE];
	size_t keylen = SM3_HSS_PRIVATE_KEY_MAX_SIZE;
	const uint8_t *cp = keybuf;
	uint8_t *p = keybuf;
	SM3_HSS_KEY key;
	SM3_HSS_SIGN_CTX ctx;
	uint8_t sig[SM3_HSS_SIGNATURE_MAX_SIZE];
	size_t siglen;

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
		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			keyfile = *(++argv);
			if (!(keyfp = fopen(keyfile, "rb+"))) {
				fprintf(stderr, "%s: open '%s' failure: %s\n", prog, keyfile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);
			if (!(infp = fopen(infile, "rb"))) {
				fprintf(stderr, "%s: open '%s' failure: %s\n", prog, infile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) goto bad;
			outfile = *(++argv);
			if (!(outfp = fopen(outfile, "wb"))) {
				fprintf(stderr, "%s: open '%s' failure: %s\n", prog, outfile, strerror(errno));
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

	if (!keyfile) {
		fprintf(stderr, "%s: `-key` option required\n", prog);
		goto end;
	}

	if ((keylen = fread(keybuf, 1, keylen, keyfp)) <= 0) {
		fprintf(stderr, "%s: read private key failure\n", prog);
		goto end;
	}
	if (sm3_hss_private_key_from_bytes(&key, &cp, &keylen) != 1) {
		error_print();
		goto end;
	}
	if (keylen) {
		error_print();
		return -1;
	}

	if (verbose) {
		sm3_hss_public_key_print(stderr, 0, 0, "hss_public_key", &key);
	}

	if (sm3_hss_sign_init(&ctx, &key) != 1) {
		error_print();
		goto end;
	}

	// write updated key back to file
	// TODO: write back `q` only
	if (sm3_hss_private_key_to_bytes(&key, &p, &keylen) != 1) {
		error_print();
		return -1;
	}
	rewind(keyfp);
	if (fwrite(keybuf, 1, keylen, keyfp) != keylen) {
		error_print();
		return -1;
	}

	while (1) {
		uint8_t buf[1024];
		size_t len = fread(buf, 1, sizeof(buf), infp);
		if (len == 0) {
			break;
		}
		if (sm3_hss_sign_update(&ctx, buf, len) != 1) {
			error_print();
			goto end;
		}
	}
	if (sm3_hss_sign_finish(&ctx, sig, &siglen) != 1) {
		error_print();
		goto end;
	}
	if (fwrite(sig, 1, siglen, outfp) != siglen) {
		error_print();
		goto end;
	}
	if (verbose) {
		sm3_hss_signature_print(stderr, 0, 0, "hss_signature", sig, siglen);
	}

	ret = 0;

end:
	gmssl_secure_clear(keybuf, sizeof(keybuf));
	gmssl_secure_clear(&key, sizeof(key));
	gmssl_secure_clear(&ctx, sizeof(ctx));
	if (keyfp) fclose(keyfp);
	if (infp && infp != stdin) fclose(infp);
	if (outfp && outfp != stdout) fclose(outfp);
	return ret;
}
