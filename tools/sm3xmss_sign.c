/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
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
#include <gmssl/error.h>
#include <gmssl/sm3_xmss.h>

static const char *usage = "-key file [-in file] [-out file]\n";

static const char *help =
"Options\n"
"    -key file                   Input private key file\n"
"    -in file                    Input data file (if not using stdin)\n"
"    -out file                   Output signature file\n"
"\n";

int sm3xmss_sign_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *keyfile = NULL;
	char *infile = NULL;
	char *outfile = NULL;
	FILE *keyfp = NULL;
	FILE *infp = stdin;
	FILE *outfp = stdout;
	SM3_XMSS_KEY key;
	SM3_XMSS_SIGN_CTX sign_ctx;
	uint8_t *sigbuf = NULL;
	size_t siglen;

	argc--;
	argv++;

	if (argc < 1) {
		fprintf(stderr, "usage: %s %s\n", prog, usage);
		return 1;
	}

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: %s %s\n", prog, usage);
			printf("%s\n", help);
			ret = 0;
			goto end;
		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			keyfile = *(++argv);
			if (!(keyfp = fopen(keyfile, "rb"))) {
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

	if (sm3_xmss_key_from_bytes(&key, NULL, 0) != 1) {
		error_print();
		goto end;
	}

	if (fread(&key, 1, sizeof(key), keyfp) != sizeof(key)) {
		fprintf(stderr, "%s: read private key failure\n", prog);
		goto end;
	}

	if (sm3_xmss_sign_init(&sign_ctx, &key) != 1) {
		error_print();
		goto end;
	}

	while (1) {
		uint8_t buf[1024];
		size_t len = fread(buf, 1, sizeof(buf), infp);
		if (len == 0) {
			break;
		}
		if (sm3_xmss_sign_update(&sign_ctx, buf, len) != 1) {
			error_print();
			goto end;
		}
	}

	if (sm3_xmss_sign_finish(&sign_ctx, &key, NULL, &siglen) != 1) {
		error_print();
		goto end;
	}

	if (!(sigbuf = malloc(siglen))) {
		fprintf(stderr, "%s: malloc failure\n", prog);
		goto end;
	}

	if (sm3_xmss_sign_finish(&sign_ctx, &key, sigbuf, &siglen) != 1) {
		error_print();
		goto end;
	}

	if (fwrite(sigbuf, 1, siglen, outfp) != siglen) {
		error_print();
		goto end;
	}

	ret = 0;

end:
	gmssl_secure_clear(&key, sizeof(key));
	gmssl_secure_clear(&sign_ctx, sizeof(sign_ctx));
	if (sigbuf) {
		gmssl_secure_clear(sigbuf, siglen);
		free(sigbuf);
	}
	if (keyfp) fclose(keyfp);
	if (infp && infp != stdin) fclose(infp);
	if (outfp && outfp != stdout) fclose(outfp);
	return ret;
}
