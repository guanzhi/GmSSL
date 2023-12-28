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
#include <gmssl/mem.h>
#include <gmssl/error.h>
#include <gmssl/sm3_xmss.h>


static const char *usage = "-oid oid [-out file] [-pubout file]\n";

static const char *help =
"Options\n"
"    -oid oid                    XMSS algorithm OID\n"
"                                 XMSS_SM3_10\n"
"                                 XMSS_SM3_16\n"
"                                 XMSS_SM3_20\n"
"    -out file                   Output private key\n"
"    -pubout file                Output public key\n"
"\n";

int sm3xmss_keygen_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *oid = NULL;
	uint32_t oid_val = 0;
	char *outfile = NULL;
	char *puboutfile = NULL;
	FILE *outfp = stdout;
	FILE *puboutfp = stdout;
	SM3_XMSS_KEY key;
	uint8_t *out = NULL;
	uint8_t *pubout = NULL;
	size_t outlen, puboutlen;

	argc--;
	argv++;

	if (argc < 1) {
		fprintf(stderr, "usage: %s %s\n", prog, help);
		return 1;
	}

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: %s %s\n", prog, usage);
			printf("%s\n", help);
			ret = 0;
			goto end;
		} else if (!strcmp(*argv, "-oid")) {
			if (--argc < 1) goto bad;
			oid = *(++argv);
			if (strcmp(oid, "XMSS_SM3_10") == 0) {
				oid_val = XMSS_SM3_10;
			} else if (strcmp(oid, "XMSS_SM3_16") == 0) {
				oid_val = XMSS_SM3_16;
			} else if (strcmp(oid, "XMSS_SM3_20") == 0) {
				oid_val = XMSS_SM3_20;
			} else {
				fprintf(stderr, "%s: invalid XMSS algor ID `%s`\n", prog, oid);
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

	if (!oid) {
		fprintf(stderr, "%s: `-oid` option required\n", prog);
		goto end;
	}


	if (sm3_xmss_key_generate(&key, oid_val) != 1) {
		error_print();
		return -1;
	}

	if (sm3_xmss_key_to_bytes(&key, NULL, &outlen) != 1) {
		error_print();
		goto end;
	}
	if (!(out = malloc(outlen))) {
		error_print();
		goto end;
	}
	if (sm3_xmss_key_to_bytes(&key, out, &outlen) != 1) {
		error_print();
	}

	if (sm3_xmss_public_key_to_bytes(&key, NULL, &puboutlen) != 1) {
		error_print();
		goto end;
	}
	if (!(pubout = malloc(puboutlen))) {
		error_print();
		goto end;
	}
	if (sm3_xmss_public_key_to_bytes(&key, pubout, &puboutlen) != 1) {
		error_print();
		goto end;
	}

	if (fwrite(out, 1, outlen, outfp) != outlen) {
		error_print();
		goto end;
	}
	if (fwrite(pubout, 1, puboutlen, puboutfp) != puboutlen) {
		error_print();
		goto end;
	}

	ret = 0;
end:
	gmssl_secure_clear(&key, sizeof(key));
	if (out) {
		gmssl_secure_clear(out, outlen);
		free(out);
	}
	if (pubout) {
		gmssl_secure_clear(pubout, puboutlen);
		free(pubout);
	}
	if (outfile && outfp) fclose(outfp);
	if (puboutfile && puboutfp) fclose(puboutfp);
	return ret;
}
