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
#include <string.h>
#include <stdlib.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/error.h>


static const char *options = "[-hex|-bin] [-pubkey pem [-id str]] [-in file] [-out file]";

int sm3_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	int bin = 0;
	char *pubkeyfile = NULL;
	char *infile = NULL;
	char *outfile = NULL;
	char *id = NULL;
	FILE *pubkeyfp = NULL;
	FILE *infp = stdin;
	FILE *outfp = stdout;
	SM3_CTX sm3_ctx;
	uint8_t dgst[32];
	uint8_t buf[4096];
	size_t len;
	int i;

	argc--;
	argv++;

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: %s %s\n", prog, options);
			printf("usage: echo -n \"abc\" | %s\n", prog);
			ret = 0;
			goto end;
		} else if (!strcmp(*argv, "-hex")) {
			if (bin) {
				error_print();
				goto end;
			}
			bin = 0;
		} else if (!strcmp(*argv, "-bin")) {
			bin = 1;
		} else if (!strcmp(*argv, "-pubkey")) {
			if (--argc < 1) goto bad;
			pubkeyfile = *(++argv);
			if (!(pubkeyfp = fopen(pubkeyfile, "rb"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, pubkeyfile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-id")) {
			if (--argc < 1) goto bad;
			id = *(++argv);
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

	sm3_init(&sm3_ctx);

	if (pubkeyfile) {
		SM2_KEY sm2_key;
		uint8_t z[32];

		if (sm2_public_key_info_from_pem(&sm2_key, pubkeyfp) != 1) {
			fprintf(stderr, "%s: parse public key failed\n", prog);
			goto end;
		}
		if (!id) {
			id = SM2_DEFAULT_ID;
		}

		sm2_compute_z(z, (SM2_POINT *)&sm2_key, id, strlen(id));
		sm3_update(&sm3_ctx, z, sizeof(z));
	} else {
		if (id) {
			fprintf(stderr, "%s: option '-id' must be with '-pubkey'\n", prog);
			goto end;
		}
	}

	while ((len = fread(buf, 1, sizeof(buf), infp)) > 0) {
		sm3_update(&sm3_ctx, buf, len);
	}
	sm3_finish(&sm3_ctx, dgst);

	if (bin) {
		if (fwrite(dgst, 1, sizeof(dgst), outfp) != sizeof(dgst)) {
			fprintf(stderr, "%s: output failure : %s\n", prog, strerror(errno));
			goto end;
		}
	} else {
		for (i = 0; i < sizeof(dgst); i++) {
			fprintf(outfp, "%02x", dgst[i]);
		}
		fprintf(outfp, "\n");
	}
	ret = 0;
end:
	if (pubkeyfp) fclose(pubkeyfp);
	if (infile && infp) fclose(infp);
	if (outfile && outfp) fclose(outfp);
	return ret;
}
