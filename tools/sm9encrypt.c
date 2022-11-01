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


static const char *options = "-pubmaster file -id str [-in file] [-out file]";


int sm9encrypt_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *mpkfile = NULL;
	char *id = NULL;
	char *infile = NULL;
	char *outfile = NULL;
	FILE *mpkfp = NULL;
	FILE *infp = stdin;
	FILE *outfp = stdout;
	SM9_ENC_MASTER_KEY mpk;
	uint8_t inbuf[SM9_MAX_PLAINTEXT_SIZE];
	uint8_t outbuf[SM9_MAX_CIPHERTEXT_SIZE];
	size_t inlen, outlen = sizeof(outbuf);

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
		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);
			if (!(infp = fopen(infile, "rb"))) {
				error_print();
				goto end;
			}
		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) goto bad;
			outfile = *(++argv);
			if (!(outfp = fopen(outfile, "wb"))) {
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

	if (!mpkfp || !id) {
		error_print();
		goto end;
	}
	if (sm9_enc_master_public_key_from_pem(&mpk, mpkfp) != 1) {
		error_print();
		return -1;
	}
	if ((inlen = fread(inbuf, 1, sizeof(inbuf), infp)) <= 0) {
		error_print();
		goto end;
	}
	if (sm9_encrypt(&mpk, id, strlen(id), inbuf, inlen, outbuf, &outlen) != 1) {
		error_print();
		goto end;
	}
	if (outlen != fwrite(outbuf, 1, outlen, outfp)) {
		error_print();
		goto end;
	}
	ret = 0;
end:
	if (infile && infp) fclose(infp);
	if (outfile && outfp) fclose(outfp);
	if (mpkfp) fclose(mpkfp);
	return ret;
}
