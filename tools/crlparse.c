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
#include <gmssl/file.h>
#include <gmssl/x509.h>
#include <gmssl/x509_crl.h>


static const char *options = "-in file [-out file]";

int crlparse_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *infile = NULL;
	char *outfile = NULL;
	FILE *infp = stdin;
	FILE *outfp = stdout;
	uint8_t *in = NULL;
	size_t inlen;
	const uint8_t *pin;
	const uint8_t *crl = NULL;
	size_t crllen;

	argc--;
	argv++;

	if (argc < 1) {
		fprintf(stderr, "usage: %s %s\n", prog, options);
		return 1;
	}

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: %s %s\n", prog, options);
			goto end;
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

	if (!infile) {
		fprintf(stderr, "%s: '-in' option required\n", prog);
		goto end;
	}
	if (file_size(infp, &inlen) != 1) {
		fprintf(stderr, "%s: get input length failed\n", prog);
		goto end;
	}
	if (!(in = malloc(inlen))) {
		fprintf(stderr, "%s: malloc failure\n", prog);
		goto end;
	}
	if (fread(in, 1, inlen, infp) != inlen) {
		fprintf(stderr, "%s: read file error : %s\n",  prog, strerror(errno));
		goto end;
	}
	pin = in;
	if (x509_crl_from_der(&crl, &crllen, &pin, &inlen) != 1
		|| asn1_length_is_zero(inlen) != 1) {
		fprintf(stderr, "%s: read CRL failure\n", prog);
		goto end;
	}
	x509_crl_print(outfp, 0, 0, "CRL", crl, crllen);
	ret = 0;

end:
	if (infile && infp) fclose(infp);
	if (outfile && outfp) fclose(outfp);
	if (in) free(in);
	return ret;
}
