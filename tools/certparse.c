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
#include <gmssl/pem.h>
#include <gmssl/x509.h>


static const char *options = "[-in file] [-out file]";

int certparse_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *infile = NULL;
	char *outfile = NULL;
	FILE *infp = stdin;
	FILE *outfp = stdout;
	uint8_t cert[18192];
	size_t certlen;

	argc--;
	argv++;

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: %s %s\n", prog, options);
			goto end;
		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);
			if (!(infp = fopen(infile, "r"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, infile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) goto bad;
			outfile = *(++argv);
			if (!(outfp = fopen(outfile, "w"))) {
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

	for (;;) {
		int rv;
		if ((rv = x509_cert_from_pem(cert, &certlen, sizeof(cert), infp)) != 1) {
			if (rv < 0) fprintf(stderr, "%s: read certificate failure\n", prog);
			else ret = 0;
			goto end;
		}
		x509_cert_print(outfp, 0, 0, "Certificate", cert, certlen);
		if (x509_cert_to_pem(cert, certlen, outfp) != 1) {
			fprintf(stderr, "%s: output certficate failure\n", prog);
			goto end;
		}
	}

end:
	if (infile && infp) fclose(infp);
	if (outfile && outfp) fclose(outfp);
	return ret;
}
