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
#include <sys/stat.h>
#include <gmssl/x509.h>
#include <gmssl/x509_crl.h>


static const char *options = "-in file -cacert file\n";

int crlverify_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *infile = NULL;
	char *cacertfile = NULL;
	FILE *infp = NULL;
	FILE *cacertfp = NULL;
	uint8_t *in = NULL;
	size_t inlen;
	struct stat st;
	const uint8_t *pin;
	const uint8_t *crl = NULL;
	size_t crllen;
	const uint8_t *subject;
	size_t subject_len;
	uint8_t cacert[1024];
	size_t cacertlen;
	int rv;

	argc--;
	argv++;

	if (argc < 1) {
		fprintf(stderr, "usage: %s %s\n", prog, options);
		return 1;
	}

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: %s %s\n", prog, options);
			ret = 0;
			goto end;
		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);
			if (!(infp = fopen(infile, "r"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, infile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-cacert")) {
			if (--argc < 1) goto bad;
			cacertfile = *(++argv);
			if (!(cacertfp = fopen(cacertfile, "r"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, cacertfile, strerror(errno));
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
	if (!cacertfile) {
		fprintf(stderr, "%s: '-cacert' option required\n", prog);
		goto end;
	}


	if (fstat(fileno(infp), &st) < 0) {
		fprintf(stderr, "%s: access file error : %s\n", prog, strerror(errno));
		goto end;
	}
	if ((inlen = st.st_size) <= 0) {
		fprintf(stderr, "%s: invalid input length\n", prog);
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

	if (x509_crl_get_issuer(crl, crllen, &subject, &subject_len) != 1) {
		fprintf(stderr, "%s: inner error\n", prog);
		goto end;
	}
	if (x509_cert_from_pem_by_subject(cacert, &cacertlen, sizeof(cacert), subject, subject_len, cacertfp) != 1) {
		fprintf(stderr, "%s: read certificate failure\n", prog);
		goto end;
	}
	if ((rv = x509_crl_verify_by_ca_cert(crl, crllen, cacert, cacertlen, SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID))) < 0) {
		fprintf(stderr, "%s: verification inner error\n", prog);
		goto end;
	}

	printf("Verification %s\n", rv ? "success" : "failure");
	if (rv == 1) ret = 0;

end:
	if (infile && infp) fclose(infp);
	if (cacertfp) fclose(cacertfp);
	if (in) free(in);
	return ret;
}





















