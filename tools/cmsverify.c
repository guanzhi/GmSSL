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
#include <gmssl/cms.h>
#include <gmssl/x509.h>
#include <gmssl/rand.h>



static const char *options = "-in file [-out file]";

int cmsverify_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *infile = NULL;
	char *outfile = NULL;
	FILE *infp = NULL;
	FILE *outfp = NULL;
	size_t inlen;
	uint8_t *cms = NULL;
	size_t cmslen, cms_maxlen;
	int content_type;
	const uint8_t *content;
	size_t content_len;
	const uint8_t *certs;
	size_t certslen;
	const uint8_t *crls;
	size_t crlslen;
	const uint8_t *signer_infos;
	size_t signer_infos_len;
	int rv;

	argc--;
	argv++;

	if (argc < 1) {
		fprintf(stderr, "usage: %s %s\n", prog, options);
		return 1;
	}

	while (argc > 1) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: %s %s\n", prog, options);
			ret = 0;
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
	cms_maxlen = (inlen * 3)/4 + 1;
	if (!(cms = malloc(cms_maxlen))) {
		fprintf(stderr, "%s: malloc failure\n", prog);
		goto end;
	}
	if (cms_from_pem(cms, &cmslen, cms_maxlen, infp) != 1) {
		fprintf(stderr, "%s: read CMS failure\n", prog);
		goto end;
	}

	if ((rv = cms_verify(cms, cmslen, NULL, 0, NULL, 0,
		&content_type, &content, &content_len,
		&certs, &certslen, &crls, &crlslen,
		&signer_infos, &signer_infos_len)) < 0) {
		fprintf(stderr, "%s: verify error\n", prog);
		goto end;
	}
	printf("verify %s\n", rv ? "success" : "failure");
	ret = rv ? 0 : 1;

	if (outfile) {
		const uint8_t *p;
		size_t len;

		if (content_type == OID_cms_data) {
			if (asn1_octet_string_from_der(&p, &len, &content, &content_len) != 1
				|| asn1_length_is_zero(content_len) != 1) {
				fprintf(stderr, "%s: invalid CMS\n", prog);
				goto end;
			}
			if (len != fwrite(p, 1, len, outfp)) {
				fprintf(stderr, "%s: output error : %s\n", prog, strerror(errno));
				goto end;
			}
		} else {
			fprintf(stderr, "%s: error\n", prog);
			goto end;
		}

	}



end:
	if (infile && infp) fclose(infp);
	if (outfile && outfp) fclose(outfp);
	if (cms) free(cms);
	return ret;
}
