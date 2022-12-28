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


static const char *options = "-in file";

int cmsparse_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *infile = NULL;
	FILE *infp = stdin;
	size_t inlen;
	uint8_t *cms = NULL;
	size_t cms_maxlen, cmslen;

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
		fprintf(stderr, "%s: option '-in' required'\n", prog);
		goto end;
	}

	if (file_size(infp, &inlen) != 1) { // FIXME: infp == stdin?
		fprintf(stderr, "%s: access '%s' failed : %s\n", prog, infile, strerror(errno));
		goto end;
	}
	cms_maxlen = (inlen * 3)/4 + 1;
	if (!(cms = malloc(cms_maxlen))) {
		fprintf(stderr, "%s: malloc failure\n", prog);
		goto end;
	}
	if (cms_from_pem(cms, &cmslen, cms_maxlen, infp) != 1) {
		fprintf(stderr, "%s: parse CMS error\n", prog);
		goto end;
	}
	cms_print(stdout, 0, 0, "CMS", cms, cmslen);
	ret = 0;
end:
	if (infp) fclose(infp);
	if (cms) free(cms);
	return ret;
}
