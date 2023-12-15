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
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <gmssl/mem.h>
#include <gmssl/rand.h>


static const char *options = "[-hex] [-rdrand|-rdseed] -outlen num [-out file]";

int rand_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	int hex = 0;
	int rdrand = 0;
	int rdseed = 0;
	int outlen = 0;
	char *outfile = NULL;
	FILE *outfp = stdout;
	uint8_t buf[2048];

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
		} else if (!strcmp(*argv, "-hex")) {
			hex = 1;
		} else if (!strcmp(*argv, "-rdrand")) {
			rdrand = 1;
		} else if (!strcmp(*argv, "-rdseed")) {
			rdseed = 1;
		} else if (!strcmp(*argv, "-outlen")) {
			if (--argc < 1) goto bad;
			outlen = atoi(*(++argv));
			if (outlen < 1 || outlen > INT_MAX) {
				fprintf(stderr, "%s: invalid outlen\n", prog);
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

	if (!outlen) {
		fprintf(stderr, "%s: option -outlen missing\n", prog);
		goto end;
	}

	while (outlen > 0) {
		size_t len = outlen < sizeof(buf) ? outlen : sizeof(buf);

		if (rdrand) {
#ifdef INTEL_RDRAND
			if (rdrand_bytes(buf, len) != 1) {
				fprintf(stderr, "%s: inner error\n", prog);
				goto end;
			}
#else
			fprintf(stderr, "%s: `-rdrand` is not supported on your platform\n", prog);
#endif
		} else if (rdseed) {
#ifdef INTEL_RDSEED
			if (rdseed_bytes(buf, len) != 1) {
				fprintf(stderr, "%s: inner error\n", prog);
				goto end;
			}
#else
			fprintf(stderr, "%s: `-rdseed` is not supported on your platform\n", prog);
#endif
		} else {
			if (rand_bytes(buf, len) != 1) {
				fprintf(stderr, "%s: inner error\n", prog);
				goto end;
			}
		}

		if (hex) {
			int i;
			for (i = 0; i < len; i++) {
				fprintf(outfp, "%02X", buf[i]);
			}
		} else {
			if (fwrite(buf, 1, len, outfp) != len) {
				fprintf(stderr, "%s: output failure : %s\n", prog, strerror(errno));
				goto end;
			}
		}
		outlen -= (int)len;
	}
	if (hex) {
		fprintf(outfp, "\n");
	}
	ret = 0;
end:
	gmssl_secure_clear(buf, sizeof(buf));
	if (outfile && outfp) fclose(outfp);
	return ret;
}
