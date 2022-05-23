/*
 * Copyright (c) 2020 - 2021 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <gmssl/mem.h>
#include <gmssl/rand.h>


static const char *options = "[-hex] [-rdrand] -outlen num [-out file]";

int rand_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	int hex = 0;
	int rdrand = 0;
	int outlen = 0;
	char *outfile = NULL;
	FILE *outfp = stdout;
	uint8_t buf[2048];
	int i;

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

	if (!outlen) {
		fprintf(stderr, "%s: option -outlen missing\n", prog);
		goto end;
	}

	while (outlen) {
		size_t len = outlen < sizeof(buf) ? outlen : sizeof(buf);

		if (rdrand) {
/*
			if (rdrand_bytes(buf, len) != 1) {
				fprintf(stderr, "%s: inner error\n", prog);
				goto end;
			}
*/
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
		outlen -= len;
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
