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
#include <gmssl/mem.h>
#include <gmssl/hex.h>
#include <gmssl/pbkdf2.h>


static const char *options = "-pass str -salt hex -iter num -outlen num [-bin|-hex] [-out file]";

int pbkdf2_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *pass = NULL;
	char *salthex = NULL;
	uint8_t salt[PBKDF2_MAX_SALT_SIZE];
	size_t saltlen;
	int iter = 0;
	int outlen = 0;
	int bin = 0;
	char *outfile = NULL;
	uint8_t outbuf[64];
	FILE *outfp = stdout;
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
		} else if (!strcmp(*argv, "-pass")) {
			if (--argc < 1) goto bad;
			pass = *(++argv);
		} else if (!strcmp(*argv, "-salt")) {
			if (--argc < 1) goto bad;
			salthex = *(++argv);
			if (strlen(salthex) > sizeof(salt) * 2) {
				fprintf(stderr, "%s: invalid salt length\n", prog);
				goto end;
			}
			if (hex_to_bytes(salthex, strlen(salthex), salt, &saltlen) != 1) {
				fprintf(stderr, "%s: invalid HEX digits\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-iter")) {
			if (--argc < 1) goto bad;
			iter = atoi(*(++argv));
			if (iter < PBKDF2_MIN_ITER || iter > INT_MAX) {
				fprintf(stderr, "%s: invalid '-iter' value\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-outlen")) {
			if (--argc < 1) goto bad;
			outlen = atoi(*(++argv));
			if (outlen < 1 || outlen > sizeof(outbuf)) {
				fprintf(stderr, "%s: invalid outlen\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-hex")) {
			bin = 0;
		} else if (!strcmp(*argv, "-bin")) {
			bin = 1;
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

	if (!pass) {
		fprintf(stderr, "%s: option '-pass' required\n", prog);
		goto end;
	}
	if (!salthex) {
		fprintf(stderr, "%s: option '-salt' required\n", prog);
		goto end;
	}
	if (!iter) {
		fprintf(stderr, "%s: option '-iter' required\n", prog);
		goto end;
	}
	if (!outlen) {
		fprintf(stderr, "%s: option '-outlen' required\n", prog);
		goto end;
	}

	if (pbkdf2_hmac_sm3_genkey(pass, strlen(pass), salt, saltlen, iter, outlen, outbuf) != 1) {
		fprintf(stderr, "%s: inner error\n", prog);
		goto end;
	}

	if (bin) {
		if (fwrite(outbuf, 1, outlen, outfp) != outlen) {
			fprintf(stderr, "%s: output failure : %s\n", prog, strerror(errno));
			goto end;
		}
	} else {
		for (i = 0; i < outlen; i++) {
			fprintf(outfp, "%02x", outbuf[i]);
		}
		fprintf(outfp, "\n");
	}
	ret = 0;

end:
	gmssl_secure_clear(outbuf, sizeof(outbuf));
	gmssl_secure_clear(salt, sizeof(salt));
	if (outfile && outfp) fclose(outfp);
	return ret;
}
