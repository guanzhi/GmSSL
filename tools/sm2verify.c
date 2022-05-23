/*
 * Copyright (c) 2021 - 2021 The GmSSL Project.  All rights reserved.
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
#include <string.h>
#include <stdlib.h>
#include <gmssl/sm2.h>
#include <gmssl/x509.h>


static const char *options = "(-pubkey pem | -cert pem) [-id str] [-in file] -sig file";

int sm2verify_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *id = SM2_DEFAULT_ID;
	char *pubkeyfile = NULL;
	char *certfile = NULL;
	char *infile = NULL;
	char *sigfile = NULL;
	FILE *pubkeyfp = NULL;
	FILE *certfp = NULL;
	FILE *infp = stdin;
	FILE *sigfp = NULL;
	SM2_KEY key;
	SM2_SIGN_CTX verify_ctx;
	uint8_t cert[1024];
	size_t certlen;
	uint8_t buf[4096];
	ssize_t len;
	uint8_t sig[SM2_MAX_SIGNATURE_SIZE];
	size_t siglen;
	int vr;

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
		} else if (!strcmp(*argv, "-pubkey")) {
			if (certfile) {
				fprintf(stderr, "%s: options '-pubkey' '-cert' conflict\n", prog);
				goto end;
			}
			if (--argc < 1) goto bad;
			pubkeyfile = *(++argv);
			if (!(pubkeyfp = fopen(pubkeyfile, "r"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, pubkeyfile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-cert")) {
			if (pubkeyfile) {
				fprintf(stderr, "%s: options '-pubkey' '-cert' conflict\n", prog);
				goto end;
			}
			if (--argc < 1) goto bad;
			certfile = *(++argv);
			if (!(certfp = fopen(certfile, "r"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, certfile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-id")) {
			if (--argc < 1) goto bad;
			id = *(++argv);
		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);
			if (!(infp = fopen(infile, "r"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, infile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-sig")) {
			if (--argc < 1) goto bad;
			sigfile = *(++argv);
			if (!(sigfp = fopen(sigfile, "r"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, sigfile, strerror(errno));
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

	if (!sigfile) {
		fprintf(stderr, "%s: '-sig' option required\n", prog);
		goto end;
	}
	if ((siglen = fread(sig, 1, sizeof(sig), sigfp)) <= 0) {
		fprintf(stderr, "%s: read signature error : %s\n", prog, strerror(errno));
		goto end;
	}

	if (pubkeyfile) {
		if (sm2_public_key_info_from_pem(&key, pubkeyfp) != 1) {
			fprintf(stderr, "%s: parse public key failed\n", prog);
			goto end;
		}
	} else if (certfile) {
		if (x509_cert_from_pem(cert, &certlen, sizeof(cert), certfp) != 1
			|| x509_cert_get_subject_public_key(cert, certlen, &key) != 1) {
			fprintf(stderr, "%s: parse certificate failed\n", prog);
			goto end;
		}
	} else {
		fprintf(stderr, "%s: '-pubkey' or '-cert' option required\n", prog);
		goto end;
	}


	if (sm2_verify_init(&verify_ctx, &key, id, strlen(id)) != 1) {
		fprintf(stderr, "%s: inner error\n", prog);
		goto end;
	}
	while ((len = fread(buf, 1, sizeof(buf), infp)) > 0) {
		if (sm2_verify_update(&verify_ctx, buf, len) != 1) {
			fprintf(stderr, "%s: inner error\n", prog);
			goto end;
		}
	}
	if ((vr = sm2_verify_finish(&verify_ctx, sig, siglen)) < 0) {
		fprintf(stderr, "%s: inner error\n", prog);
		goto end;
	}

	fprintf(stdout, "verify : %s\n", vr == 1 ? "success" : "failure");
	if (vr == 1) {
		ret = 0;
	}

end:
	if (infile && infp) fclose(infp);
	if (pubkeyfp) fclose(pubkeyfp);
	if (certfp) fclose(certfp);
	if (sigfp) fclose(sigfp);
	return ret;
}
