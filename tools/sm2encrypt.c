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
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <gmssl/hex.h>
#include <gmssl/sm2.h>
#include <gmssl/pem.h>
#include <gmssl/pkcs8.h>
#include <gmssl/x509.h>
#include <gmssl/error.h>


int main(int argc, char **argv)
{
	int ret;
	char *prog = argv[0];
	char *pubkeyfile = NULL;
	char *certfile = NULL;
	char *infile = NULL;
	char *outfile = NULL;
	FILE *pubkeyfp = NULL;
	FILE *certfp = NULL;
	FILE *infp = stdin;
	FILE *outfp = stdout;
	X509_CERTIFICATE cert;
	SM2_KEY key;
	uint8_t inbuf[SM2_MAX_PLAINTEXT_SIZE];
	uint8_t outbuf[SM2_MAX_CIPHERTEXT_SIZE];
	size_t inlen, outlen = sizeof(outbuf);

	argc--;
	argv++;

	while (argc > 1) {
		if (!strcmp(*argv, "-help")) {
help:
			fprintf(stderr, "usage: %s {-pubkey pem | -cert pem} [-in file] [-out file]\n", prog);
			return -1;

		} else if (!strcmp(*argv, "-pubkey")) {
			if (--argc < 1) goto bad;
			pubkeyfile = *(++argv);

		} else if (!strcmp(*argv, "-cert")) {
			if (--argc < 1) goto bad;
			certfile = *(++argv);

		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);

		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) goto bad;
			outfile = *(++argv);

		} else {
			goto help;
		}
		argc--;
		argv++;
	}

	if (pubkeyfile) {
		if (!(pubkeyfp = fopen(pubkeyfile, "r"))) {
			error_print();
			return -1;
		}
		if (sm2_public_key_info_from_pem(&key, pubkeyfp) != 1) {
			error_print();
			return -1;
		}
	} else if (certfile) {
		if (!(certfp = fopen(certfile, "r"))) {
			error_print();
			return -1;
		}
		if (x509_certificate_from_pem(&cert, certfp) != 1) {
			error_print();
			return -1;
		}
		if (x509_certificate_get_public_key(&cert, &key) != 1) {
			error_print();
			return -1;
		}
	} else {
		fprintf(stderr, "%s: '-pubkey' or '-cert' required\n", prog);
		goto help;
	}

	if (infile) {
		if (!(infp = fopen(infile, "rb"))) {
			error_print();
			return -1;
		}
	}
	if (outfile) {
		if (!(outfp = fopen(outfile, "wb"))) {
			error_print();
			return -1;
		}
	}


	if ((inlen = fread(inbuf, 1, sizeof(inbuf), infp)) <= 0) {
		error_print();
		return -1;
	}
	if (sm2_encrypt(&key, inbuf, inlen, outbuf, &outlen) != 1) {
		error_print();
		return -1;
	}

	if (outlen != fwrite(outbuf, 1, outlen, outfp)) {
		error_print();
		return -1;
	}
	return 0;

bad:
	fprintf(stderr, "%s: '%s' option value required\n", prog, *argv);
	return -1;
}
