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
#include <stdlib.h>
#include <string.h>
#include <gmssl/pbkdf2.h>
#include <gmssl/hex.h>
#include <gmssl/error.h>


static const char *options = "-salt hex -iter num [-pass str] -outlen num";

int pbkdf2_main(int argc, char **argv)
{
	int ret = -1;
	char *prog = argv[0];
	char *salthex = NULL;
	uint8_t salt[PBKDF2_MAX_SALT_SIZE];
	size_t saltlen;
	int iter = 0;
	char *pass = NULL;
	int outlen = 0;
	uint8_t outbuf[64];
	int i;

	argc--;
	argv++;

	if (argc < 1) {
		fprintf(stderr, "usage: %s %s\n", prog, options);
		return 1;
	}

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			fprintf(stderr, "usage: %s %s\n", prog, options);
			return 1;
		} else if (!strcmp(*argv, "-salt")) {
			if (--argc < 1) goto bad;
			salthex = *(++argv);
		} else if (!strcmp(*argv, "-iter")) {
			if (--argc < 1) goto bad;
			iter = atoi(*(++argv));
			if (iter < PBKDF2_MIN_ITER || iter > INT_MAX) {
				error_print();
				return 1;
			}
		} else if (!strcmp(*argv, "-pass")) {
			if (--argc < 1) goto bad;
			pass = *(++argv);
		} else if (!strcmp(*argv, "-outlen")) {
			if (--argc < 1) goto bad;
			outlen = atoi(*(++argv));
			if (outlen < 1 || outlen > sizeof(outbuf)) {
				error_print();
				return 1;
			}
		} else {
			fprintf(stderr, "%s: illegal option '%s'\n", prog, *argv);
			return 1;
bad:
			fprintf(stderr, "%s: invalid option argument\n", prog);
			return 1;
		}

		argc--;
		argv++;
	}

	if (!salthex) {
		error_print();
		return 1;
	}
	if (strlen(salthex) > sizeof(salt) * 2) {
		error_print();
		return 1;
	}
	if (hex_to_bytes(salthex, strlen(salthex), salt, &saltlen) != 1) {
		error_print();
		return 1;
	}

	if (!iter) {
		error_print();
		return 1;
	}
	if (!outlen) {
		error_print();
		return 1;
	}


	if (!pass) {
		error_print();
		return -1;
	}

	if (pbkdf2_hmac_sm3_genkey(pass, strlen(pass), salt, saltlen, iter, outlen, outbuf) != 1) {
		error_print();
		return -1;
	}
	for (i = 0; i < outlen; i++) {
		printf("%02X", outbuf[i]);
	}
	printf("\n");


	return 0;
}
