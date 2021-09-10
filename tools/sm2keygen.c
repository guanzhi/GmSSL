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
#include <gmssl/sm2.h>
#include <gmssl/pem.h>
#include <gmssl/pkcs8.h>
#include <gmssl/error.h>

#ifndef WIN32
#include <pwd.h>
#include <unistd.h>
#endif

int main(int argc, char **argv)
{
	char *prog = argv[0];
	char *pass = NULL;
	char passbuf[64] = {0};
	char *outfile = NULL;
	char *puboutfile = NULL;
	FILE *outfp = stdout;
	FILE *puboutfp = stdout;
	SM2_KEY key;

	argc--;
	argv++;

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
help:
			fprintf(stderr, "usage: %s [-pass passphrase] [-out pem] [-pubout pem]\n", prog);
			return -1;

		} else if (!strcmp(*argv, "-pass")) {
			if (--argc < 1) goto bad;
			pass = *(++argv);

		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) goto bad;
			outfile = *(++argv);

		} else if (!strcmp(*argv, "-pubout")) {
			if (--argc < 1) goto bad;
			puboutfile = *(++argv);

		} else {
			fprintf(stderr, "%s: illegal option '%s'\n", prog, *argv);
			goto help;
		}

		argc--;
		argv++;
	}


	if (!pass) {
#ifndef WIN32
		pass = getpass("Encryption Password : ");
		strncpy(passbuf, pass, sizeof(passbuf));
		pass = getpass("Encryption Password (Again) : ");
		if (strcmp(passbuf, pass) != 0) {
			fprintf(stderr, "error: passwords not match\n");
			return -1;
		}
#else
		fprintf(stderr, "%s: '-pass' option required\n", prog);
		goto help;
#endif
	}

	if (outfile) {
		if (!(outfp = fopen(outfile, "w"))) {
			error_print();
			return -1;
		}
	}
	if (puboutfile) {
		if (!(puboutfp = fopen(puboutfile, "w"))) {
			error_print();
			return -1;
		}
	}

	if (sm2_keygen(&key) != 1) {
		error_print();
		return -1;
	}

	if (sm2_enced_private_key_info_to_pem(&key, pass, outfp) != 1) {
		memset(&key, 0, sizeof(SM2_KEY));
		error_print();
		return -1;
	}
	if (sm2_public_key_info_to_pem(&key, puboutfp) != 1) {
		memset(&key, 0, sizeof(SM2_KEY));
		error_print();
		return -1;
	}

	memset(&key, 0, sizeof(SM2_KEY));
	return 0;

bad:
	fprintf(stderr, "%s: '%s' option value required\n", prog, *argv);
	return -1;
}
