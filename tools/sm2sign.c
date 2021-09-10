<<<<<<< HEAD
/*
 * Copyright (c) 2021 - 2021 The GmSSL Project.  All rights reserved.
=======
﻿/* 
 *   Copyright 2014-2021 The GmSSL Project Authors. All Rights Reserved.
>>>>>>> 5fc13a8aefa3fb395f32927e35dda4210a3c1a23
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <gmssl/sm2.h>
#include <gmssl/pem.h>
#include <gmssl/pkcs8.h>
#include <gmssl/error.h>

#ifndef WIN32
#include <pwd.h>
#include <unistd.h>
#endif


// echo data | sm2sign -id "Alice" -keyfile sm2.pem
// echo data | sm2verify -id "Alice" -keyfile sm2pub.pem -certfile a -cacertfile b

int main(int argc, char **argv)
{
	char *prog = argv[0];
	char *keyfile = NULL;
	char *pass = NULL;
	char *id = SM2_DEFAULT_ID;
	char *infile = NULL;
	char *outfile = NULL;
	FILE *keyfp = NULL;
	FILE *infp = stdin;
	FILE *outfp = stdout;
	SM2_KEY key;
	SM2_SIGN_CTX sign_ctx;
	uint8_t buf[4096];
	ssize_t len;
	uint8_t sig[SM2_MAX_SIGNATURE_SIZE];
	size_t siglen;

	argc--;
	argv++;

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
help:
			fprintf(stderr, "usage: %s -key pem [-pass password] [-id str] [-in file] [-out file]\n", prog);
			return -1;

		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			keyfile = *(++argv);

		} else if (!strcmp(*argv, "-pass")) {
			if (--argc < 1) goto bad;
			pass = *(++argv);

		} else if (!strcmp(*argv, "-id")) {
			if (--argc < 1) goto bad;
			id = *(++argv);

		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);

		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) goto bad;
			outfile = *(++argv);

		} else {
			fprintf(stderr, "%s: illegal option '%s'\n", prog, *argv);
			goto help;
		}

		argc--;
		argv++;
	}

	if (!keyfile) {
		error_print();
		goto help;
	}
	if (!(keyfp = fopen(keyfile, "r"))) {
		error_print();
		return -1;
	}

	if (!pass) {
#ifndef WIN32
		pass = getpass("Encryption Password : ");
#else
		fprintf(stderr, "%s: '-pass' option required\n", prog);
#endif
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

	if (sm2_enced_private_key_info_from_pem(&key, pass, keyfp) != 1) {
		error_puts("private key decryption failure");
		return -1;
	}

	sm2_sign_init(&sign_ctx, &key, id);

	while ((len = fread(buf, 1, sizeof(buf), infp)) > 0) {
		sm2_sign_update(&sign_ctx, buf, len);
	}
	sm2_sign_finish(&sign_ctx, sig, &siglen);

	fwrite(sig, 1, siglen, outfp);

	memset(&key, 0, sizeof(SM2_KEY));


	return 0;

bad:
	fprintf(stderr, "%s: '%s' option value required\n", prog, *argv);
	return -1;
}
