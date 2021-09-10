/* 
 *   Copyright 2014-2021 The GmSSL Project Authors. All Rights Reserved.
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
#include <gmssl/hex.h>
#include <gmssl/sm2.h>
#include <gmssl/pem.h>
#include <gmssl/pkcs8.h>
#include <gmssl/x509.h>
#include <gmssl/error.h>


// sm2verify [-in file] {-pubkey pem | -cert pem} [-id str] -sig file

int main(int argc, char **argv)
{
	int ret;
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
	X509_CERTIFICATE cert;
	SM2_SIGN_CTX verify_ctx;
	uint8_t buf[4096];
	ssize_t len;
	uint8_t sig[SM2_MAX_SIGNATURE_SIZE];
	size_t siglen;


	argc--;
	argv++;

	while (argc > 1) {
		if (!strcmp(*argv, "-help")) {
help:
			fprintf(stderr, "usage: %s {-pubkey pem | -cert pem} [-id str] [-in file] -sig file\n", prog);
			return -1;

		} else if (!strcmp(*argv, "-pubkey")) {
			if (--argc < 1) goto bad;
			pubkeyfile = *(++argv);

		} else if (!strcmp(*argv, "-cert")) {
			if (--argc < 1) goto bad;
			certfile = *(++argv);

		} else if (!strcmp(*argv, "-id")) {
			if (--argc < 1) goto bad;
			id = *(++argv);

		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);

		} else if (!strcmp(*argv, "-sig")) {
			if (--argc < 1) goto bad;
			sigfile = *(++argv);

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
		fprintf(stderr, "%s: '-pubkey' or '-cert' option required\n", prog);
		goto help;
	}

	if (infile) {
		if (!(infp = fopen(infile, "r"))) {
			error_print();
			return -1;
		}
	}

	if (!sigfile) {
		error_print();
		goto help;
	}
	if (!(sigfp = fopen(sigfile, "rb"))) {
		error_print();
		return -1;
	}
	if ((siglen = fread(sig, 1, sizeof(sig), sigfp)) <= 0) {
		error_print();
		return -1;
	}

	sm2_verify_init(&verify_ctx, &key, id);
	while ((len = fread(buf, 1, sizeof(buf), infp)) > 0) {
		sm2_verify_update(&verify_ctx, buf, len);
	}

	if ((ret = sm2_verify_finish(&verify_ctx, sig, siglen)) < 0) {
		error_print();
		return -1;
	}

	fprintf(stdout, "verify : %s\n", ret == 1 ? "success" : "failure");
	return ret == 1 ? 0 : -1;


bad:
	fprintf(stderr, "%s: '%s' option value required\n", prog, *argv);
	return -1;
}
