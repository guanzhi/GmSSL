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
