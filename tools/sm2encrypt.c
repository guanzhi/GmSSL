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
	const char *keyfile = NULL;
	const char *certfile = NULL;
	FILE *keyfp = NULL;
	FILE *certfp = NULL;
	X509_CERTIFICATE cert;
	SM2_KEY key;
	uint8_t inbuf[SM2_MAX_PLAINTEXT_SIZE];
	ssize_t inlen;
	uint8_t outbuf[SM2_MAX_CIPHERTEXT_SIZE];
	size_t outlen = sizeof(outbuf);

	if (argc < 2) {
bad:
		fprintf(stderr, "%s : error options\n", prog);
help:
		fprintf(stderr, "usage:\n");
		fprintf(stderr, "    %s -pubkey key.pem < file\n", prog);
		fprintf(stderr, "    %s -cert cert.pem < file\n", prog);
		fprintf(stderr, "\n");
		return 1;
	}

	argc--;
	argv++;
	while (argc > 1) {
		if (!strcmp(*argv, "-help")) {
			goto help;
		} else if (!strcmp(*argv, "-pubkey")) {
			if (--argc < 1) goto bad;
			keyfile = *(++argv);
		} else if (!strcmp(*argv, "-cert")) {
			if (--argc < 1) goto bad;
			certfile = *(++argv);
		} else {
			goto help;
		}
		argc--;
		argv++;
	}

	if ((!keyfile && !certfile) || (keyfile && certfile)) {
		error_print();
		return -1;
	}
	if (keyfile) {
		if (!(keyfp = fopen(keyfile, "r"))) {
			error_print();
			return -1;
		}
		if (sm2_public_key_info_from_pem(&key, keyfp) != 1) {
			error_print();
			return -1;
		}
	} else {
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
	}

	if ((inlen = read(STDIN_FILENO, inbuf, sizeof(inbuf))) <= 0) {
		error_print();
		return -1;
	}
	if (sm2_encrypt(&key, inbuf, inlen, outbuf, &outlen) != 1) {
		error_print();
		return -1;
	}
	format_bytes(stdout, 0, 0, "", outbuf, outlen);
	return 1;
}
