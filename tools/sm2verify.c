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
	const char *sig_hex = NULL;
	const char *id = SM2_DEFAULT_ID;
	const char *keyfile = NULL;
	const char *certfile = NULL;
	FILE *keyfp = NULL;
	FILE *certfp = NULL;
	X509_CERTIFICATE cert;
	SM2_KEY key;
	SM2_SIGN_CTX verify_ctx;
	uint8_t buf[4096];
	ssize_t len;
	uint8_t sig[SM2_MAX_SIGNATURE_SIZE];
	size_t siglen;

	if (argc < 2) {
bad:
		fprintf(stderr, "%s : error options\n", prog);
help:
		fprintf(stderr, "usage:\n");
		fprintf(stderr, "    %s -sig hex -pubkey key.pem [-id str] < file\n", prog);
		fprintf(stderr, "    %s -sig hex -cert cert.pem [-id str] < file\n", prog);
		fprintf(stderr, "\n");
		return 1;
	}

	argc--;
	argv++;
	while (argc > 1) {
		if (!strcmp(*argv, "-help")) {
			goto help;
		} else if (!strcmp(*argv, "-id")) {
			if (--argc < 1) goto bad;
			id = *(++argv);
		} else if (!strcmp(*argv, "-pubkey")) {
			if (--argc < 1) goto bad;
			keyfile = *(++argv);
		} else if (!strcmp(*argv, "-sig")) {
			if (--argc < 1) goto bad;
			sig_hex = *(++argv);
		} else if (!strcmp(*argv, "-cert")) {
			if (--argc < 1) goto bad;
			certfile = *(++argv);
		} else {
			goto help;
		}
		argc--;
		argv++;
	}

	if (!sig_hex || (!keyfile && !certfile) || (keyfile && certfile)) {
		error_print();
		return -1;
	}
	if (strlen(sig_hex) > SM2_MAX_SIGNATURE_SIZE * 2 || strlen(sig_hex) % 2) {
		error_print();
		return -1;
	}
	if (hex2bin(sig_hex, strlen(sig_hex), sig) != 1) {
		error_print();
		return -1;
	}
	siglen = strlen(sig_hex)/2;

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

	sm2_verify_init(&verify_ctx, &key, id);
	while ((len = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
		sm2_verify_update(&verify_ctx, buf, len);
	}
	if ((ret = sm2_verify_finish(&verify_ctx, sig, siglen)) < 0) {
		error_print();
		return -1;
	}
	fprintf(stdout, "verify : %s\n", ret == 1 ? "success" : "failure");
	return ret == 1 ? 0 : -1;

	return 1;
}
