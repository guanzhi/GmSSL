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
#include <gmssl/hex.h>
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
	char *keyfile = NULL;
	char *pass = NULL;
	char *infile = NULL;
	char *outfile = NULL;
	FILE *keyfp = NULL;
	FILE *infp = stdin;
	FILE *outfp = stdout;
	SM2_KEY key;
	uint8_t inbuf[SM2_MAX_CIPHERTEXT_SIZE];
	uint8_t outbuf[SM2_MAX_CIPHERTEXT_SIZE];
	size_t inlen, outlen;

	argc--;
	argv++;

	while (argc > 0) {

		if (!strcmp(*argv, "-help")) {
help:
			fprintf(stderr, "usage: %s -key pem [-pass password] [-in file] [-out file]\n", prog);
			goto help;

		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			keyfile = *(++argv);

		} else if (!strcmp(*argv, "-pass")) {
			if (--argc < 1) goto bad;
			pass = *(++argv);

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
		return -1;
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

	if ((inlen = fread(inbuf, 1, sizeof(inbuf), infp)) <= 0) {
		error_print();
		return -1;
	}
	if (sm2_decrypt(&key, inbuf, inlen, outbuf, &outlen) != 1) {
		error_print();
		return -1;
	}

	error_print_msg("outlen = %zu\n", outlen);

	if (outlen != fwrite(outbuf, 1, outlen, outfp)) {
		error_print();
		return -1;
	}

	memset(&key, 0, sizeof(SM2_KEY));

	// FIXME: 清空所有缓冲区
	if (infile) fclose(infp);
	if (outfile) fclose(outfp);
	return 0;

bad:
	fprintf(stderr, "%s: '%s' option value required\n", prog, *argv);
	return -1;

}
