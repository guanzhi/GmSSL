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
#include <gmssl/error.h>


int main(int argc, char **argv)
{
	char *prog = argv[0];
	const char *keyfile = NULL;
	FILE *keyfp = NULL;
	const char *pass = NULL;
	SM2_KEY key;
	char hexbuf[SM2_MAX_CIPHERTEXT_SIZE * 2];
	uint8_t inbuf[SM2_MAX_CIPHERTEXT_SIZE * 2];
	uint8_t outbuf[SM2_MAX_CIPHERTEXT_SIZE];
	size_t hexlen, inlen, outlen;

	if (argc < 2) {
bad:
		fprintf(stderr, "%s : error options\n", prog);
help:
		fprintf(stderr, "usage: %s -key key.pem [-id str] < file\n", prog);
		return 1;
	}

	argc--;
	argv++;
	while (argc > 1) {
		if (!strcmp(*argv, "-help")) {
			goto help;
		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			keyfile = *(++argv);
		} else {
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
	pass = getpass("Encryption Password : ");
	if (sm2_enced_private_key_info_from_pem(&key, pass, keyfp) != 1) {
		error_puts("private key decryption failure");
		return -1;
	}
	if ((hexlen = fread(hexbuf, 1, sizeof(hexbuf), stdin)) <= 0) {
		error_print();
		return -1;
	}
	if (hex2bin(hexbuf, hexlen, inbuf) != 1) {
		error_print();
		return -1;
	}
	if (sm2_decrypt(&key, inbuf, hexlen/2, outbuf, &outlen) != 1) {
		error_print();
		return -1;
	}
	fwrite(outbuf, 1, outlen, stdout);
	return 0;

}
