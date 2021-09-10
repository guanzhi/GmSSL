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
#include <stdlib.h>
#include <string.h>
#include <gmssl/sm3.h>
#include <gmssl/hex.h>
#include <gmssl/error.h>


int main(int argc, char **argv)
{
	int ret = -1;
	char *prog = argv[0];
	char *keyhex = NULL;
	char *infile = NULL;
	uint8_t key[32];
	size_t keylen;
	FILE *in = stdin;
	SM3_HMAC_CTX ctx;
	unsigned char dgst[32];
	unsigned char buf[4096];
	size_t len;

	argc--;
	argv++;

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
help:
			fprintf(stderr, "usage: %s -keyhex hex [-in file]\n", prog);
			return -1;

		} else if (!strcmp(*argv, "-keyhex")) {
			if (--argc < 1) goto bad;
			keyhex = *(++argv);

		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);

		} else {
			fprintf(stderr, "%s: illegal option '%s'\n", prog, *argv);
			goto help;
		}

		argc--;
		argv++;
	}

	if (!keyhex) {
		fprintf(stderr, "%s: option '-keyhex' required\n", prog);
		goto help;
	}
	if (strlen(keyhex) > sizeof(key) * 2) {
		error_print();
		return -1;
	}
	if (hex_to_bytes(keyhex, strlen(keyhex), key, &keylen) != 1) {
		error_print();
		return -1;
	}

	sm3_hmac_init(&ctx, key, keylen);

	while ((len = fread(buf, 1, sizeof(buf), stdin)) > 0) {
		sm3_hmac_update(&ctx, buf, len);
	}
	sm3_hmac_finish(&ctx, dgst);


	format_bytes(stdout, 0, 0, "", dgst, sizeof(dgst));

	memset(&ctx, 0, sizeof(ctx));
	memset(key, 0, sizeof(key));
	return 0;

bad:
	fprintf(stderr, "%s: '%s' option value required\n", prog, *argv);
	return -1;
}
