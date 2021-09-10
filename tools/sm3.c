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
#include <gmssl/sm3.h>
#include <gmssl/sm2.h>
#include <gmssl/error.h>


int main(int argc, char **argv)
{
	char *prog = argv[0];
	char *pubkeyfile = NULL;
	char *infile = NULL;
	char *id = NULL;
	FILE *pubkeyfp = NULL;
	FILE *infp = stdin;
	SM3_CTX sm3_ctx;
	uint8_t dgst[32];
	uint8_t buf[4096];
	ssize_t len;
	int i;

	argc--;
	argv++;

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
help:
			fprintf(stderr, "usage: %s [-pubkey pem [-id str]] [-in file]\n", prog);
			fprintf(stderr, "usage: echo -n \"abc\" | %s\n", prog);
			return -1;

		} else if (!strcmp(*argv, "-pubkey")) {
			if (--argc < 1) goto bad;
			pubkeyfile = *(++argv);

		} else if (!strcmp(*argv, "-id")) {
			if (--argc < 1) goto bad;
			id = *(++argv);

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

	sm3_init(&sm3_ctx);

	if (pubkeyfile) {
		SM2_KEY sm2_key;
		uint8_t z[32];

		if (!(pubkeyfp = fopen(pubkeyfile, "r"))) {
			error_print();
			return -1;
		}
		if (sm2_public_key_info_from_pem(&sm2_key, pubkeyfp) != 1) {
			error_print();
			return -1;
		}
		if (!id) {
			id = SM2_DEFAULT_ID;
		}

		sm2_compute_z(z, (SM2_POINT *)&sm2_key, id);
		sm3_update(&sm3_ctx, z, sizeof(z));

	} else {
		if (id) {
			fprintf(stderr, "%s: option '-id' must be with '-pubkey'\n", prog);
			goto help;
		}
	}

	if (infile) {
		if (!(infp = fopen(infile, "r"))) {
			error_print();
			return -1;
		}
	}
	while ((len = fread(buf, 1, sizeof(buf), infp)) > 0) {
		sm3_update(&sm3_ctx, buf, len);
	}

	sm3_finish(&sm3_ctx, dgst);
	for (i = 0; i < sizeof(dgst); i++) {
		printf("%02x", dgst[i]);
	}
	printf("\n");

	if (infile) {
		fclose(infp);
	}
	return 0;

bad:
	fprintf(stderr, "%s: '%s' option value required\n", prog, *argv);
	return -1;
}
