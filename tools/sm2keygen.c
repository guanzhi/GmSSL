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
