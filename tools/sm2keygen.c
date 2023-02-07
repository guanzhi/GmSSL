/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/mem.h>
#include <gmssl/sm2.h>


static const char *usage = "-pass str [-out pem] [-pubout pem]\n";

static const char *options =
"Options\n"
"    -pass pass                  Password to encrypt the private key\n"
"    -out pem                    Output password-encrypted PKCS #8 private key in PEM format\n"
"    -pubout pem                 Output public key in PEM format\n"
"\n";

int sm2keygen_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *pass = NULL;
	char *outfile = NULL;
	char *puboutfile = NULL;
	FILE *outfp = stdout;
	FILE *puboutfp = stdout;
	SM2_KEY key;

	argc--;
	argv++;

	if (argc < 1) {
		fprintf(stderr, "usage: %s %s\n", prog, options);
		return 1;
	}

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: %s %s\n", prog, usage);
			printf("%s\n", options);
			ret = 0;
			goto end;
		} else if (!strcmp(*argv, "-pass")) {
			if (--argc < 1) goto bad;
			pass = *(++argv);
		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) goto bad;
			outfile = *(++argv);
			if (!(outfp = fopen(outfile, "wb"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, outfile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-pubout")) {
			if (--argc < 1) goto bad;
			puboutfile = *(++argv);
			if (!(puboutfp = fopen(puboutfile, "wb"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, outfile, strerror(errno));
				goto end;
			}
		} else {
			fprintf(stderr, "%s: illegal option '%s'\n", prog, *argv);
			goto end;
bad:
			fprintf(stderr, "%s: `%s` option value missing\n", prog, *argv);
			goto end;
		}

		argc--;
		argv++;
	}

	if (!pass) {
		fprintf(stderr, "%s: `-pass` option required\n", prog);
		goto end;
	}

	if (sm2_key_generate(&key) != 1
		|| sm2_private_key_info_encrypt_to_pem(&key, pass, outfp) != 1
		|| sm2_public_key_info_to_pem(&key, puboutfp) != 1) {
		fprintf(stderr, "%s: inner failure\n", prog);
		goto end;
	}
	ret = 0;

end:
	gmssl_secure_clear(&key, sizeof(key));
	if (outfile && outfp) fclose(outfp);
	if (puboutfile && puboutfp) fclose(puboutfp);
	return ret;
}
