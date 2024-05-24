/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/mem.h>
#include <gmssl/sm9.h>
#include <gmssl/error.h>


static const char *usage = "-key pem -pass str [-in file] [-out file]";

static const char *options =
"Options\n"
"\n"
"    -key pem            Signing private key file in PEM format\n"
"    -pass str           Password to open the private key\n"
"    -in file | stdin    To be signed file or data\n"
"    -out file | stdout  Output signature in binary DER encoding\n"
"\n"
"Examples\n"
"\n"
"    $ gmssl sm9setup -alg sm9sign -pass P@ssw0rd -out sm9sign_msk.pem -pubout sm9sign_mpk.pem\n"
"    $ gmssl sm9keygen -alg sm9sign -in sm9sign_msk.pem -inpass P@ssw0rd -id Alice -out sm9sign.pem -outpass 123456\n"
"\n"
"    $ echo -n 'message to be signed' | gmssl sm9sign -key sm9sign.pem -pass 123456 -out sm9.sig\n"
"    $ echo -n 'message to be signed' | gmssl sm9verify -pubmaster sm9sign_mpk.pem -id Alice -sig sm9.sig\n"
"\n";

int sm9sign_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *infile = NULL;
	char *keyfile = NULL;
	char *pass = NULL;
	char *outfile = NULL;
	FILE *infp = stdin;
	FILE *keyfp = NULL;
	FILE *outfp = stdout;
	SM9_SIGN_KEY key;
	SM9_SIGN_CTX ctx;
	uint8_t buf[4096];
	size_t len;
	uint8_t sig[SM9_SIGNATURE_SIZE];
	size_t siglen;

	argc--;
	argv++;

	if (argc < 1) {
		fprintf(stderr, "usage: gmssl %s %s\n", prog, usage);
		return 1;
	}

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: gmssl %s %s\n", prog, usage);
			printf("%s\n", options);
			return 0;
		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);
			if (!(infp = fopen(infile, "rb"))) {
				error_print();
				goto end;
			}
		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			keyfile = *(++argv);
			if (!(keyfp = fopen(keyfile, "rb"))) {
				error_print();
				goto end;
			}
		} else if (!strcmp(*argv, "-pass")) {
			if (--argc < 1) goto bad;
			pass = *(++argv);
		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) goto bad;
			outfile = *(++argv);
			if (!(outfp = fopen(outfile, "wb"))) {
				error_print();
				goto end;
			}
		} else {
bad:
			fprintf(stderr, "gmssl %s: illegal option '%s'\n", prog, *argv);
			return 1;
		}

		argc--;
		argv++;
	}

	if (!keyfile || !pass) {
		error_print();
		goto end;
	}

	if (sm9_sign_key_info_decrypt_from_pem(&key, pass, keyfp) != 1) {
		error_print();
		return -1;
	}

	if (sm9_sign_init(&ctx) != 1) {
		error_print();
		goto end;
	}
	while ((len = fread(buf, 1, sizeof(buf), infp)) > 0) {
		if (sm9_sign_update(&ctx, buf, len) != 1) {
			error_print();
			goto end;
		}
	}
	if (sm9_sign_finish(&ctx, &key, sig, &siglen) != 1) {
		error_print();
		goto end;
	}

	if (siglen != fwrite(sig, 1, siglen, outfp)) {
		error_print();
		goto end;
	}



	ret = 0;

end:
	gmssl_secure_clear(&key, sizeof(key));
	gmssl_secure_clear(&ctx, sizeof(ctx));
	gmssl_secure_clear(buf, sizeof(buf));
	if (infile && infp) fclose(infp);
	if (outfile && outfp) fclose(outfp);
	return ret;
}
