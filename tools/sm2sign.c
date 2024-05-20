/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
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
#include <gmssl/sm2.h>
#include <gmssl/mem.h>


static const char *usage = "-key pem -pass str [-id str] [-in file] [-out file]";

static const char *options =
"\n"
"Options\n"
"\n"
"    -key pem            Signing private key file in PEM format\n"
"    -pass str           Password to open the private key\n"
"    -id str             Signer's identity string, '1234567812345678' by default\n"
"    -in file | stdin    To be signed file or data\n"
"    -out file | stdout  Output signature in binary DER encoding\n"
"\n"
"Examples\n"
"\n"
"    $ gmssl sm2keygen -pass P@ssw0rd -out sm2.pem -pubout sm2pub.pem\n"
"    $ echo -n 'message to be signed' | gmssl sm2sign -key sm2.pem -pass P@ssw0rd -out sm2.sig\n"
"    $ echo -n 'message to be signed' | gmssl sm2verify -pubkey sm2pub.pem -sig sm2.sig\n"
"\n";


int sm2sign_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *keyfile = NULL;
	char *pass = NULL;
	char *id = SM2_DEFAULT_ID;
	char *infile = NULL;
	char *outfile = NULL;
	FILE *keyfp = NULL;
	FILE *infp = stdin;
	FILE *outfp = stdout;
	SM2_KEY key;
	SM2_SIGN_CTX sign_ctx;
	uint8_t buf[4096];
	size_t len;
	uint8_t sig[SM2_MAX_SIGNATURE_SIZE];
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
			ret = 0;
			goto end;
		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			keyfile = *(++argv);
			if (!(keyfp = fopen(keyfile, "rb"))) {
				fprintf(stderr, "gmssl %s: open '%s' failure : %s\n", prog, keyfile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-pass")) {
			if (--argc < 1) goto bad;
			pass = *(++argv);
		} else if (!strcmp(*argv, "-id")) {
			if (--argc < 1) goto bad;
			id = *(++argv);
		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);
			if (!(infp = fopen(infile, "rb"))) {
				fprintf(stderr, "gmssl %s: open '%s' failure : %s\n", prog, infile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) goto bad;
			outfile = *(++argv);
			if (!(outfp = fopen(outfile, "wb"))) {
				fprintf(stderr, "gmssl %s: open '%s' failure : %s\n", prog, outfile, strerror(errno));
				goto end;
			}
		} else {
			fprintf(stderr, "gmssl %s: illegal option '%s'\n", prog, *argv);
			goto end;
bad:
			fprintf(stderr, "gmssl %s: '%s' option value missing\n", prog, *argv);
			goto end;
		}

		argc--;
		argv++;
	}

	if (!keyfile) {
		fprintf(stderr, "gmssl %s: '-key' option required\n", prog);
		goto end;
	}
	if (!pass) {
		fprintf(stderr, "gmssl %s: '-pass' option required\n", prog);
		goto end;
	}
	if (sm2_private_key_info_decrypt_from_pem(&key, pass, keyfp) != 1) {
		fprintf(stderr, "gmssl %s: private key decryption failure\n", prog);
		goto end;
	}

	if (sm2_sign_init(&sign_ctx, &key, id, strlen(id)) != 1) {
		fprintf(stderr, "gmssl %s: inner error\n", prog);
		goto end;
	}
	while ((len = fread(buf, 1, sizeof(buf), infp)) > 0) {
		if (sm2_sign_update(&sign_ctx, buf, len) != 1) {
			fprintf(stderr, "gmssl %s: inner error\n", prog);
			goto end;
		}
	}
	if (sm2_sign_finish(&sign_ctx, sig, &siglen) != 1) {
		fprintf(stderr, "gmssl %s: inner error\n", prog);
		goto end;
	}
	if (fwrite(sig, 1, siglen, outfp) != siglen) {
		fprintf(stderr, "gmssl %s: output signature failed : %s\n", prog, strerror(errno));
		goto end;
	}
	ret = 0;
end:
	gmssl_secure_clear(&key, sizeof(key));
	gmssl_secure_clear(&sign_ctx, sizeof(sign_ctx));
	if (keyfp) fclose(keyfp);
	if (infile && infp) fclose(infp);
	if (outfile && outfp) fclose(outfp);
	return ret;
}
