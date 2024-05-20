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
#include <gmssl/mem.h>
#include <gmssl/sm2.h>


static const char *usage = "-key pem -pass str [-in file] [-out file]";

static const char *options =
"\n"
"Options\n"
"\n"
"    -key pem            Decryption private key file in PEM format\n"
"    -pass str           Password to open the private key\n"
"    -in file | stdin    Input ciphertext in binary DER-encoding\n"
"    -in file | stdout   Output decrypted data\n"
"\n"
"Examples\n"
"\n"
"    $ gmssl sm2keygen -pass P@ssw0rd -out sm2.pem -pubout sm2pub.pem\n"
"    $ echo 'Secret message' | gmssl sm2encrypt -pubkey sm2pub.pem -out sm2.der\n"
"    $ gmssl sm2decrypt -key sm2.pem -pass P@ssw0rd -in sm2.der\n"
"\n";

int sm2decrypt_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *keyfile = NULL;
	char *pass = NULL;
	char *infile = NULL;
	char *outfile = NULL;
	FILE *keyfp = NULL;
	FILE *infp = stdin;
	FILE *outfp = stdout;
	SM2_KEY key;
	SM2_DEC_CTX ctx;
	uint8_t inbuf[SM2_MAX_CIPHERTEXT_SIZE];
	uint8_t outbuf[SM2_MAX_CIPHERTEXT_SIZE];
	size_t inlen, outlen;

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

	if ((inlen = fread(inbuf, 1, sizeof(inbuf), infp)) <= 0) {
		fprintf(stderr, "gmssl %s: read input failed : %s\n", prog, strerror(errno));
		goto end;
	}

	if (sm2_decrypt_init(&ctx) != 1) {
		fprintf(stderr, "gmssl %s: sm2_decrypt_init failed\n", prog);
		goto end;
	}
	if (sm2_decrypt_update(&ctx, inbuf, inlen) != 1) {
		fprintf(stderr, "gmssl %s: sm2_decyrpt_update failed\n", prog);
		goto end;
	}
	if (sm2_decrypt_finish(&ctx, &key, outbuf, &outlen) != 1) {
		fprintf(stderr, "gmssl %s: decryption failure\n", prog);
		goto end;
	}
	if (outlen != fwrite(outbuf, 1, outlen, outfp)) {
		fprintf(stderr, "gmssl %s: output plaintext failed : %s\n", prog, strerror(errno));
		goto end;
	}
	ret = 0;
end:
	gmssl_secure_clear(&key, sizeof(key));
	gmssl_secure_clear(&ctx, sizeof(ctx));
	gmssl_secure_clear(outbuf, sizeof(outbuf));
	if (keyfp) fclose(keyfp);
	if (infile && infp) fclose(infp);
	if (outfile && outfp) fclose(outfp);
	return ret;
}
