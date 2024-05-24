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


static const char *usage = "-key pem -pass str -id str [-in file] [-out file]";

static const char *options =
"Options\n"
"\n"
"    -key pem            Recipient's private key in PEM format\n"
"    -pass str           Password to open the private key\n"
"    -id str             Recipient's identity string\n"
"    -in file | stdin    Encrypted file or data\n"
"    -out file | stdout  Output plaintext\n"
"\n"
"Examples\n"
"\n"
"    $ gmssl sm9setup -alg sm9encrypt -pass P@ssw0rd -out sm9enc_msk.pem -pubout sm9enc_mpk.pem\n"
"    $ gmssl sm9keygen -alg sm9encrypt -in sm9enc_msk.pem -inpass P@ssw0rd -id Alice -out sm9enc.pem -outpass 123456\n"
"\n"
"    $ echo 'Secret text' | gmssl sm9encrypt -pubmaster sm9enc_mpk.pem -id Alice -out sm9_ciphertext.der\n"
"    $ gmssl sm9decrypt -key sm9enc.pem -pass 123456 -id Alice -in sm9_ciphertext.der\n"
"\n";

int sm9decrypt_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *infile = NULL;
	char *keyfile = NULL;
	char *pass = NULL;
	char *id = NULL;
	char *outfile = NULL;
	FILE *keyfp = NULL;
	FILE *infp = stdin;
	FILE *outfp = stdout;
	SM9_ENC_KEY key;
	uint8_t inbuf[SM9_MAX_CIPHERTEXT_SIZE];
	uint8_t outbuf[SM9_MAX_CIPHERTEXT_SIZE];
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
			return 0;
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
		} else if (!strcmp(*argv, "-id")) {
			if (--argc < 1) goto bad;
			id = *(++argv);
		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);
			if (!(infp = fopen(infile, "rb"))) {
				error_print();
				goto end;
			}
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

	if (!keyfile || !pass || !id) {
		error_print();
		goto end;
	}

	if (sm9_enc_key_info_decrypt_from_pem(&key, pass, keyfp) != 1) {
		error_print();
		goto end;
	}
	if ((inlen = fread(inbuf, 1, sizeof(inbuf), infp)) <= 0) {
		error_print();
		goto end;
	}
	if (sm9_decrypt(&key, id, strlen(id), inbuf, inlen, outbuf, &outlen) != 1) {
		error_print();
		goto end;
	}
	if (outlen != fwrite(outbuf, 1, outlen, outfp)) {
		error_print();
		goto end;
	}
	ret = 0;

end:
	gmssl_secure_clear(&key, sizeof(key));
	gmssl_secure_clear(outbuf, sizeof(outbuf));
	if (keyfp) fclose(keyfp);
	if (infile && infp) fclose(infp);
	if (outfile && outfp) fclose(outfp);
	return ret;
}
