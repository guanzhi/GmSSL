/*
 *  Copyright 2014-2025 The GmSSL Project. All Rights Reserved.
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
#include <gmssl/error.h>
#include <gmssl/kyber.h>


static const char *usage = "-key file [-in file] [-out file] [-verbose]\n";

static const char *options =
"Options\n"
"    -key file                   Input private key file\n"
"    -in file                    Input ciphertext (encapsulated secret)\n"
"    -out file                   Output decapsulated secret\n"
"    -verbose                    Print public key and ciphertext\n"
"\n";

int kyberdecap_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *keyfile = NULL;
	char *infile = NULL;
	char *outfile = NULL;
	int verbose = 0;
	FILE *keyfp = NULL;
	FILE *infp = stdin;
	FILE *outfp = stdout;
	uint8_t keybuf[KYBER_PRIVATE_KEY_SIZE];
	size_t keylen = KYBER_PRIVATE_KEY_SIZE;
	const uint8_t *cp = keybuf;
	uint8_t *p = keybuf;
	KYBER_PRIVATE_KEY key;

	uint8_t inbuf[sizeof(KYBER_CIPHERTEXT)];
	uint8_t outbuf[32];

	KYBER_CIPHERTEXT ciphertext;

	memset(&key, 0, sizeof(key));

	argc--;
	argv++;

	if (argc < 1) {
		fprintf(stderr, "usage: gmssl %s %s\n", prog, usage);
		return 1;
	}

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: %s %s\n", prog, usage);
			printf("%s\n", options);
			ret = 0;
			goto end;
		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			keyfile = *(++argv);
			if (!(keyfp = fopen(keyfile, "rb+"))) {
				fprintf(stderr, "%s: open '%s' failure: %s\n", prog, keyfile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);
			if (!(infp = fopen(infile, "rb"))) {
				fprintf(stderr, "%s: open '%s' failure: %s\n", prog, infile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) goto bad;
			outfile = *(++argv);
			if (!(outfp = fopen(outfile, "wb"))) {
				fprintf(stderr, "%s: open '%s' failure: %s\n", prog, outfile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-verbose")) {
			verbose = 1;
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

	if (!keyfile) {
		fprintf(stderr, "%s: `-key` option required\n", prog);
		goto end;
	}

	if (fread(keybuf, 1, keylen, keyfp) != keylen) {
		fprintf(stderr, "%s: read private key failure\n", prog);
		goto end;
	}
	if (kyber_private_key_from_bytes(&key, &cp, &keylen) != 1) {
		error_print();
		goto end;
	}
	if (keylen) {
		error_print();
		return -1;
	}

	if (verbose) {
		kyber_private_key_print(stderr, 0, 0, "kyber_private_key", &key);
	}


	size_t inlen = sizeof(inbuf);

	if (fread(inbuf, 1, inlen, infp) != inlen) {
		fprintf(stderr, "%s: read ciphertext failure\n", prog);
		goto end;
	}
	cp = inbuf;
	if (kyber_ciphertext_from_bytes(&ciphertext, &cp, &inlen) != 1) {
		error_print();
		goto end;
	}
	if (inlen) {
		error_print();
		return -1;
	}


	if (verbose) {
		kyber_ciphertext_print(stderr, 0, 0, "kyber_ciphertext" ,&ciphertext);
	}



	if (kyber_decap(&key, &ciphertext, outbuf) != 1) {
		error_print();
		return -1;
	}


	if (verbose) {
		format_bytes(stderr, 0, 0, "key", outbuf, 32);


	}


	ret = 0;

end:
	//kyber_key_cleanup(&key);
	gmssl_secure_clear(keybuf, sizeof(keybuf));
	if (keyfp) fclose(keyfp);
	if (infp && infp != stdin) fclose(infp);
	if (outfp && outfp != stdout) fclose(outfp);
	return ret;
}
