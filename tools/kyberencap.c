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


static const char *usage = "-pubkey file [-out file] -outkey file [-verbose]\n";


// decap 中的out一定是secret，而in 一定是ciphertext
// encap 中的out 是decap的in，因此encap中的out是ciphertext，而输出的secret是特殊的

static const char *options =
"Options\n"
"    -pubkey file                Input public key file\n"
"    -out file                   Output ciphertext (decapsulated secret)\n"
"    -outkey file                Output secret\n"
"    -verbose                    Print public key and ciphertext\n"
"\n";

int kyberencap_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *pubkeyfile = NULL;
	char *outfile = NULL;
	char *outkeyfile = NULL;
	int verbose = 0;
	FILE *pubkeyfp = NULL;
	FILE *outfp = stdout;
	FILE *outkeyfp = NULL;
	uint8_t pubkeybuf[KYBER_PUBLIC_KEY_SIZE];
	size_t pubkeylen = KYBER_PUBLIC_KEY_SIZE;
	const uint8_t *cp = pubkeybuf;
	uint8_t outbuf[sizeof(KYBER_CIPHERTEXT)];
	size_t outlen;
	KYBER_PRIVATE_KEY key;
	KYBER_CIPHERTEXT ciphertext;

	uint8_t outkey[32];


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
		} else if (!strcmp(*argv, "-pubkey")) {
			if (--argc < 1) goto bad;
			pubkeyfile = *(++argv);
			if (!(pubkeyfp = fopen(pubkeyfile, "rb"))) {
				fprintf(stderr, "%s: open '%s' failure: %s\n", prog, pubkeyfile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) goto bad;
			outfile = *(++argv);
			if (!(outfp = fopen(outfile, "wb"))) {
				fprintf(stderr, "%s: open '%s' failure: %s\n", prog, outfile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-outkey")) {
			if (--argc < 1) goto bad;
			outkeyfile = *(++argv);
			if (!(outkeyfp = fopen(outkeyfile, "wb"))) {
				fprintf(stderr, "%s: open '%s' failure: %s\n", prog, outkeyfile, strerror(errno));
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

	if (!pubkeyfile) {
		fprintf(stderr, "%s: `-key` option required\n", prog);
		goto end;
	}
	if (!outkeyfile) {
		fprintf(stderr, "%s: `-outkey` option required\n", prog);
		goto end;
	}

	if (fread(pubkeybuf, 1, pubkeylen, pubkeyfp) != pubkeylen) {
		fprintf(stderr, "%s: read public key failure\n", prog);
		goto end;
	}
	if (kyber_public_key_from_bytes(&key, &cp, &pubkeylen) != 1) {
		error_print();
		goto end;
	}
	if (verbose) {
		kyber_public_key_print(stderr, 0, 0, "kyber_public_key", &key);
	}


	if (kyber_encap(&key.pk, &ciphertext, outkey) != 1) {
		error_print();
		return -1;
	}

	if (verbose) {

		kyber_ciphertext_print(stderr, 0, 0, "kyber_ciphertext", &ciphertext);


		format_bytes(stderr, 0, 0, "key", outkey, 32);

	}


	uint8_t *p = outbuf;
	outlen = 0;
	if (kyber_ciphertext_to_bytes(&ciphertext, &p, &outlen) != 1) {
		error_print();
		goto end;
	}
	if (fwrite(outbuf, 1, outlen, outfp) != outlen) {
		error_print();
		goto end;
	}

	if (fwrite(outkey, 1, 32, outkeyfp) != 32) {
		error_print();
		goto end;
	}

	ret = 0;

end:
	if (pubkeyfp) fclose(pubkeyfp);
	if (outfp && outfp != stdin) fclose(outfp);
	if (outkeyfp) fclose(outkeyfp);
	return ret;
}
