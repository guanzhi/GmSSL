/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
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
#include <gmssl/xmss.h>

static const char *usage = "-key file [-in file] [-out file] [-verbose]\n";

static const char *options =
"Options\n"
"    -key file                   Input private key file\n"
"    -in file                    Input data file (if not using stdin)\n"
"    -out file                   Output signature file\n"
"    -verbose                    Print public key and signature\n"
"\n";

int xmssmtsign_main(int argc, char **argv)
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
	uint8_t pubkey[XMSSMT_PUBLIC_KEY_SIZE];
	uint8_t *keybuf = NULL;
	size_t keylen;
	const uint8_t *cp;
	uint8_t *p;
	XMSSMT_KEY key;
	XMSSMT_SIGN_CTX ctx;
	uint8_t sig[XMSSMT_SIGNATURE_MAX_SIZE];
	size_t siglen;

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

	if (fread(pubkey, 1, sizeof(pubkey), keyfp) != sizeof(pubkey)) {
		error_print();
		goto end;
	}
	cp = pubkey;
	keylen = sizeof(pubkey);
	if (xmssmt_public_key_from_bytes(&key, &cp, &keylen) != 1 ) {
		error_print();
		goto end;
	}


	if (xmssmt_private_key_size(key.public_key.xmssmt_type, &keylen) != 1) {
		error_print();
		goto end;
	}
	if (!(keybuf = malloc(keylen))) {
		error_print();
		goto end;
	}
	memcpy(keybuf, pubkey, sizeof(pubkey));


	if (fread(keybuf + sizeof(pubkey), 1, keylen - sizeof(pubkey), keyfp) != keylen - sizeof(pubkey)) {
		fprintf(stderr, "%s: read private key failure\n", prog);
		goto end;
	}
	cp = keybuf;
	if (xmssmt_private_key_from_bytes(&key, &cp, &keylen) != 1) {
		error_print();
		goto end;
	}
	if (keylen) {
		error_print();
		return -1;
	}

	if (verbose) {
		xmssmt_public_key_print(stderr, 0, 0, "lms_public_key", &key);
	}

	if (xmssmt_sign_init(&ctx, &key) != 1) {
		error_print();
		goto end;
	}

#if 0
	// write updated key back to file
	// TODO: write back `q` only
	p = keybuf;
	keylen = 0;
	if (xmssmt_private_key_to_bytes(&key, &p, &keylen) != 1) {
		error_print();
		return -1;
	}
	rewind(keyfp);
	if (fwrite(keybuf, 1, keylen, keyfp) != keylen) {
		error_print();
		return -1;
	}
#else
	if (fseek(keyfp, XMSSMT_PUBLIC_KEY_SIZE, SEEK_SET) != 0) {
		error_print();
		goto end;
	}
	uint8_t index_buf[8];
	uint8_t *pindex = index_buf;
	size_t index_len = 0;
	xmssmt_index_to_bytes(key.index, key.public_key.xmssmt_type, &pindex, &index_len);
	fwrite(index_buf, 1, index_len, keyfp);
#endif

	while (1) {
		uint8_t buf[1024];
		size_t len = fread(buf, 1, sizeof(buf), infp);
		if (len == 0) {
			break;
		}
		if (xmssmt_sign_update(&ctx, buf, len) != 1) {
			error_print();
			goto end;
		}
	}
	if (xmssmt_sign_finish(&ctx, sig, &siglen) != 1) {
		error_print();
		goto end;
	}
	if (fwrite(sig, 1, siglen, outfp) != siglen) {
		error_print();
		goto end;
	}
	if (verbose) {
		xmssmt_signature_print(stderr, 0, 0, "xmssmt_signature", sig, siglen, key.public_key.xmssmt_type);
	}

	ret = 0;

end:
	xmssmt_key_cleanup(&key);
	gmssl_secure_clear(keybuf, keylen);
	gmssl_secure_clear(&ctx, sizeof(ctx));
	if (keyfp) fclose(keyfp);
	if (infp && infp != stdin) fclose(infp);
	if (outfp && outfp != stdout) fclose(outfp);
	return ret;
}
