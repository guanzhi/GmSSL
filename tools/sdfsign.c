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
#include <gmssl/sdf.h>
#include <gmssl/mem.h>


static const char *usage = "-lib so_path -key num -pass str [-id str] [-in file] [-out file]";

static const char *options =
"\n"
"Options\n"
"\n"
"    -lib so_path        Vendor's SDF dynamic library\n"
"    -key num            Signing private key index number\n"
"    -pass str           Password to get the private key access right\n"
"    -id str             Signer's identity string, '1234567812345678' by default\n"
"    -in file | stdin    To be signed file or data\n"
"    -out file | stdout  Output signature in binary DER encoding\n"
"\n"
"Examples\n"
"\n"
"    $ echo -n 'message to be signed' | gmssl sdfsign -lib libsoftsdf.so -key 1 -pass P@ssw0rd -out sm2.sig\n"
"    $ gmssl sdfexport -lib libsoftsdf.so -sign -key 1 -out sm2pub.pem\n"
"    $ echo -n 'message to be signed' | gmssl sm2verify -pubkey sm2pub.pem -sig sm2.sig\n"
"\n";


int sdfsign_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *lib = NULL;
	int key_index = -1;
	char *pass = NULL;
	char *id = SM2_DEFAULT_ID;
	char *infile = NULL;
	char *outfile = NULL;
	FILE *infp = stdin;
	FILE *outfp = stdout;
	uint8_t buf[4096];
	size_t len;
	uint8_t sig[SM2_MAX_SIGNATURE_SIZE];
	size_t siglen;
	SDF_DEVICE dev;
	SDF_PRIVATE_KEY key;
	SDF_SIGN_CTX ctx;

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
		} else if (!strcmp(*argv, "-lib")) {
			if (--argc < 1) goto bad;
			lib = *(++argv);
		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			key_index = atoi(*(++argv));
			if (key_index < 0) {
				fprintf(stderr, "gmssl %s: illegal key index %d\n", prog, key_index);
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

	if (!lib) {
		fprintf(stderr, "gmssl %s: '-lib' option required\n", prog);
		goto end;
	}
	if (key_index < 0) {
		fprintf(stderr, "gmssl %s: '-key' option required\n", prog);
		goto end;
	}
	if (!pass) {
		fprintf(stderr, "gmssl %s: '-pass' option required\n", prog);
		goto end;
	}

	if (sdf_load_library(lib, NULL) != 1) {
		fprintf(stderr, "gmssl %s: load library failure\n", prog);
		goto end;
	}
	if (sdf_open_device(&dev) != 1) {
		fprintf(stderr, "gmssl %s: open device failure\n", prog);
		goto end;
	}

	if (sdf_load_private_key(&dev, &key, key_index, pass) != 1) {
		(void)sdf_close_device(&dev);
		fprintf(stderr,  "gmssl %s: load signing key #%d failure\n", prog, key_index);
		goto end;
	}

	if (sdf_sign_init(&ctx, &key, id, strlen(id)) != 1) {
		(void)sdf_close_device(&dev);
		fprintf(stderr, "gmssl %s: inner error\n", prog);
		goto end;
	}
	while ((len = fread(buf, 1, sizeof(buf), infp)) > 0) {
		if (sdf_sign_update(&ctx, buf, len) != 1) {
			(void)sdf_close_device(&dev);
			fprintf(stderr, "gmssl %s: inner error\n", prog);
			goto end;
		}
	}
	if (sdf_sign_finish(&ctx, sig, &siglen) != 1) {
		(void)sdf_close_device(&dev);
		fprintf(stderr, "gmssl %s: inner error\n", prog);
		goto end;
	}
	(void)sdf_close_device(&dev);

	if (fwrite(sig, 1, siglen, outfp) != siglen) {
		fprintf(stderr, "gmssl %s: output signature failed : %s\n", prog, strerror(errno));
		goto end;
	}
	ret = 0;

end:
	sdf_unload_library();
	if (infile && infp) fclose(infp);
	if (outfile && outfp) fclose(outfp);
	return ret;
}
