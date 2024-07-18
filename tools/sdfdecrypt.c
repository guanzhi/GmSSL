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
#include <gmssl/hex.h>
#include <gmssl/sm2.h>
#include <gmssl/x509.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>


static const char *usage = "-lib so_path -key num -pass str [-in file] [-out file]";

static const char *options =
"\n"
"Options\n"
"\n"
"    -lib so_path        Vendor's SDF dynamic library\n"
"    -key num            Decryption private key index number\n"
"    -pass str           Password to get the private key access right\n"
"    -in file | stdin    Input data\n"
"    -out file | stdout  Output data\n"
"\n"
"Examples\n"
"\n"
"    $ gmssl sdfexport -encrypt -key 1 -lib libsoftsdf.so -out sm2encpub.pem\n"
"    $ echo 'Secret message' | gmssl sdfencrypt -lib libsoftsdf.so -pubkey sm2encpub.pem -out sdf_ciphertext.bin\n"
"    $ gmssl sdfdecrypt -lib libsoftsdf.so -key 1 -pass P@ssw0rd -in sdf_ciphertext.bin\n"
"\n";

int sdfdecrypt_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *lib = NULL;
	int key_index = -1;
	char *pass = NULL;
	char *infile = NULL;
	char *outfile = NULL;
	FILE *infp = stdin;
	FILE *outfp = stdout;

	uint8_t iv[16];
	uint8_t buf[4096];
	size_t inlen;
	size_t outlen;
	SDF_DEVICE dev;
	SDF_KEY key;
	SDF_CBC_CTX ctx;
	const uint8_t *p;
	SM2_CIPHERTEXT ciphertext;
	uint8_t *wrappedkey;
	size_t wrappedkey_len;

	memset(&dev, 0, sizeof(dev));
	memset(&key, 0, sizeof(key));
	memset(&ctx, 0, sizeof(ctx));

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
			fprintf(stderr, "gmssl %s: illegal option `%s`\n", prog, *argv);
			goto end;
bad:
			fprintf(stderr, "gmssl %s: `%s` option value missing\n", prog, *argv);
			goto end;
		}

		argc--;
		argv++;
	}

	// load library and open device
	if (!lib) {
		fprintf(stderr, "gmssl %s: '-lib' option required\n", prog);
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

	if (key_index < 0) {
		fprintf(stderr, "gmssl %s: '-key' option required\n", prog);
		goto end;
	}
	if (!pass) {
		fprintf(stderr, "gmssl %s: '-pass' option required\n", prog);
		goto end;
	}

	// read DER(SM2_CIPHERTEXT) and following bytes
	if ((inlen = fread(buf, 1, sizeof(buf), infp)) <= 0) {
		fprintf(stderr, "gmssl %s: read failure : %s\n", prog, strerror(errno));
		goto end;
	}
	wrappedkey_len = inlen;

	p = buf;
	if (sm2_ciphertext_from_der(&ciphertext, &p, &inlen) != 1) {
		error_print();
		goto end;
	}
	wrappedkey_len -= inlen;

	// read IV
	if (inlen >= 16) {
		memcpy(iv, p, 16);
		p += 16;
		inlen -= 16;
	} else {
		memcpy(iv, p, inlen);
		if (fread(iv + inlen, 1, 16 - inlen, infp) != 16 - inlen) {
			error_print();
			goto end;
		}
		inlen = 0;
	}

	// import key
	if (sdf_import_key(&dev, key_index, pass, buf, wrappedkey_len, &key) != 1) {
		error_print();
		return -1;
	}

	// encrypt and output ciphertext
	if (sdf_cbc_decrypt_init(&ctx, &key, iv) != 1) {
		error_print();
		goto end;
	}
	if (inlen) {
		if (sdf_cbc_decrypt_update(&ctx, p, inlen, buf, &outlen) != 1) {
			error_print();
			goto end;
		}
	}
	while ((inlen = fread(buf, 1, sizeof(buf), infp)) > 0) {
		if (sdf_cbc_decrypt_update(&ctx, buf, inlen, buf, &outlen) != 1) {
			error_print();
			goto end;
		}
		if (fwrite(buf, 1, outlen, outfp) != outlen) {
			fprintf(stderr, "gmssl %s: output failure : %s\n", prog, strerror(errno));
			goto end;
		}
	}
	if (sdf_cbc_decrypt_finish(&ctx, buf, &outlen) != 1) {
		error_print();
		goto end;
	}
	if (fwrite(buf, 1, outlen, outfp) != outlen) {
		fprintf(stderr, "gmssl %s: output failure : %s\n", prog, strerror(errno));
		goto end;
	}

	ret = 0;

end:
	(void)sdf_destroy_key(&key);
	(void)sdf_close_device(&dev);
	(void)sdf_unload_library();
	gmssl_secure_clear(iv, sizeof(iv));
	gmssl_secure_clear(&ctx, sizeof(ctx));
	if (infile && infp) fclose(infp);
	if (outfile && outfp) fclose(outfp);
	return ret;
}
