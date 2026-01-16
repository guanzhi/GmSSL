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
#include <gmssl/sdf.h>
#include <gmssl/mem.h>
#include <gmssl/hex.h>
#include <gmssl/sm2.h>
#include <gmssl/x509.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>


static const char *usage = "-lib so_path (-pubkey pem | -cert pem) [-in file] [-out file]";

static const char *options =
"\n"
"Options\n"
"\n"
"    -lib so_path        Vendor's SDF dynamic library\n"
"    -pubkey pem         Recepient's public key file in PEM format\n"
"    -cert pem           Recipient's certificate in PEM format\n"
"    -in file | stdin    Input data\n"
"    -out file | stdout  Output data\n"
"\n"
"Examples\n"
"\n"
"    $ gmssl sdfexport -encrypt -key 1 -lib libsoftsdf.so -out sm2encpub.pem\n"
"    $ echo 'Secret message' | gmssl sdfencrypt -lib libsoftsdf.so -pubkey sm2encpub.pem -out sdf_ciphertext.bin\n"
"    $ gmssl sdfdecrypt -lib libsoftsdf.so -key 1 -pass P@ssw0rd -in sdf_ciphertext.bin\n"
"\n";

int sdfencrypt_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *lib = NULL;
	char *pubkeyfile = NULL;
	char *certfile = NULL;
	char *infile = NULL;
	char *outfile = NULL;
	FILE *pubkeyfp = NULL;
	FILE *certfp = NULL;
	FILE *infp = stdin;
	FILE *outfp = stdout;
	SM2_KEY sm2_key;
	X509_KEY x509_key;
	uint8_t cert[1024];
	size_t certlen;
	uint8_t iv[16];
	uint8_t buf[4096];
	size_t inlen;
	size_t outlen;
	SDF_DEVICE dev;
	SDF_KEY key;
	SDF_CBC_CTX ctx;

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
		} else if (!strcmp(*argv, "-pubkey")) {
			if (certfile) {
				fprintf(stderr, "gmssl %s: options '-pubkey' '-cert' conflict\n", prog);
				goto end;
			}
			if (--argc < 1) goto bad;
			pubkeyfile = *(++argv);
			if (!(pubkeyfp = fopen(pubkeyfile, "rb"))) {
				fprintf(stderr, "gmssl %s: open '%s' failure : %s\n", prog, pubkeyfile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-cert")) {
			if (pubkeyfile) {
				fprintf(stderr, "gmssl %s: options '-pubkey' '-cert' conflict\n", prog);
				goto end;
			}
			if (--argc < 1) goto bad;
			certfile = *(++argv);
			if (!(certfp = fopen(certfile, "rb"))) {
				fprintf(stderr, "gmssl %s: open '%s' failure : %s\n", prog, certfile, strerror(errno));
				goto end;
			}
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

	// get public key
	if (pubkeyfile) {
		if (sm2_public_key_info_from_pem(&sm2_key, pubkeyfp) != 1) {
			fprintf(stderr, "gmssl %s: parse public key failed\n", prog);
			goto end;
		}
	} else if (certfile) {
		if (x509_cert_from_pem(cert, &certlen, sizeof(cert), certfp) != 1) {
			fprintf(stderr, "gmssl %s: parse certificate from PEM failed\n", prog);
			goto end;
		}
		if (x509_cert_get_subject_public_key(cert, certlen, &x509_key) != 1) {
			fprintf(stderr, "gmssl %s: parse certificate failed\n", prog);
			goto end;
		}
		if (x509_key.algor != OID_ec_public_key
			|| x509_key.algor_param != OID_sm2) {
			fprintf(stderr, "gmssl %s: invalid certificate type\n", prog);
			goto end;
		}
		sm2_key = x509_key.u.sm2_key;
	} else {
		fprintf(stderr, "gmssl %s: '-pubkey' or '-cert' option required\n", prog);
		goto end;
	}

	// generate key and output wrapped key in DER(SM2_CIPHERTEXT) format
	if (sdf_generate_key(&dev, &key, &sm2_key, buf, &outlen) != 1) {
		error_print();
		goto end;
	}
	if (fwrite(buf, 1, outlen, outfp) != outlen) {
		fprintf(stderr, "gmssl %s: output failure : %s\n", prog, strerror(errno));
		goto end;
	}

	// output IV
	rand_bytes(iv, 16);
	if (fwrite(iv, 1, 16, outfp) != 16) {
		fprintf(stderr, "gmssl %s: output failure : %s\n", prog, strerror(errno));
		goto end;
	}

	// encrypt and output ciphertext
	if (sdf_cbc_encrypt_init(&ctx, &key, iv) != 1) {
		error_print();
		goto end;
	}
	while ((inlen = fread(buf, 1, sizeof(buf), infp)) > 0) {
		if (sdf_cbc_encrypt_update(&ctx, buf, inlen, buf, &outlen) != 1) {
			error_print();
			goto end;
		}
		if (fwrite(buf, 1, outlen, outfp) != outlen) {
			fprintf(stderr, "gmssl %s: output failure : %s\n", prog, strerror(errno));
			goto end;
		}
	}
	if (sdf_cbc_encrypt_finish(&ctx, buf, &outlen) != 1) {
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
