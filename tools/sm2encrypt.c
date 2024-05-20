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
#include <gmssl/x509.h>

static const char *usage = "(-pubkey pem | -cert pem) [-in file] [-out file]";

static const char *options =
"\n"
"Options\n"
"\n"
"    -pubkey pem         Recepient's public key file in PEM format\n"
"    -cert pem           Recipient's certificate in PEM format\n"
"    -in file | stdin    To be encrypted data, at most 255 bytes\n"
"    -out file | stdout  Output ciphertext in binary DER-encoding\n"
"\n"
"Examples\n"
"\n"
"    $ gmssl sm2keygen -pass P@ssw0rd -out sm2.pem -pubout sm2pub.pem\n"
"    $ echo 'Secret message' | gmssl sm2encrypt -pubkey sm2pub.pem -out sm2.der\n"
"    $ gmssl sm2decrypt -key sm2.pem -pass P@ssw0rd -in sm2.der\n"
"\n";

int sm2encrypt_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *pubkeyfile = NULL;
	char *certfile = NULL;
	char *infile = NULL;
	char *outfile = NULL;
	FILE *pubkeyfp = NULL;
	FILE *certfp = NULL;
	FILE *infp = stdin;
	FILE *outfp = stdout;
	uint8_t cert[1024];
	size_t certlen;
	SM2_KEY key;
	SM2_ENC_CTX ctx;
	uint8_t inbuf[SM2_MAX_PLAINTEXT_SIZE + 1];
	uint8_t outbuf[SM2_MAX_CIPHERTEXT_SIZE];
	size_t inlen, outlen = sizeof(outbuf);

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
			fprintf(stderr, "gmssl %s: illegal option '%s'\n", prog, *argv);
			goto end;
bad:
			fprintf(stderr, "gmssl %s: '%s' option value missing\n", prog, *argv);
			goto end;
		}

		argc--;
		argv++;
	}


	if (pubkeyfile) {
		if (sm2_public_key_info_from_pem(&key, pubkeyfp) != 1) {
			fprintf(stderr, "gmssl %s: parse public key failed\n", prog);
			goto end;
		}
	} else if (certfile) {
		if (x509_cert_from_pem(cert, &certlen, sizeof(cert), certfp) != 1
			|| x509_cert_get_subject_public_key(cert, certlen, &key) != 1) {
			fprintf(stderr, "gmssl %s: parse certificate failed\n", prog);
			goto end;
		}
	} else {
		fprintf(stderr, "gmssl %s: '-pubkey' or '-cert' option required\n", prog);
		goto end;
	}

	if ((inlen = fread(inbuf, 1, sizeof(inbuf), infp)) <= 0) {
		fprintf(stderr, "gmssl %s: read input error : %s\n", prog, strerror(errno));
		goto end;
	}
	if (inlen > SM2_MAX_PLAINTEXT_SIZE) {
		fprintf(stderr, "gmssl %s: input long than SM2_MAX_PLAINTEXT_SIZE (%d)\n", prog, SM2_MAX_PLAINTEXT_SIZE);
		goto end;
	}

	if (sm2_encrypt_init(&ctx) != 1) {
		fprintf(stderr, "gmssl %s: sm2_encrypt_init failed\n", prog);
		goto end;
	}
	if (sm2_encrypt_update(&ctx, inbuf, inlen) != 1) {
		fprintf(stderr, "gmssl %s: sm2_encrypt_update failed\n", prog);
		return -1;
	}
	if (sm2_encrypt_finish(&ctx, &key, outbuf, &outlen) != 1) {
		fprintf(stderr, "gmssl %s: sm2_encrypt_finish error\n", prog);
		goto end;
	}

	if (outlen != fwrite(outbuf, 1, outlen, outfp)) {
		fprintf(stderr, "gmssl %s: output error : %s\n", prog, strerror(errno));
		goto end;
	}
	ret = 0;

end:
	gmssl_secure_clear(&ctx, sizeof(ctx));
	gmssl_secure_clear(inbuf, sizeof(inbuf));
	if (infile && infp) fclose(infp);
	if (outfile && outfp) fclose(outfp);
	if (pubkeyfp) fclose(pubkeyfp);
	if (certfp) fclose(certfp);
	return ret;
}
