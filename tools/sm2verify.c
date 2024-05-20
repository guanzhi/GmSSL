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
#include <gmssl/x509.h>


static const char *usage = "(-pubkey pem | -cert pem) [-id str] [-in file] -sig file";

static const char *options =
"\n"
"Options\n"
"\n"
"    -pubkey pem         Signer's public key file in PEM format\n"
"    -cert pem           Signer's certificate in PEM format\n"
"    -id str             Signer's identity string, '1234567812345678' by default\n"
"    -in file | stdin    Signed file or data\n"
"    -sig file           Signature in binary DER encoding\n"
"\n"
"Examples\n"
"\n"
"    $ gmssl sm2keygen -pass P@ssw0rd -out sm2.pem -pubout sm2pub.pem\n"
"    $ echo -n 'message to be signed' | gmssl sm2sign -key sm2.pem -pass P@ssw0rd -out sm2.sig\n"
"    $ echo -n 'message to be signed' | gmssl sm2verify -pubkey sm2pub.pem -sig sm2.sig\n"
"\n";


int sm2verify_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *id = SM2_DEFAULT_ID;
	char *pubkeyfile = NULL;
	char *certfile = NULL;
	char *infile = NULL;
	char *sigfile = NULL;
	FILE *pubkeyfp = NULL;
	FILE *certfp = NULL;
	FILE *infp = stdin;
	FILE *sigfp = NULL;
	SM2_KEY key;
	SM2_VERIFY_CTX verify_ctx;
	uint8_t cert[1024];
	size_t certlen;
	uint8_t buf[4096];
	size_t len;
	uint8_t sig[SM2_MAX_SIGNATURE_SIZE];
	size_t siglen;
	int vr;

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
		} else if (!strcmp(*argv, "-sig")) {
			if (--argc < 1) goto bad;
			sigfile = *(++argv);
			if (!(sigfp = fopen(sigfile, "rb"))) {
				fprintf(stderr, "gmssl %s: open '%s' failure : %s\n", prog, sigfile, strerror(errno));
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

	if (!sigfile) {
		fprintf(stderr, "gmssl %s: '-sig' option required\n", prog);
		goto end;
	}
	if ((siglen = fread(sig, 1, sizeof(sig), sigfp)) <= 0) {
		fprintf(stderr, "gmssl %s: read signature error : %s\n", prog, strerror(errno));
		goto end;
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


	if (sm2_verify_init(&verify_ctx, &key, id, strlen(id)) != 1) {
		fprintf(stderr, "gmssl %s: inner error\n", prog);
		goto end;
	}
	while ((len = fread(buf, 1, sizeof(buf), infp)) > 0) {
		if (sm2_verify_update(&verify_ctx, buf, len) != 1) {
			fprintf(stderr, "gmssl %s: inner error\n", prog);
			goto end;
		}
	}
	if ((vr = sm2_verify_finish(&verify_ctx, sig, siglen)) < 0) {
		fprintf(stderr, "gmssl %s: inner error\n", prog);
		goto end;
	}

	fprintf(stdout, "verify : %s\n", vr == 1 ? "success" : "failure");
	if (vr == 1) {
		ret = 0;
	}

end:
	if (infile && infp) fclose(infp);
	if (pubkeyfp) fclose(pubkeyfp);
	if (certfp) fclose(certfp);
	if (sigfp) fclose(sigfp);
	return ret;
}
