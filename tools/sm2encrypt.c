/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
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


static const char *options = "(-pubkey pem | -cert pem) [-in file] [-out file]";

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
	uint8_t inbuf[SM2_MAX_PLAINTEXT_SIZE + 1];
	uint8_t outbuf[SM2_MAX_CIPHERTEXT_SIZE];
	size_t inlen, outlen = sizeof(outbuf);

	argc--;
	argv++;

	if (argc < 1) {
		fprintf(stderr, "usage: %s %s\n", prog, options);
		return 1;
	}

	while (argc > 1) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: %s %s\n", prog, options);
			ret = 0;
			goto end;
		} else if (!strcmp(*argv, "-pubkey")) {
			if (certfile) {
				fprintf(stderr, "%s: options '-pubkey' '-cert' conflict\n", prog);
				goto end;
			}
			if (--argc < 1) goto bad;
			pubkeyfile = *(++argv);
			if (!(pubkeyfp = fopen(pubkeyfile, "rb"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, pubkeyfile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-cert")) {
			if (pubkeyfile) {
				fprintf(stderr, "%s: options '-pubkey' '-cert' conflict\n", prog);
				goto end;
			}
			if (--argc < 1) goto bad;
			certfile = *(++argv);
			if (!(certfp = fopen(certfile, "rb"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, certfile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);
			if (!(infp = fopen(infile, "rb"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, infile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) goto bad;
			outfile = *(++argv);
			if (!(outfp = fopen(outfile, "wb"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, outfile, strerror(errno));
				goto end;
			}
		} else {
			fprintf(stderr, "%s: illegal option '%s'\n", prog, *argv);
			goto end;
bad:
			fprintf(stderr, "%s: '%s' option value missing\n", prog, *argv);
			goto end;
		}

		argc--;
		argv++;
	}


	if (pubkeyfile) {
		if (sm2_public_key_info_from_pem(&key, pubkeyfp) != 1) {
			fprintf(stderr, "%s: parse public key failed\n", prog);
			goto end;
		}
	} else if (certfile) {
		if (x509_cert_from_pem(cert, &certlen, sizeof(cert), certfp) != 1
			|| x509_cert_get_subject_public_key(cert, certlen, &key) != 1) {
			fprintf(stderr, "%s: parse certificate failed\n", prog);
			goto end;
		}
	} else {
		fprintf(stderr, "%s: '-pubkey' or '-cert' option required\n", prog);
		goto end;
	}

	if ((inlen = fread(inbuf, 1, sizeof(inbuf), infp)) <= 0) {
		fprintf(stderr, "%s: read input error : %s\n", prog, strerror(errno));
		goto end;
	}
	if (inlen > SM2_MAX_PLAINTEXT_SIZE) {
		fprintf(stderr, "%s: input long than SM2_MAX_PLAINTEXT_SIZE (%d)\n", prog, SM2_MAX_PLAINTEXT_SIZE);
		goto end;
	}

	if (sm2_encrypt(&key, inbuf, inlen, outbuf, &outlen) != 1) {
		fprintf(stderr, "%s: inner error\n", prog);
		goto end;
	}

	if (outlen != fwrite(outbuf, 1, outlen, outfp)) {
		fprintf(stderr, "%s: output error : %s\n", prog, strerror(errno));
		goto end;
	}
	ret = 0;

end:
	if (infile && infp) fclose(infp);
	if (outfile && outfp) fclose(outfp);
	if (pubkeyfp) fclose(pubkeyfp);
	if (certfp) fclose(certfp);
	return ret;
}
