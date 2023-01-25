/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
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
#include <gmssl/pem.h>
#include <gmssl/x509.h>
#include <gmssl/x509_crl.h>
#include <gmssl/file.h>


static const char *options =
	"-in RevokedCertificate.der"
	" -key pem -pass str -cert pem"
	" [-next_update timestamp] "
	" [-out crl.der]";

int crlgen_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *infile = NULL;
	uint8_t *revoked_certs = NULL;
	size_t revoked_certs_len = 0;
	char *outfile = NULL;
	FILE *outfp = stdout;
	char *keyfile = NULL;
	char *pass = NULL;
	FILE *keyfp = NULL;
	SM2_KEY sign_key;
	char *cacertfile = NULL;
	uint8_t *cacert = NULL;
	size_t cacert_len = 0;
	const uint8_t *issuer;
	size_t issuer_len;
	time_t next_update = -1;

	uint8_t outbuf[64 * 1024];
	uint8_t *out = outbuf;
	size_t outlen = 0;

	argc--;
	argv++;

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: %s %s\n", prog, options);
			goto end;

		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);
			if (file_read_all(infile, &revoked_certs, &revoked_certs_len) != 1) {
				fprintf(stderr, "%s: read input file failed\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) goto bad;
			outfile = *(++argv);
			if (!(outfp = fopen(outfile, "wb"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, outfile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			keyfile = *(++argv);
			if (!(keyfp = fopen(keyfile, "rb"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, keyfile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-pass")) {
			if (--argc < 1) goto bad;
		} else if (!strcmp(*argv, "-cacert")) {
			if (--argc < 1) goto bad;
			cacertfile = *(++argv);
			if (x509_cert_new_from_file(&cacert, &cacert_len, cacertfile) != 1) {
				goto end;
			}
		} else if (!strcmp(*argv, "-next_update")) {
			if (--argc < 1) goto bad;
			next_update = atoi(*(++argv));
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

	if (!infile) {
		fprintf(stderr, "%s: '-in' option required\n", prog);
		goto end;
	}

	if (!cacertfile) {
		fprintf(stderr, "%s: '-cacert' option required\n", prog);
		goto end;
	}

	if (!keyfile) {
		fprintf(stderr, "%s: '-key' option required\n", prog);
		goto end;
	}
	if (!pass) {
		fprintf(stderr, "%s: '-pass' option required\n", prog);
		goto end;
	}


	if (!revoked_certs || !revoked_certs_len) {
		fprintf(stderr, "usage: %s %s\n", prog, options);
		goto end;
	}

	if (x509_cert_get_subject(cacert, cacert_len, &issuer, &issuer_len) != 1) {
		fprintf(stderr, "%s: parse CA certificate failure\n", prog);
		goto end;
	}
	if (sm2_private_key_info_decrypt_from_pem(&sign_key, pass, keyfp) != 1) {
		fprintf(stderr, "%s: load private key failure\n", prog);
		goto end;
	}

	if (x509_crl_sign_to_der(
		X509_version_v2,
		OID_sm2sign_with_sm3,
		issuer, issuer_len,
		time(NULL), next_update,
		revoked_certs, revoked_certs_len,
		NULL, 0,
		&sign_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH,
		&out, &outlen) != 1) {

	//	error_print();
		return -1;
	}

	if (fwrite(outbuf, 1, outlen, outfp) != outlen) {
		fprintf(stderr, "%s: output failure\n", prog);
		return -1;
	}
	ret = 0;

end:
	//if (cert) free(cert);
	if (outfile && outfp) fclose(outfp);
	return ret;
}
