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
#include <gmssl/hex.h>
#include <gmssl/file.h>
#include <gmssl/x509.h>
#include <gmssl/x509_crl.h>


static const char *usage = " -in der -cacert pem [-req_sm2_id str | -req_sm2_id_hex hex]\n";
static const char *options =
"Options\n"
"\n"
"    -in pem                      Input CSR file in PEM format\n"
"    -cacert pem                  Issuer CA certificate\n"
"    -sm2_id str                  Authority's ID in SM2 signature algorithm\n"
"    -sm2_id_hex hex              Authority's ID in hex format\n"
"                                 When `-sm2_id` or `-sm2_id_hex` is specified,\n"
"                                   must use the same ID in other commands explicitly.\n"
"                                 If neither `-sm2_id` nor `-sm2_id_hex` is specified,\n"
"                                   the default string '1234567812345678' is used\n"
"\n"
"Examples\n"
"\n"
"    gmssl certverify -in crl.der -cacert cacert.pem\n"
"\n";

int crlverify_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *str;

	uint8_t *crl = NULL;
	size_t crl_len;
	uint8_t *cacert = NULL;
	size_t cacertlen;
	char signer_id[SM2_MAX_ID_LENGTH + 1] = SM2_DEFAULT_ID;
	size_t signer_id_len = strlen(SM2_DEFAULT_ID);
	int rv;

	argc--;
	argv++;

	if (argc < 1) {
		fprintf(stderr, "usage: %s %s\n", prog, options);
		return 1;
	}

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: %s %s\n", prog, options);
			ret = 0;
			goto end;
		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			if (file_read_all(str, &crl, &crl_len) != 1) {
				fprintf(stderr, "%s: read '%s' failure : %s\n", prog, str, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-cacert")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			if (x509_cert_new_from_file(&cacert, &cacertlen, str) != 1) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, str, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-sm2_id")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			if (strlen(str) > sizeof(signer_id) - 1) {
				fprintf(stderr, "%s: invalid `-sm2_id` length\n", prog);
				goto end;
			}
			strncpy(signer_id, str, sizeof(signer_id));
			signer_id_len = strlen(str);
		} else if (!strcmp(*argv, "-sm2_id_hex")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			if (strlen(str) > (sizeof(signer_id) - 1) * 2) {
				fprintf(stderr, "%s: invalid `-sm2_id_hex` length\n", prog);
				goto end;
			}
			if (hex_to_bytes(str, strlen(str), (uint8_t *)signer_id, &signer_id_len) != 1) {
				fprintf(stderr, "%s: invalid `-sm2_id_hex` value\n", prog);
				goto end;
			}
		} else {
			fprintf(stderr, "%s: illegal option `%s`\n", prog, *argv);
			goto end;
bad:
			fprintf(stderr, "%s: `%s` option value missing\n", prog, *argv);
			goto end;
		}

		argc--;
		argv++;
	}

	if (!crl) {
		fprintf(stderr, "%s: `-in` option required\n", prog);
		goto end;
	}
	if (!cacert) {
		fprintf(stderr, "%s: `-cacert` option required\n", prog);
		goto end;
	}

	if (x509_crl_check(crl, crl_len, time(NULL)) != 1) {
		fprintf(stderr, "%s: invalid CRL data or format\n", prog);
		goto end;
	}
	if ((rv = x509_crl_verify_by_ca_cert(crl, crl_len, cacert, cacertlen, signer_id, signer_id_len)) < 0) {
		fprintf(stderr, "%s: verification inner error\n", prog);
		goto end;
	}

	printf("Verification %s\n", rv ? "success" : "failure");
	if (rv == 1) ret = 0;

end:
	if (crl) free(crl);
	if (cacert) free(cacert);
	return ret;
}
