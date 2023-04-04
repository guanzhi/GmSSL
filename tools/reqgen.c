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
#include <gmssl/mem.h>
#include <gmssl/hex.h>
#include <gmssl/rand.h>
#include <gmssl/pkcs8.h>
#include <gmssl/x509.h>
#include <gmssl/x509_req.h>



static const char *options =
	"[-C str] [-ST str] [-L str] [-O str] [-OU str] -CN str"
	" -key pem -pass pass"
	" [-sm2_id str | -sm2_id_hex hex]"
	" [-out pem]";

static char *usage =
"Options\n"
"\n"
"    -key file                    Private key file in PEM format\n"
"    -pass pass                   Password for decrypting private key file\n"
"    -sm2_id str                  Signer's ID in SM2 signature algorithm\n"
"    -sm2_id_hex hex              Signer's ID in hex format\n"
"                                 When `-sm2_id` or `-sm2_id_hex` is specified,\n"
"                                   must use the same ID in other commands explicitly.\n"
"                                 If neither `-sm2_id` nor `-sm2_id_hex` is specified,\n"
"                                   the default string '1234567812345678' is used\n"
"    -out file                    Output Certificate Request (CSR) file in PEM format\n"
"\n"
"  Subject options\n"
"\n"
"    -C  str                      Country\n"
"    -ST str                      State or province name\n"
"    -L  str                      Locality\n"
"    -O  str                      Organization\n"
"    -OU str                      Organizational unit\n"
"    -CN str                      Common name\n"
"\n"
"Examples\n"
"\n"
"    gmssl sm2keygen -pass P@ssw0rd -out key.pem\n"
"    gmssl reqgen -CN www.gmssl.org -key key.pem -pass P@ssw0rd -out req.pem\n"
"\n";


int reqgen_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *str;

	// Subject
	uint8_t name[256];
	size_t namelen = 0;
	char *country = NULL;
	char *state = NULL;
	char *locality = NULL;
	char *org = NULL;
	char *org_unit = NULL;
	char *common_name = NULL;

	// Attributs
	uint8_t attrs[512];
	size_t attrs_len = 0;

	// Private Key
	FILE *keyfp = NULL;
	char *pass = NULL;
	SM2_KEY sm2_key;
	char signer_id[SM2_MAX_ID_LENGTH + 1] = {0};
	size_t signer_id_len = 0;

	// Output
	char *outfile = NULL;
	FILE *outfp = stdout;
	uint8_t req[1024];
	uint8_t *p = req;
	size_t reqlen = 0;

	argc--;
	argv++;

	if (argc < 1) {
		fprintf(stderr, "usage: %s %s\n", prog, options);
		return 1;
	}

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: gmssl %s %s\n\n", prog, options);
			printf("%s\n", usage);
			ret = 0;
			goto end;
		} else if (!strcmp(*argv, "-C")) {
			if (--argc < 1) goto bad;
			country = *(++argv);
		} else if (!strcmp(*argv, "-ST")) {
			if (--argc < 1) goto bad;
			state = *(++argv);
		} else if (!strcmp(*argv, "-L")) {
			if (--argc < 1) goto bad;
			locality = *(++argv);
		} else if (!strcmp(*argv, "-O")) {
			if (--argc < 1) goto bad;
			org = *(++argv);
		} else if (!strcmp(*argv, "-OU")) {
			if (--argc < 1) goto bad;
			org_unit = *(++argv);
		} else if (!strcmp(*argv, "-CN")) {
			if (--argc < 1) goto bad;
			common_name = *(++argv);

		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			if (!(keyfp = fopen(str, "rb"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, str, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-pass")) {
			if (--argc < 1) goto bad;
			pass = *(++argv);
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
			fprintf(stderr, "%s: `%s` option value missing\n", prog, *argv);
			goto end;
		}

		argc--;
		argv++;
	}

	if (!common_name) {
		fprintf(stderr, "%s: `-CN` option required\n", prog);
		printf("usage: gmssl %s %s\n\n", prog, options);
		goto end;
	}
	if (!keyfp) {
		fprintf(stderr, "%s: `-key` option required\n", prog);
		printf("usage: gmssl %s %s\n\n", prog, options);
		goto end;
	}
	if (!pass) {
		fprintf(stderr, "%s: `-pass` option required\n", prog);
		printf("usage: gmssl %s %s\n\n", prog, options);
		goto end;
	}

	if (sm2_private_key_info_decrypt_from_pem(&sm2_key, pass, keyfp) != 1) {
		fprintf(stderr, "%s: load private key failed\n", prog);
		goto end;
	}
	if (!signer_id_len) {
		strcpy(signer_id, SM2_DEFAULT_ID);
		signer_id_len = strlen(SM2_DEFAULT_ID);
	}

	if (x509_name_set(name, &namelen, sizeof(name), country, state, locality, org, org_unit, common_name) != 1) {
		fprintf(stderr, "%s: set Subject Name error\n", prog);
		goto end;
	}

	if (x509_req_sign_to_der(
		X509_version_v1,
		name, namelen,
		&sm2_key,
		attrs, attrs_len,
		OID_sm2sign_with_sm3,
		&sm2_key, signer_id, signer_id_len,
		&p, &reqlen) != 1) {
		fprintf(stderr, "%s: inner error\n", prog);
		goto end;
	}
	if (x509_req_to_pem(req, reqlen, outfp) != 1) {
		fprintf(stderr, "%s: output CSR failed\n", prog);
		goto end;
	}
	ret = 0;
end:
	gmssl_secure_clear(&sm2_key, sizeof(SM2_KEY));
	if (keyfp) fclose(keyfp);
	if (outfile && outfp) fclose(outfp);
	return ret;
}
