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
#include <gmssl/mem.h>
#include <gmssl/rand.h>
#include <gmssl/pkcs8.h>
#include <gmssl/x509.h>
#include <gmssl/x509_req.h>


static const char *options =
	"[-C str] [-ST str] [-L str] [-O str] [-OU str] -CN str -days num"
	" -key file [-pass pass] [-out file]";

int reqgen_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *country = NULL;
	char *state = NULL;
	char *locality = NULL;
	char *org = NULL;
	char *org_unit = NULL;
	char *common_name = NULL;
	int days = 0;
	char *keyfile = NULL;
	char *pass = NULL;
	char *outfile = NULL;
	uint8_t name[256];
	size_t namelen = 0;
	FILE *keyfp = NULL;
	FILE *outfp = stdout;
	uint8_t req[1024];
	size_t reqlen = 0;
	SM2_KEY sm2_key;

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
		} else if (!strcmp(*argv, "-days")) {
			if (--argc < 1) goto bad;
			days = atoi(*(++argv));
			if (days <= 0) {
				fprintf(stderr, "%s: invalid '-days' value\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			keyfile = *(++argv);
			if (!(keyfp = fopen(keyfile, "r"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, keyfile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-pass")) {
			if (--argc < 1) goto bad;
			pass = *(++argv);
		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) goto bad;
			outfile = *(++argv);
			if (!(outfp = fopen(outfile, "w"))) {
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

	if (!common_name) {
		fprintf(stderr, "%s: '-CN' option required\n", prog);
		goto end;
	}
	if (!days) {
		fprintf(stderr, "%s: '-days' option required\n", prog);
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

	if (sm2_private_key_info_decrypt_from_pem(&sm2_key, pass, keyfp) != 1) {
		fprintf(stderr, "%s: load private key failed\n", prog);
		goto end;
	}

	if (x509_name_set(name, &namelen, sizeof(name),
			country, state, locality, org, org_unit, common_name) != 1
		|| x509_req_sign(req, &reqlen, sizeof(req),
			X509_version_v1,
			name, namelen,
			&sm2_key,
			NULL, 0,
			OID_sm2sign_with_sm3,
			&sm2_key, SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID)) != 1) {
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
