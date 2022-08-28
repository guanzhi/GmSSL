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
#include <gmssl/error.h>
#include <gmssl/x509.h>
#include <gmssl/x509_ext.h>


static const char *options =
	"[-C str] [-ST str] [-L str] [-O str] [-OU str] -CN str -days num "
	"-key file [-pass pass] "
	"[-key_usage str]* [-out file]";


static int ext_key_usage_set(int *usages, const char *usage_name)
{
	int flag;
	if (x509_key_usage_from_name(&flag, usage_name) != 1) {
		error_print();
		return -1;
	}
	*usages |= flag;
	return 1;
}

int certgen_main(int argc, char **argv)
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
	int key_usage = 0;
	char *keyfile = NULL;
	char *pass = NULL;
	char *outfile = NULL;

	uint8_t serial[12];
	uint8_t name[256];
	size_t namelen;
	time_t not_before;
	time_t not_after;
	uint8_t uniq_id[32];
	uint8_t exts[512];
	size_t extslen = 0;
	FILE *keyfp = NULL;
	SM2_KEY sm2_key;
	uint8_t cert[1024];
	size_t certlen;
	FILE *outfp = stdout;

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
		} else if (!strcmp(*argv, "-CN")) {
			if (--argc < 1) goto bad;
			common_name = *(++argv);
		} else if (!strcmp(*argv, "-O")) {
			if (--argc < 1) goto bad;
			org = *(++argv);
		} else if (!strcmp(*argv, "-OU")) {
			if (--argc < 1) goto bad;
			org_unit = *(++argv);
		} else if (!strcmp(*argv, "-C")) {
			if (--argc < 1) goto bad;
			country = *(++argv);
		} else if (!strcmp(*argv, "-ST")) {
			if (--argc < 1) goto bad;
			state = *(++argv);
		} else if (!strcmp(*argv, "-L")) {
			if (--argc < 1) goto bad;
			locality = *(++argv);
		} else if (!strcmp(*argv, "-days")) {
			if (--argc < 1) goto bad;
			days = atoi(*(++argv));
			if (days <= 0) {
				fprintf(stderr, "%s: invalid '-days' value\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-key_usage")) {
			char *usage;
			if (--argc < 1) goto bad;
			usage = *(++argv);
			if (ext_key_usage_set(&key_usage, usage) != 1) {
				fprintf(stderr, "%s: invalid -key_usage value '%s'\n", prog, usage);
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
	if (!key_usage) {
		fprintf(stderr, "%s: '-key_usage' option required\n", prog);
		goto end;
	}

	if (sm2_private_key_info_decrypt_from_pem(&sm2_key, pass, keyfp) != 1) {
		fprintf(stderr, "%s: load private key failed\n", prog);
		goto end;
	}

	if (x509_exts_add_key_usage(exts, &extslen, sizeof(exts), 1, key_usage) != 1
		|| x509_exts_add_basic_constraints(exts, &extslen, sizeof(exts), 1, 1, -1) != 1
		|| x509_exts_add_default_authority_key_identifier(exts, &extslen, sizeof(exts), &sm2_key) != 1) {
		fprintf(stderr, "%s: inner error\n", prog);
		goto end;
	}

	time(&not_before);
	if (rand_bytes(serial, sizeof(serial)) != 1
		|| x509_name_set(name, &namelen, sizeof(name),
			country, state, locality, org, org_unit, common_name) != 1
		|| x509_validity_add_days(&not_after, not_before, days) != 1
		|| x509_cert_sign(
			cert, &certlen, sizeof(cert),
			X509_version_v3,
			serial, sizeof(serial),
			OID_sm2sign_with_sm3,
			name, namelen,
			not_before, not_after,
			name, namelen,
			&sm2_key,
			NULL, 0,
			NULL, 0,
			exts, extslen,
			&sm2_key, SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID)) != 1) {
		fprintf(stderr, "%s: inner error\n", prog);
		goto end;
	}
	if (x509_cert_to_pem(cert, certlen, outfp) != 1) {
		fprintf(stderr, "%s: output certificate failed\n", prog);
		goto end;
	}
	ret = 0;

end:
	gmssl_secure_clear(&sm2_key, sizeof(SM2_KEY));
	if (keyfp) fclose(keyfp);
	if (outfile && outfp) fclose(outfp);
	return ret;
}
