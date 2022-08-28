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
#include <gmssl/x509.h>
#include <gmssl/x509_ext.h>
#include <gmssl/x509_req.h>


static const char *options = "[-in pem] -days num -cacert pem -key pem [-pass str] [-out pem] "
	"-key_usage oid -path_len_constraint num  -crl_url url\n";

static int ext_key_usage_set(int *usages, const char *usage_name)
{
	int flag = 0;
	if (x509_key_usage_from_name(&flag, usage_name) != 1) {
		return -1;
	}
	*usages |= flag;
	return 1;
}

int reqsign_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *infile = NULL;
	int days = 0;
	char *cacertfile = NULL;
	char *keyfile = NULL;
	char *pass = NULL;
	char *outfile = NULL;
	FILE *infp = stdin;
	FILE *cacertfp = NULL;
	FILE *keyfp = NULL;
	FILE *outfp = stdout;

	uint8_t req[512];
	size_t reqlen;
	const uint8_t *subject;
	size_t subject_len;
	SM2_KEY subject_public_key;

	uint8_t cacert[1024];
	size_t cacertlen;
	const uint8_t *issuer;
	size_t issuer_len;
	SM2_KEY issuer_public_key;

	SM2_KEY sm2_key;

	uint8_t cert[1024];
	size_t certlen;
	uint8_t serial[12];
	time_t not_before, not_after;
	uint8_t exts[512];
	size_t extslen = 0;
	int key_usage = 0;
	int path_len_constraint = -1;

	argc--;
	argv++;

	if (argc < 1) {
		fprintf(stderr, "usage: %s %s\n", prog, options);
		return 1;
	}

	while (argc >= 1) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: %s %s\n", prog, options);
			ret = 0;
			goto end;
		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);
			if (!(infp = fopen(infile, "r"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, outfile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-days")) {
			if (--argc < 1) goto bad;
			days = atoi(*(++argv));
			if (days <= 0) {
				fprintf(stderr, "%s: invalid '-days' value\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-key_usage")) {
			if (--argc < 1) goto bad;
			if (ext_key_usage_set(&key_usage, *(++argv)) != 1) {
				fprintf(stderr, "%s: set KeyUsage extenstion failure\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-path_len_constraint")) {
			if (--argc < 1) goto bad;
			path_len_constraint = atoi(*(++argv));
			if (path_len_constraint < 0) {
				fprintf(stderr, "%s: invalid value for '-path_len_constraint'\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-crl_url")) {
			if (--argc < 1) goto bad;
			//crl_url = *(++argv);
		} else if (!strcmp(*argv, "-cacert")) {
			if (--argc < 1) goto bad;
			cacertfile = *(++argv);
			if (!(cacertfp = fopen(cacertfile, "r"))) {
				fprintf(stderr, "%s: invalid -key_usage value\n", prog);
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

	if (!days) {
		fprintf(stderr, "%s: '-days' option required\n", prog);
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


	if (x509_req_from_pem(req, &reqlen, sizeof(req), infp) != 1
		|| x509_req_get_details(req, reqlen,
			NULL, &subject, &subject_len, &subject_public_key,
			NULL, NULL, NULL, NULL, NULL) != 1) {
		fprintf(stderr, "%s: parse CSR failure\n", prog);
		goto end;
	}

	if (x509_cert_from_pem(cacert, &cacertlen, sizeof(cacert), cacertfp) != 1
		|| x509_cert_get_subject(cacert, cacertlen, &issuer, &issuer_len) != 1
		|| x509_cert_get_subject_public_key(cacert, cacertlen, &issuer_public_key) != 1) {
		fprintf(stderr, "%s: parse CA certificate failure\n", prog);
		goto end;
	}

	if (sm2_private_key_info_decrypt_from_pem(&sm2_key, pass, keyfp) != 1) {
		fprintf(stderr, "%s: load private key failure\n", prog);
		goto end;
	}
	if (sm2_public_key_equ(&sm2_key, &issuer_public_key) != 1) {
		fprintf(stderr, "%s: private key and CA certificate not match\n", prog);
		goto end;
	}

	if (rand_bytes(serial, sizeof(serial)) != 1) {
		fprintf(stderr, "%s: inner error\n", prog);
		goto end;
	}
	time(&not_before);


	if (x509_exts_add_key_usage(exts, &extslen, sizeof(exts), 1, key_usage) != 1) {
		fprintf(stderr, "%s: inner error\n", prog);
		goto end;
	}
	if (path_len_constraint >= 0) {
		if (x509_exts_add_basic_constraints(exts, &extslen, sizeof(exts), 1, 1, path_len_constraint) != 1) {
			fprintf(stderr, "%s: inner error\n", prog);
			goto end;
		}
	}
	if (x509_exts_add_default_authority_key_identifier(exts, &extslen, sizeof(exts), &sm2_key) != 1) {
		fprintf(stderr, "%s: inner error\n", prog);
		goto end;
	}

	if (x509_validity_add_days(&not_after, not_before, days) != 1
		|| x509_cert_sign(
			cert, &certlen, sizeof(cert),
			X509_version_v3,
			serial, sizeof(serial),
			OID_sm2sign_with_sm3,
			issuer, issuer_len,
			not_before, not_after,
			subject, subject_len,
			&subject_public_key,
			NULL, 0,
			NULL, 0,
			exts, extslen,
			&sm2_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1) {
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
	if (cacertfp) fclose(cacertfp);
	if (infile && infp) fclose(infp);
	if (outfile && outfp) fclose(outfp);
	return ret;
}
