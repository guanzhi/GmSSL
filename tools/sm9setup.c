/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/oid.h>
#include <gmssl/mem.h>
#include <gmssl/sm9.h>
#include <gmssl/error.h>
#include "passwd.h"

static const char *usage = "-alg (sm9sign|sm9encrypt) [-pass password] [-out pem] [-pubout pem] [-verbose]";

static const char *options =
"Options\n"
"\n"
"    -alg sm9sign|sm9encrypt     Generate maeter key for sm9sign or sm9encrypt\n"
"    -pass pass                  Password to encrypt the master private key, prompt if not given\n"
"    -out pem                    Output password-encrypted master private key in PEM format\n"
"    -pubout pem                 Output master public key in PEM format\n"
"    -verbose                    Print details\n"
"\n"
"Examples\n"
"\n"
"    gmssl sm9setup -alg sm9sign -pass P@ssw0rd -out sm9sign_msk.pem -pubout sm9sign_mpk.pem\n"
"    gmssl sm9setup -alg sm9encrypt -pass P@ssw0rd -out sm9enc_msk.pem -pubout sm9enc_mpk.pem\n"
"\n";

int sm9setup_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *alg = NULL;
	char *pass = NULL;
	char passbuf[GMSSL_PASSWORD_MAX_SIZE] = {0};
	char *outfile = NULL;
	char *puboutfile = NULL;
	int oid;
	FILE *outfp = stdout;
	FILE *puboutfp = stdout;
	SM9_SIGN_MASTER_KEY sign_msk;
	SM9_ENC_MASTER_KEY enc_msk;
	int verbose = 0;

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
			return 0;
		} else if (!strcmp(*argv, "-alg")) {
			if (--argc < 1) goto bad;
			alg = *(++argv);
			if ((oid = sm9_oid_from_name(alg)) < 1) {
				fprintf(stdout, "gmssl %s: invalid alg '%s', should be sm9sign or sm9encrypt\n", prog, alg);
				goto end;
			}
		} else if (!strcmp(*argv, "-pass")) {
			if (--argc < 1) goto bad;
			pass = *(++argv);
		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) goto bad;
			outfile = *(++argv);
			if (!(outfp = fopen(outfile, "wb"))) {
				error_print();
				goto end;
			}
		} else if (!strcmp(*argv, "-pubout")) {
			if (--argc < 1) goto bad;
			puboutfile = *(++argv);
			if (!(puboutfp = fopen(puboutfile, "wb"))) {
				error_print();
				goto end;
			}
		} else if (!strcmp(*argv, "-verbose")) {
			verbose = 1;
		} else {
bad:
			fprintf(stderr, "gmssl %s: illegal option '%s'\n", prog, *argv);
			goto end;
		}

		argc--;
		argv++;
	}

	if (!alg) {
		error_print();
		goto end;
	}
	if (gmssl_tool_get_password(prog, "Password to encrypt master private key", outfile, &pass,
		passbuf, sizeof(passbuf)) != 1) {
		goto end;
	}

	switch (oid) {
	case OID_sm9sign:
		if (sm9_sign_master_key_generate(&sign_msk) != 1
			|| sm9_sign_master_key_info_encrypt_to_pem(&sign_msk, pass, outfp) != 1
			|| sm9_sign_master_public_key_to_pem(&sign_msk, puboutfp) != 1) {
			error_print();
			goto end;
		}
		if (verbose) {
			sm9_sign_master_key_print(stdout, 0, 0, "sm9_sign_master_key", &sign_msk);
			sm9_sign_master_public_key_print(stdout, 0, 0, "sm9_sign_master_public_key", &sign_msk);
		}
		break;
	case OID_sm9encrypt:
		if (sm9_enc_master_key_generate(&enc_msk) != 1
			|| sm9_enc_master_key_info_encrypt_to_pem(&enc_msk, pass, outfp) != 1
			|| sm9_enc_master_public_key_to_pem(&enc_msk, puboutfp) != 1) {
			error_print();
			goto end;
		}
		if (verbose) {
			sm9_enc_master_key_print(stdout, 0, 0, "sm9_enc_master_key", &enc_msk);
			sm9_enc_master_public_key_print(stdout, 0, 0, "sm9_enc_master_public_key", &enc_msk);
		}
		break;
	default:
		error_print();
		goto end;
	}
	ret = 0;

end:
	gmssl_secure_clear(&sign_msk, sizeof(sign_msk));
	gmssl_secure_clear(&enc_msk, sizeof(enc_msk));
	gmssl_secure_clear(passbuf, sizeof(passbuf));
	if (outfile && outfp) fclose(outfp);
	if (puboutfile && puboutfp) fclose(puboutfp);
	return ret;
}


















