/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
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
#include <gmssl/x509_key.h>
#include "passwd.h"


static const char *usage = "-curve str [-pass str] [-out pem] [-pubout pem]\n";

static const char *options =
"Options\n"
"\n"
"    -curve str                 EC curve name, supported curves: secp256r1, prime256v1, secp384r1\n"
"                               SM2 is not supported by this command, use `sm2keygen` instead\n"
"    -pass pass                  Password to encrypt the private key, prompt if not given\n"
"    -out pem                    Output password-encrypted PKCS #8 private key in PEM format\n"
"    -pubout pem                 Output public key in PEM format\n"
"    -export pem                 Output non-encrypted EC private key in PEM format\n"
"\n"
"Examples\n"
"\n"
"    gmssl eckeygen -curve secp256r1 -pass P@ssw0rd -out p256.pem\n"
"    gmssl eckeygen -curve secp384r1 -pass P@ssw0rd -out p384.pem -pubout p384pub.pem\n"
"\n";

static int eckeygen_curve_from_name(const char *name)
{
	if (!name) {
		return OID_undef;
	}
	if (!strcmp(name, "sm2") || !strcmp(name, "sm2p256v1")) {
		return OID_sm2;
	}
#ifdef ENABLE_SECP256R1
	if (!strcmp(name, "secp256r1") || !strcmp(name, "prime256v1")) {
		return OID_secp256r1;
	}
#endif
#ifdef ENABLE_SECP384R1
	if (!strcmp(name, "secp384r1")) {
		return OID_secp384r1;
	}
#endif
	return OID_undef;
}

int eckeygen_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *curve_name = NULL;
	char *pass = NULL;
	char passbuf[GMSSL_PASSWORD_MAX_SIZE] = {0};
	char *outfile = NULL;
	char *puboutfile = NULL;
	char *exportfile = NULL;
	FILE *outfp = stdout;
	FILE *puboutfp = stdout;
	FILE *exportfp = NULL;
	int curve_oid = OID_undef;
	X509_KEY key = {0};

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
		} else if (!strcmp(*argv, "-curve")) {
			if (--argc < 1) goto bad;
			curve_name = *(++argv);
		} else if (!strcmp(*argv, "-pass")) {
			if (--argc < 1) goto bad;
			pass = *(++argv);
		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) goto bad;
			outfile = *(++argv);
			if (!(outfp = fopen(outfile, "wb"))) {
				fprintf(stderr, "gmssl %s: open '%s' failure : %s\n", prog, outfile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-pubout")) {
			if (--argc < 1) goto bad;
			puboutfile = *(++argv);
			if (!(puboutfp = fopen(puboutfile, "wb"))) {
				fprintf(stderr, "gmssl %s: open '%s' failure : %s\n", prog, puboutfile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-export")) {
			if (--argc < 1) goto bad;
			exportfile = *(++argv);
			if (!(exportfp = fopen(exportfile, "wb"))) {
				fprintf(stderr, "gmssl %s: open '%s' failure : %s\n", prog, exportfile, strerror(errno));
				goto end;
			}
		} else {
			fprintf(stderr, "gmssl %s: illegal option '%s'\n", prog, *argv);
			goto end;
bad:
			fprintf(stderr, "gmssl %s: `%s` option value missing\n", prog, *argv);
			goto end;
		}

		argc--;
		argv++;
	}

	if (!curve_name) {
		fprintf(stderr, "gmssl %s: option '-curve' required\n", prog);
		goto end;
	}
	curve_oid = eckeygen_curve_from_name(curve_name);
	if (curve_oid == OID_sm2) {
		fprintf(stderr, "gmssl %s: SM2 curve is not supported, use `sm2keygen` instead\n", prog);
		goto end;
	}
	if (curve_oid == OID_undef) {
		fprintf(stderr, "gmssl %s: unsupported curve '%s'\n", prog, curve_name);
		goto end;
	}

	if (gmssl_tool_get_password(prog, "pass", outfile, &pass,
		passbuf, sizeof(passbuf), 1) != 1) {
		goto end;
	}

	if (x509_key_generate(&key, OID_ec_public_key, &curve_oid, sizeof(curve_oid)) != 1) {
		fprintf(stderr, "gmssl %s: inner failure\n", prog);
		goto end;
	}
	if (x509_private_key_info_encrypt_to_pem(&key, pass, outfp) != 1) {
		fprintf(stderr, "gmssl %s: inner failure\n", prog);
		goto end;
	}
	if (x509_public_key_info_to_pem(&key, puboutfp) != 1) {
		fprintf(stderr, "gmssl %s: inner failure\n", prog);
		goto end;
	}
	if (exportfp) {
		switch (curve_oid) {
#ifdef ENABLE_SECP256R1
		case OID_secp256r1:
			ret = secp256r1_private_key_to_pem(&key.u.secp256r1_key, exportfp);
			break;
#endif
#ifdef ENABLE_SECP384R1
		case OID_secp384r1:
			ret = secp384r1_private_key_to_pem(&key.u.secp384r1_key, exportfp);
			break;
#endif
		default:
			ret = -1;
			break;
		}
		if (ret != 1) {
			fprintf(stderr, "gmssl %s: inner failure\n", prog);
			goto end;
		}
	}

	ret = 0;

end:
	gmssl_secure_clear(&key, sizeof(key));
	gmssl_secure_clear(passbuf, sizeof(passbuf));
	if (outfile && outfp) fclose(outfp);
	if (puboutfile && puboutfp) fclose(puboutfp);
	if (exportfile && exportfp) fclose(exportfp);
	return ret;
}
