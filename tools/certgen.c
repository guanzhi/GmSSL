/*
 * Copyright (c) 2021 - 2021 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/pem.h>
#include <gmssl/x509.h>
#include <gmssl/x509_ext.h>
#include <gmssl/pkcs8.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>

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


#ifndef WIN32
#include <pwd.h>
#include <unistd.h>
#endif

static const char *options =
	"[-C str] [-ST str] [-L str] [-O str] [-OU str] -CN str -days num "
	"-key file [-pass pass] "
	"[-key_usage str]*";


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
	char *file = NULL;
	FILE *outfp = stdout;
	FILE *keyfp = NULL;
	char *pass = NULL;

	SM2_KEY sm2_key;
	uint8_t serial[12];
	uint8_t name[256];
	size_t namelen;
	time_t not_before;
	time_t not_after;
	uint8_t uniq_id[32];
	uint8_t exts[512];
	size_t extslen = 0;
	uint8_t cert[1024];
	size_t certlen;

	argc--;
	argv++;

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
help:
			printf("usage: %s %s\n", prog, options);
			return 0;
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
		} else if (!strcmp(*argv, "-key_usage")) {
			if (--argc < 1) goto bad;
			if (ext_key_usage_set(&key_usage, *(++argv)) != 1) {
				error_print();
				return -1;
			}
		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			file = *(++argv);
			if (!(keyfp = fopen(file, "r"))) {
				error_print();
				return -1;
			}
		} else if (!strcmp(*argv, "-pass")) {
			if (--argc < 1) goto bad;
			pass = *(++argv);
		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) goto bad;
			file = *(++argv);
			if (!(outfp = fopen(file, "w"))) {
				error_print();
				return -1;
			}
		} else {
bad:
			fprintf(stderr, "%s: illegal option '%s'\n", prog, *argv);
			fprintf(stderr, "usage: %s %s\n", prog, options);
			return 1;
		}

		argc--;
		argv++;
	}

	if (!common_name || days <= 0) {
		fprintf(stderr, "%s: missing options\n", prog);
		fprintf(stderr, "usage: %s %s\n", prog, options);
		return 1;
	}

	if (!pass) {
		pass = getpass("Encryption Password : ");
	}
	if (!pass || strlen(pass) == 0) {
		fprintf(stderr, "%s: '-pass' option required\n", prog);
		error_print();
		return -1;
	}

	if (keyfp == NULL) {
		error_print();
		return -1;
	}
	if (sm2_private_key_info_decrypt_from_pem(&sm2_key, pass, keyfp) != 1) {
		error_print();
		goto end;
	}

	time(&not_before);
	if (rand_bytes(serial, sizeof(serial)) != 1
		|| x509_name_set(name, &namelen, sizeof(name),
			country, state, locality, org, org_unit, common_name) != 1
		|| x509_validity_add_days(&not_after, not_before, days) != 1
		|| x509_exts_add_key_usage(exts, &extslen, sizeof(exts), 1, key_usage) != 1
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
			&sm2_key, SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID)) != 1
		|| x509_cert_to_pem(cert, certlen, outfp) != 1) {
		error_print();
		return -1;
	}
	ret = 0;

end:
	memset(&sm2_key, 0, sizeof(SM2_KEY));
	return ret;
}
