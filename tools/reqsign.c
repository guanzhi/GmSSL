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
#include <unistd.h>
#include <gmssl/pem.h>
#include <gmssl/x509.h>
#include <gmssl/x509_ext.h>
#include <gmssl/x509_req.h>
#include <gmssl/pkcs8.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>

static int ext_key_usage_set(int *usages, const char *usage_name)
{
	int flag = 0;
	if (x509_key_usage_from_name(&flag, usage_name) != 1) {
		error_print();
		return -1;
	}
	*usages |= flag;

	printf("flag = %08x", flag);
	printf("usage = %08x", *usages);
	return 1;
}


static const char *usage = "usage: %s [-in file] -days num -cacert file -key file [-pass str] [-out file]\n";

int reqsign_main(int argc, char **argv)
{
	char *prog = argv[0];
	char *file;
	char *pass = NULL;
	int days = 0;

	FILE *infp = stdin;


	uint8_t req[512];
	size_t reqlen;
	const uint8_t *subject;
	size_t subject_len;
	SM2_KEY subject_public_key;

	FILE *outfp = stdout;

	FILE *cacertfp = NULL;
	uint8_t cacert[1024];
	size_t cacertlen;
	const uint8_t *issuer;
	size_t issuer_len;
	SM2_KEY issuer_public_key;

	FILE *keyfp = NULL;
	SM2_KEY sm2_key;

	uint8_t cert[1024];
	size_t certlen;
	uint8_t serial[12];
	time_t not_before, not_after;
	uint8_t exts[512];
	size_t extslen = 0;
	int key_usage = 0;


	if (argc < 2) {
		fprintf(stderr, usage, prog);
		return 1;
	}

	argc--;
	argv++;
	while (argc >= 1) {
		if (!strcmp(*argv, "-help")) {
help:
			printf(usage, prog);
			return 0;
		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			file = *(++argv);
			if (!(infp = fopen(file, "r"))) {
				error_print();
				return -1;
			}
		} else if (!strcmp(*argv, "-days")) {
			if (--argc < 1) goto bad;
			days = atoi(*(++argv));
		} else if (!strcmp(*argv, "-key_usage")) {
			if (--argc < 1) goto bad;
			if (ext_key_usage_set(&key_usage, *(++argv)) != 1) {
				error_print();
				return -1;
			}
		} else if (!strcmp(*argv, "-cacert")) {
			if (--argc < 1) goto bad;
			file = *(++argv);
			if (!(cacertfp = fopen(file, "r"))) {
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
			error_print();
			break;
		}

		argc--;
		argv++;
	}
	if (days <= 0
		|| !infp
		|| !cacertfp
		|| !keyfp) {
		error_print();
		return -1;
	}

	if (x509_req_from_pem(req, &reqlen, sizeof(req), infp) != 1
		|| x509_req_get_details(req, reqlen,
			NULL, &subject, &subject_len, &subject_public_key,
			NULL, NULL, NULL, NULL, NULL) != 1) {
		error_print();
		return -1;
	}

	if (x509_cert_from_pem(cacert, &cacertlen, sizeof(cacert), cacertfp) != 1
		|| x509_cert_get_subject(cacert, cacertlen, &issuer, &issuer_len) != 1
		|| x509_cert_get_subject_public_key(cacert, cacertlen, &issuer_public_key) != 1) {
 		error_print();
		return -1;
	}

	if (!pass) {
		pass = getpass("Password : ");
	}
	if (!pass || strlen(pass) == 0) {
		error_print();
		return -1;
	}
	if (sm2_private_key_info_decrypt_from_pem(&sm2_key, pass, keyfp) != 1
		|| sm2_public_key_equ(&sm2_key, &issuer_public_key) != 1) {
		error_print();
		memset(&sm2_key, 0, sizeof(SM2_KEY));
		return -1;
	}

	rand_bytes(serial, sizeof(serial));
	time(&not_before);

	if (x509_validity_add_days(&not_after, not_before, days) != 1
		|| x509_exts_add_key_usage(exts, &extslen, sizeof(exts), 1, key_usage) != 1
		|| x509_cert_sign(
			cert, &certlen, sizeof(cert),
			X509_version_v3,
			serial, sizeof(serial),
			OID_sm2sign_with_sm3,
			subject, subject_len,
			not_before, not_after,
			issuer, issuer_len,
			&subject_public_key,
			NULL, 0,
			NULL, 0,
			exts, extslen,
			&sm2_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1
		|| x509_cert_to_pem(cert, certlen, outfp) != 1) {
		memset(&sm2_key, 0, sizeof(SM2_KEY));
		error_print();
		return -1;
	}

	// FIXME: fclose() ....
	memset(&sm2_key, 0, sizeof(SM2_KEY));
	return 0;
}
