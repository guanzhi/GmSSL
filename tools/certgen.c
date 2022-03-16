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
#include <gmssl/pkcs8.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>


#ifndef WIN32
#include <pwd.h>
#include <unistd.h>
#endif


/*
from RFC 2253

String  X.500 AttributeType
------------------------------
CN      commonName
L       localityName
ST      stateOrProvinceName
O       organizationName
OU      organizationalUnitName
C       countryName
STREET  streetAddress
DC      domainComponent
UID     userid
*/

void print_usage(const char *prog)
{
	printf("Usage: %s command [options] ...\n", prog);
	printf("\n");
	printf("Options:\n");
	printf("  -C <str>           country name\n");
	printf("  -ST <str>          state of province name\n");
	printf("  -L <str>           locality name\n");
	printf("  -O <str>           orgnization name\n");
	printf("  -OU <str>          orgnizational unit name\n");
	printf("  -CN <str>          common name\n");
	printf("  -days <num>        validity days\n");
	printf("  -key <file>        private key file\n");
	printf("  -pass pass         password\n");
}

int main(int argc, char **argv)
{
	char *prog = argv[0];

	char *country = NULL;
	char *state = NULL;
	char *locality = NULL;
	char *org = NULL;
	char *org_unit = NULL;
	char *common_name = NULL;
	int days = 0;
	char *keyfile = NULL;
	FILE *keyfp = NULL;
	char *pass = NULL;
	char *outfile = NULL;
	FILE *outfp = stdout;

	SM2_KEY sm2_key;
	uint8_t serial[12];
	uint8_t name[256];
	size_t namelen;
	time_t not_before;
	time_t not_after;
	uint8_t uniq_id[32];
	uint8_t cert[1024];
	size_t certlen;

	argc--;
	argv++;

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			print_usage(prog);
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

		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			keyfile = *(++argv);

		} else if (!strcmp(*argv, "-days")) {
			if (--argc < 1) goto bad;
			days = atoi(*(++argv));

		} else if (!strcmp(*argv, "-pass")) {
			if (--argc < 1) goto bad;
			pass = *(++argv);

		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) goto bad;
			outfile = *(++argv);


		} else {
			fprintf(stderr, "%s: illegal option '%s'\n", prog, *argv);
			print_usage(prog);
			return 0;
		}

		argc--;
		argv++;
	}

	if (days <= 0 || !keyfile) {
		error_print();
		goto bad;
	}

	if (!(keyfp = fopen(keyfile, "r"))) {
		error_print();
		goto bad;
	}

	if (!pass) {
#ifndef WIN32
		pass = getpass("Encryption Password : ");
#else
		fprintf(stderr, "%s: '-pass' option required\n", prog);
#endif
	}

	if (outfile) {
		if (!(outfp = fopen(outfile, "wb"))) {
			error_print();
			return -1;
		}
	}

	time(&not_before);
	if (sm2_private_key_info_decrypt_from_pem(&sm2_key, pass, keyfp) != 1
		|| rand_bytes(serial, sizeof(serial)) != 1
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
			NULL, 0,
			&sm2_key, SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID)) != 1
		|| x509_cert_to_pem(cert, certlen, outfp) != 1) {
		error_print();
		return -1;
	}
	return 0;

bad:
	fprintf(stderr, "%s: commands should not be used together\n", prog);

end:
	return -1;
}
