/* 
 *   Copyright 2014-2021 The GmSSL Project Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <gmssl/pem.h>
#include <gmssl/x509.h>
#include <gmssl/pkcs8.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>



void print_usage(const char *prog)
{
	printf("Usage: %s command [options] ...\n", prog);
	printf("\n");
	printf("Options:\n");
	printf("  -req <file>        PKCS #10 certificate request file\n");
	printf("  -cacert <file>     CA certificate file\n");
	printf("  -keyfile <file>    private key of cacert\n");
}

int main(int argc, char **argv)
{
	int ret = -1;
	char *prog = argv[0];
	char *keyfile = NULL;

	FILE *keyfp = NULL;

	X509_CERTIFICATE cert;

	char *pass;

	uint8_t serial[12];
	X509_NAME name;
	time_t not_before;
	SM2_KEY sm2_key; // 这个应该是从文件中读取的！
	uint8_t uniq_id[32];

	uint8_t buf[1024];
	const uint8_t *cp = buf;
	uint8_t *p = buf;
	size_t len = 0;

	if (argc < 2) {
		print_usage(prog);
		return 0;
	}

	argc--;
	argv++;
	while (argc >= 1) {
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

		} else if (!strcmp(*argv, "-keyfile")) {
			if (--argc < 1) goto bad;
			keyfile = *(++argv);

		} else if (!strcmp(*argv, "-days")) {
			if (--argc < 1) goto bad;
			days = atoi(*(++argv));

		} else {
			print_usage(prog);
			return 0;
			break;
		}

		argc--;
		argv++;
	}

	if (days <= 0 && !keyfile) {
		goto bad;
	}

	if (!(keyfp = fopen(keyfile, "r"))) {
		goto bad;
	}

	pass = getpass("Password : ");
	if (sm2_enced_private_key_info_from_pem(&sm2_key, pass, keyfp) != 1) {
		error_print();
		goto end;
	}


	rand_bytes(serial, sizeof(serial));



	memset(&name, 0, sizeof(name));



	if (country) {
		if (x509_name_set_country(&name, country) != 1) {
			error_print();
			goto end;
		}
	}
	if (state) {
		if (x509_name_set_state_or_province(&name, state) != 1) {
			error_print();
			goto end;
		}
	}
	if (org) {
		if (x509_name_set_organization(&name, org) != 1) {
			error_print();
			goto end;
		}
	}
	if (org_unit) {
		if (x509_name_set_organizational_unit(&name, org_unit) != 1) {
			error_print();
			goto end;
		}
	}
	if (!common_name) {
		error_print();
		goto end;
	} else {
		if (x509_name_set_common_name(&name, common_name) != 1) {
			error_print();
			goto end;
		}
	}

	time(&not_before);


	memset(&cert, 0, sizeof(cert));
	x509_certificate_set_version(&cert, X509_version_v3);
	x509_certificate_set_serial_number(&cert, serial, sizeof(serial));
	x509_certificate_set_signature_algor(&cert, OID_sm2sign_with_sm3);
	x509_certificate_set_issuer(&cert, &name);
	x509_certificate_set_subject(&cert, &name);
	x509_certificate_set_validity(&cert, not_before, days);
	x509_certificate_set_subject_public_key_info_sm2(&cert, &sm2_key);
	x509_certificate_set_issuer_unique_id(&cert, uniq_id, sizeof(uniq_id));
	x509_certificate_set_subject_unique_id(&cert, uniq_id, sizeof(uniq_id));
	x509_certificate_sign_sm2(&cert, &sm2_key);

	x509_certificate_to_pem(&cert, stdout);
	ret = 0;
	goto end;

bad:
	fprintf(stderr, "%s: commands should not be used together\n", prog);

end:
	return ret;
}
