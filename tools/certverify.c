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
//#include <unistd.h>
#include <gmssl/pem.h>
#include <gmssl/x509.h>
#include <gmssl/pkcs8.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>


static int verify_cert(const X509_CERTIFICATE *cert, const X509_CERTIFICATE *cacert)
{
	int ret;
	SM2_KEY ca_pubkey;

	if (x509_name_equ(&cert->tbs_certificate.issuer, &cacert->tbs_certificate.subject) != 1) {
		error_print();
		return -1;
	}
	if (x509_certificate_get_public_key(cacert, &ca_pubkey) != 1) {
		error_print();
		return -1;
	}
	if ((ret = x509_certificate_verify(cert, &ca_pubkey)) < 0) {
		error_print();
		return -1;
	}
	return ret;
}

static int find_cacert(X509_CERTIFICATE *cacert, FILE *fp, const X509_NAME *issuer)
{
	int ret;
	for (;;) {
		if ((ret = x509_certificate_from_pem(cacert, fp)) != 1) {
			if (ret < 0) error_print();
			return ret;
		}
		if (x509_name_equ(&cacert->tbs_certificate.subject, issuer) == 1) {
			return 1;
		}
	}
	return 0;
}


void print_usage(const char *prog)
{
	printf("Usage: %s command [options] ...\n", prog);
	printf("\n");
	printf("Options:\n");
	printf("  -cert <file>        PKCS #10 certificate request file\n");
	printf("  -cacert <file>     CA certificate file\n");
}

int main(int argc, char **argv)
{
	int ret = -1;
	char *prog = argv[0];
	char *certfile = NULL;
	char *cacertfile = NULL;
	FILE *certfp = NULL;
	FILE *cacertfp = NULL;

	X509_CERTIFICATE cert1;
	X509_CERTIFICATE cert2;
	X509_CERTIFICATE *cert = &cert1;
	X509_CERTIFICATE *cacert = &cert2;
	X509_CERTIFICATE *tmpcert;

	SM2_KEY ca_pubkey;

	argc--;
	argv++;
	while (argc >= 1) {
		if (!strcmp(*argv, "-help")) {
			print_usage(prog);
			return 0;

		} else if (!strcmp(*argv, "-cert")) {
			if (--argc < 1) goto bad;
			certfile = *(++argv);
			if (!(certfp = fopen(certfile, "r"))) {
				error_print();
				return -1;
			}
		} else if (!strcmp(*argv, "-cacert")) {
			if (--argc < 1) goto bad;
			cacertfile = *(++argv);
			if (!(cacertfp = fopen(cacertfile, "r"))) {
				error_print();
				return -1;
			}
		} else {
			print_usage(prog);
			return 0;
			break;
		}

		argc--;
		argv++;
	}

	if (!certfp || !cacertfp) {
		print_usage(prog);
		return -1;
	}

	if (x509_certificate_from_pem(cert, certfp) != 1) {
		error_print();
		return -1;
	}
	for (;;) {
		if ((ret = x509_certificate_from_pem(cacert, certfp)) != 1) {
			if (ret < 0) error_print();
			break;
		}
		if (verify_cert(cert, cacert) != 1) {
			error_print();
			return -1;
		}
		tmpcert = cacert;
		cert = cacert;
		cacert = tmpcert;
	}

	if (find_cacert(cacert, cacertfp, &cert->tbs_certificate.issuer) != 1) {
		error_print();
		return -1;
	}
	if ((ret = verify_cert(cert, cacert)) < 0) {
		error_print();
		return -1;
	}
	printf("Verification %s\n", ret ? "success" : "failure");

	ret = 0;
	goto end;

bad:
	fprintf(stderr, "%s: commands should not be used together\n", prog);

end:
	return ret;
}
