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



void print_usage(const char *prog)
{
	printf("usage: %s command [options] ...\n", prog);
	printf("\n");
	printf("Options:\n");
	printf("  -C  <str>          country name\n");
	printf("  -O  <str>          orgnization name\n");
	printf("  -OU <str>          orgnizational unit name\n");
	printf("  -CN <str>          common name\n");
	printf("  -L  <str>          locality name\n");
	printf("  -ST <str>          state of province name\n");
	printf("\n");
	printf("  -days <num>        validity days\n");
	printf("  -keyfile <file>    private key file\n");
	printf("  -pass password     password\n");
	printf("  -out file          output req file\n");
}

int main(int argc, char **argv)
{
	int ret = -1;
	char *prog = argv[0];
	char *country = NULL;
	char *state = NULL;
	char *org = NULL;
	char *org_unit = NULL;
	char *common_name = NULL;
	char *keyfile = NULL;
	char *pass = NULL;
	char *outfile = NULL;
	int days = 0;

	FILE *keyfp = NULL;
	FILE *outfp = stdout;

	X509_CERT_REQUEST req;

	X509_NAME name;
	SM2_KEY sm2_key; // 这个应该是从文件中读取的！


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

		} else if (!strcmp(*argv, "-pass")) {
			if (--argc < 1) goto bad;
			pass = *(++argv);

		} else if (!strcmp(*argv, "-days")) {
			if (--argc < 1) goto bad;
			days = atoi(*(++argv));

		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) goto bad;
			outfile = *(++argv);

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


	if (outfile) {
		if (!(outfp = fopen(outfile, "w"))) {
			error_print();
			return -1;
		}
	}

	if (!pass) {
#ifndef WIN32
		pass = getpass("Encryption Password : ");
#else
		fprintf(stderr, "%s: '-pass' option required\n", prog);
#endif
	}

	if (sm2_enced_private_key_info_from_pem(&sm2_key, pass, keyfp) != 1) {
		error_print();
		goto end;
	}



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


	memset(&req, 0, sizeof(req));
	x509_cert_request_set(&req, &name, &sm2_key);
	x509_cert_request_sign(&req, &sm2_key);

	x509_cert_request_to_pem(&req, outfp);

	ret = 0;
	goto end;

bad:
	fprintf(stderr, "%s: commands should not be used together\n", prog);

end:
	return ret;
}
