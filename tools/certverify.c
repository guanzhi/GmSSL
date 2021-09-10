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

// 验证证书链是一个重量级的功能，应准备相应的文档，列举所有验证项目
// 比如最基本的是证书中的签名、有效期、各个扩展等
// 外部相关的：证书链、CRL等


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
