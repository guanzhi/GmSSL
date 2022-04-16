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

int certverify_main(int argc, char **argv)
{
	int ret = 0;
	char *prog = argv[0];
	char *certfile = NULL;
	FILE *certfp = NULL;

	char *cacertfile = NULL;
	FILE *cacertfp = NULL;

	uint8_t cert[1024];
	size_t certlen;
	uint8_t cacert[1024];
	size_t cacertlen;
	char *signer_id = SM2_DEFAULT_ID;

	SM2_KEY ca_pubkey;

	argc--;
	argv++;
	while (argc >= 1) {
		if (!strcmp(*argv, "-help")) {
			printf("Usage: %s [-cert pem] -cacert pem\n", prog);
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
			printf("Usage: %s [-cert pem] -cacert pem\n", prog);
			return 0;
			break;
		}

		argc--;
		argv++;
	}

	if (!certfp || !cacertfp) {
		error_print();
		return -1;
	}


	if (x509_cert_from_pem(cert, &certlen, sizeof(cert), certfp) != 1) {
		error_print();
		return -1;
	}
	if (x509_cert_from_pem(cacert, &cacertlen, sizeof(cacert), cacertfp) != 1) {
		error_print();
		return -1;
	}
	if (x509_cert_verify_by_ca_cert(cert, certlen, cacert, cacertlen, signer_id, strlen(signer_id)) != 1) {
		error_print();
		return -1;
	}
	ret = 1;
	printf("Verification %s\n", ret ? "success" : "failure");

	ret = 0;
	goto end;

bad:
	fprintf(stderr, "%s: commands should not be used together\n", prog);

end:
	return ret;
}
