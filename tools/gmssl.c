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
#include <gmssl/version.h>
#include <gmssl/error.h>


extern int rand_main(int argc, char **argv);
extern int certgen_main(int argc, char **argv);
extern int certparse_main(int argc, char **argv);
extern int certverify_main(int argc, char **argv);
extern int crlparse_main(int argc, char **argv);
extern int pbkdf2_main(int argc, char **argv);
extern int reqgen_main(int argc, char **argv);
extern int reqparse_main(int argc, char **argv);
extern int reqsign_main(int argc, char **argv);
extern int sm2decrypt_main(int argc, char **argv);
extern int sm2encrypt_main(int argc, char **argv);
extern int sm2keygen_main(int argc, char **argv);
extern int sm2sign_main(int argc, char **argv);
extern int sm2verify_main(int argc, char **argv);
extern int sm3_main(int argc, char **argv);
extern int sm3hmac_main(int argc, char **argv);
extern int sm4_main(int argc, char **argv);
extern int tlcp_client_main(int argc, char **argv);
extern int tlcp_server_main(int argc, char **argv);
extern int tls12_client_main(int argc, char **argv);
extern int tls12_server_main(int argc, char **argv);
extern int tls13_client_main(int argc, char **argv);
extern int tls13_server_main(int argc, char **argv);


static const char *options =
	"  commands:\n"
	"	help\n"
	"	version\n"
	"	rand\n"
	"	sm2keygen\n"
	"	sm2sign\n"
	"	sm2verify\n"
	"	sm2encrypt\n"
	"	sm2decrypt\n"
	"	pbkdf2\n"
	"	reqgen\n"
	"	reqsign\n"
	"	reqparse\n"
	"	crlparse\n"
	"	certgen\n"
	"	certparse\n"
	"	certverify\n"
	"	tlcp_client\n"
	"	tlcp_server\n"
	"	tls12_client\n"
	"	tls12_server\n"
	"	tls13_client\n"
	"	tls13_server\n";


int version_main(int argc, char **argv)
{
	printf("%s\n", gmssl_version_str());
	return 0;
}


int main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];


	if (argc < 2) {
		printf("usage: %s\n %s\n", prog, options);
		return 0;
	}

	argc--;
	argv++;

	while (argc > 0) {
		if (!strcmp(*argv, "help")) {
help:
			printf("usage: %s\n %s\n", prog, options);
			return 0;
		} else if (!strcmp(*argv, "version")) {
			return version_main(argc, argv);
		} else if (!strcmp(*argv, "rand")) {
			return rand_main(argc, argv);
		} else if (!strcmp(*argv, "certgen")) {
			return certgen_main(argc, argv);
		} else if (!strcmp(*argv, "certparse")) {
			return certparse_main(argc, argv);
		} else if (!strcmp(*argv, "certverify")) {
			return certverify_main(argc, argv);
		} else if (!strcmp(*argv, "reqgen")) {
			return reqgen_main(argc, argv);
		} else if (!strcmp(*argv, "reqparse")) {
			return reqparse_main(argc, argv);
		} else if (!strcmp(*argv, "reqsign")) {
			return reqsign_main(argc, argv);
		} else if (!strcmp(*argv, "pbkdf2")) {
			return pbkdf2_main(argc, argv);
		} else if (!strcmp(*argv, "sm2sign")) {
			return sm2sign_main(argc, argv);
		} else if (!strcmp(*argv, "sm2verify")) {
			return sm2verify_main(argc, argv);
		} else if (!strcmp(*argv, "sm2encrypt")) {
			return sm2encrypt_main(argc, argv);
		} else if (!strcmp(*argv, "sm2decrypt")) {
			return sm2decrypt_main(argc, argv);
		} else if (!strcmp(*argv, "sm2keygen")) {
			return sm2keygen_main(argc, argv);
		} else if (!strcmp(*argv, "tlcp_client")) {
			return tlcp_client_main(argc, argv);
		} else if (!strcmp(*argv, "tlcp_server")) {
			return tlcp_server_main(argc, argv);
		} else if (!strcmp(*argv, "tls12_client")) {
			return tls12_client_main(argc, argv);
		} else if (!strcmp(*argv, "tls12_server")) {
			return tls12_server_main(argc, argv);
		} else if (!strcmp(*argv, "tls13_client")) {
			return tls13_client_main(argc, argv);
		} else if (!strcmp(*argv, "tls13_server")) {
			return tls13_server_main(argc, argv);
		} else {
bad:
			fprintf(stderr, "%s: illegal option '%s'\n", prog, *argv);
			fprintf(stderr, "usage: %s %s\n", prog, options);
			return 1;
		}

		argc--;
		argv++;
	}

	return ret;
}
