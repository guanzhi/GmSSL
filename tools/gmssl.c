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


extern int version_main(int argc, char **argv);
extern int rand_main(int argc, char **argv);
extern int certgen_main(int argc, char **argv);
extern int certparse_main(int argc, char **argv);
extern int certverify_main(int argc, char **argv);
extern int crlparse_main(int argc, char **argv);
extern int pbkdf2_main(int argc, char **argv);
extern int reqgen_main(int argc, char **argv);
extern int reqparse_main(int argc, char **argv);
extern int reqsign_main(int argc, char **argv);
extern int sm2keygen_main(int argc, char **argv);
extern int sm2sign_main(int argc, char **argv);
extern int sm2verify_main(int argc, char **argv);
extern int sm2encrypt_main(int argc, char **argv);
extern int sm2decrypt_main(int argc, char **argv);
extern int sm3_main(int argc, char **argv);
extern int sm3hmac_main(int argc, char **argv);
extern int sm4_main(int argc, char **argv);
extern int zuc_main(int argc, char **argv);
extern int sm9setup_main(int argc, char **argv);
extern int sm9keygen_main(int argc, char **argv);
extern int sm9sign_main(int argc, char **argv);
extern int sm9verify_main(int argc, char **argv);
extern int sm9encrypt_main(int argc, char **argv);
extern int sm9decrypt_main(int argc, char **argv);
extern int tlcp_client_main(int argc, char **argv);
extern int tlcp_server_main(int argc, char **argv);
extern int tls12_client_main(int argc, char **argv);
extern int tls12_server_main(int argc, char **argv);
extern int tls13_client_main(int argc, char **argv);
extern int tls13_server_main(int argc, char **argv);
extern int sdfutil_main(int argc, char **argv);


static const char *options =
	"command [options]\n"
	"\n"
	"Commands:\n"
	"  help            Print commands list or help for one command\n"
	"  version         Print version\n"
	"  rand            Generate random bytes\n"
	"  sm2keygen       Generate SM2 keypair\n"
	"  sm2sign         Generate SM2 signature\n"
	"  sm2verify       Verify SM2 signature\n"
	"  sm2encrypt      SM2 public key encryption\n"
	"  sm2decrypt      SM2 decryption\n"
	"  sm3             Generate SM3 hash\n"
	"  sm3hmac         Generate HMAC-SM3 MAC tag\n"
	"  sm4             Encrypt or decrypt data with SM4\n"
	"  zuc             Encrypt or decrypt data with ZUC\n"
	"  sm9setup        Generate SM9 master secret\n"
	"  sm9keygen       Generate SM9 private key\n"
	"  sm9sign         Generate SM9 signature\n"
	"  sm9verify       Verify SM9 signature\n"
	"  sm9encrypt      SM9 public key encryption\n"
	"  sm9decrypt      SM9 decryption\n"
	"  pbkdf2          Generate key from password\n"
	"  reqgen          Generate PKCS #10 certificate signing request (CSR)\n"
	"  reqsign         Generate a certificate from PKCS #10 CSR\n"
	"  reqparse        Parse and print a PKCS #10 CSR\n"
	"  crlparse        Parse and print CRL\n"
	"  certgen         Generate a self-signed X.509 certificate in PEM format\n"
	"  certparse       Parse and print certificates in a PEM file\n"
	"  certverify      Verify certificate chain in a PEM file\n"
	"  tlcp_client     TLCP client\n"
	"  tlcp_server     TLCP server\n"
	"  tls12_client    TLS 1.2 client\n"
	"  tls12_server    TLS 1.2 server\n"
	"  tls13_client    TLS 1.3 client\n"
	"  tls13_server    TLS 1.3 server\n"
	"  sdfutil         SDF crypto device utility\n";



int main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];

	argc--;
	argv++;

	if (argc < 1) {
		printf("Usage: %s %s\n", prog, options);
		return 1;
	}

	while (argc > 0) {
		if (!strcmp(*argv, "help")) {
			printf("usage: %s %s\n", prog, options);
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
		} else if (!strcmp(*argv, "sm2keygen")) {
			return sm2keygen_main(argc, argv);
		} else if (!strcmp(*argv, "sm2sign")) {
			return sm2sign_main(argc, argv);
		} else if (!strcmp(*argv, "sm2verify")) {
			return sm2verify_main(argc, argv);
		} else if (!strcmp(*argv, "sm2encrypt")) {
			return sm2encrypt_main(argc, argv);
		} else if (!strcmp(*argv, "sm2decrypt")) {
			return sm2decrypt_main(argc, argv);
		} else if (!strcmp(*argv, "sm3")) {
			return sm3_main(argc, argv);
		} else if (!strcmp(*argv, "sm3hmac")) {
			return sm3hmac_main(argc, argv);
		} else if (!strcmp(*argv, "sm4")) {
			return sm4_main(argc, argv);
		} else if (!strcmp(*argv, "zuc")) {
			return zuc_main(argc, argv);
		} else if (!strcmp(*argv, "sm9setup")) {
			return sm9setup_main(argc, argv);
		} else if (!strcmp(*argv, "sm9keygen")) {
			return sm9keygen_main(argc, argv);
		} else if (!strcmp(*argv, "sm9sign")) {
			return sm9sign_main(argc, argv);
		} else if (!strcmp(*argv, "sm9verify")) {
			return sm9verify_main(argc, argv);
		} else if (!strcmp(*argv, "sm9encrypt")) {
			return sm9encrypt_main(argc, argv);
		} else if (!strcmp(*argv, "sm9decrypt")) {
			return sm9decrypt_main(argc, argv);
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
		} else if (!strcmp(*argv, "sdfutil")) {
			return sdfutil_main(argc, argv);
		} else {
			fprintf(stderr, "%s: illegal option '%s'\n", prog, *argv);
			fprintf(stderr, "usage: %s %s\n", prog, options);
			return 1;
		}

		argc--;
		argv++;
	}

	return ret;
}
