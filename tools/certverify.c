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
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/x509.h>


static const char *options = "-in pem [-double_certs] -cacert pem\n";

int certverify_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *infile = NULL;
	char *cacertfile = NULL;
	FILE *infp = stdin;
	FILE *cacertfp = NULL;
	uint8_t cert[1024];
	size_t certlen;
	uint8_t cacert[1024];
	size_t cacertlen;
	const uint8_t *subject;
	size_t subject_len;
	const uint8_t *subj;
	size_t subj_len;

	int double_certs = 0;
	uint8_t enc_cert[1024];
	size_t enc_cert_len;
	int rv;

	argc--;
	argv++;

	if (argc < 1) {
		fprintf(stderr, "usage: %s %s\n", prog, options);
		return 1;
	}

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: %s %s\n", prog, options);
			ret = 0;
			goto end;
		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);
			if (!(infp = fopen(infile, "r"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, infile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-double_certs")) {
			double_certs = 1;
		} else if (!strcmp(*argv, "-cacert")) {
			if (--argc < 1) goto bad;
			cacertfile = *(++argv);
			if (!(cacertfp = fopen(cacertfile, "r"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, cacertfile, strerror(errno));
				goto end;
			}
		} else {
			fprintf(stderr, "%s: illegal option '%s'\n", prog, *argv);
			goto end;
bad:
			fprintf(stderr, "%s: '%s' option value missing\n", prog, *argv);
			goto end;
		}

		argc--;
		argv++;
	}


	if (!infile) {
		fprintf(stderr, "%s: '-in' option required\n", prog);
		goto end;
	}
	if (!cacertfile) {
		fprintf(stderr, "%s: '-cacert' option required\n", prog);
		goto end;
	}

	if (x509_cert_from_pem(cert, &certlen, sizeof(cert), infp) != 1
		|| x509_cert_get_subject(cert, certlen, &subject, &subject_len) != 1) {
		fprintf(stderr, "%s: read certificate failure\n", prog);
		goto end;
	}
	x509_name_print(stdout, 0, 0, "Certificate", subject, subject_len);

	if (double_certs) {

		if (x509_cert_from_pem(enc_cert, &enc_cert_len, sizeof(enc_cert), infp) != 1
			|| x509_cert_get_subject(enc_cert, enc_cert_len, &subj, &subj_len) != 1) {
			fprintf(stderr, "%s: read encryption certficate failure\n", prog);
			goto end;
		}

		if (subj_len != subject_len
			|| memcmp(subject, subj, subj_len) != 0) {
			fprintf(stderr, "%s: double certificates not compatible\n", prog);
			goto end;
		}
	}

	for (;;) {
		if ((rv = x509_cert_from_pem(cacert, &cacertlen, sizeof(cacert), infp)) != 1) {
			if (rv < 0) goto end;
			goto final;
		}
		if (x509_cert_get_subject(cacert, cacertlen, &subject, &subject_len) != 1) {
			goto end;
		}

		if ((rv = x509_cert_verify_by_ca_cert(cert, certlen, cacert, cacertlen, SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID))) < 0) {
			fprintf(stderr, "%s: inner error\n", prog);
			goto end;
		}
		printf("Verification %s\n", rv ? "success" : "failure");

		if (double_certs) {
			x509_name_print(stdout, 0, 0, "Certificate", subj, subj_len);

			if ((rv = x509_cert_verify_by_ca_cert(enc_cert, enc_cert_len, cacert, cacertlen, SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID))) < 0) {
				fprintf(stderr, "%s: inner error\n", prog);
				goto end;
			}
			printf("Verification %s\n", rv ? "success" : "failure");
			double_certs = 0;
		}
		x509_name_print(stdout, 0, 0, "Signed by", subject, subject_len);

		memcpy(cert, cacert, cacertlen);
		certlen = cacertlen;
	}

final:
	if (x509_cert_get_issuer(cert, certlen, &subject, &subject_len) != 1) {
		fprintf(stderr, "%s: parse certificate error\n", prog);
		goto end;
	}
	if (x509_cert_from_pem_by_subject(cacert, &cacertlen, sizeof(cacert), subject, subject_len, cacertfp) != 1) {
		fprintf(stderr, "%s: load CA certificate failure\n", prog);
		goto end;
	}
	if ((rv = x509_cert_verify_by_ca_cert(cert, certlen, cacert, cacertlen, SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID))) < 0) {
		fprintf(stderr, "%s: inner error\n", prog);
		goto end;
	}
	printf("Verification %s\n", rv ? "success" : "failure");
	x509_name_print(stdout, 0, 0, "Signed by", subject, subject_len);

	if (double_certs) {
		if ((rv = x509_cert_verify_by_ca_cert(enc_cert, enc_cert_len, cacert, cacertlen, SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID))) < 0) {
			fprintf(stderr, "%s: inner error\n", prog);
			goto end;
		}
		printf("Verification %s\n", rv ? "success" : "failure");
	}

	ret = 0;
end:
	if (infile && infp) fclose(infp);
	if (cacertfp) fclose(cacertfp);
	return ret;
}
