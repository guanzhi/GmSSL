/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/hex.h>
#include <gmssl/x509.h>
#include <gmssl/x509_crl.h>
#include <gmssl/error.h>


static const char *usage =
	" -in pem [-double_certs]"
	" [-check_crl]"
	" -cacert pem"
	" [-sm2_id str | -sm2_id_hex hex]"
	"\n";

static const char *options =
"Options\n"
"\n"
"    -in pem             Input certificate chain file in PEM format\n"
"    -double_certs       The first two certificates are SM2 signing and encryption entity certificate\n"
"    -check_crl          If the entity certificate has CRLDistributionPoints extension, Download and check againt the CRL\n"
"    -cacert pem         CA certificate\n"
"    -sm2_id str         Signer's ID in SM2 signature algorithm\n"
"    -sm2_id_hex hex     Signer's ID in hex format\n"
"                        When `-sm2_id` or `-sm2_id_hex` is specified,\n"
"                          must use the same ID in other commands explicitly.\n"
"                        If neither `-sm2_id` nor `-sm2_id_hex` is specified,\n"
"                          the default string '1234567812345678' is used\n"
"\n";


int certverify_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *str;

	char *infile = NULL;
	char *cacertfile = NULL;
	FILE *infp = stdin;
	FILE *cacertfp = NULL;
	uint8_t cert[1024];
	size_t certlen;
	uint8_t cacert[1024];
	size_t cacertlen;
	char signer_id[SM2_MAX_ID_LENGTH + 1] = {0};
	size_t signer_id_len = 0;

	const uint8_t *serial;
	size_t serial_len;
	const uint8_t *issuer;
	size_t issuer_len;
	const uint8_t *subject;
	size_t subject_len;

	const uint8_t *enc_serial;
	size_t enc_serial_len;
	const uint8_t *enc_issuer;
	size_t enc_issuer_len;
	const uint8_t *enc_subject;
	size_t enc_subject_len;

	int double_certs = 0;
	uint8_t enc_cert[1024];
	size_t enc_cert_len;
	int rv;

	int check_crl = 0;
	int crl_ret;

	argc--;
	argv++;

	if (argc < 1) {
		fprintf(stderr, "usage: %s %s\n", prog, usage);
		return 1;
	}

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: %s %s\n", prog, usage);
			printf("%s\n", options);
			ret = 0;
			goto end;
		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);
			if (!(infp = fopen(infile, "rb"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, infile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-double_certs")) {
			double_certs = 1;
		} else if (!strcmp(*argv, "-check_crl")) {
			check_crl = 1;
		} else if (!strcmp(*argv, "-cacert")) {
			if (--argc < 1) goto bad;
			cacertfile = *(++argv);
			if (!(cacertfp = fopen(cacertfile, "rb"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, cacertfile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-sm2_id")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			if (strlen(str) > sizeof(signer_id) - 1) {
				fprintf(stderr, "%s: invalid `-sm2_id` length\n", prog);
				goto end;
			}
			strncpy(signer_id, str, sizeof(signer_id));
			signer_id_len = strlen(str);
		} else if (!strcmp(*argv, "-sm2_id_hex")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			if (strlen(str) > (sizeof(signer_id) - 1) * 2) {
				fprintf(stderr, "%s: invalid `-sm2_id_hex` length\n", prog);
				goto end;
			}
			if (hex_to_bytes(str, strlen(str), (uint8_t *)signer_id, &signer_id_len) != 1) {
				fprintf(stderr, "%s: invalid `-sm2_id_hex` value\n", prog);
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
	if (!signer_id_len) {
		strcpy(signer_id, SM2_DEFAULT_ID);
		signer_id_len = strlen(SM2_DEFAULT_ID);
	}

	// read first to be verified certificate
	if (x509_cert_from_pem(cert, &certlen, sizeof(cert), infp) != 1
		|| x509_cert_get_issuer_and_serial_number(cert, certlen,
			&issuer, &issuer_len, &serial, &serial_len) != 1
		|| x509_cert_get_subject(cert, certlen, &subject, &subject_len) != 1) {
		fprintf(stderr, "%s: read certificate failure\n", prog);
		goto end;
	}
	format_print(stdout, 0, 0, "Certificate\n");
	format_bytes(stdout, 0, 4, "serialNumber", serial, serial_len);
	x509_name_print(stdout, 0, 4, "subject", subject, subject_len);

	// read encryption cert in double certs
	if (double_certs) {
		if (x509_cert_from_pem(enc_cert, &enc_cert_len, sizeof(enc_cert), infp) != 1
			|| x509_cert_get_issuer_and_serial_number(enc_cert, enc_cert_len,
				&enc_issuer, &enc_issuer_len, &enc_serial, &enc_serial_len) != 1
			|| x509_cert_get_subject(enc_cert, enc_cert_len, &enc_subject, &enc_subject_len) != 1) {
			fprintf(stderr, "%s: read encryption certficate failure\n", prog);
			goto end;
		}
		if (x509_name_equ(enc_subject, enc_subject_len, subject, subject_len) != 1
			|| x509_name_equ(enc_issuer, enc_issuer_len, issuer, issuer_len) != 1) {
			fprintf(stderr, "%s: double certificates not compatible\n", prog);
			goto end;
		}
	}

	for (;;) {
		if ((rv = x509_cert_from_pem(cacert, &cacertlen, sizeof(cacert), infp)) != 1) {
			if (rv < 0) goto end;
			goto final;
		}

		if ((rv = x509_cert_verify_by_ca_cert(cert, certlen, cacert, cacertlen,
			signer_id, signer_id_len)) != 1) {
			fprintf(stderr, "%s: Verification failure\n", prog);
			goto end;
		}
		format_print(stdout, 0, 4, "Verification success\n");

		if (check_crl) {
			if ((crl_ret = x509_cert_check_crl(cert, certlen, cacert, cacertlen,
				signer_id, signer_id_len)) < 0) {
				fprintf(stderr, "%s: Certificate has been revoked\n", prog);
				goto end;
			}
			format_print(stdout, 0, 4, "Revocation status: %s\n",
				crl_ret ? "Not revoked by CRL" : "No CRL URI found in certificate");
		}

		if (double_certs) {
			if ((rv = x509_cert_verify_by_ca_cert(enc_cert, enc_cert_len, cacert, cacertlen,
				signer_id, signer_id_len)) < 0) {
				fprintf(stderr, "%s: Verification failure\n", prog);
				goto end;
			}
			format_print(stdout, 0, 0, "Certificate\n");
			format_bytes(stdout, 0, 4, "serialNumber", enc_serial, enc_serial_len);
			x509_name_print(stdout, 0, 4, "subject", enc_subject, enc_subject_len);
			format_print(stdout, 0, 4, "Verification success\n");
			if (check_crl) {
				if ((crl_ret = x509_cert_check_crl(enc_cert, enc_cert_len, cacert, cacertlen,
					signer_id, signer_id_len)) < 0) {
					fprintf(stderr, "%s: Certificate has been revoked\n", prog);
					goto end;
				}
				format_print(stdout, 0, 4, "Revocation status: %s\n",
					crl_ret ? "Not revoked by CRL" : "No CRL URI found in certificate");
			}
			double_certs = 0;

		}

		// NOTE: make sure the buffer (issuer, issuer_len) not crashed
		memcpy(cert, cacert, cacertlen);
		certlen = cacertlen;
		if (x509_cert_get_issuer_and_serial_number(cert, certlen,
				&issuer, &issuer_len, &serial, &serial_len) != 1
			|| x509_cert_get_subject(cert, certlen, &subject, &subject_len) != 1) {
			error_print();
			goto end;
		}
		format_print(stdout, 0, 0, "Signed by Certificate\n");
		format_bytes(stdout, 0, 4, "serialNumber", serial, serial_len);
		x509_name_print(stdout, 0, 4, "Certificate", subject, subject_len);

		check_crl = 0; // only check the entity CRL

	}

final:
	if (x509_cert_from_pem_by_subject(cacert, &cacertlen, sizeof(cacert), issuer, issuer_len, cacertfp) != 1) {
		fprintf(stderr, "%s: load CA certificate failure\n", prog);
		goto end;
	}
	if ((rv = x509_cert_verify_by_ca_cert(cert, certlen, cacert, cacertlen,
		signer_id, signer_id_len)) < 0) {
		fprintf(stderr, "%s: inner error\n", prog);
		goto end;
	}
	format_print(stdout, 0, 4, "Verification success\n");

	if (check_crl) {
		if ((crl_ret = x509_cert_check_crl(cert, certlen, cacert, cacertlen,
			signer_id, signer_id_len)) < 0) {
			fprintf(stderr, "%s: certificate has been revoked\n", prog);
			goto end;
		}
		format_print(stdout, 0, 4, "Revocation status: %s\n",
			crl_ret ? "Not revoked by CRL" : "No CRL URI found in certificate");
	}

	if (double_certs) {
		if ((rv = x509_cert_verify_by_ca_cert(enc_cert, enc_cert_len, cacert, cacertlen,
			signer_id, signer_id_len)) < 0) {
			fprintf(stderr, "%s: inner error\n", prog);
			goto end;
		}
		format_print(stdout, 0, 0, "Certificate\n");
		format_bytes(stdout, 0, 4, "serialNumber", enc_serial, enc_serial_len);
		x509_name_print(stdout, 0, 4, "subject", enc_subject, enc_subject_len);
		format_print(stdout, 0, 4, "Verification success\n");

		if (check_crl) {
			if ((crl_ret = x509_cert_check_crl(enc_cert, enc_cert_len, cacert, cacertlen,
				signer_id, signer_id_len)) < 0) {
				fprintf(stderr, "%s: certificate has been revoked\n", prog);
				goto end;
			}
			format_print(stdout, 0, 4, "Revocation status: %s\n",
				crl_ret ? "Not revoked by CRL" : "No CRL URI found in certificate");
		}
	}

	if (x509_cert_get_issuer_and_serial_number(cacert, cacertlen, NULL, NULL, &serial, &serial_len) != 1
		|| x509_cert_get_subject(cacert, cacertlen, &subject, &subject_len) != 1) {
		fprintf(stderr, "%s: parse certificate error\n", prog);
		goto end;
	}
	format_print(stdout, 0, 0, "Signed by Certificate\n");
	format_bytes(stdout, 0, 4, "serialNumber", serial, serial_len);
	x509_name_print(stdout, 0, 4, "subject", subject, subject_len);

	printf("\n");

	ret = 0;
end:
	if (infile && infp) fclose(infp);
	if (cacertfp) fclose(cacertfp);
	return ret;
}
