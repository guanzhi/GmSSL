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
#include <gmssl/pem.h>
#include <gmssl/x509.h>
#include <gmssl/x509_crl.h>

// 20220105Z

static const char *options = "-in cert.pem [-reason str] [-invalid_date timestamp] [-out RevokedCertificate.der]";

static void print_options(FILE *fp, const char *prog)
{
	int i;
	fprintf(fp, "Options:\n");
	fprintf(fp, "  -in cert.pem          Certificate in PEM format to be revoked\n");
	fprintf(fp, "  -reason code          Revocation reason code, avaiable codes:\n");
	for (i = 0; i <= X509_cr_aa_compromise; i++) {
		fprintf(fp, "                            %s (%d)\n", x509_crl_reason_name(i), i);
	}
	fprintf(fp, "  -invalid_date time    Revocation timestamp in YYYYMMDDHHMMSSZ format\n");
	fprintf(fp, "                        Example: -invalid_date 20221231000000Z\n");
	fprintf(fp, "  -out file.der         Output ASN.1 RevokedCertificate in DER format\n");

	fprintf(fp, "Examples:\n");
	fprintf(fp, "  %s -in cert1.pem -reason keyCompromise -invalid_date 20221230000000Z -out revoked_certs.der\n", prog);
	fprintf(fp, "  %s -in cert2.pem -reason keyCompromise -invalid_date 20221231000000Z >> revoked_certs.der\n", prog);
}

int certrevoke_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *infile = NULL;
	char *outfile = NULL;
	int reason = -1;
	time_t invalid_date = -1;
	uint8_t *cert = NULL;
	size_t certlen;
	uint8_t *outbuf = NULL;
	uint8_t *out;
	size_t outlen;
	FILE *outfp = stdout;

	argc--;
	argv++;

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: %s %s\n", prog, options);
			print_options(stdout, prog);
			goto end;
		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);
			if (x509_cert_new_from_file(&cert, &certlen, infile) != 1) {
				fprintf(stderr, "%s: open cert file %s failure\n", prog, infile);
				goto end;
			}
		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) goto bad;
			outfile = *(++argv);
			if (!(outfp = fopen(outfile, "wb"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, outfile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-reason")) {
			char *name;
			int i;
			if (--argc < 1) goto bad;
			name = *(++argv);
			if (x509_crl_reason_from_name(&reason, name) != 1) {
				fprintf(stderr, "%s: invalid reason '%s'\n", prog, name);
				fprintf(stderr, "-reason values:\n");
				for (i = 0; i <= X509_cr_aa_compromise; i++) {
					fprintf(stderr, "  %s\n", x509_crl_reason_name(i));
				}
			}
		} else if (!strcmp(*argv, "-invalid_date")) {
			char *time_str;
			if (--argc < 1) goto bad;
			time_str =*(++argv);
			if (asn1_time_from_str(0, &invalid_date, time_str) != 1) {
				fprintf(stderr, "%s: invalid time '%s', should provide 'YYYYMMDDHHMMSSZ'\n", prog, time_str);
				goto bad;
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
		fprintf(stderr, "usage: %s %s\n", prog, options);
		goto end;
	}
	if (x509_cert_revoke_to_der(cert, certlen, time(NULL), reason, invalid_date, NULL, 0, NULL, &outlen) != 1) {
		fprintf(stderr, "%s: inner error\n", prog);
		goto end;
	}
	if (!(outbuf = malloc(outlen))) {
		fprintf(stderr, "%s: malloc failure\n", prog);
		goto end;
	}
	out = outbuf;
	outlen = 0;
	if (x509_cert_revoke_to_der(cert, certlen, time(NULL), reason, invalid_date, NULL, 0, &out, &outlen) != 1) {
		fprintf(stderr, "%s: inner error\n", prog);
		goto end;
	}
	if (fwrite(outbuf, 1, outlen, outfp) != outlen) {
		fprintf(stderr, "%s: output failure\n", prog);
		goto end;
	}
	ret = 0;

end:
	if (cert) free(cert);
	if (outfile && outfp) fclose(outfp);
	if (outbuf) free(outbuf);
	return ret;
}
