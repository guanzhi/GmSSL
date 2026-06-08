/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
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
#include <gmssl/asn1.h>
#include <gmssl/digest.h>
#include <gmssl/x509.h>
#include <gmssl/ocsp.h>
#include <gmssl/error.h>


static const char *options = "-in pem [-digest name] [-out der] [-verbose]";

static const char *help =
"Options\n"
"\n"
"    -in pem             Input certificate chain file in PEM format\n"
"                        The first certificate is the certificate to be checked\n"
"                        The second certificate is its issuer certificate\n"
"    -digest name        Digest algorithm for CertID, default sm3\n"
"    -out der | stdout   Output OCSPRequest in DER format\n"
"    -verbose            Print OCSPRequest to stderr\n"
"\n"
"Examples\n"
"\n"
"    gmssl ocspreq -in chain.pem -out req.der -verbose\n"
"\n";


int ocspreq_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *infile = NULL;
	char *outfile = NULL;
	char *digest_name_str = "sm3";
	FILE *infp = stdin;
	FILE *outfp = stdout;
	const DIGEST *digest;
	int verbose = 0;
	uint8_t cert[18192];
	size_t certlen;
	uint8_t issuer_cert[18192];
	size_t issuer_certlen;
	uint8_t req[1024];
	size_t reqlen;
	const uint8_t *request;
	size_t request_len;
	const uint8_t *p;
	size_t len;

	argc--;
	argv++;

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: %s %s\n", prog, options);
			printf("%s\n", help);
			ret = 0;
			goto end;
		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);
			if (!(infp = fopen(infile, "rb"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, infile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-digest")) {
			if (--argc < 1) goto bad;
			digest_name_str = *(++argv);
		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) goto bad;
			outfile = *(++argv);
			if (!(outfp = fopen(outfile, "wb"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, outfile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-verbose")) {
			verbose = 1;
		} else {
			fprintf(stderr, "%s: illegal option `%s`\n", prog, *argv);
			goto end;
bad:
			fprintf(stderr, "%s: `%s` option value missing\n", prog, *argv);
			goto end;
		}

		argc--;
		argv++;
	}

	if (!infile) {
		fprintf(stderr, "%s: `-in` option required\n", prog);
		goto end;
	}
	if (!(digest = digest_from_name(digest_name_str))) {
		fprintf(stderr, "%s: invalid `-digest` value\n", prog);
		goto end;
	}
	if (x509_cert_from_pem(cert, &certlen, sizeof(cert), infp) != 1) {
		fprintf(stderr, "%s: read certificate failure\n", prog);
		goto end;
	}
	if (x509_cert_from_pem(issuer_cert, &issuer_certlen, sizeof(issuer_cert), infp) != 1) {
		fprintf(stderr, "%s: read issuer certificate failure\n", prog);
		goto end;
	}
	if (ocsp_request_generate(req, &reqlen, sizeof(req),
			cert, certlen, issuer_cert, issuer_certlen, digest) != 1) {
		fprintf(stderr, "%s: generate OCSPRequest failure\n", prog);
		goto end;
	}
	if (verbose) {
		p = req;
		len = reqlen;
		if (asn1_sequence_from_der(&request, &request_len, &p, &len) != 1
			|| asn1_length_is_zero(len) != 1
			|| ocsp_request_print(stderr, 0, 0, "OCSPRequest", request, request_len) != 1) {
			fprintf(stderr, "%s: print OCSPRequest failure\n", prog);
			goto end;
		}
	}
	if (fwrite(req, 1, reqlen, outfp) != reqlen) {
		fprintf(stderr, "%s: output failure : %s\n", prog, strerror(errno));
		goto end;
	}

	ret = 0;

end:
	if (infile && infp) fclose(infp);
	if (outfile && outfp) fclose(outfp);
	return ret;
}
