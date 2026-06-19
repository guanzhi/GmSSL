/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License);
 *  you may not use this file except in compliance with the License.
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
#include <gmssl/x509_ext.h>
#include <gmssl/ocsp.h>
#include <gmssl/error.h>


#define OCSP_RESPONSE_MAX_SIZE		131072

static const char *options = "-cert pem [-url str] [-digest name] [-out der] [-verbose]";

static const char *help =
"Options\n"
"\n"
"    -cert pem           Input certificate chain file in PEM format\n"
"                        The first certificate is the certificate to be checked\n"
"                        The second certificate is its issuer certificate\n"
"    -url str            OCSP responder URL, overrides the OCSP URI in certificate AIA\n"
"    -digest name        Digest algorithm for CertID, default sm3\n"
"    -out der | stdout   Output OCSPResponse in DER format\n"
"    -verbose            Print AuthorityInfoAccess, OCSPRequest and OCSPResponse to stderr\n"
"\n"
"Examples\n"
"\n"
"    gmssl ocspget -cert chain.pem -out resp.der\n"
"    gmssl ocspget -cert chain.pem -url http://ocsp.example.com -out resp.der -verbose\n"
"\n";

static int ocsp_request_der_print(FILE *fp, const uint8_t *req, size_t reqlen)
{
	const uint8_t *p = req;
	size_t len = reqlen;
	const uint8_t *d;
	size_t dlen;

	if (asn1_sequence_from_der(&d, &dlen, &p, &len) != 1
		|| asn1_length_is_zero(len) != 1
		|| ocsp_request_print(fp, 0, 0, "OCSPRequest", d, dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

static int ocsp_response_der_print(FILE *fp, const uint8_t *resp, size_t resplen)
{
	const uint8_t *p = resp;
	size_t len = resplen;
	const uint8_t *d;
	size_t dlen;

	if (asn1_sequence_from_der(&d, &dlen, &p, &len) != 1
		|| asn1_length_is_zero(len) != 1
		|| ocsp_response_print(fp, 0, 0, "OCSPResponse", d, dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

static int x509_cert_get_ocsp_uri(const uint8_t *cert, size_t certlen,
	const char **uri, size_t *urilen, int verbose)
{
	int ret;
	const uint8_t *exts;
	size_t extslen;
	int critical;
	const uint8_t *val;
	size_t vlen;
	const char *ca_issuers_uri;
	size_t ca_issuers_urilen;
	const uint8_t *p;
	size_t len;

	if (!cert || !certlen || !uri || !urilen) {
		error_print();
		return -1;
	}
	*uri = NULL;
	*urilen = 0;

	if ((ret = x509_cert_get_exts(cert, certlen, &exts, &extslen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (!exts || !extslen) {
		return 0;
	}
	if ((ret = x509_exts_get_ext_by_oid(exts, extslen, OID_pe_authority_info_access,
			&critical, &val, &vlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (verbose) {
		p = val;
		len = vlen;
		if (x509_authority_info_access_print(stderr, 0, 0,
				"AuthorityInfoAccess", p, len) != 1) {
			error_print();
			return -1;
		}
	}
	if (x509_authority_info_access_from_der(
			&ca_issuers_uri, &ca_issuers_urilen,
			uri, urilen, &val, &vlen) != 1
		|| asn1_length_is_zero(vlen) != 1) {
		error_print();
		return -1;
	}
	return *uri ? 1 : 0;
}

int ocspget_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *certfile = NULL;
	char *outfile = NULL;
	char *url = NULL;
	char *digest_name_str = "sm3";
	FILE *certfp = NULL;
	FILE *outfp = stdout;
	const DIGEST *digest;
	int verbose = 0;
	const char *ocsp_uri = NULL;
	size_t ocsp_uri_len = 0;

	uint8_t cert[OCSP_MAX_CERT_SIZE];
	size_t certlen = 0;
	uint8_t issuer_cert[OCSP_MAX_CERT_SIZE];
	size_t issuer_certlen = 0;
	uint8_t req[OCSP_MAX_REQUEST_SIZE];
	size_t reqlen = 0;
	uint8_t resp[OCSP_RESPONSE_MAX_SIZE];
	size_t resplen = 0;

	argc--;
	argv++;

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: %s %s\n", prog, options);
			printf("%s\n", help);
			ret = 0;
			goto end;
		} else if (!strcmp(*argv, "-cert")) {
			if (--argc < 1) goto bad;
			certfile = *(++argv);
			if (!(certfp = fopen(certfile, "rb"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, certfile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-url")) {
			if (--argc < 1) goto bad;
			url = *(++argv);
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

	if (!certfile) {
		fprintf(stderr, "%s: `-cert` option required\n", prog);
		goto end;
	}
	if (!(digest = digest_from_name(digest_name_str))) {
		fprintf(stderr, "%s: invalid `-digest` value\n", prog);
		goto end;
	}
	if (x509_cert_from_pem(cert, &certlen, sizeof(cert), certfp) != 1) {
		fprintf(stderr, "%s: read certificate failure\n", prog);
		goto end;
	}
	if (x509_cert_from_pem(issuer_cert, &issuer_certlen, sizeof(issuer_cert), certfp) != 1) {
		fprintf(stderr, "%s: read issuer certificate failure\n", prog);
		goto end;
	}
	if (url) {
		if (verbose) {
			const char *cert_ocsp_uri;
			size_t cert_ocsp_uri_len;
			if ((ret = x509_cert_get_ocsp_uri(cert, certlen,
					&cert_ocsp_uri, &cert_ocsp_uri_len, verbose)) < 0) {
				error_print();
				ret = 1;
				goto end;
			}
			if (ret == 0) {
				fprintf(stderr, "%s: no OCSP URI found in certificate\n", prog);
			}
		}
		ocsp_uri = url;
		ocsp_uri_len = strlen(url);
	} else {
		if ((ret = x509_cert_get_ocsp_uri(cert, certlen,
				&ocsp_uri, &ocsp_uri_len, verbose)) != 1) {
			if (ret < 0) error_print();
			else fprintf(stderr, "%s: no OCSP URI found in certificate\n", prog);
			ret = 1;
			goto end;
		}
	}
	if (verbose) {
		fprintf(stderr, "OCSP responder: %.*s\n", (int)ocsp_uri_len, ocsp_uri);
	}

	if (ocsp_request_generate(req, &reqlen, sizeof(req),
			cert, certlen, issuer_cert, issuer_certlen, digest) != 1) {
		fprintf(stderr, "%s: generate OCSPRequest failure\n", prog);
		goto end;
	}
	if (verbose && ocsp_request_der_print(stderr, req, reqlen) != 1) {
		fprintf(stderr, "%s: print OCSPRequest failure\n", prog);
		goto end;
	}

	if ((ret = ocsp_response_get_from_uri(ocsp_uri, ocsp_uri_len,
			req, reqlen, resp, &resplen, sizeof(resp))) != 1) {
		if (ret < 0) error_print();
		else fprintf(stderr, "%s: OCSPResponse too large\n", prog);
		ret = 1;
		goto end;
	}
	if (verbose && ocsp_response_der_print(stderr, resp, resplen) != 1) {
		fprintf(stderr, "%s: print OCSPResponse failure\n", prog);
		goto end;
	}

	if (fwrite(resp, 1, resplen, outfp) != resplen) {
		fprintf(stderr, "%s: output failure : %s\n", prog, strerror(errno));
		goto end;
	}

	ret = 0;

end:
	if (certfp) fclose(certfp);
	if (outfile && outfp) fclose(outfp);
	return ret;
}
