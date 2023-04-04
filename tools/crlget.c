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
#include <gmssl/x509_ext.h>
#include <gmssl/x509_crl.h>
#include <gmssl/http.h>

#include <gmssl/error.h>

static const char *usage = "-cert pem [-out file]\n";

static const char *options =
"Options\n"
"\n"
"    -cert pem              Input certificates in PEM format.\n"
"    -out der | stdout      Output CRL file in DER-encoding\n"
"\n"
"Examples\n"
"\n"
"    gmssl crlget -cert cert.pem -out crl.der\n"
"\n";

int crlget_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *str;

	uint8_t *cert = NULL;
	size_t certlen = 0;
	char *outfile = NULL;
	FILE *outfp = stdout;
	uint8_t *crl = NULL;
	size_t crl_len = 0;

	argc--;
	argv++;

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: gmssl %s %s\n\n", prog, usage);
			printf("%s\n", options);
			goto end;
		} else if (!strcmp(*argv, "-cert")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			if (x509_cert_new_from_file(&cert, &certlen, str) != 1) {
				fprintf(stderr, "%s: load ca certificate '%s' failure\n", prog, str);
				goto end;
			}
		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) goto bad;
			outfile = *(++argv);
			if (!(outfp = fopen(outfile, "wb"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, outfile, strerror(errno));
				goto end;
			}
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

	if (!cert) {
		fprintf(stderr, "%s: `-cert` option required\n", prog);
		printf("usage: gmssl %s %s\n\n", prog, usage);
		goto end;
	}

	/*
	const uint8_t *exts;
	size_t extslen;
	if (x509_cert_get_exts(cert, certlen, &exts, &extslen) != 1) {
		error_print();
		goto end;
	}
	if (!exts) {
		goto end;
	}

	int critical;
	const uint8_t *val;
	size_t vlen;

	if ((ret = x509_exts_get_ext_by_oid(exts, extslen, OID_ce_crl_distribution_points, &critical, &val, &vlen)) < 0) {
		error_print();
		goto end;
	}


	char *uristr;
	const char *uri;
	size_t urilen;
	int reason;
	const uint8_t *crl_issuer;
	size_t crl_issuer_len;

	if (x509_uri_as_distribution_points_from_der(&uri, &urilen, &reason, &crl_issuer, &crl_issuer_len, &val, &vlen) != 1) {
		error_print();
		goto end;
	}
	if (!(uristr = strndup(uri, urilen))) {
		error_print();
		goto end;
	}


	if (http_get(uristr, NULL, &crl_len, 0) < 0) {
		error_print();
		goto end;
	}
	if (!(crl = malloc(crl_len))) {
		error_print();
		goto end;
	}
	if (http_get(uristr, crl, &crl_len, crl_len) != 1) {
		error_print();
		goto end;
	}
	*/


	if (x509_crl_new_from_cert(&crl, &crl_len, cert, certlen) != 1) {
		error_print();
		goto end;
	}

	fwrite(crl, crl_len, 1, outfp);


	ret = 0;
end:
	if (cert) free(cert);
	if (outfile && outfp) fclose(outfp);
	return ret;
}

