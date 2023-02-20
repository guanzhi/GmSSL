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


static const char *options =
	" -in pem"
	" [-reason str]"
	" [-invalid_date time]"
	" -out der";	// on windows, send 0x0a through pipe will be connverted to 0x0d0a
			// so stdout and pipe is not supported

static char *usage =
"Options\n"
"\n"
"    -in pem                  Certificate in PEM format to be revoked\n"
"    -reason str              Revocation reason code, avaiable codes:\n"
"                                 * unspecified\n"
"                                 * keyCompromise\n"
"                                 * cACompromise\n"
"                                 * affiliationChanged\n"
"                                 * superseded\n"
"                                 * cessationOfOperation\n"
"                                 * certificateHold\n"
"                                 * notAssigned\n"
"                                 * removeFromCRL\n"
"                                 * privilegeWithdrawn\n"
"                                 * aACompromise\n"
"    -invalid_date time      The date on which it is known or suspected the certificate became invalid\n"
"                            Time in `YYYYMMDDHHMMSSZ` format such as 20221231000000Z\n"
"                            The last 'Z' means it is Zulu (GMT) time\n"
"    -out der                Output X.509 RevokedCertificate in DER-encoding\n"
"                            This file stores multiple RevokedCertificates, used as input by `crlsign`\n"
"\n"
"Examples\n"
"\n"
"    gmssl certrevoke -in cert1.pem -reason keyCompromise -invalid_date 20221230000000Z -out revoked_certs.der\n"
"    gmssl certrevoke -in cert1.pem -reason keyCompromise -invalid_date 20221230000000Z >> revoked_certs.der\n"
"\n";


int certrevoke_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *str;

	uint8_t *cert = NULL;
	size_t certlen;
	int reason = -1;
	time_t invalid_date = -1;
	char *outfile = NULL;
	FILE *outfp = NULL;
	uint8_t *outbuf = NULL;
	uint8_t *out;
	size_t outlen = 0;

	argc--;
	argv++;

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: gmssl %s %s\n\n", prog, options);
			printf("%s", usage);
			goto end;
		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			if (x509_cert_new_from_file(&cert, &certlen, str) != 1) {
				fprintf(stderr, "%s: open cert file '%s' failure\n", prog, str);
				goto end;
			}
		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) goto bad;
			outfile = *(++argv);
			if (!(outfp = fopen(outfile, "ab"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, outfile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-reason")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			if (x509_crl_reason_from_name(&reason, str) != 1) {
				fprintf(stderr, "%s: invalid reason '%s'\n", prog, str);
				goto end;
			}
		} else if (!strcmp(*argv, "-invalid_date")) {
			if (--argc < 1) goto bad;
			str =*(++argv);
			if (asn1_time_from_str(0, &invalid_date, str) != 1) {
				fprintf(stderr, "%s: invalid time '%s', should in 'YYYYMMDDHHMMSSZ' format\n", prog, str);
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
		fprintf(stderr, "%s: option `-in` missing\n", prog);
		printf("usage: gmssl %s %s\n\n", prog, options);
		goto end;
	}
	if (!outfile) {
		fprintf(stderr, "%s: option `-out` missing\n", prog);
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
