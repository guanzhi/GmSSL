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
#include <gmssl/hex.h>
#include <gmssl/asn1.h>
#include <gmssl/x509.h>
#include <gmssl/ocsp.h>
#include <gmssl/error.h>


#define OCSP_RESPONSE_MAX_SIZE		131072

static const char *options =
	"-reqin der -respin der -cacert pem -signer pem"
	" [-time time] [-clock_skew seconds]"
	" [-sm2_id str | -sm2_id_hex hex]"
	" [-certs pem] [-verbose]";

static const char *help =
"Options\n"
"\n"
"    -reqin der          Input OCSPRequest in DER format\n"
"    -respin der         Input OCSPResponse in DER format\n"
"    -cacert pem         Issuer CA certificate of the requested certificate\n"
"    -signer pem         OCSPResponse signer certificate\n"
"    -time time          Verification time, default current time\n"
"    -clock_skew seconds Allowed clock skew in seconds, default 300\n"
"    -sm2_id str         Signer's ID in SM2 signature algorithm\n"
"    -sm2_id_hex hex     Signer's ID in hex format\n"
"    -certs pem          Extra certificates for verification context\n"
"    -verbose            Print OCSPRequest and OCSPResponse to stderr\n"
"\n"
"Examples\n"
"\n"
"    gmssl ocspverify -reqin req.der -respin resp.der -cacert cacert.pem -signer ocspcert.pem -verbose\n"
"\n";

static const char *ocsp_verify_reason_name(int reason)
{
	switch (reason) {
	case OCSP_VERIFY_REASON_NONE:
		return "none";
	case OCSP_VERIFY_REASON_REVOKED:
		return "revoked";
	case OCSP_VERIFY_REASON_UNKNOWN:
		return "unknown";
	case OCSP_VERIFY_REASON_MALFORMED_RESPONSE:
		return "malformedResponse";
	case OCSP_VERIFY_REASON_RESPONSE_STATUS_NOT_SUCCESSFUL:
		return "responseStatusNotSuccessful";
	case OCSP_VERIFY_REASON_UNSUPPORTED_RESPONSE_TYPE:
		return "unsupportedResponseType";
	case OCSP_VERIFY_REASON_BAD_SIGNATURE:
		return "badSignature";
	case OCSP_VERIFY_REASON_BAD_RESPONDER_ID:
		return "badResponderID";
	case OCSP_VERIFY_REASON_NO_MATCHING_SINGLE_RESPONSE:
		return "noMatchingSingleResponse";
	case OCSP_VERIFY_REASON_THIS_UPDATE_IN_FUTURE:
		return "thisUpdateInFuture";
	case OCSP_VERIFY_REASON_NEXT_UPDATE_EXPIRED:
		return "nextUpdateExpired";
	default:
		return "unknownReason";
	}
}

static int read_der_file(const char *file, uint8_t *buf, size_t *buflen, size_t maxlen)
{
	FILE *fp;
	size_t len;

	if (!(fp = fopen(file, "rb"))) {
		return -1;
	}
	len = fread(buf, 1, maxlen, fp);
	if (ferror(fp) || (len == maxlen && fgetc(fp) != EOF)) {
		fclose(fp);
		return -1;
	}
	fclose(fp);
	*buflen = len;
	return 1;
}

static int read_certs_from_pem(const char *file, uint8_t *certs, size_t *certs_len, size_t maxlen)
{
	FILE *fp;
	uint8_t cert[OCSP_MAX_CERT_SIZE];
	size_t certlen;
	size_t len = 0;
	int ret;

	if (!(fp = fopen(file, "rb"))) {
		return -1;
	}
	while ((ret = x509_cert_from_pem(cert, &certlen, sizeof(cert), fp)) == 1) {
		if (certlen > maxlen - len) {
			fclose(fp);
			return -1;
		}
		memcpy(certs + len, cert, certlen);
		len += certlen;
	}
	fclose(fp);
	*certs_len = len;
	return len ? 1 : -1;
}

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

int ocspverify_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *reqfile = NULL;
	char *respfile = NULL;
	char *cacertfile = NULL;
	char *signerfile = NULL;
	char *certsfile = NULL;
	FILE *cacertfp = NULL;
	FILE *signerfp = NULL;
	char *str;
	int verbose = 0;

	uint8_t req[OCSP_MAX_REQUEST_SIZE];
	size_t reqlen = 0;
	uint8_t resp[OCSP_RESPONSE_MAX_SIZE];
	size_t resplen = 0;
	uint8_t cacert[OCSP_MAX_CERT_SIZE];
	size_t cacertlen = 0;
	uint8_t signer_cert[OCSP_MAX_CERT_SIZE];
	size_t signer_cert_len = 0;
	uint8_t certs[OCSP_MAX_CERTS_SIZE];
	size_t certs_len = 0;

	OCSP_SIGN_CTX ocsp_ctx;
	char signer_id[SM2_MAX_ID_LENGTH + 1] = {0};
	size_t signer_id_len = 0;
	time_t verify_time = (time_t)-1;
	int clock_skew = -1;
	int reason = OCSP_VERIFY_REASON_NONE;
	int rv;

	argc--;
	argv++;

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: %s %s\n\n", prog, options);
			printf("%s\n", help);
			ret = 0;
			goto end;
		} else if (!strcmp(*argv, "-reqin")) {
			if (--argc < 1) goto bad;
			reqfile = *(++argv);
		} else if (!strcmp(*argv, "-respin")) {
			if (--argc < 1) goto bad;
			respfile = *(++argv);
		} else if (!strcmp(*argv, "-cacert")) {
			if (--argc < 1) goto bad;
			cacertfile = *(++argv);
		} else if (!strcmp(*argv, "-signer")) {
			if (--argc < 1) goto bad;
			signerfile = *(++argv);
		} else if (!strcmp(*argv, "-time")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			if (asn1_time_from_str(0, &verify_time, str) != 1) {
				fprintf(stderr, "%s: invalid time '%s' for `-time`\n", prog, str);
				goto end;
			}
		} else if (!strcmp(*argv, "-clock_skew")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			clock_skew = atoi(str);
			if (clock_skew < 0) {
				fprintf(stderr, "%s: invalid `-clock_skew` value\n", prog);
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
			if (strlen(str) > (sizeof(signer_id) - 1) * 2
				|| hex_to_bytes(str, strlen(str), (uint8_t *)signer_id, &signer_id_len) != 1) {
				fprintf(stderr, "%s: invalid `-sm2_id_hex` value\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-certs")) {
			if (--argc < 1) goto bad;
			certsfile = *(++argv);
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

	if (!reqfile) {
		fprintf(stderr, "%s: `-reqin` option required\n", prog);
		goto end;
	}
	if (!respfile) {
		fprintf(stderr, "%s: `-respin` option required\n", prog);
		goto end;
	}
	if (!cacertfile) {
		fprintf(stderr, "%s: `-cacert` option required\n", prog);
		goto end;
	}
	if (!signerfile) {
		fprintf(stderr, "%s: `-signer` option required\n", prog);
		goto end;
	}

	if (read_der_file(reqfile, req, &reqlen, sizeof(req)) != 1) {
		fprintf(stderr, "%s: read OCSPRequest '%s' failure\n", prog, reqfile);
		goto end;
	}
	if (read_der_file(respfile, resp, &resplen, sizeof(resp)) != 1) {
		fprintf(stderr, "%s: read OCSPResponse '%s' failure\n", prog, respfile);
		goto end;
	}
	if (verbose && ocsp_request_der_print(stderr, req, reqlen) != 1) {
		fprintf(stderr, "%s: print OCSPRequest failure\n", prog);
		goto end;
	}
	if (verbose && ocsp_response_der_print(stderr, resp, resplen) != 1) {
		fprintf(stderr, "%s: print OCSPResponse failure\n", prog);
		goto end;
	}
	if (!(cacertfp = fopen(cacertfile, "rb"))) {
		fprintf(stderr, "%s: open '%s' failure : %s\n", prog, cacertfile, strerror(errno));
		goto end;
	}
	if (x509_cert_from_pem(cacert, &cacertlen, sizeof(cacert), cacertfp) != 1) {
		fprintf(stderr, "%s: read CA certificate '%s' failure\n", prog, cacertfile);
		goto end;
	}
	if (!(signerfp = fopen(signerfile, "rb"))) {
		fprintf(stderr, "%s: open '%s' failure : %s\n", prog, signerfile, strerror(errno));
		goto end;
	}
	if (x509_cert_from_pem(signer_cert, &signer_cert_len, sizeof(signer_cert), signerfp) != 1) {
		fprintf(stderr, "%s: read signer certificate '%s' failure\n", prog, signerfile);
		goto end;
	}
	if (certsfile && read_certs_from_pem(certsfile, certs, &certs_len, sizeof(certs)) != 1) {
		fprintf(stderr, "%s: read certificates '%s' failure\n", prog, certsfile);
		goto end;
	}

	if (ocsp_verify_init(&ocsp_ctx, req, reqlen, cacert, cacertlen) != 1) {
		fprintf(stderr, "%s: initialize OCSP verification context failure\n", prog);
		goto end;
	}
	if (verify_time != (time_t)-1
		&& ocsp_verify_set_time(&ocsp_ctx, verify_time) != 1) {
		fprintf(stderr, "%s: set verification time failure\n", prog);
		goto end;
	}
	if (clock_skew >= 0
		&& ocsp_verify_set_clock_skew(&ocsp_ctx, clock_skew) != 1) {
		fprintf(stderr, "%s: set clock skew failure\n", prog);
		goto end;
	}
	if (certs_len
		&& ocsp_verify_set_certs(&ocsp_ctx, certs, certs_len) != 1) {
		fprintf(stderr, "%s: set verification certificates failure\n", prog);
		goto end;
	}

	rv = ocsp_verify(&ocsp_ctx, resp, resplen,
		signer_cert, signer_cert_len,
		signer_id_len ? signer_id : NULL, signer_id_len,
		&reason);
	if (rv == 1) {
		printf("Verification success\n");
		ret = 0;
	} else if (rv == 0) {
		printf("Verification failure: %s\n", ocsp_verify_reason_name(reason));
		ret = 1;
	} else {
		fprintf(stderr, "%s: Verification error: %s\n", prog, ocsp_verify_reason_name(reason));
		goto end;
	}

end:
	if (cacertfp) fclose(cacertfp);
	if (signerfp) fclose(signerfp);
	return ret;
}
