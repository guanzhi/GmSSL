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
#include <gmssl/mem.h>
#include <gmssl/asn1.h>
#include <gmssl/x509.h>
#include <gmssl/x509_alg.h>
#include <gmssl/x509_crl.h>
#include <gmssl/x509_key.h>
#include <gmssl/ocsp.h>
#include <gmssl/error.h>
#include "passwd.h"


#define OCSP_RESPONSE_MAX_SIZE		131072

static const char *options =
	"-reqin der -cacert pem -signer pem -key pem [-pass pass]"
	" [-status good|revoked|unknown]"
	" [-sig_alg str]"
	" [-revocation_time time] [-revocation_reason reason]"
	" [-this_update time] [-next_update time] [-produced_at time]"
	" [-resp_key_id]"
	" [-sm2_id str | -sm2_id_hex hex]"
	" [-single_exts der] [-response_exts der]"
	" [-cert pem] [-certs pem] [-out der] [-verbose]";

static const char *help =
"Options\n"
"\n"
"    -reqin der              Input OCSPRequest in DER format\n"
"    -cacert pem             Issuer CA certificate of the requested certificate\n"
"    -signer pem             OCSPResponse signer certificate\n"
"    -key pem                OCSPResponse signer private key\n"
"    -pass pass              Password for decrypting private key file, prompt if not given\n"
"    -status status          Certificate status: good, revoked or unknown, default good\n"
"    -sig_alg str            Signature algorithm OID name, default sm2sign-with-sm3\n"
"    -revocation_time time   Revocation time, required when status is revoked\n"
"    -revocation_reason str  Revocation reason, optional when status is revoked\n"
"    -this_update time       SingleResponse thisUpdate, default current time\n"
"    -next_update time       SingleResponse nextUpdate\n"
"    -produced_at time       ResponseData producedAt, default current time\n"
"    -resp_key_id            Use byKey ResponderID, default byName\n"
"    -sm2_id str             Signer's ID in SM2 signature algorithm\n"
"    -sm2_id_hex hex         Signer's ID in hex format\n"
"    -single_exts der        SingleResponse extensions in DER format\n"
"    -response_exts der      ResponseData extensions in DER format\n"
"    -cert pem               Include one certificate in BasicOCSPResponse\n"
"    -certs pem              Include certificates in BasicOCSPResponse\n"
"    -out der | stdout       Output OCSPResponse in DER format\n"
"    -verbose                Print OCSPRequest and OCSPResponse to stderr\n"
"\n"
"Examples\n"
"\n"
"    gmssl ocspsign -reqin req.der -cacert cacert.pem -signer ocspcert.pem -key ocspkey.pem -pass P@ssw0rd -out resp.der -verbose\n"
"    gmssl ocspsign -reqin req.der -cacert cacert.pem -signer cacert.pem -key cakey.pem -pass P@ssw0rd -status revoked -revocation_time 20260610000000Z -revocation_reason keyCompromise -out resp.der\n"
"\n";

static int ocsp_status_from_name(const char *name)
{
	if (!strcmp(name, "good")) {
		return OCSP_cert_status_good;
	} else if (!strcmp(name, "revoked")) {
		return OCSP_cert_status_revoked;
	} else if (!strcmp(name, "unknown")) {
		return OCSP_cert_status_unknown;
	}
	return -1;
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

int ocspsign_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *reqfile = NULL;
	char *cacertfile = NULL;
	char *signerfile = NULL;
	char *keyfile = NULL;
	char *outfile = NULL;
	FILE *outfp = stdout;
	FILE *keyfp = NULL;
	FILE *cacertfp = NULL;
	FILE *signerfp = NULL;
	char *pass = NULL;
	char passbuf[GMSSL_PASSWORD_MAX_SIZE] = {0};
	char *str;
	int verbose = 0;

	uint8_t req[OCSP_MAX_REQUEST_SIZE];
	size_t reqlen = 0;
	uint8_t cacert[OCSP_MAX_CERT_SIZE];
	size_t cacertlen = 0;
	uint8_t signer_cert[OCSP_MAX_CERT_SIZE];
	size_t signer_cert_len = 0;
	uint8_t single_exts[OCSP_MAX_EXTS_SIZE];
	size_t single_exts_len = 0;
	uint8_t response_exts[OCSP_MAX_EXTS_SIZE];
	size_t response_exts_len = 0;
	uint8_t certs[OCSP_MAX_CERTS_SIZE];
	size_t certs_len = 0;
	uint8_t resp[OCSP_RESPONSE_MAX_SIZE];
	uint8_t *p = resp;
	size_t resplen = 0;

	OCSP_SIGN_CTX ocsp_ctx;
	X509_KEY signer_pub;
	X509_KEY sign_key;
	int sign_key_loaded = 0;
	char signer_id[SM2_MAX_ID_LENGTH + 1] = {0};
	size_t signer_id_len = 0;

	int cert_status = OCSP_cert_status_good;
	int sign_algor = OID_sm2sign_with_sm3;
	time_t revocation_time = (time_t)-1;
	time_t this_update = time(NULL);
	time_t next_update = (time_t)-1;
	time_t produced_at = (time_t)-1;
	int revocation_reason = -1;
	int resp_key_id = 0;

	memset(&signer_pub, 0, sizeof(signer_pub));
	memset(&sign_key, 0, sizeof(sign_key));

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
		} else if (!strcmp(*argv, "-cacert")) {
			if (--argc < 1) goto bad;
			cacertfile = *(++argv);
		} else if (!strcmp(*argv, "-signer")) {
			if (--argc < 1) goto bad;
			signerfile = *(++argv);
		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			keyfile = *(++argv);
			if (!(keyfp = fopen(keyfile, "rb"))) {
				fprintf(stderr, "%s: open '%s' failure : %s\n", prog, keyfile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-pass")) {
			if (--argc < 1) goto bad;
			pass = *(++argv);
		} else if (!strcmp(*argv, "-status")) {
			if (--argc < 1) goto bad;
			if ((cert_status = ocsp_status_from_name(*(++argv))) < 0) {
				fprintf(stderr, "%s: invalid `-status` value\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-sig_alg")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			if ((sign_algor = x509_signature_algor_from_name(str)) == OID_undef) {
				fprintf(stderr, "%s: invalid `-sig_alg` value '%s'\n", prog, str);
				goto end;
			}
		} else if (!strcmp(*argv, "-revocation_time")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			if (asn1_time_from_str(0, &revocation_time, str) != 1) {
				fprintf(stderr, "%s: invalid time '%s' for `-revocation_time`\n", prog, str);
				goto end;
			}
		} else if (!strcmp(*argv, "-revocation_reason")) {
			if (--argc < 1) goto bad;
			if (x509_crl_reason_from_name(&revocation_reason, *(++argv)) != 1) {
				fprintf(stderr, "%s: invalid `-revocation_reason` value\n", prog);
				goto end;
			}
		} else if (!strcmp(*argv, "-this_update")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			if (asn1_time_from_str(0, &this_update, str) != 1) {
				fprintf(stderr, "%s: invalid time '%s' for `-this_update`\n", prog, str);
				goto end;
			}
		} else if (!strcmp(*argv, "-next_update")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			if (asn1_time_from_str(0, &next_update, str) != 1) {
				fprintf(stderr, "%s: invalid time '%s' for `-next_update`\n", prog, str);
				goto end;
			}
		} else if (!strcmp(*argv, "-produced_at")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			if (asn1_time_from_str(0, &produced_at, str) != 1) {
				fprintf(stderr, "%s: invalid time '%s' for `-produced_at`\n", prog, str);
				goto end;
			}
		} else if (!strcmp(*argv, "-resp_key_id")) {
			resp_key_id = 1;
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
		} else if (!strcmp(*argv, "-single_exts")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			if (read_der_file(str, single_exts, &single_exts_len, sizeof(single_exts)) != 1) {
				fprintf(stderr, "%s: read single response extensions '%s' failure\n", prog, str);
				goto end;
			}
		} else if (!strcmp(*argv, "-response_exts")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			if (read_der_file(str, response_exts, &response_exts_len, sizeof(response_exts)) != 1) {
				fprintf(stderr, "%s: read response extensions '%s' failure\n", prog, str);
				goto end;
			}
		} else if (!strcmp(*argv, "-cert")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			if (read_certs_from_pem(str, certs, &certs_len, sizeof(certs)) != 1) {
				fprintf(stderr, "%s: read certificate '%s' failure\n", prog, str);
				goto end;
			}
		} else if (!strcmp(*argv, "-certs")) {
			if (--argc < 1) goto bad;
			str = *(++argv);
			if (read_certs_from_pem(str, certs, &certs_len, sizeof(certs)) != 1) {
				fprintf(stderr, "%s: read certificates '%s' failure\n", prog, str);
				goto end;
			}
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

	if (!reqfile) {
		fprintf(stderr, "%s: `-reqin` option required\n", prog);
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
	if (!keyfp) {
		fprintf(stderr, "%s: `-key` option required\n", prog);
		goto end;
	}
	if (cert_status == OCSP_cert_status_revoked && revocation_time == (time_t)-1) {
		fprintf(stderr, "%s: `-revocation_time` option required for revoked status\n", prog);
		goto end;
	}
#ifndef ENABLE_SHA1
	if (resp_key_id) {
		fprintf(stderr, "%s: `-resp_key_id` requires ENABLE_SHA1\n", prog);
		goto end;
	}
#endif

	if (read_der_file(reqfile, req, &reqlen, sizeof(req)) != 1) {
		fprintf(stderr, "%s: read OCSPRequest '%s' failure\n", prog, reqfile);
		goto end;
	}
	if (verbose && ocsp_request_der_print(stderr, req, reqlen) != 1) {
		fprintf(stderr, "%s: print OCSPRequest failure\n", prog);
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
	if (x509_cert_get_subject_public_key(signer_cert, signer_cert_len, &signer_pub) != 1) {
		fprintf(stderr, "%s: parse signer certificate failure\n", prog);
		goto end;
	}
	if (!pass && signer_pub.algor == OID_ec_public_key) {
		if (gmssl_tool_get_password(prog, "pass", keyfile, &pass,
			passbuf, sizeof(passbuf), 0) != 1) {
			goto end;
		}
	}
	if (x509_private_key_from_file(&sign_key, signer_pub.algor, pass, keyfp) != 1) {
		fprintf(stderr, "%s: load signer private key failure\n", prog);
		goto end;
	}
	sign_key_loaded = 1;
	if (x509_public_key_equ(&sign_key, &signer_pub) != 1) {
		fprintf(stderr, "%s: signer certificate and private key not match\n", prog);
		goto end;
	}

	if (ocsp_sign_init(&ocsp_ctx, req, reqlen, cacert, cacertlen) != 1) {
		fprintf(stderr, "%s: initialize OCSP signing context failure\n", prog);
		goto end;
	}
	if (resp_key_id
		&& ocsp_sign_set_responder_id_type(&ocsp_ctx, OCSP_responder_id_by_key) != 1) {
		fprintf(stderr, "%s: set OCSP responderID failure\n", prog);
		goto end;
	}
	if (ocsp_sign_set_signature_algor(&ocsp_ctx, sign_algor) != 1) {
		fprintf(stderr, "%s: set signature algorithm failure\n", prog);
		goto end;
	}
	if (produced_at != (time_t)-1
		&& ocsp_sign_set_produced_at(&ocsp_ctx, produced_at) != 1) {
		fprintf(stderr, "%s: set producedAt failure\n", prog);
		goto end;
	}
	if (next_update != (time_t)-1
		&& ocsp_sign_set_next_update(&ocsp_ctx, next_update) != 1) {
		fprintf(stderr, "%s: set nextUpdate failure\n", prog);
		goto end;
	}
	if (revocation_reason >= 0
		&& ocsp_sign_set_revocation_reason(&ocsp_ctx, revocation_reason) != 1) {
		fprintf(stderr, "%s: set revocationReason failure\n", prog);
		goto end;
	}
	if (single_exts_len
		&& ocsp_sign_set_single_response_exts(&ocsp_ctx, single_exts, single_exts_len) != 1) {
		fprintf(stderr, "%s: set SingleResponse extensions failure\n", prog);
		goto end;
	}
	if (response_exts_len
		&& ocsp_sign_set_response_exts(&ocsp_ctx, response_exts, response_exts_len) != 1) {
		fprintf(stderr, "%s: set ResponseData extensions failure\n", prog);
		goto end;
	}
	if (certs_len
		&& ocsp_sign_set_certs(&ocsp_ctx, certs, certs_len) != 1) {
		fprintf(stderr, "%s: set BasicOCSPResponse certificates failure\n", prog);
		goto end;
	}
	if (ocsp_sign(&ocsp_ctx, cert_status, revocation_time, this_update,
		signer_cert, signer_cert_len, &sign_key,
		signer_id_len ? signer_id : NULL, signer_id_len,
		NULL, &resplen) != 1
		|| resplen > sizeof(resp)) {
		fprintf(stderr, "%s: generate OCSPResponse failure\n", prog);
		goto end;
	}
	// FIXME: resplen = 0 resets buffer capacity before second ocsp_sign call.
	// If ocsp_sign() uses *outlen as input buffer capacity, passing 0 may
	// allow buffer overflow. Proposed fix: resplen = sizeof(resp);
	resplen = 0;
	if (ocsp_sign(&ocsp_ctx, cert_status, revocation_time, this_update,
		signer_cert, signer_cert_len, &sign_key,
		signer_id_len ? signer_id : NULL, signer_id_len,
		&p, &resplen) != 1) {
		fprintf(stderr, "%s: generate OCSPResponse failure\n", prog);
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
	gmssl_secure_clear(passbuf, sizeof(passbuf));
	if (keyfp) fclose(keyfp);
	if (cacertfp) fclose(cacertfp);
	if (signerfp) fclose(signerfp);
	if (outfile && outfp) fclose(outfp);
	if (sign_key_loaded) x509_key_cleanup(&sign_key);
	return ret;
}
