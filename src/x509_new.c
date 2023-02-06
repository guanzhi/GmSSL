/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <gmssl/sm2.h>
#include <gmssl/oid.h>
#include <gmssl/pem.h>
#include <gmssl/asn1.h>
#include <gmssl/x509_req.h>
#include <gmssl/x509_crl.h>
#include <gmssl/x509_ext.h>
#include <gmssl/x509.h>
#include <gmssl/error.h>
#include <gmssl/file.h>
#include <gmssl/http.h>

#include <errno.h>
#include <sys/stat.h>

int x509_cert_new_from_file(uint8_t **out, size_t *outlen, const char *file)
{
	int ret = -1;
	FILE *fp = NULL;
	size_t fsize;
	uint8_t *buf = NULL;
	size_t buflen;

	if (!(fp = fopen(file, "r"))
		|| file_size(fp, &fsize) != 1
		|| (buflen = (fsize * 3)/4 + 1) < 0
		|| (buf = malloc((fsize * 3)/4 + 1)) == NULL) {
		error_print();
		goto end;
	}
	if (x509_cert_from_pem(buf, outlen, buflen, fp) != 1) {
		error_print();
		goto end;
	}
	*out = buf;
	buf = NULL;
	ret = 1;
end:
	if (fp) fclose(fp);
	if (buf) free(buf);
	return ret;
}

int x509_certs_new_from_file(uint8_t **out, size_t *outlen, const char *file)
{
	int ret = -1;
	FILE *fp = NULL;
	size_t fsize;
	uint8_t *buf = NULL;
	size_t buflen;

	if (!(fp = fopen(file, "r"))
		|| file_size(fp, &fsize) != 1
		|| (buflen = (fsize * 3)/4 + 1) < 0
		|| (buf = malloc((fsize * 3)/4 + 1)) == NULL) {
		error_print();
		goto end;
	}
	if (x509_certs_from_pem(buf, outlen, buflen, fp) != 1) {
		error_print();
		goto end;
	}
	*out = buf;
	buf = NULL;
	ret = 1;
end:
	if (fp) fclose(fp);
	if (buf) free(buf);
	return ret;
}

int x509_req_new_from_pem(uint8_t **out, size_t *outlen, FILE *fp)
{
	uint8_t *req;
	size_t reqlen;
	size_t maxlen;

	if (!out || !outlen || !fp) {
		error_print();
		return -1;
	}
	if (file_size(fp, &maxlen) != 1) {
		error_print();
		return -1;
	}
	if (!(req = malloc(maxlen))) {
		error_print();
		return -1;
	}
	if (x509_req_from_pem(req, &reqlen, maxlen, fp) != 1) {
		free(req);
		error_print();
		return -1;
	}
	*out = req;
	*outlen = reqlen;
	return 1;
}

int x509_req_new_from_file(uint8_t **req, size_t *reqlen, const char *file)
{
	FILE *fp = NULL;

	if (!(fp = fopen(file, "rb"))) {
		error_print();
		return -1;
	}
	if (x509_req_new_from_pem(req, reqlen, fp) != 1) {
		error_print();
		fclose(fp);
		return -1;
	}
	fclose(fp);
	return 1;
}

int x509_crl_new_from_uri(uint8_t **crl, size_t *crl_len, const char *uri, size_t urilen)
{
	int ret = -1;
	char *uristr = NULL;
	uint8_t *buf = NULL;
	size_t buflen;
	const uint8_t *p;

	if (!(uristr = malloc(urilen + 1))) {
		error_print();
		return -1;
	}
	memcpy(uristr, uri, urilen);
	uristr[urilen] = 0;

	if (http_get(uristr, NULL, &buflen, 0) < 0) {
		error_print();
		goto end;
	}
	if (!buflen) {
		error_print();
		goto end;
	}
	if (!(buf = malloc(buflen))) {
		error_print();
		goto end;
	}
	if (http_get(uristr, buf, &buflen, buflen) != 1) {
		error_print();
		goto end;
	}
	p = buf;
	if (x509_crl_from_der((const uint8_t **)crl, crl_len, &p, &buflen) != 1) {
		error_print();
		goto end;
	}
	buf = NULL;
	ret = 1;
end:
	if (uristr) free(uristr);
	if (buf) free(buf);
	return ret;
}

int x509_crl_new_from_cert(uint8_t **crl, size_t *crl_len, const uint8_t *cert, size_t certlen)
{
	int ret;
	const uint8_t *exts;
	size_t extslen;

	int critical;
	const uint8_t *val;
	size_t vlen;

	const char *uri;
	size_t urilen;
	int reason;
	const uint8_t *crl_issuer;
	size_t crl_issuer_len;

	if ((ret = x509_cert_get_exts(cert, certlen, &exts, &extslen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if ((ret = x509_exts_get_ext_by_oid(exts, extslen,
		OID_ce_crl_distribution_points, &critical, &val, &vlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (x509_uri_as_distribution_points_from_der(&uri, &urilen,
		&reason, &crl_issuer, &crl_issuer_len, &val, &vlen) != 1
		|| asn1_length_is_zero(vlen) != 1) {
		error_print();
		return -1;
	}
	if (!uri) {
		*crl = NULL;
		*crl_len = 0;
		return 0;
	}
	if (x509_crl_new_from_uri(crl, crl_len, uri, urilen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_cert_check_crl(const uint8_t *cert, size_t certlen, const uint8_t *cacert, size_t cacertlen,
	const char *ca_signer_id, size_t ca_signer_id_len)
{
	int ret = -1;
	uint8_t *crl = NULL;
	size_t crl_len = 0;
	const uint8_t *crl_issuer;
	size_t crl_issuer_len;

	const uint8_t *issuer;
	size_t issuer_len;
	const uint8_t *serial;
	size_t serial_len;

	time_t revoke_date;
	const uint8_t *crl_entry_exts;
	size_t crl_entry_exts_len;

	// download CRL and do basic validation
	if (x509_crl_new_from_cert(&crl, &crl_len, cert, certlen) != 1) {
		error_print();
		return -1;
	}
	if (x509_crl_check(crl, crl_len, time(NULL)) != 1) {
		error_print();
		goto end;
	}

	if (x509_cert_get_issuer_and_serial_number(cert, certlen, &issuer, &issuer_len, &serial, &serial_len) != 1) {
		error_print();
		goto end;
	}

	// make sure CRL's issuer is the certificate issuer
	if (x509_crl_get_issuer(crl, crl_len, &crl_issuer, &crl_issuer_len) != 1) {
		error_print();
		goto end;
	}
	if (x509_name_equ(issuer, issuer_len, crl_issuer, crl_issuer_len) != 1) {
		error_print();
		goto end;
	}

	// verify CRL
	if (x509_crl_verify_by_ca_cert(crl, crl_len, cacert, cacertlen, ca_signer_id, ca_signer_id_len) != 1) {
		error_print();
		goto end;
	}

	// check if the certificate in the CRL
	if ((ret = x509_crl_find_revoked_cert_by_serial_number(crl, crl_len, serial, serial_len,
		&revoke_date, &crl_entry_exts, &crl_entry_exts_len)) < 0) {
		error_print();
		goto end;
	}
	if (ret == 1) {
		ret = -1;
		error_print();
		goto end;
	}
	ret = 1;

end:
	if (crl) free(crl);
	return ret;
}
