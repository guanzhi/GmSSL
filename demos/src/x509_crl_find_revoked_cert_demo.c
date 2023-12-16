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
#include <gmssl/file.h>
#include <gmssl/x509_crl.h>

// 为了这些demo，应该准备好测试的文件，而不是把文件都放在源代码里面
// 这样会更灵活一些

int main(int argc, char **argv)
{
	int ret = -1;

	uint8_t *crl;
	size_t crllen;

	char *cert;
	size_t certlen;

	const uint8_t *cert_serial;
	size_t cert_serial_len;
	time_t cert_revoke_date;
	const uint8_t *crl_entry_exts;
	size_t crl_entry_exts_len;

	int revoked;

	printf("Demo - Check if a Certificate has been revoked in a CRL\n");


	if (x509_cert_get_issuer_and_serial_number(cert, certlen,
		NULL, NULL, &cert_serial, &cert_serial_len) != 1) {
		fprintf(stderr, "x509_cert_get_issuer_and_serial_number() error\n");
		goto err;
	}

	if ((revoked = x509_crl_find_revoked_cert_by_serial_number(
		crl, crllen,
		cert_serial, cert_serial_len,
		&cert_revoked_date,
		&crl_entry_exts, &crl_entry_exts_len)) == -1) {

		fprintf(stderr, "x509_crl_find_revoked_cert_by_serial_number() error\n");
		goto err;
	}

	if (revoked) {
		printf("    The certificate has been revoked\n");
		format_bytes(stderr, 0, 4, "SerialNumber", cert_serial, cert_serial_len);
		x509_crl_entry_exts_print(stderr, 0, 4, "CRLEntryExts", crl_entry_exts, crl_entry_exts_len);
	} else {
		printf("    The certificate not in the given CRL\n");
	}

	ret = 0;
err:
	if (der) free(der);
	return ret;
}
