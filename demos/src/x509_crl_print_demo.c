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


char *crl_file = "../../demos/certs/crl/Civil Servant ROOT.crl";

int main(int argc, char **argv)
{
	int ret = -1;
	uint8_t *der = NULL;
	size_t derlen;
	const uint8_t *cp;
	const uint8_t *crl;
	size_t crllen;

	printf("Demo - Read and print CRL in DER-encoding\n");

	if (file_read_all(crl_file, &der, &derlen) != 1) {
		fprintf(stderr, "file_read_all() error\n");
		goto err;
	}

	cp = der;
	if (x509_crl_from_der(&crl, &crllen, &cp, &derlen) != 1) {
		fprintf(stderr, "x509_crl_from_der() error\n");
		goto err;
	}

	x509_crl_print(stdout, 0, 0, "CRL", crl, crllen);

	ret = 0;
err:
	if (der) free(der);
	return ret;
}
