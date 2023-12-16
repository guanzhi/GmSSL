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


char *http_uri = "http://mscrl.microsoft.com/pki/mscorp/crl/Microsoft%20RSA%20TLS%20CA%2002.crl";
char *file_name = "Microsoft RSA TLS CA 02.crl";

int main(int argc, char **argv)
{
	int ret = -1;
	uint8_t *crl = NULL;
	size_t crllen;
	FILE *fp = NULL;

	printf("Demo - Download CRL from HTTP\n\n");

	printf("    Download from %s\n", http_uri);

	if (x509_crl_new_from_uri(&crl, &crllen, http_uri, strlen(http_uri)) != 1) {
		fprintf(stderr, "x509_crl_new_from_uri() error\n");
		goto err;
	}

	//x509_crl_print(stdout, 0, 0, "CRL", crl, crllen);

	if (!(fp = fopen(file_name, "wb"))) {
		fprintf(stderr, "fopen() error\n");
		goto err;
	}
	fwrite(crl, 1, crllen, fp);

	printf("    Save to %s\n", file_name);
	printf("    Run `gmssl crlparse -in \"%s\"` to print the downloaded CRL\n", file_name);
	printf("\n");

	ret = 0;
err:
	if (crl) free(crl);
	if (fp) fclose(fp);
	return ret;
}
