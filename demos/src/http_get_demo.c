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
#include <gmssl/http.h>
#include <gmssl/error.h>

char *http_uri = "http://mscrl.microsoft.com/pki/mscorp/crl/Microsoft%20RSA%20TLS%20CA%2002.crl";
char *file_name = "Microsoft RSA TLS CA 02.crl";

int main(int argc, char **argv)
{
	uint8_t *buf = NULL;
	size_t buflen;
	size_t len;
	FILE *fp = NULL;

	printf("http_get %s\n", http_uri);

	if (http_get(http_uri, NULL, &buflen, 0) != 1) {
		fprintf(stderr, "http_get() error\n");
		goto err;
	}

	if (!(buf = malloc(len))) {
		fprintf(stderr, "malloc() error\n");
		goto err;
	}

	if (http_get(http_uri, buf, &len, buflen) != 1) {
		fprintf(stderr, "http_get() error\n");
		goto err;
	}

	if (!(fp = fopen(file_name, "wb"))) {
		fprintf(stderr, "fopen() error\n");
		goto err;
	}

	fwrite(buf, 1, len, fp);

	printf("save to %s\n", file_name);

err:
	if (buf) free(buf);
	if (fp) fclose(fp);
	return 0;
}
