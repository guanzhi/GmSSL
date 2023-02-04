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
#include <gmssl/x509_str.h>
#include <gmssl/x509_req.h>
#include <gmssl/x509.h>
#include <gmssl/error.h>
#include <gmssl/file.h>

#include <errno.h>
#include <sys/stat.h>

/*
DirectoryString ::= CHOICE {
	teletexString		TeletexString (SIZE (1..MAX)),
	printableString 	PrintableString (SIZE (1..MAX)),
	universalString		UniversalString (SIZE (1..MAX)),
	utf8String		UTF8String (SIZE (1..MAX)),
	bmpString		BMPString (SIZE (1..MAX)) }

BMPString has zeros!
	"Cert" in BMPStirng is 00 43 00 65 00 72 00 74

RDN 中很多值都是这个类型，但是有特定的长度限制，因此这个函数应该增加一个长度限制选项。
*/






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
