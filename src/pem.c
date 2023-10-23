/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <gmssl/pem.h>
#include <gmssl/error.h>


static int remove_newline(char *line)
{
	size_t len;
	len = strlen(line);

	if (len >= 2) {
		if (line[len - 2] == '\r' && line[len - 1] == '\n') {
			line[len - 2] = line[len - 1] = 0;
			return 1;
		}
	}
	if (len) {
		if (line[len - 1] == '\n') {
			line[len - 1] = 0;
			return 1;
		}
	}
	return 0; // No newline found, might not be an error
}

int pem_write(FILE *fp, const char *name, const uint8_t *data, size_t datalen)
{
	BASE64_CTX ctx;
	uint8_t out[168];
	int inlen, outlen;

	if (!datalen) {
		error_print();
		return -1;
	}
	if (datalen > INT_MAX) {
		error_print();
		return -1;
	}

	fprintf(fp, "-----BEGIN %s-----\n", name);
	base64_encode_init(&ctx);
	while (datalen) {
		inlen = datalen < 48 ? (int)datalen : 48;
		base64_encode_update(&ctx, data, inlen, out, &outlen);
		fwrite(out, 1, outlen, fp);
		data += inlen;
		datalen -= inlen;
	}
	base64_encode_finish(&ctx, out, &outlen);
	fwrite(out, 1, outlen, fp);
	fprintf(fp, "-----END %s-----\n", name);

	return 1;
}

int pem_read(FILE *fp, const char *name, uint8_t *data, size_t *datalen, size_t maxlen)
{
	char line[80];
	char begin_line[80];
	char end_line[80];
	int len;
	BASE64_CTX ctx;

	snprintf(begin_line, sizeof(begin_line), "-----BEGIN %s-----", name);
	snprintf(end_line, sizeof(end_line), "-----END %s-----", name);

	if (feof(fp)) {
		error_print();
		return 0;
	}

	if (!fgets(line, sizeof(line), fp)) {
		if (feof(fp)) {
			error_print();
			return 0;
		} else {
			error_print();
			return -1;
		}
	}
	remove_newline(line);

	if (strcmp(line, begin_line) != 0) {
		fprintf(stderr, "%s %d: %s\n", __FILE__, __LINE__, line);
		fprintf(stderr, "%s %d: %s\n", __FILE__, __LINE__, begin_line);
		error_print();
		return -1;
	}

	*datalen = 0;

	base64_decode_init(&ctx);

	for (;;) {
		if (!fgets(line, sizeof(line), fp)) {
			error_print();
			return -1;
		}
		remove_newline(line);

		if (strcmp(line, end_line) == 0) {
			break;
		}

		base64_decode_update(&ctx, (uint8_t *)line, (int)strlen(line), data, &len);
		data += len;
		*datalen += len;
	}

	base64_decode_finish(&ctx, data, &len);
	*datalen += len;
	return 1;
}
