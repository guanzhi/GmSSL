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

int main(int argc, char **argv)
{
	uint8_t buf[65536];
	uint8_t *content;
	size_t contentlen;

	if (argc < 2) {
		printf("usage: %s <uri>\n", argv[0]);
		return 1;
	}
	if (http_get(argv[1], buf, sizeof(buf), &content, &contentlen) != 1) {
		error_print();
		return -1;
	}
	fwrite(content, contentlen, 1, stdout);
	return 0;
}
