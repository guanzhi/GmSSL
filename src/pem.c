/* 
 *   Copyright 2014-2021 The GmSSL Project Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/pem.h>
#include <gmssl/error.h>


int pem_write(FILE *fp, const char *name, const uint8_t *data, size_t datalen)
{
	int ret = 0;
	BASE64_CTX ctx;
	uint8_t b64[datalen * 2];
	int len;

	base64_encode_init(&ctx);
	base64_encode_update(&ctx, data, (int)datalen, b64, &len);
	base64_encode_finish(&ctx, b64 + len, &len);

	ret += fprintf(fp, "-----BEGIN %s-----\n", name);
	ret += fprintf(fp, "%s", (char *)b64);
	ret += fprintf(fp, "-----END %s-----\n", name);
	return ret;
}

int pem_read(FILE *fp, const char *name, uint8_t *data, size_t *datalen)
{
	char line[80];
	char begin_line[80];
	char end_line[80];
	int len;
	BASE64_CTX ctx;

	snprintf(begin_line, sizeof(begin_line), "-----BEGIN %s-----\n", name);
	snprintf(end_line, sizeof(end_line), "-----END %s-----\n", name);

	if (!fgets(line, sizeof(line), fp)) {
		//FIXME: feof 判断是不是文件结束了呢
		return 0;
	}

	if (strcmp(line, begin_line) != 0) {
		// FIXME: 这里是不是应该容忍一些错误呢？
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
		if (strcmp(line, end_line) == 0) {
			break;
		}

		base64_decode_update(&ctx, (uint8_t *)line, strlen(line), data, &len);
		data += len;
		*datalen += len;
	}

	base64_decode_finish(&ctx, data, &len);
	*datalen += len;
	return 1;
}
