/*
 * Copyright (c) 2020 - 2021 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
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
