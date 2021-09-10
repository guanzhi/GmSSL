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
#include <stdint.h>
#include <gmssl/error.h>

void print_der(const uint8_t *in, size_t inlen)
{
	size_t i;
	for (i = 0; i < inlen; i++) {
		printf("%02x ", in[i]);
	}
}

void print_bytes(const uint8_t *data, size_t datalen)
{
	size_t i;
	for (i = 0; i < datalen; i++) {
		printf("%02X ", data[i]);
		if ((i + 1) % 32 == 0)
			printf("\n");
	}
	printf("\n");
}

void print_nodes(const uint32_t *in, size_t inlen)
{
	size_t i;
	printf("%u", in[0]);
	for (i = 1; i < inlen; i++) {
		printf(".%u", in[i]);
	}
}



int format_print(FILE *fp, int format, int indent, const char *str, ...)
{
	va_list args;
	int i;
	for (i = 0; i < indent; i++) {
		fprintf(fp, " ");
	}
	va_start(args, str);
	vfprintf(fp, str, args);
	va_end(args);
	return 1;
}

int format_bytes(FILE *fp, int format, int indent, const char *str, const uint8_t *data, size_t datalen)
{
	int i;

	if (datalen > 4096) {
		error_print();
		return -1;
	}

	for (i = 0; i < indent; i++) {
		fprintf(fp, " ");
	}
	fprintf(fp, "%s", str);
	if (!datalen) {
		fprintf(fp, "(null)\n");
		return 1;
	}
	for (i = 0; i < datalen; i++) {
		fprintf(fp, "%02X", data[i]);
	}
	fprintf(fp, "\n");
	return 1;
}


int tls_trace(int format, int indent, const char *str, ...)
{
	FILE *fp = stderr;
	va_list args;
	int i;
	for (i = 0; i < indent; i++) {
		fprintf(fp, " ");
	}
	va_start(args, str);
	vfprintf(fp, str, args);
	va_end(args);
	fprintf(fp, "\n");
	return 1;
}

