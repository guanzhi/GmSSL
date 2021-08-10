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


#ifndef GMSSL_ERROR_H
#define GMSSL_ERROR_H


#include <stdio.h>
#include <stdarg.h>


#ifdef __cplusplus
extern "C" {
#endif


#define DEBUG 1

#define error_print() \
	do { if (DEBUG) fprintf(stderr, "%s:%d:%s():\n",__FILE__, __LINE__, __func__); } while (0)

#define error_print_msg(fmt, ...) \
	do { if (DEBUG) fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, __LINE__, __func__, __VA_ARGS__); } while (0)

#define error_puts(str) \
            do { if (DEBUG) fprintf(stderr, "%s: %d: %s: %s", __FILE__, __LINE__, __func__, str); } while (0)


void print_der(const uint8_t *in, size_t inlen);
void print_bytes(const uint8_t *in, size_t inlen);
void print_nodes(const uint32_t *in, size_t inlen);


int format_print(FILE *fp, int format, int indent, const char *str, ...);
int format_bytes(FILE *fp, int format, int indent, const char *str, const uint8_t *data, size_t datalen);

//int tls_trace(int format, int indent, const char *str, ...);


#ifdef __cplusplus
}
#endif
#endif
