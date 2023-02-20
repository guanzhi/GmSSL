/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#ifndef GMSSL_ERROR_H
#define GMSSL_ERROR_H


#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


#define GMSSL_FMT_BIN	1
#define GMSSL_FMT_HEX	2
#define GMSSL_FMT_DER	4
#define GMSSL_FMT_PEM	8



#define DEBUG 1

#define warning_print() \
	do { if (DEBUG) fprintf(stderr, "%s:%d:%s():\n",__FILE__, __LINE__, __func__); } while (0)

#define error_print() \
	do { if (DEBUG) fprintf(stderr, "%s:%d:%s():\n",__FILE__, __LINE__, __func__); } while (0)

#define error_print_msg(fmt, ...) \
	do { if (DEBUG) fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, __LINE__, __func__, __VA_ARGS__); } while (0)

#define error_puts(str) \
            do { if (DEBUG) fprintf(stderr, "%s: %d: %s: %s", __FILE__, __LINE__, __func__, str); } while (0)


void print_der(const uint8_t *in, size_t inlen);
void print_bytes(const uint8_t *in, size_t inlen);
void print_nodes(const uint32_t *in, size_t inlen);

#define FMT_CARRAY 0x80


int format_print(FILE *fp, int format, int indent, const char *str, ...);
int format_bytes(FILE *fp, int format, int indent, const char *str, const uint8_t *data, size_t datalen);
int format_string(FILE *fp, int format, int indent, const char *str, const uint8_t *data, size_t datalen);



//int tls_trace(int format, int indent, const char *str, ...);


#ifdef __cplusplus
}
#endif
#endif
