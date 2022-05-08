/*
 * Copyright (c) 2014 - 2021 The GmSSL Project.  All rights reserved.
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
