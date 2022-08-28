/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#ifndef GMSSL_X509_STR_H
#define GMSSL_X509_STR_H


#include <time.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <gmssl/sm2.h>
#include <gmssl/oid.h>
#include <gmssl/asn1.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
DirectoryString or DirectoryName

DirectoryName ::= CHOICE {
	teletexString		TeletexString	(SIZE (1..MAX)),
	printableString		PrintableString	(SIZE (1..MAX)),
	universalString		UniversalString	(SIZE (1..MAX)),
	utf8String		UTF8String	(SIZE (1..MAX)),
	bmpString		BMPString	(SIZE (1..MAX)),
}
*/
int x509_directory_name_check(int tag, const uint8_t *d, size_t dlen);
int x509_directory_name_check_ex(int tag, const uint8_t *d, size_t dlen, size_t minlen, size_t maxlen);
int x509_directory_name_to_der(int tag, const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen);
int x509_directory_name_from_der(int *tag, const uint8_t **d, size_t *dlen, const uint8_t **in, size_t *inlen);
int x509_explicit_directory_name_to_der(int index, int tag, const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen);
int x509_explicit_directory_name_from_der(int index, int *tag, const uint8_t **d, size_t *dlen, const uint8_t **in, size_t *inlen);
int x509_directory_name_print(FILE *fp, int fmt, int ind, const char *label, int tag, const uint8_t *d, size_t dlen);


/*
DisplayText ::= CHOICE {
	ia5String		IA5String	(SIZE (1..200)),
	visibleString		VisibleString	(SIZE (1..200)),
	bmpString		BMPString	(SIZE (1..200)),
	utf8String		UTF8String	(SIZE (1..200))
}
*/
#define X509_DISPLAY_TEXT_MIN_LEN 1
#define X509_DISPLAY_TEXT_MAX_LEN 200

int x509_display_text_check(int tag, const uint8_t *d, size_t dlen);
int x509_display_text_to_der(int tag, const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen);
int x509_display_text_from_der(int *tag, const uint8_t **d, size_t *dlen, const uint8_t **in, size_t *inlen);
int x509_display_text_print(FILE *fp, int fmt, int ind, const char *label, int tag, const uint8_t *d, size_t dlen);


#ifdef __cplusplus
}
#endif
#endif
