/*
 * Copyright (c) 2014 - 2020 The GmSSL Project.  All rights reserved.
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
#include <stdint.h>
#include <assert.h>
#include <gmssl/sm2.h>
#include <gmssl/oid.h>
#include <gmssl/pem.h>
#include <gmssl/asn1.h>
#include <gmssl/x509_str.h>
#include <gmssl/error.h>

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


int x509_directory_name_check(int tag, const uint8_t *d, size_t dlen)
{
	switch (tag) {
	case ASN1_TAG_TeletexString:
	case ASN1_TAG_PrintableString:
	case ASN1_TAG_UniversalString:
	case ASN1_TAG_UTF8String:
		if (d && strnlen((char *)d, dlen) != dlen) {
			error_print();
			return -1;
		}
		break;
	case ASN1_TAG_BMPString:
		if (d && dlen % 2) {
			error_print();
			return -1;
		}
		break;
	default:
		error_print();
		return -1;
	}
	return 1;
}

int x509_directory_name_check_ex(int tag, const uint8_t *d, size_t dlen, size_t minlen, size_t maxlen)
{
	if (x509_directory_name_check(tag, d, dlen) != 1) {
		error_print();
		return -1;
	}
	if (dlen < minlen || dlen > maxlen) {
		printf("%s %d: dlen = %zu, minlen = %zu, maxlne = %zu\n", __FILE__, __LINE__, dlen, minlen, maxlen);
		error_print();
		return -1;
	}
	return 1;
}

int x509_directory_name_to_der(int tag, const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen)
{
	int ret;
	if (x509_directory_name_check(tag, d, dlen) != 1) {
		error_print();
		return -1;
	}
	if ((ret = asn1_type_to_der(tag, d, dlen, out, outlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	return 1;
}

int x509_directory_name_from_der(int *tag, const uint8_t **d, size_t *dlen, const uint8_t **in, size_t *inlen)
{
	int ret;

	if ((ret = asn1_tag_get(tag, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	switch (*tag) {
	case ASN1_TAG_TeletexString:
	case ASN1_TAG_PrintableString:
	case ASN1_TAG_UniversalString:
	case ASN1_TAG_UTF8String:
	case ASN1_TAG_BMPString:
		break;
	default:
		return 0;
	}

	if ((ret = asn1_any_type_from_der(tag, d, dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (x509_directory_name_check(*tag, *d, *dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_explicit_directory_name_to_der(int index, int tag, const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen)
{
	int ret;
	size_t len = 0;

	if ((ret = x509_directory_name_to_der(tag, d, dlen, NULL, &len)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_explicit_header_to_der(index, len, out, outlen) != 1
		|| x509_directory_name_to_der(tag, d, dlen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_explicit_directory_name_from_der(int index, int *tag, const uint8_t **d, size_t *dlen, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *p;
	size_t len;

	if ((ret = asn1_explicit_from_der(index, &p, &len, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (x509_directory_name_from_der(tag, d, dlen, &p, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_directory_name_print(FILE *fp, int fmt, int ind, const char *label, int tag, const uint8_t *d, size_t dlen)
{
	return asn1_string_print(fp, fmt, ind, label, tag, d, dlen);
}

int x509_display_text_check(int tag, const uint8_t *d, size_t dlen)
{
	switch (tag) {
	case ASN1_TAG_IA5String:
	case ASN1_TAG_VisibleString:
	case ASN1_TAG_UTF8String:
		if (d && strnlen((char *)d, dlen) != dlen) {
			error_print();
			return -1;
		}
		break;
	case ASN1_TAG_BMPString:
		if (d && dlen % 2) {
			error_print();
			return -1;
		}
		break;
	default:
		error_print();
		return -1;
	}
	if (dlen < X509_DISPLAY_TEXT_MIN_LEN || dlen > X509_DISPLAY_TEXT_MAX_LEN) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_display_text_to_der(int tag, const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen)
{
	int ret;
	if (x509_display_text_check(tag, d, dlen) != 1) {
		error_print();
		return -1;
	}
	if ((ret = asn1_type_to_der(tag, d, dlen, out, outlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	return 1;
}

int x509_display_text_from_der(int *tag, const uint8_t **d, size_t *dlen, const uint8_t **in, size_t *inlen)
{
	int ret;

	if ((ret = asn1_tag_get(tag, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	switch (*tag) {
	case ASN1_TAG_IA5String:
	case ASN1_TAG_VisibleString:
	case ASN1_TAG_UTF8String:
	case ASN1_TAG_BMPString:
		break;
	default:
		return 0;
	}

	if ((ret = asn1_any_type_from_der(tag, d, dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (x509_display_text_check(*tag, *d, *dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_display_text_print(FILE *fp, int fmt, int ind, const char *label, int tag, const uint8_t *d, size_t dlen)
{
	return asn1_string_print(fp, fmt, ind, label, tag, d, dlen);
}
