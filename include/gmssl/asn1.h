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

#ifndef GMSSL_ASN1_H
#define GMSSL_ASN1_H


#include <time.h>
#include <stdlib.h>
#include <stdint.h>


#if __cplusplus
extern "C" {
#endif


#define ASN1_TAG_UNIVERSAL		0x00
#define ASN1_TAG_APPLICATION		0x40
#define ASN1_TAG_CONTENT_SPECIFIC	0x80
#define ASN1_TAG_PRIVATE		0xC0
#define ASN1_TAG_PRIMITIVE		0x00
#define ASN1_TAG_CONSTRUCTED		0x20

#define ASN1_TAG_IMPLICIT(index)	(ASN1_TAG_CONTENT_SPECIFIC|(index))
#define ASN1_TAG_EXPLICIT(index)	ASN1_TAG_IMPLICIT(ASN1_TAG_CONSTRUCTED|(index))


// https://www.obj-sys.com/asn1tutorial/node128.html

enum ASN1_TAG {
	ASN1_TAG_BOOLEAN		= 1,
	ASN1_TAG_INTEGER		= 2,
	ASN1_TAG_BIT_STRING		= 3,
	ASN1_TAG_OCTET_STRING		= 4,
	ASN1_TAG_NULL			= 5,
	ASN1_TAG_OBJECT_IDENTIFIER	= 6,
	ASN1_TAG_ObjectDescriptor	= 7,
	ASN1_TAG_EXTERNAL		= 8,
	ASN1_TAG_REAL			= 9,
	ASN1_TAG_ENUMERATED		= 10,
	ASN1_TAG_EMBEDDED		= 11,
	ASN1_TAG_UTF8String		= 12,
	ASN1_TAG_RELATIVE_OID		= 13,
	ASN1_TAG_NumericString		= 18,
	ASN1_TAG_PrintableString	= 19, // printable subset of ascii
	ASN1_TAG_TeletexString		= 20, // T61String
	ASN1_TAG_VideotexString		= 21,
	ASN1_TAG_IA5String		= 22, // 7-bit ascii
	ASN1_TAG_UTCTime		= 23,
	ASN1_TAG_GeneralizedTime	= 24,
	ASN1_TAG_GraphicString		= 25,
	ASN1_TAG_VisibleString		= 26,
	ASN1_TAG_GeneralString		= 27,
	ASN1_TAG_UniversalString	= 28,
	ASN1_TAG_CHARACTER_STRING	= 29,
	ASN1_TAG_BMPString		= 30, // 2-byte unicode with zeros
	ASN1_TAG_SEQUENCE		= 0x30,
	ASN1_TAG_SET			= 0x31,
	ASN1_TAG_EXPLICIT		= 0xa0,
};



#define ASN1_TRUE 0xff
#define ASN1_FALSE 0x00



// 用来解析未定义的OID
typedef struct {
	int oid;
	uint32_t nodes[16];
	size_t nodes_count;
} ASN1_OID_INFO;

const char *asn1_tag_name(int tag);




// private
void asn1_tag_to_der(int tag, uint8_t **out, size_t *outlen);
void asn1_length_to_der(size_t len, uint8_t **in, size_t *inlen);
void asn1_data_to_der(const uint8_t *data, size_t datalen, uint8_t **out, size_t *outlen);

int asn1_tag_from_der(int tag, const uint8_t **in, size_t *inlen);
int asn1_length_from_der(size_t *len, const uint8_t **in, size_t *inlen);
int asn1_data_from_der(const uint8_t **data, size_t datalen, const uint8_t **in, size_t *inlen);


const char *asn1_object_identifier_name(int oid);
const char *asn1_object_identifier_description(int oid);
int asn1_object_identifier_from_name(int *oid, const char *name);

int asn1_utf8_string_check(const char *a, size_t alen);
int asn1_printable_string_check(const char *a, size_t alen);
int asn1_ia5_string_check(const char *a, size_t alen);

int asn1_header_to_der(int tag, size_t len, uint8_t **out, size_t *outlen);
int asn1_type_to_der(int tag, const uint8_t *data, size_t datalen, uint8_t **out, size_t *outlen);
int asn1_type_from_der(int tag, const uint8_t **data, size_t *datalen, const uint8_t **in, size_t *inlen);

int asn1_type_copy_from_der(int tag, size_t maxlen, uint8_t *data, size_t *datalen, const uint8_t **in, size_t *inlen);
#define asn1_sequence_copy_from_der(maxl,d,dl,i,il) asn1_type_copy_from_der(ASN1_TAG_SEQUENCE,maxl,d,dl,i,il)
// FIXME: 调整一下参数位置，maxl放在dl前面

int asn1_any_tag_from_der(int *tag, const uint8_t **in, size_t *inlen);
int asn1_any_type_from_der(int *tag, const uint8_t **data, size_t *datalen, const uint8_t **in, size_t *inlen);

int asn1_any_from_der(const uint8_t **tlv, size_t *tlvlen, const uint8_t **in, size_t *inlen);

int asn1_boolean_to_der_ex(int tag, int val, uint8_t **out, size_t *outlen);
int asn1_integer_to_der_ex(int tag, const uint8_t *a, size_t alen, uint8_t **out, size_t *outlen);
int asn1_int_to_der_ex(int tag, int a, uint8_t **out, size_t *outlen);
int asn1_bit_string_to_der_ex(int tag, const uint8_t *bits, size_t nbits, uint8_t **out, size_t *outlen);
int asn1_bits_to_der_ex(int tag, int bits, uint8_t **out, size_t *outlen);
int asn1_null_to_der(uint8_t **out, size_t *outlen);
int asn1_object_identifier_to_der_ex(int tag, int oid, const uint32_t *nodes, size_t nodes_count, uint8_t **out, size_t *outlen);
int asn1_utf8_string_to_der_ex(int tag, const char *a, uint8_t **out, size_t *outlen);
int asn1_printable_string_to_der_ex(int tag, const char *a, uint8_t **out, size_t *outlen);
int asn1_ia5_string_to_der_ex(int tag, const char *a, uint8_t **out, size_t *outlen);
int asn1_utc_time_to_der_ex(int tag, time_t a, uint8_t **out, size_t *outlen);
int asn1_generalized_time_to_der_ex(int tag, time_t a, uint8_t **out, size_t *outlen);

int asn1_boolean_from_der_ex(int tag, int *val, const uint8_t **in, size_t *inlen);
int asn1_integer_from_der_ex(int tag, const uint8_t **a, size_t *alen, const uint8_t **in, size_t *inlen);
int asn1_int_from_der_ex(int tag, int *a, const uint8_t **in, size_t *inlen);
int asn1_bit_string_from_der_ex(int tag, const uint8_t **bits, size_t *nbits, const uint8_t **in, size_t *inlen);
int asn1_bits_from_der_ex(int tag, int *bits, const uint8_t **in, size_t *inlen);
int asn1_octet_string_from_der_ex(int tag, const uint8_t **a, size_t *alen, const uint8_t **in, size_t *inlen);
int asn1_null_from_der(const uint8_t **in, size_t *inlen);
int asn1_object_identifier_from_der_ex(int tag, int *oid, uint32_t *nodes, size_t *nodes_count, const uint8_t **in, size_t *inlen);
int asn1_utf8_string_from_der_ex(int tag, const char **a, size_t *alen, const uint8_t **in, size_t *inlen);
int asn1_printable_string_from_der_ex(int tag, const char **a, size_t *alen, const uint8_t **in, size_t *inlen);
int asn1_ia5_string_from_der_ex(int tag, const char **a, size_t *alen, const uint8_t **in, size_t *inlen);
int asn1_utc_time_from_der_ex(int tag, time_t *t, const uint8_t **in, size_t *inlen);
int asn1_generalized_time_from_der_ex(int tag, time_t *t, const uint8_t **in, size_t *inlen);



#define asn1_boolean_to_der(a,d,dl)			asn1_boolean_to_der_ex(ASN1_TAG_BOOLEAN,a,d,dl)
#define asn1_integer_to_der(a,al,d,dl)			asn1_integer_to_der_ex(ASN1_TAG_INTEGER,a,al,d,dl)
#define asn1_int_to_der(a,d,dl)				asn1_int_to_der_ex(ASN1_TAG_INTEGER,a,d,dl)
#define asn1_bit_string_to_der(a,al,d,dl)		asn1_bit_string_to_der_ex(ASN1_TAG_BIT_STRING,a,al,d,dl)
#define asn1_bits_to_der(a,d,dl)			asn1_bits_to_der_ex(ASN1_TAG_BIT_STRING,a,d,dl)
#define asn1_octet_string_to_der(a,al,d,dl)		asn1_type_to_der(ASN1_TAG_OCTET_STRING,a,al,d,dl)
#define asn1_object_identifier_to_der(oid,a,al,d,dl)	asn1_object_identifier_to_der_ex(ASN1_TAG_OBJECT_IDENTIFIER,oid,a,al,d,dl)
#define asn1_utf8_string_to_der(a,d,dl)			asn1_utf8_string_to_der_ex(ASN1_TAG_UTF8String,a,d,dl)
#define asn1_printable_string_to_der(a,d,dl)		asn1_printable_string_to_der_ex(ASN1_TAG_PrintableString,a,d,dl)
#define asn1_ia5_string_to_der(a,d,dl)			asn1_ia5_string_to_der_ex(ASN1_TAG_IA5String,a,d,dl)
#define asn1_utc_time_to_der(a,d,dl)			asn1_utc_time_to_der_ex(ASN1_TAG_UTCTime,a,d,dl)
#define asn1_generalized_time_to_der(a,d,dl)		asn1_generalized_time_to_der_ex(ASN1_TAG_GeneralizedTime,a,d,dl)
#define asn1_sequence_header_to_der(al,d,dl)		asn1_header_to_der(ASN1_TAG_SEQUENCE,al,d,dl)
#define asn1_set_header_to_der(al,d,dl)			asn1_header_to_der(ASN1_TAG_SET,al,d,dl)
#define asn1_explicit_header_to_der(i,al,d,dl)		asn1_header_to_der(ASN1_TAG_EXPLICIT(i),al,d,dl)
#define asn1_sequence_to_der(a,al,d,dl)			asn1_type_to_der(ASN1_TAG_SEQUENCE,a,al,d,dl)
#define asn1_set_to_der(a,al,d,dl)			asn1_type_to_der(ASN1_TAG_SET,a,al,d,dl)
#define asn1_explicit_to_der(i,a,al,d,dl)		asn1_type_to_der(ASN1_TAG_EXPLICIT(i),a,al,d,dl)

#define asn1_boolean_from_der(a,d,dl)			asn1_boolean_from_der_ex(ASN1_TAG_BOOLEAN,a,d,dl)
#define asn1_integer_from_der(a,al,d,dl)		asn1_integer_from_der_ex(ASN1_TAG_INTEGER,a,al,d,dl)
#define asn1_int_from_der(a,d,dl)			asn1_int_from_der_ex(ASN1_TAG_INTEGER,a,d,dl)
#define asn1_bit_string_from_der(a,al,d,dl)		asn1_bit_string_from_der_ex(ASN1_TAG_BIT_STRING,a,al,d,dl)
#define asn1_bits_from_der(a,d,dl)			asn1_bits_from_der_ex(ASN1_TAG_BIT_STRING,a,d,dl)
#define asn1_octet_string_from_der(a,al,d,dl)		asn1_type_from_der(ASN1_TAG_OCTET_STRING,a,al,d,dl)
#define asn1_object_identifier_from_der(oid,a,al,d,dl)	asn1_object_identifier_from_der_ex(ASN1_TAG_OBJECT_IDENTIFIER,oid,a,al,d,dl)
#define asn1_utf8_string_from_der(a,al,d,dl)		asn1_utf8_string_from_der_ex(ASN1_TAG_UTF8String,a,al,d,dl)
#define asn1_printable_string_from_der(a,al,d,dl)	asn1_printable_string_from_der_ex(ASN1_TAG_PrintableString,a,al,d,dl)
#define asn1_ia5_string_from_der(a,al,d,dl)		asn1_ia5_string_from_der_ex(ASN1_TAG_IA5String,a,al,d,dl)
#define asn1_utc_time_from_der(a,d,dl)			asn1_utc_time_from_der_ex(ASN1_TAG_UTCTime,a,d,dl)
#define asn1_generalized_time_from_der(a,d,dl)		asn1_generalized_time_from_der_ex(ASN1_TAG_GeneralizedTime,a,d,dl)
#define asn1_sequence_from_der(a,al,d,dl)		asn1_type_from_der(ASN1_TAG_SEQUENCE,a,al,d,dl)
#define asn1_set_from_der(a,al,d,dl)			asn1_type_from_der(ASN1_TAG_SET,a,al,d,dl)
#define asn1_implicit_from_der(i,a,al,d,dl)		asn1_type_from_der(ASN1_TAG_EXPLICIT(i),a,al,d,dl)
#define asn1_explicit_from_der(i,a,al,d,dl)		asn1_type_from_der(ASN1_TAG_EXPLICIT(i),a,al,d,dl)

#define asn1_implicit_boolean_to_der(i,a,d,dl)			asn1_boolean_to_der_ex(ASN1_TAG_IMPLICIT(i),a,d,dl)
#define asn1_implicit_integer_to_der(i,a,al,d,dl)		asn1_integer_to_der_ex(ASN1_TAG_IMPLICIT(i),a,al,d,dl)
#define asn1_implicit_int_to_der(i,a,d,dl)			asn1_int_to_der_ex(ASN1_TAG_IMPLICIT(i),a,d,dl)
#define asn1_implicit_bit_string_to_der(i,a,al,d,dl)		asn1_bit_string_to_der_ex(ASN1_TAG_IMPLICIT(i),a,al,d,dl)
#define asn1_implicit_bits_to_der(i,a,d,dl)			asn1_bits_to_der_ex(ASN1_TAG_IMPLICIT(i),a,d,dl)
#define asn1_implicit_octet_string_to_der(i,a,al,d,dl)		asn1_type_to_der(ASN1_TAG_IMPLICIT(i),a,al,d,dl)
#define asn1_implicit_object_identifier_to_der(i,oid,a,al,d,dl)	asn1_object_identifier_to_der_ex(ASN1_TAG_IMPLICIT(i),oid,a,al,d,dl)
#define asn1_implicit_utf8_string_to_der(i,a,d,dl)		asn1_utf8_string_to_der_ex(ASN1_TAG_IMPLICIT(i),a,d,dl)
#define asn1_implicit_printable_string_to_der(i,a,d,dl)		asn1_printable_string_to_der_ex(ASN1_TAG_IMPLICIT(i),a,d,dl)
#define asn1_implicit_ia5_string_to_der(i,a,d,dl)		asn1_ia5_string_to_der_ex(ASN1_TAG_IMPLICIT(i),a,d,dl)
#define asn1_implicit_utc_time_to_der(i,a,d,dl)			asn1_utc_time_to_der_ex(ASN1_TAG_IMPLICIT(i),a,d,dl)
#define asn1_implicit_generalized_time_to_der(i,a,d,dl)		asn1_generalized_time_to_der_ex(ASN1_TAG_IMPLICIT(i),a,d,dl)
#define asn1_implicit_sequence_header_to_der(i,al,d,dl)		asn1_header_to_der(ASN1_TAG_EXPLICIT(i),al,d,dl)
#define asn1_implicit_set_header_to_der(i,al,d,dl)		asn1_header_to_der(ASN1_TAG_EXPLICIT(i),al,d,dl)
#define asn1_implicit_sequence_to_der(i,a,al,d,dl)		asn1_type_to_der(ASN1_TAG_EXPLICIT(i),a,al,d,dl)
#define asn1_implicit_set_to_der(i,a,al,d,dl)			asn1_type_to_der(ASN1_TAG_EXPLICIT(i),a,al,d,dl)

#define asn1_implicit_boolean_from_der(i,a,d,dl)			asn1_boolean_from_der_ex(ASN1_TAG_IMPLICIT(i),a,d,dl)
#define asn1_implicit_integer_from_der(i,a,al,d,dl)			asn1_integer_from_der_ex(ASN1_TAG_IMPLICIT(i),a,al,d,dl)
#define asn1_implicit_int_from_der(i,a,d,dl)				asn1_int_from_der_ex(ASN1_TAG_IMPLICIT(i),a,d,dl)
#define asn1_implicit_bit_string_from_der(i,a,al,d,dl)			asn1_bit_string_from_der_ex(ASN1_TAG_IMPLICIT(i),a,al,d,dl)
#define asn1_implicit_bits_from_der(i,a,d,dl)				asn1_bits_from_der_ex(ASN1_TAG_IMPLICIT(i),a,d,dl)
#define asn1_implicit_octet_string_from_der(i,a,al,d,dl)		asn1_type_from_der(ASN1_TAG_IMPLICIT(i),a,al,d,dl)
#define asn1_implicit_object_identifier_from_der(i,oid,a,al,d,dl)	asn1_object_identifier_from_der_ex(ASN1_TAG_IMPLICIT(i),oid,a,al,d,dl)
#define asn1_implicit_utf8_string_from_der(i,a,d,dl)			asn1_utf8_string_from_der_ex(ASN1_TAG_IMPLICIT(i),a,d,dl)
#define asn1_implicit_printable_string_from_der(i,a,d,dl)		asn1_printable_string_from_der_ex(ASN1_TAG_IMPLICIT(i),a,d,dl)
#define asn1_implicit_ia5_string_from_der(i,a,d,dl)			asn1_ia5_string_from_der_ex(ASN1_TAG_IMPLICIT(i),a,d,dl)
#define asn1_implicit_utc_time_from_der(i,a,d,dl)			asn1_utc_time_from_der_ex(ASN1_TAG_IMPLICIT(i),a,d,dl)
#define asn1_implicit_generalized_time_from_der(i,a,d,dl)		asn1_generalized_time_from_der_ex(ASN1_TAG_IMPLICIT(i),a,d,dl)
#define asn1_implicit_sequence_from_der(i,a,al,d,dl)			asn1_type_from_der(ASN1_TAG_EXPLICIT(i),a,al,d,dl)
#define asn1_implicit_set_from_der(i,a,al,d,dl)				asn1_type_from_der(ASN1_TAG_EXPLICIT(i),a,al,d,dl)


int asn1_cstring_to_der(int tag, const char *a, uint8_t **out, size_t *outlen);
int asn1_cstring_from_der(int tag, const char **a, size_t *alen, const uint8_t **in, size_t *inlen);




typedef struct {
	size_t datalen;
	uint8_t data[1];
} ASN1_SEQUENCE_OF;

int asn1_sequence_of_get_next_item(const ASN1_SEQUENCE_OF *a, const uint8_t **next, const uint8_t **data, size_t *datalen);
int asn1_sequence_of_get_count(const ASN1_SEQUENCE_OF *a, size_t *count);


int asn1_check(int expr);
int asn1_length_is_zero(size_t len);



#if __cplusplus
}
#endif
#endif
