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

// https://www.obj-sys.com/asn1tutorial/node128.html


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

const char *asn1_tag_name(int tag);
int asn1_tag_to_der(int tag, uint8_t **out, size_t *outlen);
int asn1_tag_from_der(int tag, const uint8_t **in, size_t *inlen);
int asn1_any_tag_from_der(int *tag, const uint8_t **in, size_t *inlen);
int asn1_tag_get(int *tag, const uint8_t **in, size_t *inlen); // 这个函数是看看下一个tag是什么，并不修改in,inlen
int asn1_tag_is_cstring(int tag);
int asn1_length_to_der(size_t len, uint8_t **in, size_t *inlen);
int asn1_length_from_der(size_t *len, const uint8_t **in, size_t *inlen);
int asn1_length_is_zero(size_t len);
int asn1_data_to_der(const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen);
int asn1_data_from_der(const uint8_t **d, size_t dlen, const uint8_t **in, size_t *inlen);

int asn1_type_to_der(int tag, const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen);
int asn1_type_from_der(int tag, const uint8_t **d, size_t *dlen, const uint8_t **in, size_t *inlen);
int asn1_any_type_from_der(int *tag, const uint8_t **d, size_t *dlen, const uint8_t **in, size_t *inlen);
int asn1_any_to_der(const uint8_t *a, size_t alen, uint8_t **out, size_t *outlen);
int asn1_any_from_der(const uint8_t **a, size_t *alen, const uint8_t **in, size_t *inlen);

int asn1_boolean_to_der_ex(int tag, int val, uint8_t **out, size_t *outlen);
int asn1_boolean_from_der_ex(int tag, int *val, const uint8_t **in, size_t *inlen);
#define asn1_boolean_to_der(val,out,outlen)			asn1_boolean_to_der_ex(ASN1_TAG_BOOLEAN,val,out,outlen)
#define asn1_boolean_from_der(val,in,inlen)			asn1_boolean_from_der_ex(ASN1_TAG_BOOLEAN,val,in,inlen)
#define asn1_implicit_boolean_to_der(idx,val,out,outlen)	asn1_boolean_to_der_ex(ASN1_TAG_IMPLICIT(idx),val,out,outlen)
#define asn1_implicit_boolean_from_der(idx,val,in,inlen)	asn1_boolean_from_der_ex(ASN1_TAG_IMPLICIT(idx),val,in,inlen)

int asn1_integer_to_der_ex(int tag, const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen);
int asn1_integer_from_der_ex(int tag, const uint8_t **d, size_t *dlen, const uint8_t **in, size_t *inlen);
#define asn1_integer_to_der(d,dlen,out,outlen)			asn1_integer_to_der_ex(ASN1_TAG_INTEGER,d,dlen,out,outlen)
#define asn1_integer_from_der(d,dlen,in,inlen)			asn1_integer_from_der_ex(ASN1_TAG_INTEGER,d,dlen,in,inlen)
#define asn1_implicit_integer_to_der(idx,d,dlen,out,outlen)	asn1_integer_to_der_ex(ASN1_TAG_IMPLICIT(idx),d,dlen,out,outlen)
#define asn1_implicit_integer_from_der(idx,d,dlen,in,inlen)	asn1_integer_from_der_ex(ASN1_TAG_IMPLICIT(idx),d,dlen,in,inlen)

int asn1_int_to_der_ex(int tag, int a, uint8_t **out, size_t *outlen);
int asn1_int_from_der_ex(int tag, int *a, const uint8_t **in, size_t *inlen);
#define asn1_int_to_der(val,out,outlen)				asn1_int_to_der_ex(ASN1_TAG_INTEGER,val,out,outlen)
#define asn1_int_from_der(val,in,inlen)				asn1_int_from_der_ex(ASN1_TAG_INTEGER,val,in,inlen)
#define asn1_implicit_int_to_der(idx,val,out,outlen)		asn1_int_to_der_ex(ASN1_TAG_IMPLICIT(idx),val,out,outlen)
#define asn1_implicit_int_from_der(idx,val,in,inlen)		asn1_int_from_der_ex(ASN1_TAG_IMPLICIT(idx),val,in,inlen)

int asn1_bit_string_to_der_ex(int tag, const uint8_t *d, size_t nbits, uint8_t **out, size_t *outlen);
int asn1_bit_string_from_der_ex(int tag, const uint8_t **d, size_t *nbits, const uint8_t **in, size_t *inlen);
#define asn1_bit_string_to_der(d,nbits,out,outlen)		asn1_bit_string_to_der_ex(ASN1_TAG_BIT_STRING,d,nbits,out,outlen)
#define asn1_bit_string_from_der(d,nbits,in,inlen)		asn1_bit_string_from_der_ex(ASN1_TAG_BIT_STRING,d,nbits,in,inlen)
#define asn1_implicit_bit_string_to_der(idx,d,nbits,out,outlen)	asn1_bit_string_to_der_ex(ASN1_TAG_IMPLICIT(idx),d,nbits,out,outlen)
#define asn1_implicit_bit_string_from_der(idx,d,nbits,in,inlen)	asn1_bit_string_from_der_ex(ASN1_TAG_IMPLICIT(idx),d,nbits,in,inlen)

int asn1_bit_octets_to_der_ex(int tag, const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen);
int asn1_bit_octets_from_der_ex(int tag, const uint8_t **d, size_t *dlen, const uint8_t **in, size_t *inlen);
#define asn1_bit_octets_to_der(d,dlen,out,outlen)		asn1_bit_octets_to_der_ex(ASN1_TAG_BIT_STRING,d,dlen,out,outlen)
#define asn1_bit_octets_from_der(d,dlen,in,inlen)		asn1_bit_octets_from_der_ex(ASN1_TAG_BIT_STRING,d,dlen,out,outlen)
#define asn1_implicit_bit_octets_to_der(idx,d,dlen,out,outlen)	asn1_bit_octets_to_der_ex(ASN1_TAG_IMPLICIT(idx),d,dlen,out,outlen)
#define asn1_implicit_bit_octets_from_der(idx,d,dlen,in,inlen)	asn1_bit_octets_from_der_ex(ASN1_TAG_IMPLICIT(idx),d,dlen,out,outlen)

int asn1_bits_to_der_ex(int tag, int bits, uint8_t **out, size_t *outlen);
int asn1_bits_from_der_ex(int tag, int *bits, const uint8_t **in, size_t *inlen);
#define asn1_bits_to_der(val,out,outlen)			asn1_bits_to_der_ex(ASN1_TAG_BIT_STRING,val,out,outlen)
#define asn1_bits_from_der(val,out,outlen)			asn1_bits_from_der_ex(ASN1_TAG_BIT_STRING,val,out,outlen)
#define asn1_implicit_bits_to_der(idx,val,out,outlen)		asn1_bits_to_der_ex(ASN1_TAG_IMPLICIT(idx),val,out,outlen)
#define asn1_implicit_bits_from_der(idx,val,out,outlen)		asn1_bits_from_der_ex(ASN1_TAG_IMPLICIT(idx),val,out,outlen)
int asn1_bits_print(FILE *fp, int fmt, int ind, const char *label, const char **names, size_t names_cnt, int bits);

#define asn1_octet_string_to_der_ex(tag,a,alen,d,dlen)	asn1_type_to_der(tag,a,alen,d,dlen)
#define asn1_octet_string_from_der_ex(tag,a,alen,d,dlen)	asn1_type_from_der(tag,a,alen,d,dlen)
#define asn1_octet_string_to_der(val,d,dlen,out,outlen)		asn1_type_to_der(ASN1_TAG_OCTET_STRING,val,d,dlen,out,outlen)
#define asn1_octet_string_from_der(val,d,dlen,out,outlen)		asn1_type_from_der(ASN1_TAG_OCTET_STRING,val,d,dlen,out,outlen)
#define asn1_implicit_octet_string_to_der(idx,val,d,dlen,out,outlen)	asn1_type_to_der(ASN1_TAG_IMPLICIT(idx),val,d,dlen,out,outlen)
#define asn1_implicit_octet_string_from_der(idx,val,d,dlen,out,outlen)	asn1_type_from_der(ASN1_TAG_IMPLICIT(idx),val,d,dlen,out,outlen)

int asn1_null_to_der(uint8_t **out, size_t *outlen);
int asn1_null_from_der(const uint8_t **in, size_t *inlen);

#define ASN1_OID_MAX_NODES 32
int asn1_object_identifier_to_octets(const uint32_t *nodes, size_t nodes_count, uint8_t *out, size_t *outlen);
int asn1_object_identifier_from_octets(uint32_t *nodes, size_t *nodes_count, const uint8_t *in, size_t inlen);

int asn1_object_identifier_equ(const uint32_t *a, size_t a_count, const uint32_t *b, size_t b_count);
int asn1_object_identifier_to_der_ex(int tag, const uint32_t *nodes, size_t nodes_count, uint8_t **out, size_t *outlen);
int asn1_object_identifier_from_der_ex(int tag, uint32_t *nodes, size_t *nodes_count, const uint8_t **in, size_t *inlen);
#define asn1_object_identifier_to_der(val,d,dlen,out,outlen)		asn1_object_identifier_to_der_ex(ASN1_TAG_OBJECT_IDENTIFIER,val,d,dlen,out,outlen)
#define asn1_object_identifier_from_der(val,d,dlen,out,outlen)		asn1_object_identifier_from_der_ex(ASN1_TAG_OBJECT_IDENTIFIER,val,d,dlen,out,outlen)
#define asn1_implicit_object_identifier_to_der(idx,val,d,dlen,out,outlen)	asn1_object_identifier_to_der_ex(ASN1_TAG_IMPLICIT(idx),val,d,dlen,out,outlen)
#define asn1_implicit_object_identifier_from_der(idx,val,d,dlen,out,outlen)	asn1_object_identifier_from_der_ex(ASN1_TAG_IMPLICIT(idx),val,d,dlen,out,outlen)
int asn1_object_identifier_print(FILE *fp, int fmt, int ind, const char *label, const char *name,
	const uint32_t *nodes, size_t nodes_count);

#define asn1_enumerated_to_der_ex(tag,val,out,outlen)		asn1_int_to_der_ex(tag,val,out,outlen)
#define asn1_enumerated_from_der_ex(tag,val,out,outlen)		asn1_int_from_der_ex(tag,val,out,outlen)
#define asn1_enumerated_to_der(val,out,outlen)			asn1_int_to_der_ex(ASN1_TAG_ENUMERATED,val,out,outlen)
#define asn1_enumerated_from_der(val,out,outlen)		asn1_int_from_der_ex(ASN1_TAG_ENUMERATED,val,out,outlen)
#define asn1_implicit_enumerated_to_der(idx,val,out,outlen)	asn1_int_to_der_ex(ASN1_TAG_IMPLICIT(idx),val,out,outlen)
#define asn1_implicit_enumerated_from_der(idx,val,out,outlen)	asn1_int_from_der_ex(ASN1_TAG_IMPLICIT(idx),val,out,outlen)

int asn1_utf8_string_check(const char *d, size_t dlen);
int asn1_utf8_string_to_der_ex(int tag, const char *a, uint8_t **out, size_t *outlen);
int asn1_utf8_string_from_der_ex(int tag, const char **a, size_t *alen, const uint8_t **in, size_t *inlen);
#define asn1_utf8_string_to_der(val,out,outlen)			asn1_utf8_string_to_der_ex(ASN1_TAG_UTF8String,val,out,outlen)
#define asn1_utf8_string_from_der(val,d,dlen,out,outlen)		asn1_utf8_string_from_der_ex(ASN1_TAG_UTF8String,val,d,dlen,out,outlen)
#define asn1_implicit_utf8_string_to_der(i,val,out,outlen)	asn1_utf8_string_to_der_ex(ASN1_TAG_IMPLICIT(i),val,out,outlen)
#define asn1_implicit_utf8_string_from_der(i,val,out,outlen)	asn1_utf8_string_from_der_ex(ASN1_TAG_IMPLICIT(i),val,out,outlen)

int asn1_printable_string_check(const char *d, size_t dlen);
int asn1_printable_string_to_der_ex(int tag, const char *a, uint8_t **out, size_t *outlen);
int asn1_printable_string_from_der_ex(int tag, const char **a, size_t *alen, const uint8_t **in, size_t *inlen);
#define asn1_printable_string_to_der(val,out,outlen)		asn1_printable_string_to_der_ex(ASN1_TAG_PrintableString,val,out,outlen)
#define asn1_printable_string_from_der(val,d,dlen,out,outlen)	asn1_printable_string_from_der_ex(ASN1_TAG_PrintableString,val,d,dlen,out,outlen)
#define asn1_implicit_printable_string_to_der(i,val,out,outlen)		asn1_printable_string_to_der_ex(ASN1_TAG_IMPLICIT(i),val,out,outlen)
#define asn1_implicit_printable_string_from_der(i,val,out,outlen)	asn1_printable_string_from_der_ex(ASN1_TAG_IMPLICIT(i),val,out,outlen)

int asn1_ia5_string_check(const char *d, size_t dlen);
int asn1_ia5_string_to_der_ex(int tag, const char *a, uint8_t **out, size_t *outlen);
int asn1_ia5_string_from_der_ex(int tag, const char **a, size_t *alen, const uint8_t **in, size_t *inlen);
#define asn1_ia5_string_to_der(val,out,outlen)			asn1_ia5_string_to_der_ex(ASN1_TAG_IA5String,val,out,outlen)
#define asn1_ia5_string_from_der(val,d,dlen,out,outlen)		asn1_ia5_string_from_der_ex(ASN1_TAG_IA5String,val,d,dlen,out,outlen)
#define asn1_implicit_ia5_string_to_der(i,val,out,outlen)	asn1_ia5_string_to_der_ex(ASN1_TAG_IMPLICIT(i),val,out,outlen)
#define asn1_implicit_ia5_string_from_der(i,val,out,outlen)	asn1_ia5_string_from_der_ex(ASN1_TAG_IMPLICIT(i),val,out,outlen)

int asn1_string_print(FILE *fp, int fmt, int ind, const char *label, int tag, const uint8_t *d, size_t dlen);


int asn1_utc_time_to_der_ex(int tag, time_t a, uint8_t **out, size_t *outlen);
int asn1_utc_time_from_der_ex(int tag, time_t *t, const uint8_t **in, size_t *inlen);
#define asn1_utc_time_to_der(val,out,outlen)			asn1_utc_time_to_der_ex(ASN1_TAG_UTCTime,val,out,outlen)
#define asn1_utc_time_from_der(val,out,outlen)			asn1_utc_time_from_der_ex(ASN1_TAG_UTCTime,val,out,outlen)
#define asn1_implicit_utc_time_to_der(i,val,out,outlen)		asn1_utc_time_to_der_ex(ASN1_TAG_IMPLICIT(i),val,out,outlen)
#define asn1_implicit_utc_time_from_der(i,val,out,outlen)	asn1_utc_time_from_der_ex(ASN1_TAG_IMPLICIT(i),val,out,outlen)

int asn1_generalized_time_to_der_ex(int tag, time_t a, uint8_t **out, size_t *outlen);
int asn1_generalized_time_from_der_ex(int tag, time_t *t, const uint8_t **in, size_t *inlen);
#define asn1_generalized_time_to_der(val,out,outlen)		asn1_generalized_time_to_der_ex(ASN1_TAG_GeneralizedTime,val,out,outlen)
#define asn1_generalized_time_from_der(val,out,outlen)		asn1_generalized_time_from_der_ex(ASN1_TAG_GeneralizedTime,val,out,outlen)
#define asn1_implicit_generalized_time_to_der(i,val,out,outlen)		asn1_generalized_time_to_der_ex(ASN1_TAG_IMPLICIT(i),val,out,outlen)
#define asn1_implicit_generalized_time_from_der(i,val,out,outlen)	asn1_generalized_time_from_der_ex(ASN1_TAG_IMPLICIT(i),val,out,outlen)


#define asn1_sequence_to_der(val,d,dlen,out,outlen)			asn1_type_to_der(ASN1_TAG_SEQUENCE,val,d,dlen,out,outlen)
#define asn1_sequence_from_der(val,d,dlen,out,outlen)		asn1_type_from_der(ASN1_TAG_SEQUENCE,val,d,dlen,out,outlen)
#define asn1_implicit_sequence_to_der(i,val,d,dlen,out,outlen)	asn1_type_to_der(ASN1_TAG_EXPLICIT(i),val,d,dlen,out,outlen)
#define asn1_implicit_sequence_from_der(i,val,d,dlen,out,outlen)	asn1_type_from_der(ASN1_TAG_EXPLICIT(i),val,d,dlen,out,outlen)


#define asn1_set_to_der(val,d,dlen,out,outlen)			asn1_type_to_der(ASN1_TAG_SET,val,d,dlen,out,outlen)
#define asn1_set_from_der(val,d,dlen,out,outlen)			asn1_type_from_der(ASN1_TAG_SET,val,d,dlen,out,outlen)
#define asn1_implicit_set_to_der(i,val,d,dlen,out,outlen)		asn1_type_to_der(ASN1_TAG_EXPLICIT(i),val,d,dlen,out,outlen)
#define asn1_implicit_set_from_der(i,val,d,dlen,out,outlen)		asn1_type_from_der(ASN1_TAG_EXPLICIT(i),val,d,dlen,out,outlen)

#define asn1_implicit_to_der(i,val,d,dlen,out,outlen)		asn1_type_to_der(ASN1_TAG_EXPLICIT(i),val,d,dlen,out,outlen)
#define asn1_implicit_from_der(i,val,d,dlen,out,outlen)		asn1_type_from_der(ASN1_TAG_EXPLICIT(i),val,d,dlen,out,outlen)


int asn1_header_to_der(int tag, size_t len, uint8_t **out, size_t *outlen);
#define asn1_sequence_header_to_der(al,d,dl)		asn1_header_to_der(ASN1_TAG_SEQUENCE,al,d,dl)
#define asn1_implicit_sequence_header_to_der(i,al,d,dl)	asn1_header_to_der(ASN1_TAG_EXPLICIT(i),al,d,dl)

#define asn1_set_header_to_der(al,d,dl)			asn1_header_to_der(ASN1_TAG_SET,al,d,dl)
#define asn1_implicit_set_header_to_der(i,al,d,dl)	asn1_header_to_der(ASN1_TAG_EXPLICIT(i),al,d,dl)

#define asn1_explicit_header_to_der(i,al,d,dl)		asn1_header_to_der(ASN1_TAG_EXPLICIT(i),al,d,dl)

#define asn1_explicit_to_der(i,val,d,dlen,out,outlen)		asn1_type_to_der(ASN1_TAG_EXPLICIT(i),val,d,dlen,out,outlen)
#define asn1_explicit_from_der(i,val,d,dlen,out,outlen)		asn1_type_from_der(ASN1_TAG_EXPLICIT(i),val,d,dlen,out,outlen)


int asn1_types_get_count(const uint8_t *d, size_t dlen, int tag, int *count);
int asn1_types_get_type_by_index(const uint8_t *d, size_t *dlen, int tag, const uint8_t **val, size_t *vlen);

int asn1_sequence_of_integer_to_der(const int *nums, size_t nums_cnt, uint8_t **out, size_t *outlen);
int asn1_sequence_of_integer_from_der(int *nums, size_t *nums_cnt, const uint8_t **in, size_t *inlen);
int asn1_sequence_of_integer_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);


typedef struct {
	int oid;
	char *name;
	uint32_t *nodes;
	size_t nodes_count;
	int flags;
	char *description;
} ASN1_OID_INFO;

const ASN1_OID_INFO *asn1_oid_info_from_name(const ASN1_OID_INFO *infos, size_t count, const char *name);
const ASN1_OID_INFO *asn1_oid_info_from_oid(const ASN1_OID_INFO *infos, size_t count, int oid);
int asn1_oid_info_from_der_ex(const ASN1_OID_INFO **info, uint32_t *nodes, size_t *nodes_count,
	const ASN1_OID_INFO *infos, size_t count, const uint8_t **in, size_t *inlen);
int asn1_oid_info_from_der(const ASN1_OID_INFO **info,
	const ASN1_OID_INFO *infos, size_t count, const uint8_t **in, size_t *inlen);


int asn1_check(int expr);


#if __cplusplus
}
#endif
#endif
