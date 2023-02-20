/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
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


#define ASN1_FMT_FULL	0x01


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
	ASN1_TAG_ENUMERATED		= 10, // 0x0A
	ASN1_TAG_EMBEDDED		= 11, // 0x0B
	ASN1_TAG_UTF8String		= 12, // 0x0C
	ASN1_TAG_RELATIVE_OID		= 13, // 0x0D
	ASN1_TAG_NumericString		= 18, // 0x12
	ASN1_TAG_PrintableString	= 19, // 0x13, printable subset of ascii
	ASN1_TAG_TeletexString		= 20, // 0x14, T61String
	ASN1_TAG_VideotexString		= 21, // 0x15
	ASN1_TAG_IA5String		= 22, // 0x16, 7-bit ascii
	ASN1_TAG_UTCTime		= 23, // 0x17
	ASN1_TAG_GeneralizedTime	= 24, // 0x18
	ASN1_TAG_GraphicString		= 25, // 0x19
	ASN1_TAG_VisibleString		= 26, // 0x20
	ASN1_TAG_GeneralString		= 27, // 0x21
	ASN1_TAG_UniversalString	= 28, // 0x22
	ASN1_TAG_CHARACTER_STRING	= 29, // 0x23
	ASN1_TAG_BMPString		= 30, // 0x24, 2-byte unicode with zeros
	ASN1_TAG_SEQUENCE		= 0x30,
	ASN1_TAG_SET			= 0x31,
	ASN1_TAG_EXPLICIT		= 0xa0,
};


const char *asn1_tag_name(int tag);
int asn1_tag_is_cstring(int tag);
int asn1_tag_to_der(int tag, uint8_t **out, size_t *outlen);
int asn1_tag_from_der(int *tag, const uint8_t **in, size_t *inlen);
int asn1_tag_from_der_readonly(int *tag, const uint8_t **in, size_t *inlen); // read the next tag without changing *in,*inlen
int asn1_length_to_der(size_t dlen, uint8_t **out, size_t *outlen);
int asn1_length_from_der(size_t *dlen, const uint8_t **in, size_t *inlen);
int asn1_length_is_zero(size_t len);
int asn1_length_le(size_t len1, size_t len2); // less than
int asn1_data_to_der(const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen);
int asn1_data_from_der(const uint8_t **d, size_t dlen, const uint8_t **in, size_t *inlen);

int asn1_type_to_der(int tag, const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen);
int asn1_type_from_der(int tag, const uint8_t **d, size_t *dlen, const uint8_t **in, size_t *inlen);
int asn1_nonempty_type_to_der(int tag, const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen);
int asn1_nonempty_type_from_der(int tag, const uint8_t **d, size_t *dlen, const uint8_t **in, size_t *inlen);
int asn1_any_type_from_der(int *tag, const uint8_t **d, size_t *dlen, const uint8_t **in, size_t *inlen);
int asn1_any_to_der(const uint8_t *a, size_t alen, uint8_t **out, size_t *outlen); // 调用方应保证a,alen为TLV
int asn1_any_from_der(const uint8_t **a, size_t *alen, const uint8_t **in, size_t *inlen); // 该函数会检查输入是否为TLV

#define ASN1_TRUE 0xff
#define ASN1_FALSE 0x00

const char *asn1_boolean_name(int val);
int asn1_boolean_from_name(int *val, const char *name);
int asn1_boolean_to_der_ex(int tag, int val, uint8_t **out, size_t *outlen);
int asn1_boolean_from_der_ex(int tag, int *val, const uint8_t **in, size_t *inlen);
#define asn1_boolean_to_der(val,out,outlen) asn1_boolean_to_der_ex(ASN1_TAG_BOOLEAN,val,out,outlen)
#define asn1_boolean_from_der(val,in,inlen) asn1_boolean_from_der_ex(ASN1_TAG_BOOLEAN,val,in,inlen)
#define asn1_implicit_boolean_to_der(i,val,out,outlen) asn1_boolean_to_der_ex(ASN1_TAG_IMPLICIT(i),val,out,outlen)
#define asn1_implicit_boolean_from_der(i,val,in,inlen) asn1_boolean_from_der_ex(ASN1_TAG_IMPLICIT(i),val,in,inlen)

// asn1_integer_ 不支持负数编解码
int asn1_integer_to_der_ex(int tag, const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen);
int asn1_integer_from_der_ex(int tag, const uint8_t **d, size_t *dlen, const uint8_t **in, size_t *inlen);
#define asn1_integer_to_der(d,dlen,out,outlen) asn1_integer_to_der_ex(ASN1_TAG_INTEGER,d,dlen,out,outlen)
#define asn1_integer_from_der(d,dlen,in,inlen) asn1_integer_from_der_ex(ASN1_TAG_INTEGER,d,dlen,in,inlen)
#define asn1_implicit_integer_to_der(i,d,dlen,out,outlen) asn1_integer_to_der_ex(ASN1_TAG_IMPLICIT(i),d,dlen,out,outlen)
#define asn1_implicit_integer_from_der(i,d,dlen,in,inlen) asn1_integer_from_der_ex(ASN1_TAG_IMPLICIT(i),d,dlen,in,inlen)

// asn1_int_ 只支持小的无符号整数的编解码，不支持负数
int asn1_int_to_der_ex(int tag, int val, uint8_t **out, size_t *outlen); // 当 val == -1 时，不输出，返回 0
int asn1_int_from_der_ex(int tag, int *val, const uint8_t **in, size_t *inlen); // 不支持负数，返回0时 *val 设置为 -1
#define asn1_int_to_der(val,out,outlen) asn1_int_to_der_ex(ASN1_TAG_INTEGER,val,out,outlen)
#define asn1_int_from_der(val,in,inlen) asn1_int_from_der_ex(ASN1_TAG_INTEGER,val,in,inlen)
#define asn1_implicit_int_to_der(i,val,out,outlen) asn1_int_to_der_ex(ASN1_TAG_IMPLICIT(i),val,out,outlen)
#define asn1_implicit_int_from_der(i,val,in,inlen) asn1_int_from_der_ex(ASN1_TAG_IMPLICIT(i),val,in,inlen)

// 比特长度不必须为8的整数倍
int asn1_bit_string_to_der_ex(int tag, const uint8_t *d, size_t nbits, uint8_t **out, size_t *outlen);
int asn1_bit_string_from_der_ex(int tag, const uint8_t **d, size_t *nbits, const uint8_t **in, size_t *inlen);
#define asn1_bit_string_to_der(d,nbits,out,outlen) asn1_bit_string_to_der_ex(ASN1_TAG_BIT_STRING,d,nbits,out,outlen)
#define asn1_bit_string_from_der(d,nbits,in,inlen) asn1_bit_string_from_der_ex(ASN1_TAG_BIT_STRING,d,nbits,in,inlen)
#define asn1_implicit_bit_string_to_der(i,d,nbits,out,outlen) asn1_bit_string_to_der_ex(ASN1_TAG_IMPLICIT(i),d,nbits,out,outlen)
#define asn1_implicit_bit_string_from_der(i,d,nbits,in,inlen) asn1_bit_string_from_der_ex(ASN1_TAG_IMPLICIT(i),d,nbits,in,inlen)

// 比特长度必须为8的整数倍，因此使用字节长度
int asn1_bit_octets_to_der_ex(int tag, const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen);
int asn1_bit_octets_from_der_ex(int tag, const uint8_t **d, size_t *dlen, const uint8_t **in, size_t *inlen);
#define asn1_bit_octets_to_der(d,dlen,out,outlen) asn1_bit_octets_to_der_ex(ASN1_TAG_BIT_STRING,d,dlen,out,outlen)
#define asn1_bit_octets_from_der(d,dlen,in,inlen) asn1_bit_octets_from_der_ex(ASN1_TAG_BIT_STRING,d,dlen,in,inlen)
#define asn1_implicit_bit_octets_to_der(i,d,dlen,out,outlen) asn1_bit_octets_to_der_ex(ASN1_TAG_IMPLICIT(i),d,dlen,out,outlen)
#define asn1_implicit_bit_octets_from_der(i,d,dlen,in,inlen) asn1_bit_octets_from_der_ex(ASN1_TAG_IMPLICIT(i),d,dlen,in,inlen)

// bits == -1 不编码，只支持较少的比特数量
int asn1_bits_to_der_ex(int tag, int bits, uint8_t **out, size_t *outlen);
int asn1_bits_from_der_ex(int tag, int *bits, const uint8_t **in, size_t *inlen);
#define asn1_bits_to_der(bits,out,outlen) asn1_bits_to_der_ex(ASN1_TAG_BIT_STRING,bits,out,outlen)
#define asn1_bits_from_der(bits,in,inlen) asn1_bits_from_der_ex(ASN1_TAG_BIT_STRING,bits,in,inlen)
#define asn1_implicit_bits_to_der(i,bits,out,outlen) asn1_bits_to_der_ex(ASN1_TAG_IMPLICIT(i),bits,out,outlen)
#define asn1_implicit_bits_from_der(i,bits,in,inlen) asn1_bits_from_der_ex(ASN1_TAG_IMPLICIT(i),bits,in,inlen)
// names[i]对应第i个比特
int asn1_bits_print(FILE *fp, int fmt, int ind, const char *label, const char **names, size_t names_cnt, int bits);

#define asn1_octet_string_to_der_ex(tag,d,dlen,out,outlen) asn1_type_to_der(tag,d,dlen,out,outlen)
#define asn1_octet_string_from_der_ex(tag,d,dlen,in,inlen) asn1_type_from_der(tag,d,dlen,in,inlen)
#define asn1_octet_string_to_der(d,dlen,out,outlen) asn1_type_to_der(ASN1_TAG_OCTET_STRING,d,dlen,out,outlen)
#define asn1_octet_string_from_der(d,dlen,in,inlen) asn1_type_from_der(ASN1_TAG_OCTET_STRING,d,dlen,in,inlen)
#define asn1_implicit_octet_string_to_der(i,d,dlen,out,outlen) asn1_type_to_der(ASN1_TAG_IMPLICIT(i),d,dlen,out,outlen)
#define asn1_implicit_octet_string_from_der(i,d,dlen,in,inlen) asn1_type_from_der(ASN1_TAG_IMPLICIT(i),d,dlen,in,inlen)

const char *asn1_null_name(void);
int asn1_null_to_der(uint8_t **out, size_t *outlen);
int asn1_null_from_der(const uint8_t **in, size_t *inlen);

#define ASN1_OID_MIN_NODES 2
#define ASN1_OID_MAX_NODES 32
#define ASN1_OID_MIN_OCTETS 1
#define ASN1_OID_MAX_OCTETS (1 + (ASN1_OID_MAX_NODES - 2) * 5)
int asn1_object_identifier_to_octets(const uint32_t *nodes, size_t nodes_cnt, uint8_t *out, size_t *outlen);
int asn1_object_identifier_from_octets(uint32_t *nodes, size_t *nodes_cnt, const uint8_t *in, size_t inlen);

int asn1_object_identifier_to_der_ex(int tag, const uint32_t *nodes, size_t nodes_cnt, uint8_t **out, size_t *outlen);
int asn1_object_identifier_from_der_ex(int tag, uint32_t *nodes, size_t *nodes_cnt, const uint8_t **in, size_t *inlen);
#define asn1_object_identifier_to_der(nodes,nodes_cnt,out,outlen) asn1_object_identifier_to_der_ex(ASN1_TAG_OBJECT_IDENTIFIER,nodes,nodes_cnt,out,outlen)
#define asn1_object_identifier_from_der(nodes,nodes_cnt,in,inlen) asn1_object_identifier_from_der_ex(ASN1_TAG_OBJECT_IDENTIFIER,nodes,nodes_cnt,in,inlen)
#define asn1_implicit_object_identifier_to_der(i,nodes,nodes_cnt,out,outlen) asn1_object_identifier_to_der_ex(ASN1_TAG_IMPLICIT(i),nodes,nodes_cnt,out,outlen)
#define asn1_implicit_object_identifier_from_der(i,nodes,nodes_cnt,in,inlen) asn1_object_identifier_from_der_ex(ASN1_TAG_IMPLICIT(i),nodes,nodes_cnt,in,inlen)
int asn1_object_identifier_equ(const uint32_t *a, size_t a_cnt, const uint32_t *b, size_t b_cnt);
int asn1_object_identifier_print(FILE *fp, int fmt, int ind, const char *label, const char *name,
	const uint32_t *nodes, size_t nodes_cnt);

typedef struct {
	int oid;
	char *name;
	uint32_t *nodes;
	size_t nodes_cnt;
	int flags;
	char *description;
} ASN1_OID_INFO;

const ASN1_OID_INFO *asn1_oid_info_from_name(const ASN1_OID_INFO *infos, size_t count, const char *name);
const ASN1_OID_INFO *asn1_oid_info_from_oid(const ASN1_OID_INFO *infos, size_t count, int oid);
// 如果一个正确解析的OID并不在infos列表中，那么仍然返回1，但是调用方必须检查返回的info是否为空
int asn1_oid_info_from_der_ex(const ASN1_OID_INFO **info, uint32_t *nodes, size_t *nodes_cnt,
	const ASN1_OID_INFO *infos, size_t count, const uint8_t **in, size_t *inlen);
int asn1_oid_info_from_der(const ASN1_OID_INFO **info,
	const ASN1_OID_INFO *infos, size_t count, const uint8_t **in, size_t *inlen);

#define asn1_enumerated_to_der_ex(tag,val,out,outlen) asn1_int_to_der_ex(tag,val,out,outlen)
#define asn1_enumerated_from_der_ex(tag,val,in,inlen) asn1_int_from_der_ex(tag,val,in,inlen)
#define asn1_enumerated_to_der(val,out,outlen) asn1_int_to_der_ex(ASN1_TAG_ENUMERATED,val,out,outlen)
#define asn1_enumerated_from_der(val,in,inlen) asn1_int_from_der_ex(ASN1_TAG_ENUMERATED,val,in,inlen)
#define asn1_implicit_enumerated_to_der(i,val,out,outlen) asn1_int_to_der_ex(ASN1_TAG_IMPLICIT(i),val,out,outlen)
#define asn1_implicit_enumerated_from_der(i,val,in,inlen) asn1_int_from_der_ex(ASN1_TAG_IMPLICIT(i),val,in,inlen)

int asn1_string_is_utf8_string(const char *d, size_t dlen);
int asn1_utf8_string_to_der_ex(int tag, const char *d, size_t dlen, uint8_t **out, size_t *outlen);
int asn1_utf8_string_from_der_ex(int tag, const char **d, size_t *dlen, const uint8_t **in, size_t *inlen);
#define asn1_utf8_string_to_der(d,dlen,out,outlen) asn1_utf8_string_to_der_ex(ASN1_TAG_UTF8String,d,dlen,out,outlen)
#define asn1_utf8_string_from_der(d,dlen,in,inlen) asn1_utf8_string_from_der_ex(ASN1_TAG_UTF8String,d,dlen,in,inlen)
#define asn1_implicit_utf8_string_to_der(i,d,dlen,out,outlen) asn1_utf8_string_to_der_ex(ASN1_TAG_IMPLICIT(i),d,dlen,out,outlen)
#define asn1_implicit_utf8_string_from_der(i,d,dlen,in,inlen) asn1_utf8_string_from_der_ex(ASN1_TAG_IMPLICIT(i),d,dlen,in,inlen)

int asn1_string_is_printable_string(const char *d, size_t dlen);
int asn1_printable_string_case_ignore_match(const char *a, size_t alen, const char *b, size_t blen);
int asn1_printable_string_to_der_ex(int tag, const char *d, size_t dlen, uint8_t **out, size_t *outlen);
int asn1_printable_string_from_der_ex(int tag, const char **d, size_t *dlen, const uint8_t **in, size_t *inlen);
#define asn1_printable_string_to_der(d,dlen,out,outlen)	asn1_printable_string_to_der_ex(ASN1_TAG_PrintableString,d,dlen,out,outlen)
#define asn1_printable_string_from_der(d,dlen,in,inlen)	asn1_printable_string_from_der_ex(ASN1_TAG_PrintableString,d,dlen,in,inlen)
#define asn1_implicit_printable_string_to_der(i,d,dlen,out,outlen) asn1_printable_string_to_der_ex(ASN1_TAG_IMPLICIT(i),d,dlen,out,outlen)
#define asn1_implicit_printable_string_from_der(i,d,dlen,in,inlen) asn1_printable_string_from_der_ex(ASN1_TAG_IMPLICIT(i),d,dlen,in,inlen)

int asn1_string_is_ia5_string(const char *d, size_t dlen);
int asn1_ia5_string_to_der_ex(int tag, const char *d, size_t dlen, uint8_t **out, size_t *outlen);
int asn1_ia5_string_from_der_ex(int tag, const char **d, size_t *dlen, const uint8_t **in, size_t *inlen);
#define asn1_ia5_string_to_der(d,dlen,out,outlen) asn1_ia5_string_to_der_ex(ASN1_TAG_IA5String,d,dlen,out,outlen)
#define asn1_ia5_string_from_der(d,dlen,in,inlen) asn1_ia5_string_from_der_ex(ASN1_TAG_IA5String,d,dlen,in,inlen)
#define asn1_implicit_ia5_string_to_der(i,d,dlen,out,outlen) asn1_ia5_string_to_der_ex(ASN1_TAG_IMPLICIT(i),d,dlen,out,outlen)
#define asn1_implicit_ia5_string_from_der(i,d,dlen,in,inlen) asn1_ia5_string_from_der_ex(ASN1_TAG_IMPLICIT(i),d,dlen,in,inlen)

int asn1_string_print(FILE *fp, int fmt, int ind, const char *label, int tag, const uint8_t *d, size_t dlen);

#define ASN1_UTC_TIME_STRLEN		(sizeof("YYMMDDHHMMSSZ")-1)
#define ASN1_GENERALIZED_TIME_STRLEN	(sizeof("YYYYMMDDHHMMSSZ")-1)
#define ASN1_GENERALIZED_TIME_MAX_SIZE	(2 + ASN1_GENERALIZED_TIME_STRLEN)

int asn1_time_to_str(int utc_time, time_t timestamp, char *str);
int asn1_time_from_str(int utc_time, time_t *timestamp, const char *str);

int asn1_utc_time_to_der_ex(int tag, time_t tv, uint8_t **out, size_t *outlen);
int asn1_utc_time_from_der_ex(int tag, time_t *tv, const uint8_t **in, size_t *inlen);
#define asn1_utc_time_to_der(tv,out,outlen) asn1_utc_time_to_der_ex(ASN1_TAG_UTCTime,tv,out,outlen)
#define asn1_utc_time_from_der(tv,in,inlen) asn1_utc_time_from_der_ex(ASN1_TAG_UTCTime,tv,in,inlen)
#define asn1_implicit_utc_time_to_der(i,tv,out,outlen) asn1_utc_time_to_der_ex(ASN1_TAG_IMPLICIT(i),tv,out,outlen)
#define asn1_implicit_utc_time_from_der(i,tv,in,inlen) asn1_utc_time_from_der_ex(ASN1_TAG_IMPLICIT(i),tv,in,inlen)

int asn1_generalized_time_to_der_ex(int tag, time_t tv, uint8_t **out, size_t *outlen);
int asn1_generalized_time_from_der_ex(int tag, time_t *tv, const uint8_t **in, size_t *inlen);
#define asn1_generalized_time_to_der(tv,out,outlen) asn1_generalized_time_to_der_ex(ASN1_TAG_GeneralizedTime,tv,out,outlen)
#define asn1_generalized_time_from_der(tv,in,inlen) asn1_generalized_time_from_der_ex(ASN1_TAG_GeneralizedTime,tv,in,inlen)
#define asn1_implicit_generalized_time_to_der(i,tv,out,outlen) asn1_generalized_time_to_der_ex(ASN1_TAG_IMPLICIT(i),tv,out,outlen)
#define asn1_implicit_generalized_time_from_der(i,tv,in,inlen) asn1_generalized_time_from_der_ex(ASN1_TAG_IMPLICIT(i),tv,in,inlen)

// BasicConstraints might be an empty sequence in entity certificates
#define asn1_sequence_to_der(d,dlen,out,outlen) asn1_type_to_der(ASN1_TAG_SEQUENCE,d,dlen,out,outlen)
#define asn1_sequence_from_der(d,dlen,in,inlen) asn1_type_from_der(ASN1_TAG_SEQUENCE,d,dlen,in,inlen)
#define asn1_implicit_sequence_to_der(i,d,dlen,out,outlen) asn1_nonempty_type_to_der(ASN1_TAG_EXPLICIT(i),d,dlen,out,outlen)
#define asn1_implicit_sequence_from_der(i,d,dlen,in,inlen) asn1_nonempty_type_from_der(ASN1_TAG_EXPLICIT(i),d,dlen,in,inlen)

#define asn1_sequence_of_to_der(d,dlen,out,outlen) asn1_nonempty_type_to_der(ASN1_TAG_SEQUENCE,d,dlen,out,outlen)
#define asn1_sequence_of_from_der(d,dlen,in,inlen) asn1_nonempty_type_from_der(ASN1_TAG_SEQUENCE,d,dlen,in,inlen)
int asn1_sequence_of_int_to_der(const int *nums, size_t nums_cnt, uint8_t **out, size_t *outlen);
int asn1_sequence_of_int_from_der(int *nums, size_t *nums_cnt, size_t max_nums, const uint8_t **in, size_t *inlen);
int asn1_sequence_of_int_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

#define asn1_set_to_der(d,dlen,out,outlen) asn1_nonempty_type_to_der(ASN1_TAG_SET,d,dlen,out,outlen)
#define asn1_set_from_der(d,dlen,in,inlen) asn1_nonempty_type_from_der(ASN1_TAG_SET,d,dlen,in,inlen)
#define asn1_implicit_set_to_der(i,d,dlen,out,outlen) asn1_type_to_der(ASN1_TAG_EXPLICIT(i),d,dlen,out,outlen)
#define asn1_implicit_set_from_der(i,d,dlen,in,inlen) asn1_type_from_der(ASN1_TAG_EXPLICIT(i),d,dlen,in,inlen)

#define asn1_set_of_to_der(d,dlen,out,outlen) asn1_nonempty_type_to_der(ASN1_TAG_SET,d,dlen,out,outlen)
#define asn1_set_of_from_der(d,dlen,in,inlen) asn1_nonempty_type_from_der(ASN1_TAG_SET,d,dlen,in,inlen)

#define asn1_implicit_to_der(i,d,dlen,out,outlen) asn1_type_to_der(ASN1_TAG_IMPLICIT(i),d,dlen,out,outlen)
#define asn1_implicit_from_der(i,d,dlen,in,inlen) asn1_type_from_der(ASN1_TAG_IMPLICIT(i),d,dlen,in,inlen)

int asn1_header_to_der(int tag, size_t dlen, uint8_t **out, size_t *outlen);
#define asn1_implicit_header_to_der(i,dlen,out,outlen) asn1_header_to_der(ASN1_TAG_EXPLICIT(i),dlen,out,outlen)

#define asn1_octet_string_header_to_der(dlen,out,outlen) asn1_header_to_der(ASN1_TAG_OCTET_STRING,dlen,out,outlen)

#define asn1_sequence_header_to_der_ex(tag,dlen,out,outlen) asn1_header_to_der(tag,dlen,out,outlen)
#define asn1_sequence_header_to_der(dlen,out,outlen) asn1_header_to_der(ASN1_TAG_SEQUENCE,dlen,out,outlen)
#define asn1_implicit_sequence_header_to_der(i,dlen,out,outlen) asn1_header_to_der(ASN1_TAG_EXPLICIT(i),dlen,out,outlen)

#define asn1_set_header_to_der(dlen,out,outlen) asn1_header_to_der(ASN1_TAG_SET,dlen,out,outlen)
#define asn1_implicit_set_header_to_der(i,dlen,out,outlen) asn1_header_to_der(ASN1_TAG_EXPLICIT(i),dlen,out,outlen)

#define asn1_explicit_header_to_der(i,dlen,out,outlen) asn1_header_to_der(ASN1_TAG_EXPLICIT(i),dlen,out,outlen)

#define asn1_explicit_to_der(i,d,dlen,out,outlen) asn1_nonempty_type_to_der(ASN1_TAG_EXPLICIT(i),d,dlen,out,outlen)
#define asn1_explicit_from_der(i,d,dlen,in,inlen) asn1_nonempty_type_from_der(ASN1_TAG_EXPLICIT(i),d,dlen,in,inlen)

// d,dlen 是 SEQUENCE OF, SET OF 中的值
int asn1_types_get_count(const uint8_t *d, size_t dlen, int tag, size_t *cnt);
int asn1_types_get_item_by_index(const uint8_t *d, size_t dlen, int tag,
	int index, const uint8_t **item_d, size_t *item_dlen);





int asn1_check(int expr);


#if __cplusplus
}
#endif
#endif
