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
#include <assert.h>
#include <limits.h>
#include <time.h>
#include <ctype.h>
#include <gmssl/oid.h>
#include <gmssl/asn1.h>
#include <gmssl/error.h>
#include "endian.h"


/*

## 返回值

解析函数返回错误：

1. 输入数据长度为0，如待解析的对象具有OPTIONAL属性，那么不意味错误。
   应显式告知调用方对象编码为空，由调用方判断是否为错误。
2. 输入数据和目标对象类型不符，如待解析的对象具有OPTIONAL属性，那么意味目标对象为空。
3. 长度和负载数据解析出错，这意味绝对的错误。
4. 数据类型具有IMPLICIT属性时，意味着该对象的Tag被修改了，那么解析时调用方必须提供新的Tag。

DEFAULT值在接口上不提供这个功能，这个可以在数据的初始化时完成。

	内部接口不支持参数默认值或者多态的接口，例如不允许输入参数为空。
	接口具有单一的逻辑可以通过严格的检查避免隐藏错误，提高健壮性。

*/


static char *asn1_tag_index[] = {
	"[0]",  "[1]",  "[2]",  "[3]",  "[4]",  "[5]",  "[6]",  "[7]",  "[8]",  "[9]",
	"[10]", "[11]", "[12]", "[13]", "[14]", "[15]", "[16]", "[17]", "[18]", "[19]",
	"[20]", "[21]", "[22]", "[23]", "[24]", "[25]", "[26]", "[27]", "[28]", "[29]",
	"[30]", "[31]",
};

const char *asn1_tag_name(int tag)
{
	if (tag < 0 || tag > 0xff) {
		error_print();
		return NULL;
	}

	switch (tag & 0xc0) {
	case ASN1_TAG_CONTENT_SPECIFIC: return asn1_tag_index[tag & 0xe0];
	case ASN1_TAG_APPLICATION: return "Application";
	case ASN1_TAG_PRIVATE: return "Private";
	}

	switch (tag) {
	case ASN1_TAG_BOOLEAN: return "BOOLEAN";
	case ASN1_TAG_INTEGER: return "INTEGER";
	case ASN1_TAG_BIT_STRING: return "BIT STRING";
	case ASN1_TAG_OCTET_STRING: return "OCTET STRING";
	case ASN1_TAG_NULL: return "NULL";
	case ASN1_TAG_OBJECT_IDENTIFIER: return "OBJECT IDENTIFIER";
	case ASN1_TAG_ObjectDescriptor: return "ObjectDescriptor";
	case ASN1_TAG_EXTERNAL: return "EXTERNAL";
	case ASN1_TAG_REAL: return "REAL";
	case ASN1_TAG_ENUMERATED: return "ENUMERATED";
	case ASN1_TAG_UTF8String: return "UTF8String";
	case ASN1_TAG_PrintableString: return "PrintableString";
	case ASN1_TAG_TeletexString: return "TeletexString";
	case ASN1_TAG_VideotexString: return "VideotexString";
	case ASN1_TAG_IA5String: return "IA5String";
	case ASN1_TAG_UTCTime: return "UTCTime";
	case ASN1_TAG_GeneralizedTime: return "GeneralizedTime";
	case ASN1_TAG_GraphicString: return "GraphicString";
	case ASN1_TAG_VisibleString: return "VisibleString";
	case ASN1_TAG_GeneralString: return "GeneralString";
	case ASN1_TAG_UniversalString: return "UniversalString";
	case ASN1_TAG_CHARACTER_STRING: return "CHARACTER STRING";
	case ASN1_TAG_BMPString: return "BMPString";
	case ASN1_TAG_SEQUENCE: return "SEQUENCE";
	case ASN1_TAG_SET: return "SET";
	}

	error_print();
	return NULL;
}

static int asn1_tag_is_cstring(int tag)
{
	switch (tag) {
	case ASN1_TAG_UTF8String:
	case ASN1_TAG_NumericString:
	case ASN1_TAG_PrintableString:
	case ASN1_TAG_TeletexString:
	case ASN1_TAG_IA5String:
	case ASN1_TAG_GeneralString:
		return 1;
	}
	return 0;
}

int asn1_utf8_string_check(const char *a, size_t alen)
{
	return 1;
}

int asn1_printable_string_check(const char *a, size_t alen)
{
	return 1;
}

int asn1_ia5_string_check(const char *a, size_t alen)
{
	return 1;
}

/////////////////////////////////////////////////////////////////////////////////////////////
// DER encoding
/////////////////////////////////////////////////////////////////////////////////////////////
// 这组函数不对输入进行检查			
// 还是检查报错比较方便，这样调用的函数更容易实现
// asn.1编解码不考虑效率的问题

void asn1_tag_to_der(int tag, uint8_t **out, size_t *outlen)
{
	if (out) {
		*(*out)++ = (uint8_t)tag;
	}
	(*outlen)++;
}

void asn1_length_to_der(size_t len, uint8_t **out, size_t *outlen)
{
	if (len < 128) {
		if (out) {
			*(*out)++ = (uint8_t)len;
		}
		(*outlen)++;

	} else {
		uint8_t buf[4];
		int i;

		PUTU32(buf, (uint32_t)len);
		if (len < 256) i = 1;
		else if (len < 65536) i = 2;
		else if (len < (1 << 24)) i = 3;
		else i = 4;

		if (out) {
			*(*out)++ = 0x80 + i;
			memcpy(*out, buf + 4 - i, i);
			(*out) += i;
		}
		(*outlen) += 1 + i;
	}
}

void asn1_data_to_der(const uint8_t *data, size_t datalen, uint8_t **out, size_t *outlen)
{
	if (out) {
		memcpy(*out, data, datalen);
		*out += datalen;
	}
	*outlen += datalen;
}

int asn1_tag_from_der(int tag, const uint8_t **in, size_t *inlen)
{
	if (*inlen == 0) {
		//error_print_msg("inlen = %zu\n", *inlen);
		return 0;
	}
	if  (**in != tag) {
		//error_print_msg("tag get %d instead of %d\n", **in, tag);
		return 0;
	}
	(*in)++;
	(*inlen)--;
	return 1;
}

int asn1_length_from_der(size_t *plen, const uint8_t **pin, size_t *pinlen)
{
	const uint8_t *in = *pin;
	size_t inlen = *pinlen;
	size_t len;

	if (inlen <= 0) {
		return -1;
	}


	if (*in < 128) {
		len = *in++;
		inlen--;
	} else {
		uint8_t buf[4] = {0};
		int nbytes = *in++ & 0x7f;
		//error_print_msg("nbytes = %d\n", nbytes);

		if (nbytes < 1 || nbytes > 4) {
			error_print();
			return -1;
		}
		inlen--;
		if (inlen < nbytes) {
			error_print();
			return -1;
		}
		memcpy(buf + sizeof(buf) - nbytes, in, nbytes);
		len = (size_t)GETU32(buf);
		in += nbytes;
		inlen -= nbytes;
	}

	if (inlen < len) {
		error_print_msg("inlen = %zu\n", *pinlen);
		error_print_msg("length = %zu, left = %zu\n", len, inlen);
		return -1;
	}

	*plen = len;
	*pin = in;
	*pinlen = inlen;
	return 1;
}

int asn1_data_from_der(const uint8_t **data, size_t datalen, const uint8_t **in, size_t *inlen)
{
	if (*inlen < datalen) {
		error_print();
		return -1;
	}
	*data = *in;
	*in += datalen;
	*inlen -= datalen;
	return 1;
}

int asn1_header_to_der(int tag, size_t len, uint8_t **out, size_t *outlen)
{
	if ((out && !(*out)) || !outlen) {
		error_print();
		return -1;
	}
	asn1_tag_to_der(tag, out, outlen);
	asn1_length_to_der(len, out, outlen);
	return 1;
}


// If data == NULL, out should not be NULL
// 这个实现是不支持OPTIONAL的
int asn1_type_to_der(int tag, const uint8_t *data, size_t datalen, uint8_t **out, size_t *outlen)
{
	// 针对IMPLICIT, OPTIONAL
	if (data == NULL && datalen == 0) {
		return 0;
	}

	// FIXME: asn1_tag,length,data_to_der这几个函数增加错误检查
	// 检查这几个函数的返回值				
	asn1_tag_to_der(tag, out, outlen);
	asn1_length_to_der(datalen, out, outlen);
	asn1_data_to_der(data, datalen, out, outlen);
	return 1;
}


int asn1_type_from_der(int tag, const uint8_t **data, size_t *datalen, const uint8_t **in, size_t *inlen)
{
	int ret;
	*data = NULL;
	*datalen = 0;
	if ((ret = asn1_tag_from_der(tag, in, inlen)) != 1) {
		if (ret < 0) error_print();
		//if (ret == 0) error_print();
		return ret;
	}
	if (asn1_length_from_der(datalen, in, inlen) != 1
		|| asn1_data_from_der(data, *datalen, in, inlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int asn1_type_copy_from_der(int tag, size_t maxlen, uint8_t *data, size_t *datalen, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *p;

	if ((ret = asn1_tag_from_der(tag, in, inlen)) != 1) {
		return ret;
	}
	if (asn1_length_from_der(datalen, in, inlen) != 1
		|| asn1_data_from_der(&p, *datalen, in, inlen) != 1) {
		error_print();
		return -1;
	}
	if (*datalen > maxlen) {
		error_print();
		return -1;
	}
	memcpy(data, p, *datalen);
	return 1;
}

int asn1_any_tag_from_der(int *tag, const uint8_t **in, size_t *inlen)
{
	if (*inlen == 0) {
		return 0;
	}
	*tag = *(*in)++;
	(*inlen)--;
	return 1;
}



int asn1_any_type_from_der(int *tag, const uint8_t **data, size_t *datalen, const uint8_t **in, size_t *inlen)
{
	int ret;
	if ((ret = asn1_any_tag_from_der(tag, in, inlen)) != 1) {
		return ret;
	}
	if (asn1_length_from_der(datalen, in, inlen) != 1) {
		error_print();
		return -1;
	}
	*data = *in;
	*in += *datalen;
	*inlen -= *datalen;
	return 1;
}

int asn1_any_from_der(const uint8_t **tlv, size_t *tlvlen, const uint8_t **in, size_t *inlen)
{
	int ret;
	int tag;
	const uint8_t *data;
	size_t datalen;

	*tlv = *in;
	*tlvlen = *inlen;
	if ((ret = asn1_any_type_from_der(&tag, &data, &datalen, in, inlen)) != 1) {
		error_print();
		return ret;
	}
	*tlvlen -= *inlen;
	return 1;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////

int asn1_boolean_to_der_ex(int tag, int val, uint8_t **out, size_t *outlen)
{
	if ((out && !(*out)) || !outlen) {
		return -1;
	}
	if (out) {
		*(*out)++ = tag;
		*(*out)++ = 0x01;
		*(*out)++ = val ? 0xff : 0x00;
	}
	(*outlen) += 3;
	return 1;
}

int asn1_integer_to_der_ex(int tag, const uint8_t *a, size_t alen, uint8_t **out, size_t *outlen)
{
	if (!a || alen <= 0 || alen > INT_MAX || (out && !(*out)) || !outlen) {
		error_print();
		return -1;
	}

	if (out)
		*(*out)++ = tag;
	(*outlen)++;

	if (a[0] & 0x80) {
		asn1_length_to_der(alen + 1, out, outlen);
		if (out) {
			*(*out)++ = 0x00;
			memcpy(*out, a, alen);
			(*out) += alen;
		}
		(*outlen) += 1 + alen;
	} else {
		while (*a == 0 && alen > 1) {
			a++;
			alen--;
		}
		asn1_length_to_der(alen, out, outlen);
		if (out) {
			memcpy(*out, a, alen);
			(*out) += alen;
		}
		(*outlen) += alen;
	}

	return 1;
}

int asn1_int_to_der_ex(int tag, int a, uint8_t **out, size_t *outlen)
{
	int i;
	uint8_t buf[4] = {0};
	size_t len = 0;

	if (a == -1) {
		return 0;
	}

	while (a > 0) {
		buf[3 - len] = a & 0xff;
		a >>= 8;
		len++;
	}
	if (!len) {
		len = 1;
	}

	return asn1_integer_to_der_ex(tag, buf + 4 - len, len, out, outlen);
}

int asn1_bit_string_to_der_ex(int tag, const uint8_t *bits, size_t nbits, uint8_t **out, size_t *outlen)
{
	int unused = (8 - nbits % 8) % 8;
	size_t nbytes = (nbits + 7) / 8;

	if (!bits || nbits >= INT_MAX || (out && !(*out)) || !outlen) {
		return -1;
	}

	if (out)
		*(*out)++ = tag;
	(*outlen)++;

	asn1_length_to_der(nbytes + 1, out, outlen);

	if (out) {
		*(*out)++ = (uint8_t)unused;
		memcpy(*out, bits, nbytes);
		(*out) += nbytes;
	}
	*outlen += 1 + nbytes;


	return 1;
}

int asn1_bits_to_der_ex(int tag, int bits, uint8_t **out, size_t *outlen)
{
	size_t nbits = 0;
	uint8_t buf[4] = {0};
	int i = 0;

	if (bits < 0) {
		return 0;
	}
	while (bits) {
		buf[i] = (buf[i] << 1) | (bits & 1);
		bits >>= 1;
		nbits++;
		if (nbits % 8) {
			i++;
		}
	}
	if (!nbits) {
		nbits = 1;
	}
	return asn1_bit_string_to_der_ex(tag, buf, nbits, out, outlen);
}

int asn1_null_to_der(uint8_t **out, size_t *outlen)
{
	if ((out && !(*out)) || !outlen) {
		return -1;
	}

	if (out) {
		*(*out)++ = ASN1_TAG_NULL;
		*(*out)++ = 0x00;
	}
	*outlen += 2;
	return 1;
}

int asn1_object_identifier_to_der_ex(int tag, int oid, const uint32_t *nodes, size_t nodes_count, uint8_t **out, size_t *outlen)
{
	uint8_t octets[32];
	size_t octetslen = 0;

	if ((out && !(*out)) || !outlen) {
		return -1;
	}

	if (out)
		*(*out)++ = tag;
	(*outlen)++;

	if (oid != OID_undef)
		asn1_oid_to_octets(oid, octets, &octetslen);
	else asn1_oid_nodes_to_octets(nodes, nodes_count, octets, &octetslen);

	asn1_length_to_der(octetslen, out, outlen);

	if (out) {
		// 注意：If out == NULL, *out ==> Segment Fault
		memcpy(*out, octets, octetslen);
		*out += octetslen;
	}
	*outlen += octetslen;
	return 1;
}

int asn1_utf8_string_to_der_ex(int tag, const char *a, uint8_t **out, size_t *outlen)
{
	return asn1_type_to_der(tag, (const uint8_t *)a, strlen(a), out, outlen);
}

int asn1_printable_string_to_der_ex(int tag, const char *a, uint8_t **out, size_t *outlen)
{
	return asn1_type_to_der(tag, (const uint8_t *)a, strlen(a), out, outlen);
}

int asn1_ia5_string_to_der_ex(int tag, const char *a, uint8_t **out, size_t *outlen)
{
	return asn1_type_to_der(tag, (const uint8_t *)a, strlen(a), out, outlen);
}

int asn1_utc_time_to_der_ex(int tag, time_t a, uint8_t **out, size_t *outlen)
{
	struct tm tm_val;
	char buf[sizeof("YYMMDDHHMMSSZ")];

	if ((out && !(*out)) || !outlen) {
		return -1;
	}

	// 注意，这个函数可能在Windows上是没有的！
	gmtime_r(&a, &tm_val);
	strftime(buf, sizeof(buf), "%y%m%d%H%M%SZ", &tm_val);

	if (out)
		*(*out)++ = tag;
	(*outlen)++;
	asn1_length_to_der(sizeof(buf)-1, out, outlen);
	if (out) {
		memcpy(*out, buf, sizeof(buf)-1);
		(*out) += sizeof(buf)-1;
	}
	*outlen += sizeof(buf)-1;

	return 1;
}

int asn1_generalized_time_to_der_ex(int tag, time_t a, uint8_t **out, size_t *outlen)
{
	struct tm tm_val;
	char buf[sizeof("YYYYMMDDHHMMSSZ")];

	if ((out && !(*out)) || !outlen) {
		error_print();
		return -1;
	}

	gmtime_r(&a, &tm_val);
	strftime(buf, sizeof(buf), "%Y%m%d%H%M%SZ", &tm_val);

	if (out)
		*(*out)++ = tag;
	(*outlen)++;
	asn1_length_to_der(sizeof(buf)-1, out, outlen);
	if (out) {
		memcpy(*out, buf, sizeof(buf)-1);
		(*out) += sizeof(buf)-1;
	}
	*outlen += sizeof(buf)-1;

	return 1;
}


/////////////////////////////////////////////////////////////////////////////////////////////
// DER decoding
/////////////////////////////////////////////////////////////////////////////////////////////


/*
解码函数的返回值：

	ret == 0
		当前剩余的数据数据长度为0
		或者下一个对象与期待不符，即输入对象的标签不等于输入的tag
		当对象为OPTIONAL时，调用方可以通过判断返回值是否为0进行处理
	ret < 0
		标签正确但是长度或数据解析出错
	ret == 1
		解析正确


解码函数的输入：

	*in != NULL
		例如一个SEQUENCE中的属性均为OPTIONAL，解析后指针仍不为空
		因此不允许输入空的输入数据指针


处理规则

	当返回值 ret <= 0 时，*tag, *in, *inlen 的值保持不变

	如果一个类型有 DEFAULT 属性，调用方可以将返回数据预先设置为默认值，
	如果该对象未被编码，即返回值为0，那么解码函数不会修改已经设置的默认值

*/

int asn1_boolean_from_der_ex(int tag, int *val, const uint8_t **in, size_t *inlen)
{
	if (!val || !in || !(*in) || !inlen) {
		return -1;
	}

	if (*inlen <= 0 || **in != tag) {
		return 0;
	}
	if (*inlen < 3
		|| *(*in + 1) != 0x01
		|| (*(*in + 2) != 0 && *(*in + 2) != 0xff)) {
		return -1;
	}
	*val = *(*in + 2) ? 1 : 0;
	*in += 3;
	*inlen -= 3;
	return 1;
}

int asn1_integer_from_der_ex(int tag, const uint8_t **a, size_t *alen, const uint8_t **pin, size_t *pinlen)
{
	const uint8_t *in = *pin;
	size_t inlen = *pinlen;
	size_t len;

	if (!a || !alen || !pin || !(*pin) || !pinlen) {
		error_print();
		return -1;
	}

	if (inlen-- <= 0 || *in++ != tag) {
		return 0;
	}
	if (asn1_length_from_der(&len, &in, &inlen) != 1
		|| len <= 0) {
		error_print();
		return -1;
	}

	// 判断 ASN1_INTEGER 是否为负数，我们不支持负整数，返回特性不支持错误
	if (*in & 0x80) {
		error_print();
		return -255;
	}

	if (*in == 0 && len > 1) {
		inlen--;
		in++;
		len--;
	}
	if (*in == 0 && len > 1) {
		error_print();
		return -1;
	}
	*a = in;
	*alen = len;
	*pin = in + len;
	*pinlen = inlen - len;
	return 1;
}

int asn1_int_from_der_ex(int tag, int *a, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *p;
	size_t len, i;
	unsigned int val = 0;

	if (!a || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}
	if ((ret = asn1_integer_from_der_ex(tag, &p, &len, in, inlen)) != 1) {
		if (ret < 0) error_print();
		else *a = -1;
		return ret;
	}
	if (len > 8) {
		error_print();
		return -1;
	}

	for (i = 0; i < len; i++) {
		val = (val << 8) | p[i];
	}
	*a = val;
	return 1;
}

int asn1_bit_string_from_der_ex(int tag, const uint8_t **bits, size_t *nbits, const uint8_t **pin, size_t *pinlen)
{
	const uint8_t *in = *pin;
	size_t inlen = *pinlen;
	size_t len;
	int unused_bits;

	if (!bits || !nbits || !pin || !(*pin) || !pinlen) {
		error_print();
		return -1;
	}

	// FIXME: 其他函数可能存在类似情况				
	*bits = NULL;
	*nbits = 0;

	if (inlen-- < 1 || *in++ != tag) {
		return 0;
	}
	if (asn1_length_from_der(&len, &in, &inlen) != 1
		|| len <= 0) {
		error_print();
		return -1;
	}

	unused_bits = *in;
	if (unused_bits > 8 || (len == 1 && unused_bits > 0)) {
		error_print();
		return -1;
	}

	*bits = in + 1;
	*nbits = (len - 1) * 8 - unused_bits;
	*pin = in + len;
	*pinlen = inlen - len;
	return 1;
}

int asn1_bits_from_der_ex(int tag, int *bits, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *p;
	size_t nbits, i;
	uint8_t c;

	if ((ret = asn1_bit_string_from_der_ex(tag, &p, &nbits, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (nbits > 31) {
		error_print();
		return -1;
	}

	*bits = 0;
	for (i = 0; i < nbits; i++) {
		if (i % 8 == 0) {
			c = *p++;
		}
		*bits |= ((c & 0x80) >> 7) << i;
		c <<= 1;
	}
	return 1;
}

int asn1_null_from_der(const uint8_t **in, size_t *inlen)
{
	if (!in || !(*in) || !inlen) {
		return -1;
	}
	if (*inlen <= 0 || **in != ASN1_TAG_NULL) {
		return 0;
	}
	if (*inlen < 2
		|| (*in)[1] != 0x00) {
		return -1;
	}
	*in += 2;
	*inlen -= 2;
	return 1;
}

// FIXME：这个函数应该最终取消返回oid				
int asn1_object_identifier_from_der_ex(int tag, int *oid, uint32_t nodes[32], size_t *nodes_count,
	const uint8_t **pin, size_t *pinlen)
{
	const uint8_t *in = *pin;
	size_t inlen = *pinlen;
	size_t len;

	if (!nodes || !nodes_count || !pin || !(*pin) || !pinlen) {
		error_print();
		return -1;
	}

	if (inlen-- <= 0 || *in++ != tag) {
		error_print();
		return 0;
	}
	if (asn1_length_from_der(&len, &in, &inlen) != 1
		|| len <= 0) {
		error_print();
		return -1;
	}
	// 由于 asn1_oid_from_der 无法判断不识别的 OID 数据编码是否正确，因此必须先解码
	if (asn1_oid_nodes_from_octets(nodes, nodes_count, in, len) < 0) {
		error_print();
		return -1;
	}
	if (oid) {
		*oid = asn1_oid_from_octets(in, len);
	}
	*pin = in + len;
	*pinlen = inlen - len;
	return 1;
}

int asn1_string_from_der(int tag, const char **a, size_t *alen, const uint8_t **pin, size_t *pinlen)
{
	const uint8_t *in = *pin;
	size_t inlen = *pinlen;
	size_t len;

	if (!a || !alen || !pin || !(*pin) || !pinlen) {
		return -1;
	}

	if (inlen-- <= 0 || *in++ != tag) {
		return 0;
	}
	if (asn1_length_from_der(&len, &in, &inlen) != 1
		|| len <= 0) {
		return -1;
	}
	*a = (char *)in;
	*alen = len;

	*pin = in + len;
	*pinlen = inlen - len;
	return 1;
}

int asn1_utf8_string_from_der_ex(int tag, const char **a, size_t *alen, const uint8_t **in, size_t *inlen)
{
	return asn1_type_from_der(tag, (const uint8_t **)a, alen, in, inlen);
}

int asn1_printable_string_from_der_ex(int tag, const char **a, size_t *alen, const uint8_t **in, size_t *inlen)
{
	return asn1_type_from_der(tag, (const uint8_t **)a, alen, in, inlen);
}

int asn1_ia5_string_from_der_ex(int tag, const char **a, size_t *alen, const uint8_t **in, size_t *inlen)
{
	return asn1_type_from_der(tag, (const uint8_t **)a, alen, in, inlen);
}

/*
int hh, mm, ss;
struct tm when = {0};

sscanf_s(date, "%d:%d:%d", &hh, &mm, &ss);


when.tm_hour = hh;
when.tm_min = mm;
when.tm_sec = ss;

time_t converted;
converted = mktime(&when);
*/

int asn1_utc_time_from_der_ex(int tag, time_t *t, const uint8_t **pin, size_t *pinlen)
{
	const uint8_t *in = *pin;
	size_t inlen = *pinlen;
	struct tm tm_val;
	char buf[sizeof("YYYYMMDDHHMMSSZ")] = {0};
	size_t len;
	int year;


	if (!t || !pin || !(*pin) || !pinlen) {
		return -1;
	}
	if (inlen-- <= 0 || *in++ != tag) {
		return 0;
	}
	if (asn1_length_from_der(&len, &in, &inlen) != 1
		|| (len != sizeof("YYMMDDHHMMSSZ")-1 && len != sizeof("YYMMDDHHMMSS+HHMM")-1)) {
		return -1;
	}
	memcpy(buf + 2, in, len);

	if (!isdigit(buf[2]) && !isdigit(buf[3])) {
		return -1;
	}
	year = (buf[2] - '0') * 10 + (buf[3] - '0');
	if (year >= 50) {
		buf[0] = '1';
		buf[1] = '9';
	} else {
		buf[0] = '2';
		buf[1] = '0';
	}
	if (len == sizeof("YYMMDDHHMMSSZ")-1) {
		//  这里应该自己写一个函数来解析
		if (!strptime(buf, "%Y%m%d%H%M%SZ", &tm_val)) { // 注意：这个函数在Windows上没有！！		
			return -1;
		}
	} else {
		return -1;
	}
	*t = timegm(&tm_val); // FIXME: Windows !				

	*pin = in + len;
	*pinlen = inlen - len;
	return 1;
}

int asn1_generalized_time_from_der_ex(int tag, time_t *t, const uint8_t **pin, size_t *pinlen)
{
	int ret;
	const uint8_t *in = *pin;
	size_t inlen = *pinlen;
	struct tm tm_val;
	char buf[sizeof("YYYYMMDDHHMMSS+HHMM")] = {0};
	size_t len;

	if ((ret = asn1_tag_from_der(tag, &in, &inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_length_from_der(&len, &in, &inlen) != 1) {
		error_print();
		return -1;
	}
	if (len != sizeof("YYYYMMDDHHMMSSZ")-1 && len != sizeof("YYYYMMDDHHMMSS+HHMM")-1) {
		error_print();
		return -1;
	}
	memcpy(buf, in, len);



	if (len == sizeof("YYYYMMDDHHMMSSZ")-1) {
		if (!strptime(buf, "%Y%m%d%H%M%SZ", &tm_val)) {
			error_print();
			return -1;
		}
	} else {
		// TODO: 处理这种情况		
		error_print();
		return -2;
	}
	*t = timegm(&tm_val);
	*pin = in + len;
	*pinlen = inlen - len;
	return 1;
}

// 其中的每一个data/datalen都是一个ASN1的TLV，因此我们可以去解析
int asn1_sequence_of_get_next_item(const ASN1_SEQUENCE_OF *a, const uint8_t **next, const uint8_t **data, size_t *datalen)
{
	int ret;
	size_t len;
	int tag;
	const uint8_t *value;
	size_t valuelen;

	if (*next == NULL) {
		*next = a->data;
	}
	if (*next < a->data || *next > a->data + a->datalen) {
		error_print();
		return -1;
	}
	*data = *next;
	len = a->data + a->datalen - *next;
	ret = asn1_any_type_from_der(&tag, &value, &valuelen, next, &len);
	if (ret < 0) error_print();
	*datalen = *next - *data;
	return ret;
}

int asn1_sequence_of_get_count(const ASN1_SEQUENCE_OF *a, size_t *count)
{
	int ret;
	const uint8_t *next = NULL;
	const uint8_t *data;
	size_t datalen;

	*count = 0;
	while ((ret = asn1_sequence_of_get_next_item(a, &next, &data, &datalen)) == 1) {
		(*count)++;
	}
	if (ret < 0) {
		error_print();
		return -1;
	}
	return 1;
}

int asn1_check(int expr)
{
	if (expr)
		return 1;
	error_print();
	return -1;
}

int asn1_length_is_zero(size_t len)
{
	if (len) {
		error_print();
		return 0;
	}
	return 1;
}
