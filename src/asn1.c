/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


// https://www.obj-sys.com/asn1tutorial/node128.html

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
#include <gmssl/endian.h>


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
	case ASN1_TAG_EMBEDDED: return "EMBEDDED";
	case ASN1_TAG_UTF8String: return "UTF8String";
	case ASN1_TAG_RELATIVE_OID: return "RELATIVE_OID";
	case ASN1_TAG_NumericString: return "NumericString";
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
	case ASN1_TAG_EXPLICIT: return "EXPLICIT";
	}

	error_print();
	return NULL;
}

int asn1_tag_is_cstring(int tag)
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

int asn1_tag_to_der(int tag, uint8_t **out, size_t *outlen)
{
	if (out && *out) {
		*(*out)++ = (uint8_t)tag;
	}
	(*outlen)++;
	return 1;
}

int asn1_length_to_der(size_t len, uint8_t **out, size_t *outlen)
{
	if (len < 128) {
		if (out && *out) {
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

		if (out && *out) {
			*(*out)++ = 0x80 + i;
			memcpy(*out, buf + 4 - i, i);
			(*out) += i;
		}
		(*outlen) += 1 + i;
	}
	return 1;
}

// 提供返回值是为了和其他to_der函数一致
int asn1_data_to_der(const uint8_t *data, size_t datalen, uint8_t **out, size_t *outlen)
{
	if (out && *out) {
		memcpy(*out, data, datalen);
		*out += datalen;
	}
	*outlen += datalen;
	return 1;
}

int asn1_tag_from_der(int tag, const uint8_t **in, size_t *inlen)
{
	if (*inlen == 0) {
		return 0;
	}
	if  (**in != tag) {
		return 0;
	}
	(*in)++;
	(*inlen)--;
	return 1;
}

int asn1_tag_get(int *tag, const uint8_t **in, size_t *inlen)
{
	if (*inlen == 0) {
		return 0;
	}
	*tag = **in;
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

	*plen = len;
	*pin = in;
	*pinlen = inlen;

	if (inlen < len) {
		error_print_msg("inlen = %zu\n", *pinlen);
		error_print_msg("length = %zu, left = %zu\n", len, inlen);
		return -2; // 特殊错误值用于 test_asn1_length() 的测试
	}
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
	if (!outlen) {
		error_print();
		return -1;
	}
	asn1_tag_to_der(tag, out, outlen);
	asn1_length_to_der(len, out, outlen);
	return 1;
}


// If data == NULL, out should not be NULL
// 这个实现是不支持OPTIONAL的
int asn1_type_to_der(int tag, const uint8_t *d, size_t dlen, uint8_t **out, size_t *outlen)
{
	if (!d) {
		if (dlen) {
			error_print();
			return -1;
		}
		return 0;
	}
	if (asn1_tag_to_der(tag, out, outlen) != 1
		|| asn1_length_to_der(dlen, out, outlen) != 1
		|| asn1_data_to_der(d, dlen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int asn1_type_from_der(int tag, const uint8_t **d, size_t *dlen, const uint8_t **in, size_t *inlen)
{
	int ret;
	if ((ret = asn1_tag_from_der(tag, in, inlen)) != 1) {
		if (ret < 0) error_print();
		else {
			*d = NULL;
			*dlen = 0;
		}
		return ret;
	}
	if (asn1_length_from_der(dlen, in, inlen) != 1
		|| asn1_data_from_der(d, *dlen, in, inlen) != 1) {
		error_print();
		return -1;
	}
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

int asn1_any_to_der(const uint8_t *tlv, size_t tlvlen, uint8_t **out, size_t *outlen)
{
	return asn1_data_to_der(tlv, tlvlen, out, outlen);
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

#define ASN1_TRUE 0xff
#define ASN1_FALSE 0x00

const char *asn1_boolean_name(int val)
{
	switch (val) {
	case 1: return "true";
	case 0: return "false";
	}
	return NULL;
}

int asn1_boolean_from_name(int *val, const char *name)
{
	if (strcmp(name, "true") == 0) {
		*val = 1;
		return 1;
	} else if (strcmp(name, "false") == 0) {
		*val = 0;
		return 1;
	}
	*val = -1;
	return -1;
}

int asn1_boolean_to_der_ex(int tag, int val, uint8_t **out, size_t *outlen)
{
	if (!outlen) {
		error_print();
		return -1;
	}

	if (val < 0) {
		return 0;
	}

	if (out && *out) {
		*(*out)++ = tag;
		*(*out)++ = 0x01;
		*(*out)++ = val ? 0xff : 0x00;
	}
	(*outlen) += 3;
	return 1;
}

int asn1_integer_to_der_ex(int tag, const uint8_t *a, size_t alen, uint8_t **out, size_t *outlen)
{
	if (!outlen) {
		error_print();
		return -1;
	}

	if (!a) {
		return 0;
	}
	if (alen <= 0 || alen > INT_MAX) {
		error_print();
		return -1;
	}

	if (out && *out)
		*(*out)++ = tag;
	(*outlen)++;

	while (*a == 0 && alen > 1) {
		a++;
		alen--;
	}

	if (a[0] & 0x80) {
		asn1_length_to_der(alen + 1, out, outlen);
		if (out && *out) {
			*(*out)++ = 0x00;
			memcpy(*out, a, alen);
			(*out) += alen;
		}
		(*outlen) += 1 + alen;
	} else {
		asn1_length_to_der(alen, out ,outlen);
		if (out && *out) {
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
	uint8_t unused = (8 - nbits % 8) % 8;
	size_t nbytes = (nbits + 7) / 8;

	if (!bits) {
		return 0;
	}
	if (asn1_tag_to_der(tag, out, outlen) != 1
		|| asn1_length_to_der(nbytes + 1, out, outlen) != 1
		|| asn1_data_to_der(&unused, 1, out, outlen) != 1
		|| asn1_data_to_der(bits, nbytes, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int asn1_bit_octets_to_der_ex(int tag, const uint8_t *octs, size_t nocts, uint8_t **out, size_t *outlen)
{
	return asn1_bit_string_to_der_ex(tag, octs, nocts << 3, out, outlen);
}

int asn1_bits_to_der_ex(int tag, int bits, uint8_t **out, size_t *outlen)
{
	size_t nbits = 0;
	uint8_t buf[4] = {0};
	int i = 0;
	uint8_t mask = 0x80;

	if (bits < 0) {
		return 0;
	}
	while (bits > 0) {
		if (bits & 1)
			buf[i] |= mask;
		mask >>= 1;
		bits >>= 1;
		nbits++;
		if (nbits % 8 == 0) {
			i++;
			mask = 0x80;
		}
	}
	if (!nbits) {
		nbits = 1;
	}
	return asn1_bit_string_to_der_ex(tag, buf, nbits, out, outlen);
}

const char *asn1_null_name(void)
{
	return "null";
}

int asn1_null_to_der(uint8_t **out, size_t *outlen)
{
	if (!outlen) {
		error_print();
		return -1;
	}
	if (out && *out) {
		*(*out)++ = ASN1_TAG_NULL;
		*(*out)++ = 0x00;
	}
	*outlen += 2;
	return 1;
}

static void asn1_oid_node_to_base128(uint32_t a, uint8_t **out, size_t *outlen)
{
	uint8_t buf[5];
	int n = 0;

	buf[n++] = a & 0x7f;
	a >>= 7;

	while (a) {
		buf[n++] = 0x80 | (a & 0x7f);
		a >>= 7;
	}

	while (n--) {
		if (out && *out)
			*(*out)++ = buf[n];
		(*outlen)++;
	}
}

// 实际上我们在解析的时候是不知道具体在哪里结束的
// 解析是有可能出错的，如果没有发现最后一个0开头的字节就出错了
// 还有值太大也会出错，我们最多读取5个字节
// { 0x81, 0x82 }
// { 0x81, 0x82, 0x83, 0x84, 0x85, 0x06 }
static int asn1_oid_node_from_base128(uint32_t *a, const uint8_t **in, size_t *inlen)
{
	uint8_t buf[5];
	int n = 0;
	int i;

	for (;;) {
		if ((*inlen)-- < 1 || n >= 5) {
			return -1;
		}
		buf[n] = *(*in)++;
		if ((buf[n++] & 0x80) == 0) {
			break;
		}
	}

	// 32 - 7*4 = 4, so the first byte should be like 1000bbbb
	if (n == 5 && (buf[0] & 0x70)) {
		return -1;
	}

	*a = 0;
	for (i = 0; i < n; i++) {
		*a = ((*a) << 7) | (buf[i] & 0x7f);
	}

	return 1;
}

int asn1_object_identifier_to_octets(const uint32_t *nodes, size_t nodes_cnt, uint8_t *out, size_t *outlen)
{
	if (!outlen) {
		error_print();
		return -1;
	}
	if (nodes_cnt < 2 || nodes_cnt > 32) {
		return -1;
	}
	if (out)
		*out++ = (uint8_t)(nodes[0] * 40 + nodes[1]);
	(*outlen) = 1;
	nodes += 2;
	nodes_cnt -= 2;

	while (nodes_cnt--) {
		asn1_oid_node_to_base128(*nodes++, &out, outlen);
	}
	return 1;
}

// 因为这个函数总是被asn1函数调用的，因此给的输入数据长度是已知的
int asn1_object_identifier_from_octets(uint32_t *nodes, size_t *nodes_cnt, const uint8_t *in, size_t inlen)
{
	size_t count = 0;
	const uint8_t *p = in;
	size_t len = inlen;

	if (!nodes || !nodes_cnt || !in || inlen <= 0) {
		error_print();
		return -1;
	}

	if (inlen < 1) {
		error_print();
		return -1;
	}

	// FIXME: 需要支持 nodes = NULL 吗？
	if (nodes) {
		*nodes++ = (*in) / 40;
		*nodes++ = (*in) % 40;
	}
	in++;
	inlen--;
	count += 2;

	while (inlen) {
		uint32_t val;
		if (count > 32) {
			error_print();
			return -1;
		}
		if (asn1_oid_node_from_base128(&val, &in, &inlen) < 0) {
			error_print();
			return -1;
		}
		if (nodes) {
			*nodes++ = val;
		}
		count++;
	}

	*nodes_cnt = count;
	return 1;
}

int asn1_object_identifier_to_der_ex(int tag, const uint32_t *nodes, size_t nodes_cnt, uint8_t **out, size_t *outlen)
{
	uint8_t octets[32];
	size_t octetslen = 0;

	if (!outlen) {
		error_print();
		return -1;
	}

	if (out && *out)
		*(*out)++ = tag;
	(*outlen)++;

	asn1_object_identifier_to_octets(nodes, nodes_cnt, octets, &octetslen);

	asn1_length_to_der(octetslen, out, outlen);

	if (out && *out) {
		// 注意：If out == NULL, *out ==> Segment Fault
		memcpy(*out, octets, octetslen);
		*out += octetslen;
	}
	*outlen += octetslen;
	return 1;
}

const ASN1_OID_INFO *asn1_oid_info_from_name(const ASN1_OID_INFO *infos, size_t count, const char *name)
{
	size_t i;
	for (i = 0; i < count; i++) {
		if (strcmp(infos[i].name, name) == 0) {
			return &infos[i];
		}
	}
	return NULL;
}

const ASN1_OID_INFO *asn1_oid_info_from_oid(const ASN1_OID_INFO *infos, size_t count, int oid)
{
	size_t i;
	for (i = 0; i < count; i++) {
		if (infos[i].oid == oid) {
			return &infos[i];
		}
	}
	return NULL;
}

// 如果一个正确解析的OID并不在infos列表中，那么仍然返回1，但是调用方必须检查返回的info是否为空
int asn1_oid_info_from_der_ex(const ASN1_OID_INFO **info, uint32_t *nodes, size_t *nodes_cnt,
	const ASN1_OID_INFO *infos, size_t count, const uint8_t **in, size_t *inlen)
{
	int ret;
	size_t i;

	if ((ret = asn1_object_identifier_from_der(nodes, nodes_cnt, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	*info = NULL;
	for (i = 0; i < count; i++) {
		if (*nodes_cnt == infos[i].nodes_cnt
			&& memcmp(nodes, infos[i].nodes, (*nodes_cnt) * sizeof(int)) == 0) {
			*info = &infos[i];
			goto end;
		}
	}
end:
	return 1;
}

// 和ex版本不同的是，如果在infos列表中未找到OID，返回错误
int asn1_oid_info_from_der(const ASN1_OID_INFO **info, const ASN1_OID_INFO *infos, size_t count, const uint8_t **in, size_t *inlen)
{
	int ret;
	uint32_t nodes[32];
	size_t nodes_cnt;

	if ((ret = asn1_oid_info_from_der_ex(info, nodes, &nodes_cnt, infos, count, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (*info == NULL) {
		asn1_object_identifier_print(stderr, 0, 0, "Unknown OID", NULL, nodes, nodes_cnt);
		error_print();
		return -1;
	}
	return 1;
}


// asn1_oid_from_octets 不返回错误值，只返回 OID_undef
// 但是数据编码仍可能是非法的
// 如果返回 OID_undef，需要通过 asn1_object_identifier_from_octets 判断格式是否正确

// 显然这个函数并不合适，因为在整个gmssl中，我们不提供完整的ASN.1数据库，无法从一个OID中给出解析








int asn1_utf8_string_to_der_ex(int tag, const char *d, size_t dlen, uint8_t **out, size_t *outlen)
{
	return asn1_type_to_der(tag, (const uint8_t *)d, dlen, out, outlen);
}

int asn1_printable_string_to_der_ex(int tag, const char *d, size_t dlen, uint8_t **out, size_t *outlen)
{
	return asn1_type_to_der(tag, (const uint8_t *)d, dlen, out, outlen);
}

int asn1_ia5_string_to_der_ex(int tag, const char *d, size_t dlen, uint8_t **out, size_t *outlen)
{
	return asn1_type_to_der(tag, (const uint8_t *)d, dlen, out, outlen);
}

int asn1_utc_time_to_der_ex(int tag, time_t a, uint8_t **out, size_t *outlen)
{
	struct tm tm_val;
	char buf[ASN1_UTC_TIME_LEN + 1];

	if (!outlen) {
		error_print();
		return -1;
	}

	gmtime_r(&a, &tm_val);
	strftime(buf, sizeof(buf), "%y%m%d%H%M%SZ", &tm_val);

	if (out && *out)
		*(*out)++ = tag;
	(*outlen)++;
	asn1_length_to_der(sizeof(buf)-1, out, outlen);
	if (out && *out) {
		memcpy(*out, buf, sizeof(buf)-1);
		(*out) += sizeof(buf)-1;
	}
	*outlen += sizeof(buf)-1;

	return 1;
}


int asn1_generalized_time_to_der_ex(int tag, time_t a, uint8_t **out, size_t *outlen)
{
	struct tm tm_val;
	char buf[ASN1_GENERALIZED_TIME_LEN + 1];

	if (!outlen) {
		error_print();
		return -1;
	}

	gmtime_r(&a, &tm_val);
	strftime(buf, sizeof(buf), "%Y%m%d%H%M%SZ", &tm_val);
	//printf("%s %d: generalized time : %s\n", __FILE__, __LINE__, buf);

	if (out && *out)
		*(*out)++ = tag;
	(*outlen)++;
	asn1_length_to_der(ASN1_GENERALIZED_TIME_LEN, out, outlen);
	if (out && *out) {
		memcpy(*out, buf, ASN1_GENERALIZED_TIME_LEN);
		(*out) += ASN1_GENERALIZED_TIME_LEN;
	}
	*outlen += ASN1_GENERALIZED_TIME_LEN;

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
		*val = -1;
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

int asn1_bit_string_from_der_ex(int tag, const uint8_t **bits, size_t *nbits, const uint8_t **in, size_t *inlen)
{
	int ret;
	size_t len;
	int unused_bits;

	if ((ret = asn1_tag_from_der(tag, in, inlen)) != 1) {
		if (ret < 0) error_print();
		else {
			*bits = NULL;
			*nbits = 0;
		}
		return ret;
	}
	if (asn1_length_from_der(&len, in, inlen) != 1
		|| asn1_data_from_der(bits, len, in, inlen) != 1) {
		error_print();
		return -1;
	}
	if (len < 2) {
		error_print();
		return -1;
	}


	unused_bits = **bits;

	if (len < 1) {
		error_print();
		return -1;
	}
	if (unused_bits > 8 || (len == 1 && unused_bits > 0)) {
		error_print();
		return -1;
	}

	(*bits)++;
	*nbits = (len - 1) << 3;

	return 1;
}

int asn1_bit_octets_from_der_ex(int tag, const uint8_t **octs, size_t *nocts, const uint8_t **in, size_t *inlen)
{
	int ret;
	size_t nbits;

	if ((ret = asn1_bit_string_from_der_ex(tag, octs, &nbits, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (nbits % 8) {
		error_print();
		return -1;
	}
	*nocts = nbits >> 3;
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

int asn1_object_identifier_from_der_ex(int tag, uint32_t *nodes, size_t *nodes_cnt,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	size_t len;
	const uint8_t *p;

	if ((ret = asn1_tag_from_der(tag, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_length_from_der(&len, in, inlen) != 1
		|| asn1_data_from_der(&p, len, in, inlen) != 1
		|| asn1_object_identifier_from_octets(nodes, nodes_cnt, p, len) != 1) {
		error_print();
		return -1;
	}
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
		return -1;
	}
	return 1;
}

int asn1_length_le(size_t len1, size_t len2)
{
	if (len1 > len2) {
		error_print();
		format_print(stderr, 0, 0, "%s: %zu <= %zu failed\n", __FUNCTION__, len1, len2);
		return -1;
	}
	return 1;
}

int asn1_object_identifier_equ(const uint32_t *a, size_t a_cnt, const uint32_t *b, size_t b_cnt)
{
	if (a_cnt == b_cnt
		&& memcmp(a, b, b_cnt * sizeof(uint32_t)) == 0) {
		return 1;
	}
	return 0;
}


int asn1_sequence_of_int_to_der(const int *nums, size_t nums_cnt, uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	size_t i;
	for (i = 0; i < nums_cnt; i++) {
		if (asn1_int_to_der(nums[i], NULL, &len) != 1) {
			error_print();
			return -1;
		}
	}
	if (asn1_sequence_header_to_der(len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	for (i = 0; i < nums_cnt; i++) {
		if (asn1_int_to_der(nums[i], out, outlen) != 1) {
			error_print();
			return -1;
		}
	}
	return 1;
}

int asn1_sequence_of_int_from_der(int *nums, size_t *nums_cnt, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	*nums_cnt = 0;
	while (dlen) {
		int num;
		if (asn1_int_from_der(&num, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		if (nums) {
			*nums++ = num;
		}
		(*nums_cnt)++;
	}
	return 1;
}

int asn1_sequence_of_int_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int val;
	format_print(fp, fmt, ind, "%s: ", label);
	while (dlen) {
		if (asn1_int_from_der(&val, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		fprintf(fp, "%d%s", val, dlen ? "," : "");
	}
	fprintf(fp, "\n");
	return 1;
}


int asn1_object_identifier_print(FILE *fp, int format, int indent, const char *label, const char *name,
	const uint32_t *nodes, size_t nodes_cnt)
{
	size_t i;
	format_print(fp, format, indent, "%s: %s", label, name ? name : "(unknown)");
	if (nodes) {
		fprintf(fp, " (");
		for (i = 0; i < nodes_cnt - 1; i++) {
			fprintf(fp, "%d.", (int)nodes[i]);
		}
		fprintf(fp, "%d)", nodes[i]);
	}
	fprintf(fp, "\n");
	return 1;
}

int asn1_string_print(FILE *fp, int fmt, int ind, const char *label, int tag, const uint8_t *d, size_t dlen)
{
	format_print(fp, fmt, ind, "%s: ", label);
	while (dlen--) {
		fprintf(fp, "%c", *d++);
	}
	fprintf(fp, "\n");
	return 1;
}

int asn1_bits_print(FILE *fp, int fmt, int ind, const char *label, const char **names, size_t names_cnt, int bits)
{
	size_t i;
	format_print(fp, fmt, ind, "%s: ", label);

	for (i = 0; i < names_cnt; i++) {
		if (bits & 0x01)
			fprintf(fp, "%s%s", names[i], bits >> 1 ? "," : "");
		bits >>= 1;
	}
	fprintf(fp, "\n");
	if (bits) {
		error_print();
		return -1;
	}
	return 1;
}

int asn1_types_get_count(const uint8_t *d, size_t dlen, int tag, size_t *cnt)
{
	error_print();
	return -1;
}

int asn1_types_get_item_by_index(const uint8_t *d, size_t *dlen, int tag,
	int index, const uint8_t **item_d, size_t *item_dlen)
{
	error_print();
	return -1;
}
