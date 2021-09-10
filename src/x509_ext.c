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
#include <gmssl/asn1.h>
#include <gmssl/x509.h>
#include <gmssl/error.h>



/*
首先应该完成一些重要的证书扩展


BasicConstraints:

  CA证书必须包含这个扩展（但是如果证书是v1版本的，那么不支持扩展，我们直接不支持V1证书的验证）
  这个扩展中包含depth值，在验证证书链是必须检查depth是否正确

KeyUsage

  CA证书如果包含这个扩展，那么应该设置 CertificateSigner, CRLSigner
  SSL终端证书需要这个扩展吗？

ExtKeyUsage

  SSL终端证书应该包含serverAuth, clientAuth
  RFC 5480要求这个扩展只能被用于终端证书，但是有些中间CA证书也包含了这个扩展

*/


/*
BEGIN SEQUENCE OF

	X509_GENERAL_NAMES
	X509_POLICY_QUALIFIER_INFOS
	X509_CERTIFICATE_POLICIES
	X509_POLICY_MAPPINGS
	X509_ATTRIBUTES
	X509_GENERAL_SUBTREES
	X509_CRL_DISTRIBUTION_POINTS

这些类型 to_der 还是 implicit to der 都比较简单，只要调用 type_to_der 就可以了
但是这些类型 from_der 就不一样，必须还要检查输入的长度，如果输入的长度超过了buffer空间，就只能返回错误了


*/



//////////////////////////////////////////////////////////////////////////////////////////
// x509_[type_name]_[to|from]_der
//////////////////////////////////////////////////////////////////////////////////////////

/*
int x509_general_names_from_der_ex(int tag, X509_GENERAL_NAMES *a, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;

	if ((ret = asn1_constructed_from_der_ex(tag, &data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (datalen > 256) {
		error_print();
		return -1;
	}
	memcpy(a->data, data, datalen);
	a->datalen = datalen;
	return 1;
}

int x509_general_names_from_der(X509_GENERAL_NAMES *a, const uint8_t **in, size_t *inlen)
{
	return x509_general_names_from_der_ex(ASN1_TAG_SEQUENCE, a, in, inlen);
}

int x509_implicit_general_names_from_der(int index, X509_GENERAL_NAMES *a, const uint8_t **in, size_t *inlen)
{
	return x509_general_names_from_der_ex(ASN1_TAG_EXPLICIT(index), a, in, inlen);
}

int x509_certificate_policies_to_der(const X509_CERTIFICATE_POLICIES *a, uint8_t **out, size_t *outlen)
{
	return asn1_sequence_to_der(a->data, a->datalen, out, outlen);
}

int x509_certificate_policies_from_der(X509_CERTIFICATE_POLICIES *a, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (datalen > 128) {
		error_print();
		return -1;
	}
	memcpy(a->data, data, datalen);
	a->datalen = datalen;
	return 1;
}




int x509_policy_qualifier_infos_to_der(const X509_POLICY_QUALIFIER_INFOS *a, uint8_t **out, size_t *outlen)
{
	return asn1_sequence_to_der(a->data, a->datalen, out, outlen);
}

int x509_policy_qualifier_infos_from_der(X509_POLICY_QUALIFIER_INFOS *a, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (datalen > 256) {
		error_print();
		return -1;
	}
	memcpy(a->data, data, datalen);
	a->datalen = datalen;
	return 1;
}




int x509_certificate_policies_to_der(const X509_CERTIFICATE_POLICIES *a, uint8_t **out, size_t *outlen)
{
	return asn1_sequence_to_der(a->data, a->datalen, out, outlen);
}

int x509_certificate_policies_from_der(X509_CERTIFICATE_POLICIES *a, const uint8_t **in, size_t *inlen)
{
	int ret
	const uint8_t *data;
	size_t datalen;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (datalen > 1024) {
		error_print();
		return -1;
	}
	memcpy(a->data, data, datalen);
	a->datalen = datalen;
	return 1;
}

int x509_policy_mappings_to_der(const X509_POLICY_MAPPINGS *a, uint8_t **out, size_t *outlen)
{
	return asn1_sequence_to_der(a->data, a->datalen, out, outlen);
}

int x509_policy_mappings_from_der(X509_POLICY_MAPPINGS *a, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (datalen > 1024) {
		error_print();
		return -1;
	}
	memcpy(a->data, data, datalen);
	a->datalen = datalen;
	return 1;
}

int x509_attributess_to_der(const X509_ATTRIBUTES *a, uint8_t **out, size_t *outlen)
{
	asn1_sequence_to_der(a->data, a->datalen, out, outlen);
	return 1;
}

int x509_attributes_from_der(X509_ATTRIBUTES *a, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (datalen > 128) {
		error_print();
		return -1;
	}
	memcpy(a->data, data, datalen);
	a->datalen = datalen;
	return 1;
}


int x509_general_subtrees_to_der(const X509_GENERAL_SUBTREES *a, uint8_t **out, size_t *outlen)
{
	return asn1_sequence_to_der(a->data, a->datalen, out, outlen);
}

int x509_general_subtrees_from_der(X509_GENERAL_SUBTREES *a, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (datalen > 128) {
		error_print();
		return -1;
	}
	memcpy(a->data, data, datalen);
	a->datalen = datalen;
	return 1;
}



*/


static const struct {
	uint8_t der;
	int oid;
	char *name;
	char *text;
} x509_kp[] = {
	{ 1, OID_kp_serverAuth, "serverAuth", "TLS WWW server authentication" },
	{ 2, OID_kp_clientAuth, "clientAuth", "TLS WWW client authentication" },
	{ 3, OID_kp_codeSigning, "codeSigning", "Signing of downloadable executable code" },
	{ 4, OID_kp_emailProtection, "emailProtection", "Email protection" },
	{ 8, OID_kp_timeStamping, "timeStamping", "Binding the hash of an object to a time" },
	{ 9, OID_kp_OCSPSigning, "OCSPSigning", "Signing OCSP responses" },
};

int x509_key_purpose_from_name(int *oid, const char *name)
{
	int i;
	for (i = 0; i < sizeof(x509_kp)/sizeof(x509_kp[0]); i++) {
		if (strcmp(name, x509_kp[i].name) == 0) {
			*oid = x509_kp[i].oid;
			return 1;
		}
	}
	error_print();
	return -1;
}

const char *x509_key_purpose_name(int oid)
{
	int i;
	for (i = 0; i < sizeof(x509_kp)/sizeof(x509_kp[0]); i++) {
		if (oid == x509_kp[i].oid) {
			return x509_kp[i].name;
		}
	}
	return NULL;
}

const char *x509_key_purpose_text(int oid)
{
	int i;
	for (i = 0; i < sizeof(x509_kp)/sizeof(x509_kp[0]); i++) {
		if (oid == x509_kp[i].oid) {
			return x509_kp[i].text;
		}
	}
	return NULL;
}

int x509_key_purpose_to_der(int oid, uint8_t **out, size_t *outlen)
{
	uint8_t der[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x00 };
	int i;
	for (i = 0; i < sizeof(x509_kp)/sizeof(x509_kp[0]); i++) {
		if (oid == x509_kp[i].oid) {
			der[sizeof(der) - 1] = x509_kp[i].der;
			if (asn1_type_to_der(ASN1_TAG_OBJECT_IDENTIFIER, der, sizeof(der), out, outlen) != 1) {
				error_print();
				return -1;
			}
			return 1;
		}
	}
	error_print_msg("unknown key purpose oid %d", oid);
	return -1;

}

int x509_key_purpose_from_der(int *oid, const uint8_t **in, size_t *inlen)
{
	const uint8_t der[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x00 };
	const uint8_t *data;
	size_t datalen;
	int ret, i;

	if ((ret = asn1_type_from_der(ASN1_TAG_OBJECT_IDENTIFIER, &data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (datalen != sizeof(der) || memcmp(data, der, sizeof(der)-1) != 0) {
		error_print();
		return -1;
	}
	for (i = 0; i < sizeof(x509_kp)/sizeof(x509_kp[0]); i++) {
		if (data[datalen-1] == x509_kp[i].der) {
			*oid = x509_kp[i].oid;
			return 1;
		}
	}
	// 这种情况下应该把这个值打印出来
	error_puts("unknown ExtKeyUsage OID");
	return -1;
}

int x509_ext_key_usage_to_der(const int *oids, size_t oids_count, uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	size_t i;
	for (i = 0; i < oids_count; i++) {
		x509_key_purpose_to_der(oids[i], NULL, &len);
	}
	asn1_sequence_header_to_der(len, out, outlen);
	for (i = 0; i < oids_count; i++) {
		x509_key_purpose_to_der(oids[i], out, outlen);
	}
	return 1;
}

int x509_ext_key_usage_from_der(int *oids, size_t *oids_count, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	*oids_count = 0;
	while (datalen) {
		if (x509_key_purpose_from_der(oids, &data, &datalen) != 1) {
			error_print();
			return -1;
		}
		oids++;
		(*oids_count)++;
	}
	return 1;
}




int x509_crl_distribution_points_to_der(const X509_CRL_DISTRIBUTION_POINTS *a, uint8_t **out, size_t *outlen)
{
	return asn1_sequence_to_der(a->data, a->datalen, out, outlen);
}

int x509_crl_distribution_points_from_der(X509_CRL_DISTRIBUTION_POINTS *a, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;
	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (datalen > 128) {
		error_print();
		return -1;
	}
	memcpy(a->data, data, datalen);
	a->datalen = datalen;
	return 1;
}











// x509_[type_name]_add_item

int x509_general_names_add_item(X509_GENERAL_NAMES *a,
	int choice, const uint8_t *data, size_t datalen)
{
	uint8_t *p = a->data + a->datalen;
	size_t len = 0;
	if (x509_general_name_to_der(choice, data, datalen, &p, &len) != 1) {
		error_print();
		return -1;
	}
	a->datalen += len;
	return 1;
}

int x509_policy_qualifier_infos_add_item(X509_POLICY_QUALIFIER_INFOS *a,
	int oid, const uint8_t *qualifier, size_t qualifier_len)
{
	uint8_t *p = a->data + a->datalen;
	size_t len = 0;
	if (x509_policy_qualifier_info_to_der(oid, qualifier, qualifier_len, &p, &len) != 1) {
		error_print();
		return -1;
	}
	a->datalen += len;
	return 1;
}

int x509_certificate_policies_add_item(X509_CERTIFICATE_POLICIES *a,
	int oid, const uint32_t *nodes, size_t nodes_count,
	const X509_POLICY_QUALIFIER_INFOS *qualifiers)
{
	uint8_t *p = a->data + a->datalen;
	size_t len = 0;
	if (x509_policy_information_to_der(oid, nodes, nodes_count, qualifiers, &p, &len) != 1) {
		error_print();
		return -1;
	}
	a->datalen += len;
	return 1;
}

int x509_policy_mappings_add_item(X509_POLICY_MAPPINGS *a,
	int issuer_policy_oid, const uint32_t *issuer_policy_nodes, size_t issuer_policy_nodes_count,
	int subject_policy_oid, const uint32_t *subject_policy_nodes, size_t subject_policy_nodes_count)
{
	uint8_t *p = a->data + a->datalen;
	size_t len = 0;
	if (x509_policy_mapping_to_der(
		issuer_policy_oid, issuer_policy_nodes, issuer_policy_nodes_count,
		subject_policy_oid, subject_policy_nodes, subject_policy_nodes_count,
		&p, &len) != 1) {
		error_print();
		return -1;
	}
	a->datalen += len;
	return 1;
}

int x509_attributes_add_item(X509_ATTRIBUTES *a,
	int oid, const uint32_t *nodes, size_t nodes_count,
	const uint8_t *values, size_t valueslen)
{
	uint8_t *p = a->data + a->datalen;
	size_t len = 0;
	if (x509_attribute_to_der(oid, nodes, nodes_count, values, valueslen, &p, &len) != 1) {
		error_print();
		return -1;
	}
	a->datalen += len;
	return 1;
}

int x509_general_subtrees_add_item(X509_GENERAL_SUBTREES *a,
	int base_choise, const uint8_t *base_data, size_t base_datalen,
	int minimum,
	int maximum)
{
	uint8_t *p = a->data + a->datalen;
	size_t len = 0;
	if (x509_general_subtree_to_der(base_choise, base_data, base_datalen, minimum, maximum, &p, &len) != 1) {
		error_print();
		return -1;
	}
	a->datalen += len;
	return 1;
}

int x509_crl_distribution_points_add_item(X509_CRL_DISTRIBUTION_POINTS *a,
	const X509_DISTRIBUTION_POINT_NAME *dist_point_name,
	int reason_bits,
	const X509_GENERAL_NAMES *crl_issuer)
{
	uint8_t *p = a->data + a->datalen;
	size_t len = 0;
	if (x509_distribution_point_to_der(dist_point_name, reason_bits, crl_issuer, &p, &len) != 1) {
		error_print();
		return -1;
	}
	a->datalen += len;
	return 1;
}


//////////////////////////////////////////////////////////////////////////////////////////
// x509_[type_name]_get_next_item
// *next == NULL 表示从头开始
// 应该吧公共代码提取为一个公共函数
//////////////////////////////////////////////////////////////////////////////////////////


int x509_general_names_get_next_item(const X509_GENERAL_NAMES *a, const uint8_t **next,
	int *choice, const uint8_t **data, size_t *datalen)
{
	int ret;
	const uint8_t *value;
	size_t valuelen;
	if ((ret = asn1_sequence_of_get_next_item((ASN1_SEQUENCE_OF *)a, next, &value, &valuelen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	ret = x509_general_name_from_der(choice, data, datalen, &value, &valuelen);
	if (ret < 0) error_print();
	return ret;
}

int x509_policy_qualifier_infos_get_next_item(const X509_POLICY_QUALIFIER_INFOS *a, const uint8_t **next,
	int *oid, const uint8_t **qualifier, size_t *qualifier_len)
{
	int ret;
	const uint8_t *value;
	size_t valuelen;
	if ((ret = asn1_sequence_of_get_next_item((ASN1_SEQUENCE_OF *)a, next, &value, &valuelen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	ret = x509_policy_qualifier_info_from_der(oid, qualifier, qualifier_len, &value, &valuelen);
	if (ret < 0) error_print();
	return ret;
}

int x509_certificate_policies_get_next_item(const X509_CERTIFICATE_POLICIES *a, const uint8_t **next,
	int *oid, const uint32_t *nodes, size_t *nodes_count,
	X509_POLICY_QUALIFIER_INFOS *qualifiers)
{
	int ret;
	const uint8_t *value;
	size_t valuelen;
	/*
	if ((ret = asn1_sequence_of_get_next_item((ASN1_SEQUENCE_OF *)a, next, &value, &valuelen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	ret = x509_certificate_policy_from_der(oid, nodes, nodes_count, qualifiers, qualifiers_len, &value, &valuelen);
	if (ret < 0) error_print();
	*/
	return ret;
}

int x509_policy_mappings_get_next_item(const X509_POLICY_MAPPINGS *a, const uint8_t **next,
	uint32_t *issuer_policy_nodes, size_t *issuer_policy_nodes_count,
	uint32_t *subject_policy_nodes, size_t *subject_policy_nodes_count)
{
	int ret;
	const uint8_t *value;
	size_t valuelen;
	if ((ret = asn1_sequence_of_get_next_item((ASN1_SEQUENCE_OF *)a, next, &value, &valuelen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	/*
	ret = x509_policy_mapping_from_der(
		issuer_policy_nodes, issuer_policy_nodes_count,
		subject_policy_nodes, subject_policy_nodes_count,
		&value, &valuelen);
	*/
	if (ret < 0) error_print();
	return ret;
}

int x509_attributes_get_next_item(const X509_ATTRIBUTES *a, const uint8_t **next,
	int *oid, uint32_t *nodes, size_t *nodes_count,
	const uint8_t **data, size_t *datalen)
{
	int ret;
	const uint8_t *value;
	size_t valuelen;
	if ((ret = asn1_sequence_of_get_next_item((ASN1_SEQUENCE_OF *)a, next, &value, &valuelen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	ret = x509_attribute_from_der(oid, nodes, nodes_count, data, datalen, &value, &valuelen);
	if (ret < 0) error_print();
	return ret;
}

int x509_general_subtrees_get_next_item(const X509_GENERAL_SUBTREES *a, const uint8_t **next,
	int *base_choise, const uint8_t **base_data, size_t *base_datalen,
	int *minimum,
	int *maximum)
{
	int ret;
	const uint8_t *value;
	size_t valuelen;
	if ((ret = asn1_sequence_of_get_next_item((ASN1_SEQUENCE_OF *)a, next, &value, &valuelen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	ret = x509_general_subtree_from_der(
		base_choise, base_data, base_datalen,
		minimum, maximum,
		&value, &valuelen);
	if (ret < 0) error_print();
	return ret;
}

int x509_crl_distribution_points_get_next_item(const X509_CRL_DISTRIBUTION_POINTS *a,
	const uint8_t **next,
	X509_DISTRIBUTION_POINT_NAME *distribution_point,
	int *reasons,
	X509_GENERAL_NAMES *crl_issuer)
{
	int ret;
	const uint8_t *value;
	size_t valuelen;
	if ((ret = asn1_sequence_of_get_next_item((ASN1_SEQUENCE_OF *)a, next, &value, &valuelen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	ret = x509_distribution_point_from_der(distribution_point, reasons, crl_issuer, &value, &valuelen);
	if (ret < 0) error_print();
	return ret;
}

// END SEQUENCE OF



/*
	DisplayText		CHOICE Universal
	Name			SEQUENCE OF
	OtherName		SEQUENCE
	EDIPartyName		SEQUENCE
	GeneralName		CHOICE
	GeneralNames		SEQUENCE OF
	AuthorityKeyIdentifier	SEQUENCE
	CertificatePolicies	SEQUENCE OF
	PolicyInformation
	UserNotice
*/

/*
DisplayText ::= CHOICE { IA5String, VisibleString, BMPString, UTF8String }

*/
int x509_display_text_to_der(int tag, const char *text, size_t textlen, uint8_t **out, size_t *outlen)
{
	int ret;
	switch (tag) {
	case ASN1_TAG_IA5String:
	case ASN1_TAG_VisibleString:
	case ASN1_TAG_UTF8String:
		if (strlen(text) != textlen) {
			error_print();
			return -1;
		}
		break;
	case ASN1_TAG_BMPString:
		break;
	default:
		error_print();
		return -1;
	}
	ret = asn1_type_to_der(tag, (const uint8_t *)text, textlen, out, outlen);
	if (ret < 0) error_print();
	return ret;
}

int x509_display_text_from_der(int *tag, const char **text, size_t *textlen, const uint8_t **in, size_t *inlen)
{
	int ret;

	if ((ret = asn1_any_type_from_der(tag, (const uint8_t **)text, textlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	switch (*tag) {
	case ASN1_TAG_IA5String:
	case ASN1_TAG_VisibleString:
	case ASN1_TAG_UTF8String:
		if (strlen(*text) != *textlen) {
			error_print();
			return -1;
		}
		break;
	case ASN1_TAG_BMPString:
		break;
	default:
		error_print();
		return -1;
	}
	return 1;
}

/*
EDIPartyName ::= SEQUENCE {
	nameAssigner	[0] EXPLICIT DirectoryString OPTIONAL,
	partyName	[1] EXPLICIT DirectoryString }

	DirectoryString 是 CHOICE 类型，因此必须为 EXPLICIT Tag
*/
int x509_edi_party_name_to_der(
	int assigner_tag, const char *assigner, size_t assigner_len,
	int party_name_tag, const char *party_name, size_t party_name_len,
	uint8_t **out, size_t *outlen)
{
	size_t sublen0;
	size_t sublen1;
	size_t len = 0;
	if ((assigner && x509_directory_string_to_der(assigner_tag, assigner, assigner_len, NULL, &sublen0) != 1)
		|| (assigner && asn1_explicit_to_der(0, NULL, sublen0, NULL, &len) != 1)
		|| x509_directory_string_to_der(party_name_tag, party_name, party_name_len, NULL, &sublen1) != 1
		|| asn1_explicit_to_der(1, NULL, sublen1, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| (assigner && asn1_explicit_header_to_der(0, sublen0, out, outlen) != 1)
		|| (assigner && x509_directory_string_to_der(assigner_tag, assigner, assigner_len, out, outlen) != 1)
		|| asn1_explicit_header_to_der(1, sublen1, out, outlen) != 1
		|| x509_directory_string_to_der(party_name_tag, party_name, party_name_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_edi_party_name_from_der(int *assigner_tag, const char **assigner, size_t *assigner_len,
	int *party_name_tag, const char **party_name, size_t *party_name_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data, *subdata0;
	size_t datalen;
	const uint8_t *exp0, *exp1;
	size_t explen0, explen1;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_explicit_from_der(0, &exp0, &explen0, &data, &datalen) < 0
		|| asn1_explicit_from_der(1, &exp1, &explen1, &data, &datalen) != 1
		|| datalen > 0) {
		error_print();
		return -1;
	}
	if ((exp0 && x509_directory_string_from_der(assigner_tag, assigner, assigner_len, &exp0, &explen0) != 1)
		|| x509_directory_string_from_der(party_name_tag, party_name, party_name_len, &exp1, &explen1) != 1) {
		error_print();
		return -1;
	}
	return -1;
}

/*
OtherName ::= SEQUENCE {
	type-id		OBJECT IDENTIFIER,
	value		[0] EXPLICIT ANY DEFINED BY type-id
}
*/
int x509_other_name_to_der(int oid, const uint32_t *nodes, size_t nodes_count,
	const uint8_t *value, size_t valuelen,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (asn1_object_identifier_to_der(oid, nodes, nodes_count, NULL, &len) != 1
		|| asn1_explicit_to_der(0, value, valuelen, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_object_identifier_to_der(oid, nodes, nodes_count, out, outlen) != 1
		|| asn1_explicit_to_der(0, value, valuelen, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_other_name_from_der(int *oid, uint32_t *nodes, size_t *nodes_count,
	const uint8_t **value, size_t *valuelen, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;
	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_object_identifier_from_der(oid, nodes, nodes_count, &data, &datalen) != 1
		|| asn1_explicit_from_der(0, value, valuelen, &data, &datalen) != 1
		|| datalen > 0) {
		error_print();
		return -1;
	}
	return 1;
}

/*
GeneralName ::= CHOICE {
        otherName                       [0] IMPLICIT OtherName,
        rfc822Name                      [1] IMPLICIT IA5String,
        dNSName                         [2] IMPLICIT IA5String,
        x400Address                     [3] IMPLICIT ORAddress,
        directoryName                   [4] IMPLICIT Name,
        ediPartyName                    [5] IMPLICIT EDIPartyName,
        uniformResourceIdentifier       [6] IMPLICIT IA5String,
        iPAddress                       [7] IMPLICIT OCTET STRING,
        registeredID                    [8] IMPLICIT OBJECT IDENTIFIER }

	这个类型非常讨厌，IMPLICT类型导致影响了的Tag，看来所有的类型都需要为Tag的修改做准备

	当 choice 为基本类型时，输入为类型的值数据
	当 choice 为 SEQUENCE 时，输入为该 SEQUENCE 的TLV DER编码

	由于X509_NAME是一个存储类型，因此也污染了这个CHOICE
*/
int x509_general_name_to_der(int choice, const uint8_t *data, size_t datalen, uint8_t **out, size_t *outlen)
{
	uint8_t *tag = *out;
	switch (choice) {
	case X509_gn_rfc822Name:
	case X509_gn_dnsName:
	case X509_gn_uniformResourceIdentifier:
		if (strlen((char *)data) != datalen) {
			error_print();
			return -1;
		}
	case X509_gn_ipAddress:
		asn1_type_to_der(ASN1_TAG_IMPLICIT(choice), data, datalen, out, outlen);
		break;

	case X509_gn_otherName:
	case X509_gn_x400Address:
	case X509_gn_directoryName:
	case X509_gn_ediPartyName:
	case X509_gn_registeredID:
		asn1_data_to_der(data, datalen, out, outlen);
		*tag = ASN1_TAG_IMPLICIT(choice);
		break;

	default:
		error_print();
		return -1;
	}
	return 1;
}

int x509_general_name_from_der(int *choice, const uint8_t **data, size_t *datalen, const uint8_t **in, size_t *inlen)
{
	return -1;
}








int x509_authority_key_identifier_to_der(
	const uint8_t *keyid, size_t keyid_len,
	const X509_GENERAL_NAMES *issuer,
	const uint8_t *serial_number, size_t serial_number_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	asn1_implicit_octet_string_to_der(0, keyid, keyid_len, NULL, &len);
	x509_implicit_general_names_to_der(1, issuer, NULL, &len);
	asn1_implicit_integer_to_der(2, serial_number, serial_number_len, NULL, &len);
	asn1_sequence_header_to_der(len, out, outlen);
	asn1_implicit_octet_string_to_der(0, keyid, keyid_len, out, outlen);
	x509_implicit_general_names_to_der(1, issuer, out, outlen);
	asn1_implicit_integer_to_der(2, serial_number, serial_number_len, out, outlen);
	return 1;
}

int x509_authority_key_identifier_from_der(
	const uint8_t **keyid, size_t *keyid_len,
	X509_GENERAL_NAMES *issuer,
	const uint8_t **serial_number, size_t *serial_number_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}

	if (asn1_implicit_octet_string_from_der(0, keyid, keyid_len, in, inlen) < 0
		|| x509_implicit_general_names_from_der(1, issuer, in, inlen) < 0
		|| asn1_implicit_integer_from_der(2, serial_number, serial_number_len, in, inlen) < 0
		|| datalen > 0) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_authority_key_identifier_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent)
{
	int ret;
	const uint8_t *p;
	size_t len;
	const uint8_t *keyid;
	size_t keyidlen;
	X509_GENERAL_NAMES issuer;
	const uint8_t *serial;
	size_t seriallen;

	if (asn1_sequence_from_der(&p, &len, &data, &datalen) != 1
		|| datalen) {
		error_print();
		return -1;
	}
	if ((ret = asn1_implicit_octet_string_from_der(0, &keyid, &keyidlen, &p, &len)) < 0) {
		error_print();
		return -1;
	} else if (ret) {
		format_bytes(fp, format, indent, "KeyIdentifier : ", keyid, keyidlen);
	}
	if ((ret = x509_implicit_general_names_from_der(1, &issuer, &p, &len)) < 0) {
		error_print();
		return -1;
	} else if (ret) {
		format_print(fp, format, indent, "AuthorityCertIssuer\n");
		//x509_general_names_print(fp, &issuer, format, indent + 4);
	}
	if ((ret = asn1_implicit_integer_from_der(2, &serial, &seriallen, &p, &len)) < 0) {
		error_print();
		return -1;
	} else if (ret) {
		format_bytes(fp, format, indent, "AuthorityCertSerialNumber : ", serial, seriallen);
	}
	if (len) {
		error_print();
		return -1;
	}
	return 1;
}













/*
3
KeyUsage ::= BIT STRING {
           digitalSignature        (0),
           nonRepudiation          (1), -- recent editions of X.509 have
                                -- renamed this bit to contentCommitment
           keyEncipherment         (2),
           dataEncipherment        (3),
           keyAgreement            (4),
           keyCertSign             (5),
           cRLSign                 (6),
           encipherOnly            (7),
           decipherOnly            (8) }
*/




/*
4
CertificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation

PolicyInformation ::= SEQUENCE {
     policyIdentifier   OBJECT IDENTIFIER,
     policyQualifiers   SEQUENCE SIZE (1..MAX) OF
                             PolicyQualifierInfo OPTIONAL }

PolicyQualifierInfo ::= SEQUENCE {
     policyQualifierId  OBJECT IDENTIFIER,
     qualifier          ANY DEFINED BY policyQualifierId }

Qualifier ::= CHOICE {
     cPSuri           IA5String,
     userNotice       UserNotice }

UserNotice ::= SEQUENCE {
     noticeRef        NoticeReference OPTIONAL,
     explicitText     DisplayText OPTIONAL }

NoticeReference ::= SEQUENCE {
     organization     DisplayText,
     noticeNumbers    SEQUENCE OF INTEGER }


看来这是一个非常复杂的扩展，可能很难通过简单的接口去设置。
我应该把这个设为一个独立的对象，在设置的时候，直接提供这个对象的DER
在解析的时候，可以有独立的函数将其解析成文本之类的可能更好

虽然这个扩展很复杂，但是我们的主要需求就是能够解析并转化为可显示的字符串

这个扩展在证书中确实是出现的，但是我们主要的目标还是显示这个扩展的内容

*/















/*
NoticeReference ::= SEQUENCE {
	organization     DisplayText,
	noticeNumbers    SEQUENCE OF INTEGER
}
*/
int x509_notice_reference_to_der(
	int organization_tag, const char *organization, size_t organization_len,
	const int *notice_numbers, size_t notice_numbers_count,
	uint8_t **out, size_t *outlen)
{
	size_t sublen, len;
	size_t i;

	x509_display_text_to_der(organization_tag, organization, organization_len, NULL, &len);
	for (i = 0; i < notice_numbers_count; i++) {
		asn1_int_to_der(notice_numbers[i], NULL, &len);
	}
	asn1_sequence_to_der(NULL, sublen, NULL, &len);

	asn1_sequence_header_to_der(len, out, outlen);
	x509_display_text_to_der(organization_tag, organization, organization_len, out, outlen);
	asn1_sequence_header_to_der(sublen, out, outlen);
	for (i = 0; i < notice_numbers_count; i++) {
		asn1_int_to_der(notice_numbers[i], out, outlen);
	}
	return -1;
}

int x509_notice_reference_from_der(
	int *organization_tag, const char **organization, size_t *organization_len,
	int *notice_numbers, size_t *notice_numbers_count,
	const uint8_t **in, size_t *inlen)
{
	const uint8_t *data, *subdata;
	size_t datalen = 0, subdatalen = 0;
	int ret;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}

	if (x509_display_text_from_der(organization_tag, organization, organization_len, &data, &datalen) != 1
		|| asn1_sequence_from_der(&subdata, &subdatalen, &data, &datalen) != 1
		|| datalen > 0
		|| subdatalen <= 0) {
		error_print();
		return -1;
	}

	*notice_numbers_count = 0;
	while (subdatalen) {
		if (asn1_int_from_der(notice_numbers, &subdata, &subdatalen) != 1) {
			error_print();
			return -1;
		}
		(*notice_numbers_count)++;
	}

	return 1;
}


/*
UserNotice ::= SEQUENCE {
	noticeRef        NoticeReference OPTIONAL,
	explicitText     DisplayText OPTIONAL }
*/
int x509_user_notice_to_der(
	const uint8_t *notice_ref_der, size_t notice_ref_der_len,
	int explicit_text_tag, const char *explicit_text, size_t explicit_text_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	asn1_data_to_der(notice_ref_der, notice_ref_der_len, NULL, &len);
	x509_display_text_to_der(explicit_text_tag, explicit_text, explicit_text_len, NULL, &len);

	asn1_sequence_header_to_der(len, out, outlen);
	asn1_data_to_der(notice_ref_der, notice_ref_der_len, out, outlen);
	x509_display_text_to_der(explicit_text_tag, explicit_text, explicit_text_len, out, outlen);

	return -1;
}

int x509_user_notice_from_der(
	const uint8_t **notice_ref_der, size_t *notice_ref_der_len,
	int *explicit_text_tag, const char **explicit_text, size_t *explicit_text_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;
	const uint8_t *subdata;
	size_t subdatalen;


	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}

	*notice_ref_der = data;
	asn1_sequence_from_der(&subdata, &subdatalen, &data, &datalen);
	*notice_ref_der_len = data - (*notice_ref_der);
	x509_display_text_from_der(explicit_text_tag, explicit_text, explicit_text_len, in, inlen);

	return -1;
}


/*
PolicyQualifierInfo ::= SEQUENCE {
     policyQualifierId	OBJECT IDENTIFIER ( id-qt-cps | id-qt-unotice ),
     qualifier          ANY DEFINED BY policyQualifierId }

当policyQualifierId == id-qt-cps 时，qualifier为CPSuri，否则为UserNotice

	Qualifier ::= CHOICE {
	     cPSuri           IA5String,
	     userNotice       UserNotice }

*/
int x509_policy_qualifier_info_to_der(int oid,
	const uint8_t *qualifier, size_t qualifier_len, uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	asn1_object_identifier_to_der(oid, NULL, 0, NULL, &len);
	switch (oid) {
	case OID_qt_cps:
		asn1_ia5_string_to_der((char *)qualifier, NULL, &len);
		break;
	case OID_qt_unotice:
		asn1_data_to_der(qualifier, qualifier_len, NULL, &len);
		break;
	}

	asn1_sequence_header_to_der(len, out, outlen);
	asn1_object_identifier_to_der(oid, NULL, 0, out, outlen);
	switch (oid) {
	case OID_qt_cps:
		asn1_ia5_string_to_der((char *)qualifier, out, &len);
		break;
	case OID_qt_unotice:
		asn1_data_to_der(qualifier, qualifier_len, out, &len);
		break;
	}

	return 1;
}

int x509_policy_qualifier_info_from_der(int *oid, const uint8_t **qualifier, size_t *qualifier_len, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;
	uint32_t nodes[16];
	size_t nodes_count;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_object_identifier_from_der(oid, nodes, &nodes_count, &data, &datalen) != 1) {
		error_print();
		return -1;
	}

	switch (*oid) {
	case OID_qt_cps:
		asn1_ia5_string_from_der((const char **)qualifier, qualifier_len, &data, &datalen);
		break;
	case OID_qt_unotice:
		*qualifier_len = datalen;
		asn1_data_from_der(qualifier, *qualifier_len, &data, &datalen);
		break;
	}

	return -1;
}

/*
PolicyInformation ::= SEQUENCE {
	policyIdentifier   OBJECT IDENTIFIER,
                           -- 由CA定义的，RFC 5280中仅规定为一个可选的OID anyPolicy
	policyQualifiers   SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo OPTIONAL
			   -- 必须为这个准备一个独立的类型
}
*/

int x509_policy_information_to_der(
	int oid, const uint32_t *nodes, size_t nodes_count,
	const X509_POLICY_QUALIFIER_INFOS *qualifiers,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	asn1_object_identifier_to_der(oid, nodes, nodes_count, NULL, &len);
	x509_policy_qualifier_infos_to_der(qualifiers, NULL, &len);
	asn1_sequence_header_to_der(len, out, outlen);
	asn1_object_identifier_to_der(oid, nodes, nodes_count, out, outlen);
	x509_policy_qualifier_infos_to_der(qualifiers, out, outlen);

	return 1;
}

int x509_policy_information_from_der(
	int *oid, uint32_t *nodes, size_t *nodes_count,
	X509_POLICY_QUALIFIER_INFOS *qualifiers,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_object_identifier_from_der(oid, nodes, nodes_count, &data, &datalen) != 1
		|| x509_policy_qualifier_infos_from_der(qualifiers, &data, &datalen) != 1
		|| datalen > 0) {
		error_print();
		return -1;
	}
	return 1;
}


/*
CertificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
*/







// 这个扩展的数据是一个SEQUENCE OF SEQUENCE，应该统一考虑一下如何处理SEQUENCE OF 这样的返回值
// 一种是提供一个数组，每个数组是一个SEQUENCE
// 还是只返回这个SEQUENCE OF的数据？


/*
5

PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
        issuerDomainPolicy      CertPolicyId,
        subjectDomainPolicy     CertPolicyId }

CertPolicyId ::= OBJECT IDENTIFIER

This extension MAY be supported by CAs and/or applications.
   Conforming CAs SHOULD mark this extension as critical.

这个也是SEQUENCE OF SEQUENCE
在设置的时候给出数组实际上不太方便
*/



int x509_policy_mapping_to_der(
	int issuer_policy_oid, const uint32_t *issuer_policy_nodes, size_t issuer_policy_nodes_count,
	int subject_policy_oid, const uint32_t *subject_policy_nodes, size_t subject_policy_nodes_count,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (asn1_object_identifier_to_der(issuer_policy_oid, issuer_policy_nodes, issuer_policy_nodes_count, NULL, &len) != 1
		|| asn1_object_identifier_to_der(subject_policy_oid, subject_policy_nodes, subject_policy_nodes_count, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_object_identifier_to_der(issuer_policy_oid, issuer_policy_nodes, issuer_policy_nodes_count, out, outlen) != 1
		|| asn1_object_identifier_to_der(subject_policy_oid, subject_policy_nodes, subject_policy_nodes_count, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_policy_mapping_from_der(
	int *issuer_policy_oid, uint32_t *issuer_policy_nodes, size_t *issuer_policy_nodes_count,
	int *subject_policy_oid, uint32_t *subject_policy_nodes, size_t *subject_policy_nodes_count,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;
	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_object_identifier_from_der(issuer_policy_oid, issuer_policy_nodes, issuer_policy_nodes_count, &data, &datalen) != 1
		|| asn1_object_identifier_from_der(subject_policy_oid, subject_policy_nodes, subject_policy_nodes_count, &data, &datalen) != 1
		|| datalen > 0) {
		error_print();
		return -1;
	}
	return 1;
}



/*
## 6

SubjectAltName ::= GeneralNames

GeneralNames 也是 SEQUENCE OF SEQUENCE

提供证书主体的多个可替代的名字，如域名、IP地址、邮件地址等。



*/



/*
7
IssuerAltName ::= GeneralNames
*/




/*
8
SubjectDirectoryAttributes ::= SEQUENCE SIZE (1..MAX) OF Attribute

Attribute ::= SEQUENCE {
	type	OBJECT IDENTIFIER,
	values	SET OF AttributeValue
		-- values的类型是SET OF !
}
AttributeValue ::=  ANY
*/

int x509_attribute_to_der(
	int oid, const uint32_t *nodes, size_t nodes_count,
	const uint8_t *values, size_t valueslen,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	asn1_object_identifier_to_der(oid, nodes, nodes_count, NULL, &len);
	asn1_set_to_der(values, valueslen, NULL, &len);
	asn1_sequence_header_to_der(len, out, outlen);
	asn1_object_identifier_to_der(oid, nodes, nodes_count, out, outlen);
	asn1_set_to_der(values, valueslen, out, outlen);
	return 1;
}

int x509_attribute_from_der(
	int *oid, uint32_t *nodes, size_t *nodes_count,
	const uint8_t **values, size_t *valueslen,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_object_identifier_from_der(oid, nodes, nodes_count, &data, &datalen) != 1
		|| asn1_set_from_der(values, valueslen, &data, &datalen) != 1
		|| datalen > 0) {
		error_print();
		return -1;
	}
	return 1;
}


/*

9

   BasicConstraints ::= SEQUENCE {
        cA                      BOOLEAN DEFAULT FALSE,
        pathLenConstraint       INTEGER (0..MAX) OPTIONAL }

 FIXME: 从这个类型看起来，一个 SEQUENCE 中的数据可能是空的
	但是问题是，如果这两个元素都没有内容，那么这个扩展就完全没有必要提供了！


  如果一个证书是CA证书，那么必须包含这个扩展

  没有为这个扩展建立一个独立的对象，这是因为在 x509_certificate_set_ 系列函数中
  如果有一个独立的对象，那么会增加接口的复杂度。

一般来说在完成了证书的解析后，证书对象中有所有的扩展列表，有了扩展的OID，但是这些扩展的内容还没有解析
现在还不太确定到底在什么时候需要获取某个证书扩展的内容，以及以何种方式获取
可能还要等到验证证书链的时候才能定下来

*/





int x509_basic_constraints_to_der(int is_ca_cert, // 必须设置为 0 或 1，如果设为 0 那么不编码
	int cert_chain_maxlen, // -1 means omitted，FIXME: 应该设置一个最大值
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (is_ca_cert) {
		if (asn1_boolean_to_der(ASN1_TRUE, NULL, &len) != 1) {
			error_print();
			return -1;
		}
	}
	if (cert_chain_maxlen >= 0) {
		if (asn1_int_to_der((uint32_t)cert_chain_maxlen, NULL, &len) != 1) {
			error_print();
			return -1;
		}
	}
	asn1_sequence_header_to_der(len, out, outlen);
	if (is_ca_cert) {
		if (asn1_boolean_to_der(ASN1_TRUE, out, outlen) != 1) {
			error_print();
			return -1;
		}
	}
	if (cert_chain_maxlen >= 0) {
		if (asn1_int_to_der((uint32_t)cert_chain_maxlen, out, outlen) != 1) {
			error_print();
			return -1;
		}
	}
	return 1;
}

// 解码的时候如果 is_ca_cert 没有，那么会强制设置为0，因此从本函数无法知道 is_ca_cert 是否被编码
// 如果 cert_chain_maxlen 没有编码，那么这个值会被强制设置为 -1
int x509_basic_constraints_from_der(int *is_ca_cert, int *cert_chain_maxlen, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;
	int maxlen;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		return ret;
	}

	if ((ret = asn1_boolean_from_der(is_ca_cert, &data, &datalen)) < 0) {
		error_print();
		return -1;
	} else if (ret == 0) {
		*is_ca_cert = -1;
	}

	if ((ret = asn1_int_from_der(&maxlen, &data, &datalen)) < 0
		|| datalen > 0) {
		error_print();
		return -1;
	} else if (ret == 0) {
		*cert_chain_maxlen = -1;
	} else {
		if (maxlen > 6) {
			error_print();
			return -1;
		}
		*cert_chain_maxlen = (int)maxlen;
	}
	return 1;
}

int x509_basic_constraints_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent)
{
	int is_ca_cert;
	int cert_chain_maxlen;

	if (x509_basic_constraints_from_der(&is_ca_cert, &cert_chain_maxlen, &data, &datalen) != 1) {
		error_print();
		return -1;
	}
	if (datalen) {
		error_print();
		return -1;
	}
	if (is_ca_cert >= 0) {

		format_print(fp, format, indent, "cA : %s\n", is_ca_cert ? "true" : "false");

	}
	if (cert_chain_maxlen >= 0) {
		format_print(fp, format, indent, "pathLenConstraint : %d\n", cert_chain_maxlen);
	}
	return 1;
}

/*
10
GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree

GeneralSubtree ::= SEQUENCE {
           base                    GeneralName,
           minimum         [0] IMPLICIT    INTEGER (0..MAX) DEFAULT 0,
           maximum         [1] IMPLICIT    INTEGER (0..MAX) OPTIONAL }


	这里还是要用到GeneralName，这个类型非常难处理

	如果比较难构造，是否我们目前只支持解析，不支持构造呢？


	这个比较复杂的是其中的两个元素都是SEQUENCE OF SEQUENCE,
	这意味着我们必须对这种常见的形式给出一个统一的解析方案

*/



int x509_general_subtree_to_der(
	int base_choise, const uint8_t *base_data, size_t base_datalen,
	int minimum,
	int maximum,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	x509_general_name_to_der(base_choise, base_data, base_datalen, NULL, &len);
	asn1_implicit_int_to_der(0, minimum, NULL, &len);
	asn1_implicit_int_to_der(1, maximum, NULL, &len);

	asn1_sequence_header_to_der(len, out, outlen);

	x509_general_name_to_der(base_choise, base_data, base_datalen, out, outlen);
	asn1_implicit_int_to_der(0, minimum, out, outlen);
	asn1_implicit_int_to_der(1, maximum, out, outlen);

	return 1;
}

int x509_general_subtree_from_der(
	int *base_choice, const uint8_t **base_data, size_t *base_datalen,
	int *minimum,
	int *maximum,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (x509_general_name_from_der(base_choice, base_data, base_datalen, &data, &datalen) != 1
		|| asn1_implicit_int_from_der(0, minimum, &data, &datalen) < 0
		|| asn1_implicit_int_from_der(1, maximum, &data, &datalen) < 0
		|| datalen > 0) {
		error_print();
		return ret;
	}

	return 1;
}

/*
NameConstraints ::= SEQUENCE {
           permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
           excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }
*/
int x509_name_constraints_to_der(
	const X509_GENERAL_SUBTREES *permitted_subtrees,
	const X509_GENERAL_SUBTREES *excluded_subtrees,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	x509_general_subtrees_to_der(permitted_subtrees, NULL, &len);
	x509_general_subtrees_to_der(excluded_subtrees, NULL, &len);

	asn1_sequence_header_to_der(len, out, outlen);
	x509_general_subtrees_to_der(permitted_subtrees, out, outlen);
	x509_general_subtrees_to_der(excluded_subtrees, out, outlen);

	return 1;
}

int x509_name_constraints_from_der(
	X509_GENERAL_SUBTREES *permitted_subtrees,
	X509_GENERAL_SUBTREES *excluded_subtrees,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;


	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}

	if (x509_general_subtrees_from_der(permitted_subtrees, &data, &datalen) < 0
		|| x509_general_subtrees_from_der(excluded_subtrees, &data, &datalen) < 0
		|| datalen > 0) {
		error_print();
		return -1;
	}

	return 1;
}


/*
11
PolicyConstraints ::= SEQUENCE {
	requireExplicitPolicy	[0] IMPLICIT INTEGER (0..MAX) OPTIONAL,
	inhibitPolicyMapping	[1] IMPLICIT INTEGER (0..MAX) OPTIONAL
}

Conforming CAs MUST mark this extension as critical.
*/

int x509_policy_constraints_print(FILE *fp, const uint8_t *p, size_t len, int format, int indent)
{
	int require_explicit_policy = -1;
	int inhibit_policy_mapping = -1;
	if (x509_policy_constraints_from_der(&require_explicit_policy, &inhibit_policy_mapping, &p, &len) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, format, indent, "policyConstraints:\n");
	if (require_explicit_policy >= 0) {
		format_print(fp, format, indent+4, "requireExplicitPolicy: %d\n", require_explicit_policy);
	}
	if (inhibit_policy_mapping >= 0) {
		format_print(fp, format, indent+4, "inhibitPolicyMapping: %d\n", inhibit_policy_mapping);
	}
	if (len) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_policy_constraints_to_der(int require_explicit_policy, int inhibit_policy_mapping, uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	asn1_implicit_int_to_der(0, require_explicit_policy, NULL, &len);
	asn1_implicit_int_to_der(1, inhibit_policy_mapping, NULL, &len);

	asn1_sequence_header_to_der(len, out, outlen);

	asn1_implicit_int_to_der(0, require_explicit_policy, out, outlen);
	asn1_implicit_int_to_der(1, inhibit_policy_mapping, out, outlen);

	return 1;
}

int x509_policy_constraints_from_der(int *require_explicit_policy, int *inhibit_policy_mapping, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}

	if (asn1_implicit_int_from_der(0, require_explicit_policy, &data, &datalen) < 0
		|| asn1_implicit_int_from_der(1, inhibit_policy_mapping, &data, &datalen) < 0
		|| datalen > 0) {
		error_print();
		return -1;
	}


	return 1;
}




/*
12
ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF OBJECT IDENTIFIER

	ExtKeyUsage OIDs:

	OID_kp_serverAuth,
	OID_kp_clientAuth,
	OID_kp_codeSigning,
	OID_kp_emailProtection,
	OID_kp_timeStamping,
	OID_kp_OCSPSigning,


这里的问题是，有可能出现新的OID，比如微软定义的或者Google定义的
所以在解码的时候不能假定所有的OID都是已知的

但是在设置的时候应该只能设置已知的OID

解析的时候不可能只用oid来承接了，必须用带buffer的来承接
*/

int x509_ext_key_usage_print(FILE *fp, const uint8_t *p, size_t len, int format, int indent)
{
	const uint8_t *data;
	size_t datalen;

	if (asn1_sequence_from_der(&data, &datalen, &p, &len) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, format, indent, "extKeyUsages:\n");
	while (datalen) {
		int key_usage;
		uint32_t nodes[32];
		size_t nodes_count;
		size_t i;

		if (asn1_object_identifier_from_der(&key_usage, nodes, &nodes_count, &data, &datalen) != 1) {
			error_print();
			return -1;
		}
		format_print(fp, format, indent + 4, "%s (", "unknown");
		for (i = 0; i < nodes_count - 1; i++) {
			fprintf(fp, "%d.", nodes[i]);
		}
		fprintf(fp, "%d)\n", nodes[i]);
	}

	if (len) {
		error_print();
		return -1;
	}
	return 1;
}


/*
## 13 CRLDistributionPoints

SHOULD be non-critical



实际上我现在没有一个统一的方法去处理CHOICE类型的设置和解析
首先是否要给一个CHOICE类型设置一个新的对象，按照我们的设置，如果设置的话，就需要这个对象能够承载内部数据



   CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint

   ReasonFlags ::= BIT STRING {
        unused                  (0),
        keyCompromise           (1),
        cACompromise            (2),
        affiliationChanged      (3),
        superseded              (4),
        cessationOfOperation    (5),
        certificateHold         (6),
        privilegeWithdrawn      (7),
        aACompromise            (8) }

*/


/*
DistributionPointName ::= CHOICE {
        fullName                [0] IMPLICIT GeneralNames,
        nameRelativeToCRLIssuer [1] IMPLICIT RelativeDistinguishedName }

	GeneralNames 类型为 SEQUENCE OF
	RelativeDistinguishedName 类型为 SET OF
	因此需要为 DistributionPointName 建立一个新类型

	这两个类型实际上都是 SEQUENCE OF/SET OF

	因为GeneralNames是一个类型，因此污染了X509_CRL_DISTRIBUTION_POINT_NAME


*/

int x509_distribution_point_name_to_der(const X509_DISTRIBUTION_POINT_NAME *a, uint8_t **out, size_t *outlen)
{

	return 1;
}

int x509_distribution_point_name_from_der(X509_DISTRIBUTION_POINT_NAME *a, const uint8_t **in, size_t *inlen)
{
	return 1;
}

int x509_distribution_point_to_der(				// DistributionPoint
	const X509_DISTRIBUTION_POINT_NAME *dist_point_name,	// [0] EXPLICIT OPTIONAL
	int reason_bits,					// [1] IMPLICIT OPTIONAL
	const X509_GENERAL_NAMES *crl_issuer,			// [2] IMPLICIT OPTIONAL
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	size_t sublen = 0;

	//x509_distribution_point_name_to_der(dist_point_name, NULL, &sublen);
	asn1_explicit_to_der(0, NULL, sublen, NULL, &len);
	asn1_implicit_bits_to_der(1, reason_bits, NULL, &len);
	x509_implicit_general_names_to_der(2, crl_issuer, NULL, &len);

	asn1_sequence_header_to_der(len, out, outlen);
	asn1_explicit_header_to_der(0, sublen, out, outlen);
		x509_distribution_point_name_to_der(dist_point_name, out, outlen);
	asn1_implicit_bits_to_der(1, reason_bits, out, outlen);
	x509_implicit_general_names_to_der(2, crl_issuer, out, outlen);

	return 1;
}

int x509_distribution_point_from_der(
	X509_DISTRIBUTION_POINT_NAME *dist_point_name,
	int *reason_bits,
	X509_GENERAL_NAMES *crl_issuer,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;
	const uint8_t *subdata;
	size_t subdatalen;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}

	if (asn1_explicit_from_der(0, &subdata, &subdatalen, &data, &datalen) < 0
		|| x509_distribution_point_name_from_der(dist_point_name, &subdata, &subdatalen) != 1
		|| subdatalen > 0
		//|| asn1_implicit_bit_string_from_der(1, reason_bits, &data, &datalen) < 0
		|| x509_implicit_general_names_from_der(2, crl_issuer, &data, &datalen) < 0
		|| datalen > 0) {
		error_print();
		return -1;
	}

	return 1;
}

/*

   CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint

*/





/*
14
InhibitAnyPolicy ::= INTEGER (0..MAX)

Conforming CAs MUST mark this extension as critical.
*/



/*
15
FreshestCRL ::= CRLDistributionPoints
MUST be marked as non-critical by conforming CAs.
*/








/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Public APIs
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


struct {
	int oid;
	int is_critical;
	int tag;
} x509_exts[] = {
	{ OID_ce_authorityKeyIdentifier,	1, ASN1_TAG_SEQUENCE     },
	{ OID_ce_subjectKeyIdentifier,		1, ASN1_TAG_OCTET_STRING },
	{ OID_ce_keyUsage,			1, ASN1_TAG_BIT_STRING		},
	{ OID_ce_certificatePolicies,		1, ASN1_TAG_SEQUENCE },
	{ OID_ce_policyMappings,		1, ASN1_TAG_SEQUENCE },
	{ OID_ce_subjectAltName,		1, ASN1_TAG_SEQUENCE },
	{ OID_ce_issuerAltName,			1, ASN1_TAG_SEQUENCE },
	{ OID_ce_subjectDirectoryAttributes,	1, ASN1_TAG_SEQUENCE },
	{ OID_ce_basicConstraints,		1, ASN1_TAG_SEQUENCE },
	{ OID_ce_nameConstraints,		1, ASN1_TAG_SEQUENCE },
	{ OID_ce_policyConstraints,		1, ASN1_TAG_SEQUENCE },
	{ OID_ce_extKeyUsage,			1, ASN1_TAG_SEQUENCE },
	{ OID_ce_crlDistributionPoints,		1, ASN1_TAG_SEQUENCE },
	{ OID_ce_inhibitAnyPolicy,		1, ASN1_TAG_INTEGER },
	{ OID_ce_freshestCRL,			1, ASN1_TAG_SEQUENCE },
};




int x509_certificate_set_authority_key_identifier(X509_CERTIFICATE *cert,
	int is_critical,
	const uint8_t *keyid, size_t keyid_len,
	const X509_GENERAL_NAMES *issuer,
	const uint8_t *serial_number, size_t serial_number_len)
{
	int oid = OID_ce_authorityKeyIdentifier;
	uint8_t data[1024];
	uint8_t *p = data;
	size_t datalen = 0;

	if (x509_authority_key_identifier_to_der(keyid, keyid_len, issuer, serial_number, serial_number_len, &p, &datalen) != 1
		|| x509_certificate_add_extension(cert, oid, is_critical, data, datalen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_certificate_set_subject_key_identifier(X509_CERTIFICATE *cert,
	int is_critical,
	const uint8_t *keyid, size_t keyid_len)
{
	int oid = OID_ce_subjectKeyIdentifier;
	uint8_t data[1024];
	uint8_t *p = data;
	size_t datalen = 0;

	if (asn1_octet_string_to_der(keyid, keyid_len, &p, &datalen) != 1
		|| x509_certificate_add_extension(cert, oid, is_critical, data, datalen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_certificate_generate_subject_key_identifier(X509_CERTIFICATE *cert, int is_critical)
{
	uint8_t keyid[32];
	sm2_public_key_digest(&cert->tbs_certificate.subject_public_key_info.sm2_key, keyid);
	x509_certificate_set_subject_key_identifier(cert, is_critical, keyid, sizeof(keyid));
	return 1;
}

int x509_subject_key_identifier_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent)
{
	const uint8_t *keyid;
	size_t keyidlen;
	if (asn1_octet_string_from_der(&keyid, &keyidlen, &data, &datalen) != 1
		|| datalen) {
		error_print();
		return -1;
	}
	format_bytes(fp, format, indent, "keyIdentifier: ", keyid, keyidlen);
	return 1;
}

int x509_certificate_set_key_usage(X509_CERTIFICATE *cert,
	int is_critical,
	int usages)
{
	int oid = OID_ce_keyUsage;
	uint8_t data[32];
	uint8_t *p = data;
	size_t datalen = 0;

/*
	if (//asn1_bits_to_der(usages, &p, &datalen) != 1
		|| x509_certificate_add_extension(cert, oid, is_critical, data, datalen) != 1) {
		error_print();
		return -1;
	}
*/
	return 1;
}

int x509_certificate_set_certificate_policies(X509_CERTIFICATE *cert,
	int is_critical,
	const X509_CERTIFICATE_POLICIES *policies)
{
	int oid = OID_ce_certificatePolicies;
	uint8_t data[1024];
	uint8_t *p = data;
	size_t datalen = 0;

	if (x509_certificate_policies_to_der(policies, &p, &datalen) != 1
		|| x509_certificate_add_extension(cert, oid, is_critical, data, datalen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_certificate_set_policy_mappings(X509_CERTIFICATE *cert,
	int is_critical,
	const X509_POLICY_MAPPINGS *mappings)
{
	int oid = OID_ce_policyMappings;
	uint8_t data[1024];
	uint8_t *p = data;
	size_t datalen = 0;

	if (x509_policy_mappings_to_der(mappings, &p, &datalen) != 1
		|| x509_certificate_add_extension(cert, oid, is_critical, data, datalen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_certificate_set_subject_alt_name(X509_CERTIFICATE *cert,
	int is_critical,
	const X509_GENERAL_NAMES *name)
{
	int oid = OID_ce_subjectAltName;
	uint8_t data[1024];
	uint8_t *p = data;
	size_t datalen = 0;

	if (x509_general_names_to_der(name, &p, &datalen) != 1
		|| x509_certificate_add_extension(cert, oid, is_critical, data, datalen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_certificate_set_issuer_alt_name(X509_CERTIFICATE *cert,
	int is_critical,
	const X509_GENERAL_NAMES *name)
{
	int oid = OID_ce_issuerAltName;
	uint8_t data[1024];
	uint8_t *p = data;
	size_t datalen = 0;

	if (x509_general_names_to_der(name, &p, &datalen) != 1
		|| x509_certificate_add_extension(cert, oid, is_critical, data, datalen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_certificate_set_subject_directory_attributes(X509_CERTIFICATE *cert,
	int is_critical,
	const X509_ATTRIBUTES *attrs)
{
	int oid = OID_ce_subjectDirectoryAttributes;
	uint8_t data[1024];
	uint8_t *p = data;
	size_t datalen = 0;

	if (x509_attributes_to_der(attrs, &p, &datalen) != 1
		|| x509_certificate_add_extension(cert, oid, is_critical, data, datalen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_certificate_set_basic_constraints(X509_CERTIFICATE *cert,
	int is_critical,
	int is_ca_cert,
	int cert_chain_maxlen)
{
	int oid = OID_ce_basicConstraints;
	uint8_t data[1024];
	uint8_t *p = data;
	size_t datalen = 0;

	if (x509_basic_constraints_to_der(is_ca_cert, cert_chain_maxlen, &p, &datalen) != 1
		|| x509_certificate_add_extension(cert, oid, is_critical, data, datalen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_certificate_set_name_constraints(X509_CERTIFICATE *cert,
	int is_critical,
	const X509_GENERAL_SUBTREES *permitted_subtrees,
	const X509_GENERAL_SUBTREES *excluded_subtrees)
{
	int oid = OID_ce_nameConstraints;
	uint8_t data[1024];
	uint8_t *p = data;
	size_t datalen = 0;

	if (x509_name_constraints_to_der(permitted_subtrees, excluded_subtrees, &p, &datalen) != 1
		|| x509_certificate_add_extension(cert, oid, is_critical, data, datalen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_certificate_set_policy_constraints(X509_CERTIFICATE *cert,
	int is_critical,
	int require_explicit_policy,
	int inhibit_policy_mapping)
{
	int oid = OID_ce_policyConstraints;
	uint8_t data[1024];
	uint8_t *p = data;
	size_t datalen = 0;

	if (x509_policy_constraints_to_der(require_explicit_policy, inhibit_policy_mapping, &p, &datalen) != 1
		|| x509_certificate_add_extension(cert, oid, is_critical, data, datalen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_certificate_set_ext_key_usage(X509_CERTIFICATE *cert,
	int is_critical,
	const int *key_purpose_oids, size_t key_purpose_oids_count)
{
	int oid = OID_ce_extKeyUsage;
	uint8_t data[1024];
	uint8_t *p = data;
	size_t datalen = 0;

	if (x509_ext_key_usage_to_der(key_purpose_oids, key_purpose_oids_count, &p, &datalen) != 1
		|| x509_certificate_add_extension(cert, oid, is_critical, data, datalen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_certificate_set_crl_distribution_points(X509_CERTIFICATE *cert,
	int is_critical,
	const X509_CRL_DISTRIBUTION_POINTS *crl_dist_points)
{
	int oid = OID_ce_crlDistributionPoints;
	uint8_t data[1024];
	uint8_t *p = data;
	size_t datalen = 0;

	if (x509_crl_distribution_points_to_der(crl_dist_points, &p, &datalen) != 1
		|| x509_certificate_add_extension(cert, oid, is_critical, data, datalen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_certificate_set_inhibit_any_policy(X509_CERTIFICATE *cert,
	int is_critical,
	int skip_certs)
{
	int oid = OID_ce_inhibitAnyPolicy;
	uint8_t data[16];
	uint8_t *p = data;
	size_t datalen = 0;

	if (asn1_int_to_der(skip_certs, &p, &datalen) != 1
		|| x509_certificate_add_extension(cert, oid, is_critical, data, datalen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_certificate_set_freshest_crl(X509_CERTIFICATE *cert,
	int is_critical,
	const X509_CRL_DISTRIBUTION_POINTS *crl_dist_points)
{
	int oid = OID_ce_freshestCRL;
	uint8_t data[1024];
	uint8_t *p = data;
	size_t datalen = 0;

	if (x509_crl_distribution_points_to_der(crl_dist_points, &p, &datalen) != 1
		|| x509_certificate_add_extension(cert, oid, is_critical, data, datalen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

// x509_certificate_get_[extension_name]
// return values:
//	ret == 0  no such extension
//	ret < 0   error
//	ret == 1  ok


int x509_certificate_get_authority_key_identifier(const X509_CERTIFICATE *cert,
	int *is_critical,
	const uint8_t **keyid, size_t *keyid_len,
	X509_GENERAL_NAMES *issuer,
	const uint8_t **serial_number, size_t *serial_number_len)
{
	int oid = OID_ce_authorityKeyIdentifier;
	int ret;
	const uint8_t *data;
	size_t datalen;

	if ((ret = x509_certificate_get_extension_from_oid(cert, oid, is_critical, &data, &datalen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (x509_authority_key_identifier_from_der(keyid, keyid_len, issuer, serial_number, serial_number_len, &data, &datalen) != 1
		|| datalen > 0) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_certificate_get_subject_key_identifier(const X509_CERTIFICATE *cert,
	int *is_critical,
	const uint8_t **keyid, size_t *keyid_len)
{
	int oid = OID_ce_subjectKeyIdentifier;
	int ret;
	const uint8_t *data;
	size_t datalen;

	if ((ret = x509_certificate_get_extension_from_oid(cert, oid, is_critical, &data, &datalen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_octet_string_from_der(keyid, keyid_len, &data, &datalen) != 1
		|| datalen > 0) {
		error_print();
		return -1;
	}
	if (*keyid_len <= 0) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_certificate_get_key_usage(const X509_CERTIFICATE *cert,
	int *is_critical,
	int *usage_bits)
{
	int oid = OID_ce_keyUsage;
	int ret;
	const uint8_t *data;
	size_t datalen;

	if ((ret = x509_certificate_get_extension_from_oid(cert, oid, is_critical, &data, &datalen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_bits_from_der(usage_bits, &data, &datalen) != 1
		|| datalen > 0) {
		error_print();
		return -1;
	}
	// 应该检查一下bits对不对
	return 1;
}


#if 0
 983 /*         
 984 3          
 985 KeyUsage ::= BIT STRING {          
 986            digitalSignature        (0),
 987            nonRepudiation          (1), -- recent editions of X.509 have
 988                                 -- renamed this bit to contentCommitment
 989            keyEncipherment         (2),
 990            dataEncipherment        (3),
 991            keyAgreement            (4),
 992            keyCertSign             (5),
 993            cRLSign                 (6),
 994            encipherOnly            (7),
 995            decipherOnly            (8) }
 996 */

#endif


int x509_key_usage_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent)
{
	int usage;
	if (asn1_bits_from_der(&usage, &data, &datalen) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, format, indent, "%s", usage == 0 ? "(null)" : "");
	if (usage & (1 << X509_ku_digital_signature)) fprintf(fp, "DigitalSignature, ");
	if (usage & (1 << X509_ku_non_repudiation)) fprintf(fp, "NonRepudiation, ");
	if (usage & (1 << X509_ku_key_encipherment)) fprintf(fp, "KeyEncipherment, ");
	if (usage & (1 << X509_ku_data_encipherment)) fprintf(fp, "DataEncipherment, ");
	if (usage & (1 << X509_ku_key_agreement)) fprintf(fp, "KeyAgreement, ");
	if (usage & (1 << X509_ku_key_cert_sign)) fprintf(fp, "KeyCertSign, ");
	if (usage & (1 << X509_ku_crl_sign)) fprintf(fp, "CRLSign, ");
	if (usage & (1 << X509_ku_encipher_only)) fprintf(fp, "EncipherOnly, ");
	if (usage & (1 << X509_ku_decipher_only)) fprintf(fp, "DecipherOnly, ");
	// FIXME: more bits ?			
	fprintf(fp, "\n");

	if (datalen) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_certificate_get_certificate_policies(const X509_CERTIFICATE *cert,
	int *is_critical,
	X509_CERTIFICATE_POLICIES *policies)
{
	int oid = OID_ce_certificatePolicies;
	int ret;
	const uint8_t *data;
	size_t datalen;

	if ((ret = x509_certificate_get_extension_from_oid(cert, oid, is_critical, &data, &datalen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (x509_certificate_policies_from_der(policies, &data, &datalen) != 1
		|| datalen > 0) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_certificate_get_policy_mappings(const X509_CERTIFICATE *cert,
	int *is_critical,
	X509_POLICY_MAPPINGS *mappings)
{
	int oid = OID_ce_policyMappings;
	int ret;
	const uint8_t *data;
	size_t datalen;

	if ((ret = x509_certificate_get_extension_from_oid(cert, oid, is_critical, &data, &datalen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (x509_policy_mappings_from_der(mappings, &data, &datalen) != 1
		|| datalen > 0) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_certificate_get_subject_directory_attributes(const X509_CERTIFICATE *cert,
	int *is_critical,
	X509_ATTRIBUTES *attrs)
{
	int oid = OID_ce_subjectDirectoryAttributes;
	int ret;
	const uint8_t *data;
	size_t datalen;

	if ((ret = x509_certificate_get_extension_from_oid(cert, oid, is_critical, &data, &datalen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (x509_attributes_from_der(attrs, &data, &datalen) != 1
		|| datalen > 0) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_certificate_get_basic_constraints(const X509_CERTIFICATE *cert,
	int *is_critical,
	int *is_ca_cert,
	int *cert_chain_maxlen)
{
	int oid = OID_ce_basicConstraints;
	int ret;
	const uint8_t *data;
	size_t datalen;

	if ((ret = x509_certificate_get_extension_from_oid(cert, oid, is_critical, &data, &datalen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (x509_basic_constraints_from_der(is_ca_cert, cert_chain_maxlen, &data, &datalen) != 1
		|| datalen > 0) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_certificate_get_name_constraints(X509_CERTIFICATE *cert,
	int *is_critical,
	X509_GENERAL_SUBTREES *permitted_subtrees,
	X509_GENERAL_SUBTREES *excluded_subtrees)
{
	int oid = OID_ce_nameConstraints;
	int ret;
	const uint8_t *data;
	size_t datalen;

	if ((ret = x509_certificate_get_extension_from_oid(cert, oid, is_critical, &data, &datalen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (x509_name_constraints_from_der(permitted_subtrees, excluded_subtrees, &data, &datalen) != 1
		|| datalen > 0) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_certificate_get_policy_constraints(const X509_CERTIFICATE *cert,
	int *is_critical,
	int *requireExplicitPolicy,
	int *inhibitPolicyMapping)
{
	int oid = OID_ce_policyConstraints;
	int ret;
	const uint8_t *data;
	size_t datalen;

	if ((ret = x509_certificate_get_extension_from_oid(cert, oid, is_critical, &data, &datalen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (x509_policy_constraints_from_der(requireExplicitPolicy, inhibitPolicyMapping, &data, &datalen) != 1
		|| datalen > 0) {
		error_print();
	}
	return 1;
}

int x509_certificate_get_ext_key_usage(const X509_CERTIFICATE *cert,
	int *is_critical,
	int *key_purposes, size_t *key_purposes_count)
{
	int oid = OID_ce_extKeyUsage;
	int ret;
	const uint8_t *data;
	size_t datalen;

	if ((ret = x509_certificate_get_extension_from_oid(cert, oid, is_critical, &data, &datalen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (x509_ext_key_usage_from_der(key_purposes, key_purposes_count, &data, &datalen) != 1
		|| datalen > 0) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_certificate_get_crl_distribution_points(const X509_CERTIFICATE *cert,
	int *is_critical,
	X509_CRL_DISTRIBUTION_POINTS *crl_dist_points)
{
	int oid = OID_ce_crlDistributionPoints;
	int ret;
	const uint8_t *data;
	size_t datalen;

	if ((ret = x509_certificate_get_extension_from_oid(cert, oid, is_critical, &data, &datalen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (x509_crl_distribution_points_from_der(crl_dist_points, &data, &datalen) != 1
		|| datalen > 0) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_certificate_get_inhibit_any_policy(const X509_CERTIFICATE *cert,
	int *is_critical,
	int *skip_certs)
{
	int oid = OID_ce_inhibitAnyPolicy;
	int ret;
	const uint8_t *data;
	size_t datalen;

	if ((ret = x509_certificate_get_extension_from_oid(cert, oid, is_critical, &data, &datalen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_int_from_der(skip_certs, &data, &datalen) != 1
		|| datalen > 0) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_certificate_get_freshest_crl(const X509_CERTIFICATE *cert,
	int *is_critical,
	X509_CRL_DISTRIBUTION_POINTS *crl_dist_points)
{
	int oid = OID_ce_freshestCRL;
	int ret;
	const uint8_t *data;
	size_t datalen;

	if ((ret = x509_certificate_get_extension_from_oid(cert, oid, is_critical, &data, &datalen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (x509_crl_distribution_points_from_der(crl_dist_points, &data, &datalen) != 1
		|| datalen > 0) {
		error_print();
		return -1;
	}
	return 1;
}
