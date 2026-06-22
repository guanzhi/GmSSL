/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <gmssl/asn1.h>
#include <gmssl/endian.h>
#include <gmssl/oid.h>
#include <gmssl/x509_ext.h>
#include <gmssl/x509_cer.h>
#include <gmssl/x509_crl.h>
#include <gmssl/ocsp.h>
#include <gmssl/error.h>



static int x509_cert_get_authority_key_identifier(const uint8_t *cert, size_t certlen,
	const uint8_t **keyid, size_t *keyid_len,
	const uint8_t **issuer, size_t *issuer_len,
	const uint8_t **serial, size_t *serial_len)
{
	int ret;
	int critical;
	const uint8_t *exts;
	size_t extslen;
	const uint8_t *val;
	size_t vlen;

	if (!cert || !certlen || !keyid || !keyid_len
		|| !issuer || !issuer_len || !serial || !serial_len) {
		error_print();
		return -1;
	}

	*keyid = NULL;
	*keyid_len = 0;
	*issuer = NULL;
	*issuer_len = 0;
	*serial = NULL;
	*serial_len = 0;

	if ((ret = x509_cert_get_exts(cert, certlen, &exts, &extslen)) != 1) {
		if (ret) error_print();
		return ret;
	}
	if ((ret = x509_exts_get_ext_by_oid(exts, extslen, OID_ce_authority_key_identifier,
		&critical, &val, &vlen)) != 1) {
		if (ret) error_print();
		return ret;
	}
	if (x509_authority_key_identifier_from_der(keyid, keyid_len,
		issuer, issuer_len, serial, serial_len, &val, &vlen) != 1
		|| asn1_length_is_zero(vlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

static int x509_cert_get_subject_key_identifier(const uint8_t *cert, size_t certlen,
	const uint8_t **keyid, size_t *keyid_len)
{
	int ret;
	int critical;
	const uint8_t *exts;
	size_t extslen;
	const uint8_t *val;
	size_t vlen;

	if (!cert || !certlen || !keyid || !keyid_len) {
		error_print();
		return -1;
	}

	*keyid = NULL;
	*keyid_len = 0;

	if ((ret = x509_cert_get_exts(cert, certlen, &exts, &extslen)) != 1) {
		if (ret) error_print();
		return ret;
	}
	if ((ret = x509_exts_get_ext_by_oid(exts, extslen, OID_ce_subject_key_identifier,
		&critical, &val, &vlen)) != 1) {
		if (ret) error_print();
		return ret;
	}
	if (asn1_octet_string_from_der(keyid, keyid_len, &val, &vlen) != 1
		|| asn1_length_is_zero(vlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

static int x509_signed_is_verified_by_key(const uint8_t *a, size_t alen,
	const X509_KEY *key, const char *signer_id, size_t signer_id_len)
{
	const uint8_t *tbs;
	size_t tbslen;
	int sig_alg;
	const uint8_t *sig;
	size_t siglen;
	void *sign_args = NULL;
	size_t sign_argslen = 0;
	X509_SIGN_CTX verify_ctx;

	if (!a || !alen || !key) {
		error_print();
		return -1;
	}
	if (x509_signed_from_der(&tbs, &tbslen, &sig_alg, &sig, &siglen, &a, &alen) != 1
		|| asn1_length_is_zero(alen) != 1) {
		error_print();
		return -1;
	}
	if (x509_key_supports_sign_algor(key, sig_alg) != 1) {
		return 0;
	}


	// X509_sign/verify 还是默认就使用SM2的默认ID吧
	if (key->algor == OID_ec_public_key && key->algor_param == OID_sm2) {
		sign_args = (uint8_t *)signer_id;
		sign_argslen = signer_id_len;
	}
	if (x509_verify_init(&verify_ctx, key, sig_alg, sign_args, sign_argslen, sig, siglen) != 1
		|| x509_verify_update(&verify_ctx, tbs, tbslen) != 1
		|| x509_verify_finish(&verify_ctx) != 1) {
		return 0;
	}
	return 1;
}

// 其实只要把验证签名的步骤拿出来，就可以重用已有的函数
int x509_cert_is_signed_by_root_ca_cert(const uint8_t *cert, size_t certlen,
	const uint8_t *rootcacert, size_t rootcacertlen,
	const char *signer_id, size_t signer_id_len)
{
	const uint8_t *issuer;
	size_t issuer_len;
	const uint8_t *subject;
	size_t subject_len;

	const uint8_t *aki;
	size_t aki_len;
	const uint8_t *aki_issuer;
	size_t aki_issuer_len;
	const uint8_t *aki_serial;
	size_t aki_serial_len;
	const uint8_t *ski;
	size_t ski_len;
	const uint8_t *root_serial;
	size_t root_serial_len;
	const uint8_t *directory_name;
	size_t directory_name_len;
	int issuer_match;
	X509_KEY public_key;
	int ret;

	if (!cert || !certlen || !rootcacert || !rootcacertlen) {
		error_print();
		return -1;
	}

	// check issuer == subject
	if (x509_cert_get_issuer(cert, certlen, &issuer, &issuer_len) != 1
		|| x509_cert_get_subject(rootcacert, rootcacertlen, &subject, &subject_len) != 1) {
		error_print();
		return -1;
	}
	if ((ret = x509_name_equ(issuer, issuer_len, subject, subject_len)) != 1) {
		if (ret) error_print();
		return ret;
	}

	// if AKI not exist
	if ((ret = x509_cert_get_authority_key_identifier(cert, certlen,
		&aki, &aki_len, &aki_issuer, &aki_issuer_len, &aki_serial, &aki_serial_len)) < 0) {
		error_print();
		return -1;
	} else if (ret) {
		// AKI exist

		// SKI not exist => not_match
		if ((ret = x509_cert_get_subject_key_identifier(rootcacert, rootcacertlen, &ski, &ski_len)) < 0) {
			if (ret) error_print();
			return ret;
		}

		if (aki_len) {
			if (aki_len != ski_len || memcmp(aki, ski, ski_len) != 0) {
				return 0;
			}
		}

		if (aki_issuer_len || aki_serial_len) {
			if (!aki_issuer_len || !aki_serial_len) {
				error_print();
				return -1;
			}
			if (x509_cert_get_issuer_and_serial_number(rootcacert, rootcacertlen,
				NULL, NULL, &root_serial, &root_serial_len) != 1) {
				error_print();
				return -1;
			}

			// aki_issuer AKI 中的Issuer 是一个GeneralNames.directoryName == ROOTCACERT.subject

			if ((ret = x509_general_names_get_first(aki_issuer, aki_issuer_len, NULL,
				X509_gn_directory_name, &directory_name, &directory_name_len)) < 0) {
				if (ret) error_print();
				return ret;
			}
			if (ret == 0) {
				return 0;
			}
			if ((issuer_match = x509_name_equ(directory_name, directory_name_len,
				subject, subject_len)) != 1) {
				if (issuer_match) error_print();
				return issuer_match;
			}

			if (aki_serial_len != root_serial_len
				|| memcmp(aki_serial, root_serial, root_serial_len) != 0) {
				return 0;
			}
		}

	}


	if (x509_cert_get_subject_public_key(rootcacert, rootcacertlen, &public_key) != 1) {
		error_print();
		return -1;
	}

	// 最后才是verify
	// 可以修改一下 x509_signed_verify_ex ，验证失败不都显式打印错误。
	if ((ret = x509_signed_is_verified_by_key(cert, certlen, &public_key, signer_id, signer_id_len)) < 0) {
		error_print();
		return -1;
	}
	return ret;
}

static int x509_general_name_check(int choice, const uint8_t *d, size_t dlen)
{
	const uint8_t *p;
	size_t len;
	const uint8_t *q;
	size_t qlen;
	uint32_t nodes[32];
	size_t nodes_cnt;
	int tag;
	int ret;

	if (!d || !dlen) {
		error_print();
		return -1;
	}

	switch (choice) {
	case X509_gn_other_name:
		if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1
			|| asn1_length_is_zero(dlen) != 1
			|| asn1_object_identifier_from_der(nodes, &nodes_cnt, &p, &len) != 1
			|| asn1_explicit_from_der(0, &q, &qlen, &p, &len) != 1
			|| asn1_length_is_zero(len) != 1) {
			error_print();
			return -1;
		}
		if (!qlen) {
			error_print();
			return -1;
		}
		break;

	case X509_gn_rfc822_name:
	case X509_gn_dns_name:
	case X509_gn_uniform_resource_identifier:
		if (asn1_string_is_ia5_string((const char *)d, dlen) != 1) {
			error_print();
			return -1;
		}
		break;

	case X509_gn_x400_address:
		if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1
			|| asn1_length_is_zero(dlen) != 1
			|| !len) {
			error_print();
			return -1;
		}
		break;

	case X509_gn_directory_name:
		if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1
			|| asn1_length_is_zero(dlen) != 1
			|| x509_name_check(p, len) != 1) {
			error_print();
			return -1;
		}
		break;

	case X509_gn_edi_party_name:
		if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1
			|| asn1_length_is_zero(dlen) != 1) {
			error_print();
			return -1;
		}
		if ((ret = x509_explicit_directory_name_from_der(0, &tag, &q, &qlen, &p, &len)) < 0) {
			error_print();
			return -1;
		}
		if (ret && x509_directory_name_check(tag, q, qlen) != 1) {
			error_print();
			return -1;
		}
		if (x509_explicit_directory_name_from_der(1, &tag, &q, &qlen, &p, &len) != 1
			|| x509_directory_name_check(tag, q, qlen) != 1
			|| asn1_length_is_zero(len) != 1) {
			error_print();
			return -1;
		}
		break;

	case X509_gn_ip_address:
		if (dlen != 4 && dlen != 16) {
			error_print();
			return -1;
		}
		break;

	case X509_gn_registered_id:
		if (asn1_object_identifier_from_octets(nodes, &nodes_cnt, d, dlen) != 1) {
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

static int x509_general_names_check(const uint8_t *d, size_t dlen)
{
	int choice;
	const uint8_t *name;
	size_t namelen;

	if (!d || !dlen) {
		error_print();
		return -1;
	}

	while (dlen) {
		if (x509_general_name_from_der(&choice, &name, &namelen, &d, &dlen) != 1
			|| x509_general_name_check(choice, name, namelen) != 1) {
			error_print();
			return -1;
		}
	}

	return 1;
}

int x509_cert_check_subject(const uint8_t *cert, size_t certlen, int cert_type)
{
	int has_subject;
	const uint8_t *subject;
	size_t subject_len;

	if (!cert || !certlen) {
		error_print();
		return -1;
	}

	if (x509_cert_get_subject(cert, certlen, &subject, &subject_len) != 1) {
		error_print();
		return -1;
	}
	if ((has_subject = x509_name_check(subject, subject_len)) < 0) {
		error_print();
		return -1;
	}

	if (!has_subject) {
		int is_cacert;
		const uint8_t *exts;
		size_t extslen;
		int critical;
		const uint8_t *val;
		size_t vlen;
		const uint8_t *gns;
		size_t gnslen;

		switch (cert_type) {
		case X509_cert_server_auth:
		case X509_cert_client_auth:
		case X509_cert_server_key_encipher:
		case X509_cert_client_key_encipher:
		case X509_cert_ocsp_signing:
			is_cacert = 0;
			break;
		case X509_cert_ca:
		case X509_cert_root_ca:
		case X509_cert_crl_sign:
			is_cacert = 1;
			break;
		default:
			error_print();
			return -1;
		}

		if (is_cacert) {
			error_print();
			return -1;
		}
		if (x509_cert_get_exts(cert, certlen, &exts, &extslen) != 1
			|| x509_exts_get_ext_by_oid(exts, extslen, OID_ce_subject_alt_name, &critical, &val, &vlen) != 1) {
			error_print();
			return -1;
		}
		if (critical != X509_critical) {
			error_print();
			return -1;
		}
		if (asn1_sequence_from_der(&gns, &gnslen, &val, &vlen) != 1
			|| asn1_length_is_zero(vlen) != 1
			|| x509_general_names_check(gns, gnslen) != 1) {
			error_print();
			return -1;
		}
	}

	return 1;
}

static int x509_name_string_char_from_bytes(int tag, uint32_t *ch, const uint8_t **in, size_t *inlen)
{
	int ret;

	if (!in || !*in || !inlen || !ch) {
		error_print();
		return -1;
	}
	if (*inlen == 0) {
		return 0;
	}

	switch (tag) {
	case ASN1_TAG_TeletexString:
		*ch = *(*in)++;
		(*inlen)--;
		ret = 1;
		break;
	case ASN1_TAG_PrintableString:
		if ((ret = asn1_printable_string_code_point_from_bytes(ch, in, inlen)) < 0) {
			error_print();
			return -1;
		}
		break;
	case ASN1_TAG_IA5String:
		if ((ret = asn1_ia5_string_code_point_from_bytes(ch, in, inlen)) < 0) {
			error_print();
			return -1;
		}
		break;
	case ASN1_TAG_UTF8String:
		if ((ret = asn1_utf8_string_code_point_from_bytes(ch, in, inlen)) < 0) {
			error_print();
			return -1;
		}
		break;
	case ASN1_TAG_BMPString:
		if ((ret = asn1_bmp_string_code_point_from_bytes(ch, in, inlen)) < 0) {
			error_print();
			return -1;
		}
		break;
	case ASN1_TAG_UniversalString:
		if ((ret = asn1_universal_string_code_point_from_bytes(ch, in, inlen)) < 0) {
			error_print();
			return -1;
		}
		break;
	default:
		error_print();
		return -1;
	}

	return ret;
}

static int x509_name_string_skip_spaces(int tag, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *p;
	size_t len;
	uint32_t ch;

	if (!in || !*in || !inlen) {
		error_print();
		return -1;
	}

	while (*inlen) {
		p = *in;
		len = *inlen;
		if ((ret = x509_name_string_char_from_bytes(tag, &ch, &p, &len)) != 1) {
			error_print();
			return -1;
		}
		if (ch != ' ') {
			return 1;
		}
		*in = p;
		*inlen = len;
	}
	return 1;
}

static int x509_name_string_code_point_from_bytes(int tag, uint32_t *code_point,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	uint32_t ch;

	if (!code_point || !in || !*in || !inlen) {
		error_print();
		return -1;
	}
	if ((ret = x509_name_string_char_from_bytes(tag, &ch, in, inlen)) != 1) {
		if (ret == 0) {
			return 0;
		}
		error_print();
		return -1;
	}
	if ('A' <= ch && ch <= 'Z') {
		ch += 'a' - 'A';
	}
	if (ch == ' ') {
		if (x509_name_string_skip_spaces(tag, in, inlen) != 1) {
			error_print();
			return -1;
		}
		if (*inlen == 0) {
			return 0;
		}
		ch = ' ';
	}
	*code_point = ch;
	return 1;
}

static int x509_name_string_normalized_equ(int a_tag, const uint8_t *a, size_t alen,
	int b_tag, const uint8_t *b, size_t blen)
{
	int a_ret;
	int b_ret;
	uint32_t a_ch;
	uint32_t b_ch;

	if ((!a && alen) || (!b && blen)) {
		error_print();
		return -1;
	}
	if (alen && x509_name_string_skip_spaces(a_tag, &a, &alen) != 1) {
		error_print();
		return -1;
	}
	if (blen && x509_name_string_skip_spaces(b_tag, &b, &blen) != 1) {
		error_print();
		return -1;
	}

	for (;;) {
		a_ret = x509_name_string_code_point_from_bytes(a_tag, &a_ch, &a, &alen);
		if (a_ret < 0) {
			error_print();
			return -1;
		}
		b_ret = x509_name_string_code_point_from_bytes(b_tag, &b_ch, &b, &blen);
		if (b_ret < 0) {
			error_print();
			return -1;
		}
		if (a_ret == 0 || b_ret == 0) {
			return a_ret == b_ret ? 1 : 0;
		}
		if (a_ch != b_ch) {
			return 0;
		}
	}
}


/*
 * 这个 _ex 版本和 x509_attr_type_and_value_from_der() 的区别是：
 * 1. 保留 type 的原始 OBJECT IDENTIFIER DER 编码，因此未知 OID 也可以参与比较；
 * 2. 保留 value 的完整 DER 编码，因此未知或非字符串类型的 value 可以退化为严格 DER 比较；
 * 3. 不调用 x509_attr_type_and_value_check()，避免证书验证时因为本库暂未内置的
 *    AttributeTypeAndValue 类型而提前失败。
 *
 * TODO: 以后可以让 x509_attr_type_and_value_from_der() 基于这个 _ex 版本实现，
 *       在通用解析结果之上再做已知 OID 映射和属性值检查。
 */
static int x509_attr_type_and_value_from_der_ex(const uint8_t **oid, size_t *oid_len,
	int *val_tag, const uint8_t **val, size_t *val_len,
	const uint8_t **val_der, size_t *val_der_len,
	const uint8_t **in, size_t *inlen)
{
	int ret = -1;
	const uint8_t *d;
	size_t dlen;
	const uint8_t *p;
	size_t len;
	const uint8_t *oid_val;
	size_t oid_val_len;

	if (!oid || !oid_len || !val_tag || !val || !val_len || !val_der || !val_der_len
		|| !in || !*in || !inlen) {
		error_print();
		return -1;
	}
	if (asn1_sequence_from_der(&d, &dlen, in, inlen) != 1) {
		error_print();
		goto end;
	}
	if (asn1_any_from_der(oid, oid_len, &d, &dlen) != 1) {
		error_print();
		goto end;
	}
	p = *oid;
	len = *oid_len;
	if (asn1_type_from_der(ASN1_TAG_OBJECT_IDENTIFIER, &oid_val, &oid_val_len, &p, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		goto end;
	}
	*val_der = d;
	*val_der_len = dlen;
	if (asn1_any_type_from_der(val_tag, val, val_len, &d, &dlen) != 1) {
		error_print();
		goto end;
	}
	*val_der_len -= dlen;
	if (asn1_length_is_zero(dlen) != 1) {
		error_print();
		goto end;
	}
	ret = 1;
end:
	return ret;
}

static int x509_attr_type_and_value_normalized_equ(const uint8_t *a, size_t alen,
	const uint8_t *b, size_t blen)
{
	int ret = 0;
	const uint8_t *a_oid;
	const uint8_t *b_oid;
	size_t a_oid_len;
	size_t b_oid_len;
	int a_tag;
	int b_tag;
	const uint8_t *a_val;
	const uint8_t *b_val;
	size_t a_val_len;
	size_t b_val_len;
	const uint8_t *a_val_der;
	const uint8_t *b_val_der;
	size_t a_val_der_len;
	size_t b_val_der_len;

	if (x509_attr_type_and_value_from_der_ex(&a_oid, &a_oid_len, &a_tag,
			&a_val, &a_val_len, &a_val_der, &a_val_der_len, &a, &alen) != 1
		|| asn1_length_is_zero(alen) != 1
		|| x509_attr_type_and_value_from_der_ex(&b_oid, &b_oid_len, &b_tag,
			&b_val, &b_val_len, &b_val_der, &b_val_der_len, &b, &blen) != 1
		|| asn1_length_is_zero(blen) != 1) {
		error_print();
		return -1;
	}
	if (a_oid_len != b_oid_len || memcmp(a_oid, b_oid, a_oid_len) != 0) {
		ret = 0;
	} else if (a_val_der_len == b_val_der_len
		&& memcmp(a_val_der, b_val_der, a_val_der_len) == 0) {
		ret = 1;
	} else if (asn1_tag_is_cstring(a_tag) && asn1_tag_is_cstring(b_tag)) {
		ret = x509_name_string_normalized_equ(a_tag, a_val, a_val_len, b_tag, b_val, b_val_len);
		if (ret < 0) {
			error_print();
			return -1;
		}
	}
	return ret;
}

static int x509_rdn_count(const uint8_t *d, size_t dlen, size_t *count)
{
	int ret = -1;
	const uint8_t *p;
	size_t len;
	size_t n = 0;

	if (!count) {
		error_print();
		return -1;
	}
	while (dlen) {
		if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) {
			error_print();
			goto end;
		}
		n++;
	}
	*count = n;
	ret = 1;
end:
	return ret;
}

/*
 * 统计一个 RDN SET 中和给定 AttributeTypeAndValue 规范化相等的项数。
 *
 * 例如同一个 RDN 允许包含多个 AVA：
 *     SET {
 *         commonName = "Alice",
 *         commonName = " ALICE "
 *     }
 * 如果待匹配的 AVA 是 commonName = "alice"，规范化比较会使 count == 2。
 */
static int x509_rdn_count_attr_type_and_value(const uint8_t *rdn, size_t rdnlen,
	const uint8_t *ava, size_t avalen, size_t *count)
{
	int ret;
	const uint8_t *p;
	size_t len;
	size_t n = 0;

	if (!count) {
		error_print();
		return -1;
	}
	while (rdnlen) {
		if (asn1_any_from_der(&p, &len, &rdn, &rdnlen) != 1) {
			error_print();
			return -1;
		}
		if ((ret = x509_attr_type_and_value_normalized_equ(ava, avalen, p, len)) < 0) {
			error_print();
			return -1;
		}
		if (ret) {
			n++;
		}
	}
	*count = n;
	return 1;
}

static int x509_rdn_normalized_equ(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen)
{
	int ret = 0;
	const uint8_t *a_orig = a;
	size_t a_orig_len = alen;
	const uint8_t *a_ava;
	size_t a_ava_len;
	size_t a_count = 0;
	size_t b_count = 0;
	size_t a_ava_count;
	size_t b_ava_count;
	size_t prev_len;

	if (x509_rdn_count(a, alen, &a_count) != 1
		|| x509_rdn_count(b, blen, &b_count) != 1) {
		error_print();
		ret = -1;
		goto end;
	}
	if (a_count != b_count) {
		goto end;
	}

	while (alen) {
		if (asn1_any_from_der(&a_ava, &a_ava_len, &a, &alen) != 1) {
			error_print();
			ret = -1;
			goto end;
		}
		prev_len = (size_t)(a_ava - a_orig);
		if (prev_len) {
			if (x509_rdn_count_attr_type_and_value(a_orig, prev_len, a_ava, a_ava_len, &a_ava_count) != 1) {
				error_print();
				ret = -1;
				goto end;
			}
			if (a_ava_count) {
				continue;
			}
		}
		if (x509_rdn_count_attr_type_and_value(a_orig, a_orig_len, a_ava, a_ava_len, &a_ava_count) != 1
			|| x509_rdn_count_attr_type_and_value(b, blen, a_ava, a_ava_len, &b_ava_count) != 1) {
			error_print();
			ret = -1;
			goto end;
		}
		if (a_ava_count != b_ava_count) {
			goto end;
		}
	}
	ret = 1;
end:
	return ret;
}

int x509_name_normalized_equ(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen)
{
	int ret;
	const uint8_t *a_rdn;
	const uint8_t *b_rdn;
	size_t a_rdn_len;
	size_t b_rdn_len;

	if ((!a && alen) || (!b && blen)) {
		error_print();
		return -1;
	}
	while (alen && blen) {
		if (asn1_set_from_der(&a_rdn, &a_rdn_len, &a, &alen) != 1
			|| asn1_set_from_der(&b_rdn, &b_rdn_len, &b, &blen) != 1) {
			error_print();
			return -1;
		}
		ret = x509_rdn_normalized_equ(a_rdn, a_rdn_len, b_rdn, b_rdn_len);
		if (ret < 0) {
			error_print();
			return -1;
		}
		if (ret == 0) {
			return 0;
		}
	}
	if (alen || blen) {
		return 0;
	}
	return 1;
}

int asn1_utf8_string_code_point_from_bytes(uint32_t *code_point, const uint8_t **in, size_t *inlen)
{
	const uint8_t *p;
	size_t rem;
	uint32_t cp;

	if (!code_point || !in || !*in || !inlen) {
		error_print();
		return -1;
	}
	if (*inlen == 0) {
		return 0;
	}

	p = *in;
	rem = *inlen;
	if (p[0] < 0x80) {
		cp = p[0];
		p++;
	} else if ((p[0] & 0xe0) == 0xc0) {
		if (rem < 2 || (p[1] & 0xc0) != 0x80 || p[0] < 0xc2) {
			error_print();
			return -1;
		}
		cp = ((uint32_t)(p[0] & 0x1f) << 6) | (p[1] & 0x3f);
		p += 2;
	} else if ((p[0] & 0xf0) == 0xe0) {
		if (rem < 3
			|| (p[1] & 0xc0) != 0x80
			|| (p[2] & 0xc0) != 0x80
			|| (p[0] == 0xe0 && p[1] < 0xa0)
			|| (p[0] == 0xed && p[1] >= 0xa0)) {
			error_print();
			return -1;
		}
		cp = ((uint32_t)(p[0] & 0x0f) << 12)
			| ((uint32_t)(p[1] & 0x3f) << 6)
			| (p[2] & 0x3f);
		p += 3;
	} else if ((p[0] & 0xf8) == 0xf0) {
		if (rem < 4
			|| (p[1] & 0xc0) != 0x80
			|| (p[2] & 0xc0) != 0x80
			|| (p[3] & 0xc0) != 0x80
			|| (p[0] == 0xf0 && p[1] < 0x90)
			|| p[0] > 0xf4
			|| (p[0] == 0xf4 && p[1] >= 0x90)) {
			error_print();
			return -1;
		}
		cp = ((uint32_t)(p[0] & 0x07) << 18)
			| ((uint32_t)(p[1] & 0x3f) << 12)
			| ((uint32_t)(p[2] & 0x3f) << 6)
			| (p[3] & 0x3f);
		p += 4;
	} else {
		error_print();
		return -1;
	}

	*code_point = cp;
	*inlen -= (size_t)(p - *in);
	*in = p;
	return 1;
}

int asn1_printable_string_code_point_from_bytes(uint32_t *code_point, const uint8_t **in, size_t *inlen)
{
	if (!code_point || !in || !*in || !inlen) {
		error_print();
		return -1;
	}
	if (*inlen == 0) {
		return 0;
	}
	if (asn1_string_is_printable_string((const char *)*in, 1) != 1) {
		error_print();
		return -1;
	}
	*code_point = **in;
	(*in)++;
	(*inlen)--;
	return 1;
}

int asn1_ia5_string_code_point_from_bytes(uint32_t *code_point, const uint8_t **in, size_t *inlen)
{
	if (!code_point || !in || !*in || !inlen) {
		error_print();
		return -1;
	}
	if (*inlen == 0) {
		return 0;
	}
	if (asn1_string_is_ia5_string((const char *)*in, 1) != 1) {
		error_print();
		return -1;
	}
	*code_point = **in;
	(*in)++;
	(*inlen)--;
	return 1;
}

int asn1_bmp_string_code_point_from_bytes(uint32_t *code_point, const uint8_t **in, size_t *inlen)
{
	if (!code_point || !in || !*in || !inlen) {
		error_print();
		return -1;
	}
	if (*inlen == 0) {
		return 0;
	}
	if (*inlen < 2 || *inlen % 2) {
		error_print();
		return -1;
	}
	*code_point = GETU16(*in);
	*in += 2;
	*inlen -= 2;
	return 1;
}

int asn1_universal_string_code_point_from_bytes(uint32_t *code_point, const uint8_t **in, size_t *inlen)
{
	if (!code_point || !in || !*in || !inlen) {
		error_print();
		return -1;
	}
	if (*inlen == 0) {
		return 0;
	}
	if (*inlen < 4 || *inlen % 4) {
		error_print();
		return -1;
	}
	*code_point = GETU32(*in);
	*in += 4;
	*inlen -= 4;
	return 1;
}

// GeneralNames 子树匹配

static int x509_ascii_char_equ_case_insensitive(uint8_t a, uint8_t b)
{
	if ('A' <= a && a <= 'Z') {
		a += 'a' - 'A';
	}
	if ('A' <= b && b <= 'Z') {
		b += 'a' - 'A';
	}
	return a == b;
}

static int x509_ia5_string_equ_case_insensitive(
	const uint8_t *a, size_t alen, const uint8_t *b, size_t blen)
{
	size_t i;

	if ((!a && alen) || (!b && blen)) {
		error_print();
		return -1;
	}
	if (alen != blen) {
		return 0;
	}
	for (i = 0; i < alen; i++) {
		if (!x509_ascii_char_equ_case_insensitive(a[i], b[i])) {
			return 0;
		}
	}
	return 1;
}

static int x509_ia5_string_has_suffix_case_insensitive(
	const uint8_t *str, size_t str_len, const uint8_t *suffix, size_t suffix_len)
{
	int ret;

	if ((!str && str_len) || (!suffix && suffix_len)) {
		error_print();
		return -1;
	}
	if (str_len < suffix_len) {
		return 0;
	}
	if ((ret = x509_ia5_string_equ_case_insensitive(
		str + str_len - suffix_len, suffix_len, suffix, suffix_len)) < 0) {
		error_print();
		return -1;
	}
	return ret;
}

static int x509_dns_name_is_in_subtree(
	const uint8_t *dns, size_t dns_len, const uint8_t *base, size_t base_len)
{
	int ret;

	if (!dns || !dns_len || !base || !base_len) {
		error_print();
		return -1;
	}
	if (base[0] == '.') {
		if (dns_len <= base_len) {
			return 0;
		}
		if ((ret = x509_ia5_string_has_suffix_case_insensitive(dns, dns_len, base, base_len)) < 0) {
			error_print();
			return -1;
		}
		return ret;
	}
	if ((ret = x509_ia5_string_equ_case_insensitive(dns, dns_len, base, base_len)) != 0) {
		if (ret < 0) error_print();
		return ret;
	}
	if (dns_len <= base_len || dns[dns_len - base_len - 1] != '.') {
		return 0;
	}
	if ((ret = x509_ia5_string_has_suffix_case_insensitive(dns, dns_len, base, base_len)) < 0) {
		error_print();
		return -1;
	}
	return ret;
}

static int x509_rfc822_name_get_host(
	const uint8_t *name, size_t name_len, const uint8_t **host, size_t *host_len)
{
	size_t i;
	const uint8_t *p = NULL;

	if (!name || !name_len || !host || !host_len) {
		error_print();
		return -1;
	}
	*host = NULL;
	*host_len = 0;

	for (i = 0; i < name_len; i++) {
		if (name[i] == '@') {
			p = name + i + 1;
		}
	}
	if (!p || p == name + name_len) {
		return 0;
	}
	*host = p;
	*host_len = (size_t)(name + name_len - p);
	return 1;
}

static int x509_rfc822_name_is_in_subtree(
	const uint8_t *name, size_t name_len, const uint8_t *base, size_t base_len)
{
	int ret;
	const uint8_t *host;
	size_t host_len;

	if (!name || !name_len || !base || !base_len) {
		error_print();
		return -1;
	}
	if (memchr(base, '@', base_len)) {
		if ((ret = x509_ia5_string_equ_case_insensitive(name, name_len, base, base_len)) < 0) {
			error_print();
			return -1;
		}
		return ret;
	}
	if ((ret = x509_rfc822_name_get_host(name, name_len, &host, &host_len)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (base[0] == '.') {
		if (host_len <= base_len) {
			return 0;
		}
		if ((ret = x509_ia5_string_has_suffix_case_insensitive(host, host_len, base, base_len)) < 0) {
			error_print();
			return -1;
		}
		return ret;
	}
	if ((ret = x509_ia5_string_equ_case_insensitive(host, host_len, base, base_len)) < 0) {
		error_print();
		return -1;
	}
	return ret;
}

static int x509_uri_get_host(
	const uint8_t *uri, size_t urilen, const uint8_t **host, size_t *host_len)
{
	const uint8_t *p;
	const uint8_t *end;
	const uint8_t *authority_end;
	const uint8_t *last_at = NULL;
	const uint8_t *q;

	if (!uri || !urilen || !host || !host_len) {
		error_print();
		return -1;
	}
	*host = NULL;
	*host_len = 0;

	p = uri;
	end = uri + urilen;
	while (p + 2 < end) {
		if (p[0] == ':' && p[1] == '/' && p[2] == '/') {
			p += 3;
			break;
		}
		p++;
	}
	if (p + 2 >= end) {
		return 0;
	}

	authority_end = p;
	while (authority_end < end
		&& *authority_end != '/'
		&& *authority_end != '?'
		&& *authority_end != '#') {
		if (*authority_end == '@') {
			last_at = authority_end;
		}
		authority_end++;
	}
	if (last_at) {
		p = last_at + 1;
	}
	if (p == authority_end) {
		return 0;
	}

	if (*p == '[') {
		q = p + 1;
		while (q < authority_end && *q != ']') {
			q++;
		}
		if (q == authority_end || q == p + 1) {
			return 0;
		}
		*host = p + 1;
		*host_len = (size_t)(q - p - 1);
		return 1;
	}

	q = p;
	while (q < authority_end && *q != ':') {
		q++;
	}
	if (q == p) {
		return 0;
	}
	*host = p;
	*host_len = (size_t)(q - p);
	return 1;
}

static int x509_uri_name_is_in_subtree(
	const uint8_t *uri, size_t uri_len, const uint8_t *base, size_t base_len)
{
	int ret;
	const uint8_t *host;
	size_t host_len;

	if (!uri || !uri_len || !base || !base_len) {
		error_print();
		return -1;
	}
	if ((ret = x509_uri_get_host(uri, uri_len, &host, &host_len)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (base[0] == '.') {
		if (host_len <= base_len) {
			return 0;
		}
		if ((ret = x509_ia5_string_has_suffix_case_insensitive(host, host_len, base, base_len)) < 0) {
			error_print();
			return -1;
		}
		return ret;
	}
	if ((ret = x509_ia5_string_equ_case_insensitive(host, host_len, base, base_len)) < 0) {
		error_print();
		return -1;
	}
	return ret;
}

static int x509_ip_address_is_in_subtree(
	const uint8_t *ip, size_t ip_len, const uint8_t *base, size_t base_len)
{
	const uint8_t *addr;
	const uint8_t *mask;
	size_t i;

	if (!ip || !base) {
		error_print();
		return -1;
	}
	if ((ip_len != 4 && ip_len != 16) || base_len != ip_len * 2) {
		error_print();
		return -1;
	}

	addr = base;
	mask = base + ip_len;
	for (i = 0; i < ip_len; i++) {
		if ((ip[i] & mask[i]) != (addr[i] & mask[i])) {
			return 0;
		}
	}
	return 1;
}

static int x509_registered_id_is_in_subtree(
	const uint8_t *oid, size_t oid_len, const uint8_t *base, size_t base_len)
{
	uint32_t oid_nodes[32];
	uint32_t base_nodes[32];
	size_t oid_nodes_count;
	size_t base_nodes_count;
	size_t i;

	if (!oid || !oid_len || !base || !base_len) {
		error_print();
		return -1;
	}
	if (asn1_object_identifier_from_octets(oid_nodes, &oid_nodes_count, oid, oid_len) != 1
		|| asn1_object_identifier_from_octets(base_nodes, &base_nodes_count, base, base_len) != 1) {
		error_print();
		return -1;
	}
	if (oid_nodes_count < base_nodes_count) {
		return 0;
	}
	for (i = 0; i < base_nodes_count; i++) {
		if (oid_nodes[i] != base_nodes[i]) {
			return 0;
		}
	}
	return 1;
}

static int x509_name_is_in_subtree(const uint8_t *name, size_t name_len,
	const uint8_t *base, size_t base_len)
{
	int ret;
	const uint8_t *name_rdn;
	const uint8_t *base_rdn;
	size_t name_rdn_len;
	size_t base_rdn_len;

	if ((!name && name_len) || (!base && base_len)) {
		error_print();
		return -1;
	}

	while (base_len) {
		if (!name_len) {
			return 0;
		}
		if (asn1_set_from_der(&base_rdn, &base_rdn_len, &base, &base_len) != 1
			|| asn1_set_from_der(&name_rdn, &name_rdn_len, &name, &name_len) != 1) {
			error_print();
			return -1;
		}
		if ((ret = x509_rdn_normalized_equ(name_rdn, name_rdn_len, base_rdn, base_rdn_len)) != 1) {
			if (ret < 0) error_print();
			return ret;
		}
	}
	return 1;
}

int x509_general_name_normalized_equ(int a_choice, const uint8_t *a, size_t alen,
	int b_choice, const uint8_t *b, size_t blen)
{
	int ret;

	if (a_choice != b_choice) {
		return 0;
	}
	if (x509_general_name_check(a_choice, a, alen) != 1
		|| x509_general_name_check(b_choice, b, blen) != 1) {
		error_print();
		return -1;
	}

	switch (a_choice) {
	case X509_gn_rfc822_name:
	case X509_gn_dns_name:
		if ((ret = x509_ia5_string_equ_case_insensitive(a, alen, b, blen)) < 0) {
			error_print();
			return -1;
		}
		return ret;
	case X509_gn_directory_name:
		if ((ret = x509_name_normalized_equ(a, alen, b, blen)) < 0) {
			error_print();
			return -1;
		}
		return ret;
	case X509_gn_other_name:
	case X509_gn_x400_address:
	case X509_gn_edi_party_name:
	case X509_gn_uniform_resource_identifier:
	case X509_gn_ip_address:
	case X509_gn_registered_id:
		if (alen == blen && memcmp(a, b, alen) == 0) {
			return 1;
		}
		return 0;
	default:
		error_print();
		return -1;
	}
}

int x509_general_name_is_in_subtree(int name_choice, const uint8_t *name, size_t name_len,
	int base_choice, const uint8_t *base, size_t base_len)
{
	int ret;

	if ((!name && name_len) || (!base && base_len) || !name_len || !base_len) {
		error_print();
		return -1;
	}
	if (name_choice != base_choice) {
		return 0;
	}
	if (x509_general_name_check(name_choice, name, name_len) != 1) {
		error_print();
		return -1;
	}

	switch (name_choice) {
	case X509_gn_rfc822_name:
		if (asn1_string_is_ia5_string((const char *)base, base_len) != 1) {
			error_print();
			return -1;
		}
		if ((ret = x509_rfc822_name_is_in_subtree(name, name_len, base, base_len)) < 0) {
			error_print();
			return -1;
		}
		return ret;
	case X509_gn_dns_name:
		if (asn1_string_is_ia5_string((const char *)base, base_len) != 1) {
			error_print();
			return -1;
		}
		if ((ret = x509_dns_name_is_in_subtree(name, name_len, base, base_len)) < 0) {
			error_print();
			return -1;
		}
		return ret;
	case X509_gn_directory_name:
		if (x509_name_check(base, base_len) != 1) {
			error_print();
			return -1;
		}
		if ((ret = x509_name_is_in_subtree(name, name_len, base, base_len)) < 0) {
			error_print();
			return -1;
		}
		return ret;
	case X509_gn_uniform_resource_identifier:
		if (asn1_string_is_ia5_string((const char *)base, base_len) != 1) {
			error_print();
			return -1;
		}
		if ((ret = x509_uri_name_is_in_subtree(name, name_len, base, base_len)) < 0) {
			error_print();
			return -1;
		}
		return ret;
	case X509_gn_ip_address:
		if ((ret = x509_ip_address_is_in_subtree(name, name_len, base, base_len)) < 0) {
			error_print();
			return -1;
		}
		return ret;
	case X509_gn_registered_id:
		if ((ret = x509_registered_id_is_in_subtree(name, name_len, base, base_len)) < 0) {
			error_print();
			return -1;
		}
		return ret;
	case X509_gn_other_name:
	case X509_gn_x400_address:
	case X509_gn_edi_party_name:
		if ((ret = x509_general_name_normalized_equ(name_choice, name, name_len,
			base_choice, base, base_len)) != 1) {
			if (ret < 0) error_print();
			return ret;
		}
		return 1;
	default:
		error_print();
		return -1;
	}
}

int x509_general_name_is_in_general_subtree(int name_choice, const uint8_t *name, size_t name_len,
	const uint8_t *general_subtree, size_t general_subtree_len)
{
	int ret;
	int base_choice;
	const uint8_t *base;
	size_t base_len;
	int minimum = -1;
	int maximum = -1;

	if (!general_subtree || !general_subtree_len) {
		error_print();
		return -1;
	}
	if (x509_general_subtree_from_der(&base_choice, &base, &base_len,
		&minimum, &maximum, &general_subtree, &general_subtree_len) != 1
		|| asn1_length_is_zero(general_subtree_len) != 1) {
		error_print();
		return -1;
	}

	/*
	当前证书验证只支持 RFC 5280 profile 中的 GeneralSubtree：
	minimum 必须为 0，maximum 必须缺省。x509_general_subtree_from_der()
	已经把缺省 minimum 转换为 0，并用 maximum == -1 表示缺省。
	如果遇到 minimum != 0 或 maximum present，当前实现不能静默忽略，
	必须作为不支持的语义错误返回 -1。
	*/
	if (minimum != 0 || maximum >= 0) {
		error_print();
		return -1;
	}
	if ((ret = x509_general_name_is_in_subtree(name_choice, name, name_len,
		base_choice, base, base_len)) < 0) {
		error_print();
		return -1;
	}
	return ret;
}

int x509_general_name_is_in_general_subtrees(int name_choice, const uint8_t *name, size_t name_len,
	const uint8_t *general_subtrees, size_t general_subtrees_len)
{
	int ret;
	const uint8_t *general_subtree;
	size_t general_subtree_len;

	if (!general_subtrees || !general_subtrees_len) {
		error_print();
		return -1;
	}

	while (general_subtrees_len) {
		if (asn1_any_from_der(&general_subtree, &general_subtree_len,
			&general_subtrees, &general_subtrees_len) != 1) {
			error_print();
			return -1;
		}
		if ((ret = x509_general_name_is_in_general_subtree(name_choice, name, name_len,
			general_subtree, general_subtree_len)) != 0) {
			if (ret < 0) error_print();
			return ret;
		}
	}
	return 0;
}

// end of general name in subtree


static int x509_general_subtree_from_der_for_verify(int *base_choice,
	const uint8_t **base, size_t *base_len,
	const uint8_t *general_subtree, size_t general_subtree_len)
{
	int minimum = -1;
	int maximum = -1;

	if (!base_choice || !base || !base_len || !general_subtree || !general_subtree_len) {
		error_print();
		return -1;
	}
	if (x509_general_subtree_from_der(base_choice, base, base_len,
		&minimum, &maximum, &general_subtree, &general_subtree_len) != 1
		|| asn1_length_is_zero(general_subtree_len) != 1) {
		error_print();
		return -1;
	}
	if (minimum != 0 || maximum >= 0) {
		error_print();
		return -1;
	}
	return 1;
}

static int x509_general_name_is_permitted_by_general_subtrees(int name_choice,
	const uint8_t *name, size_t name_len,
	const uint8_t *general_subtrees, size_t general_subtrees_len)
{
	int ret;
	int base_choice;
	const uint8_t *general_subtree;
	size_t general_subtree_len;
	const uint8_t *base;
	size_t base_len;
	int has_base_choice = 0;

	if (!name || !name_len || !general_subtrees || !general_subtrees_len) {
		error_print();
		return -1;
	}

	while (general_subtrees_len) {
		if (asn1_any_from_der(&general_subtree, &general_subtree_len,
			&general_subtrees, &general_subtrees_len) != 1) {
			error_print();
			return -1;
		}
		if (x509_general_subtree_from_der_for_verify(&base_choice, &base, &base_len,
			general_subtree, general_subtree_len) != 1) {
			error_print();
			return -1;
		}
		if (base_choice != name_choice) {
			continue;
		}
		has_base_choice = 1;
		if ((ret = x509_general_name_is_in_subtree(name_choice, name, name_len,
			base_choice, base, base_len)) < 0) {
			error_print();
			return -1;
		}
		if (ret) {
			return 1;
		}
	}
	if (has_base_choice) {
		return 0;
	}
	return 1;
}

static int x509_general_name_check_name_constraints(int choice,
	const uint8_t *name, size_t name_len,
	const uint8_t *permitted_subtrees, size_t permitted_subtrees_len,
	const uint8_t *excluded_subtrees, size_t excluded_subtrees_len)
{
	int ret;

	if (!name || !name_len) {
		error_print();
		return -1;
	}

	if (excluded_subtrees_len) {
		if (!excluded_subtrees) {
			error_print();
			return -1;
		}
		if ((ret = x509_general_name_is_in_general_subtrees(choice, name, name_len,
			excluded_subtrees, excluded_subtrees_len)) < 0) {
			error_print();
			return -1;
		}
		if (ret) {
			return 0;
		}
	}

	if (permitted_subtrees_len) {
		if (!permitted_subtrees) {
			error_print();
			return -1;
		}
		if ((ret = x509_general_name_is_permitted_by_general_subtrees(choice, name, name_len,
			permitted_subtrees, permitted_subtrees_len)) < 0) {
			error_print();
			return -1;
		}
		return ret;
	}
	return 1;
}

static int x509_cert_subject_alt_name_check_name_constraints(const uint8_t *cert, size_t certlen,
	const uint8_t *permitted_subtrees, size_t permitted_subtrees_len,
	const uint8_t *excluded_subtrees, size_t excluded_subtrees_len)
{
	int ret;
	int critical;
	int choice;
	const uint8_t *exts;
	size_t extslen;
	const uint8_t *val;
	size_t vlen;
	const uint8_t *general_names;
	size_t general_names_len;
	const uint8_t *name;
	size_t name_len;

	if (!cert || !certlen) {
		error_print();
		return -1;
	}
	if ((ret = x509_cert_get_exts(cert, certlen, &exts, &extslen)) < 0) {
		error_print();
		return -1;
	}
	if (ret == 0) {
		/*
		证书没有扩展时也就没有 subjectAltName 可检查。
		这里把“未找到扩展”的 0 转换为“没有 SAN 违反约束”的 1。
		*/
		return 1;
	}
	if ((ret = x509_exts_get_ext_by_oid(exts, extslen, OID_ce_subject_alt_name,
		&critical, &val, &vlen)) < 0) {
		error_print();
		return -1;
	}
	if (ret == 0) {
		/*
		没有 subjectAltName 扩展时，本函数只负责 SAN 的 NameConstraints 检查。
		这里把“未找到 SAN”的 0 转换为“SAN 检查通过”的 1。
		*/
		return 1;
	}
	if (x509_general_names_from_der(&general_names, &general_names_len, &val, &vlen) != 1
		|| asn1_length_is_zero(vlen) != 1) {
		error_print();
		return -1;
	}

	while (general_names_len) {
		if (x509_general_name_from_der(&choice, &name, &name_len,
			&general_names, &general_names_len) != 1) {
			error_print();
			return -1;
		}
		if ((ret = x509_general_name_check_name_constraints(choice, name, name_len,
			permitted_subtrees, permitted_subtrees_len,
			excluded_subtrees, excluded_subtrees_len)) < 0) {
			error_print();
			return -1;
		}
		if (ret == 0) {
			return 0;
		}
	}
	return 1;
}

int x509_cert_check_name_constraints(const uint8_t *cert, size_t certlen,
	const uint8_t *name_constraints, size_t name_constraints_len)
{
	int ret;
	const uint8_t *p;
	size_t len;
	const uint8_t *permitted_subtrees;
	size_t permitted_subtrees_len;
	const uint8_t *excluded_subtrees;
	size_t excluded_subtrees_len;
	const uint8_t *subject;
	size_t subject_len;

	if (!cert || !certlen || !name_constraints || !name_constraints_len) {
		error_print();
		return -1;
	}

	p = name_constraints;
	len = name_constraints_len;
	if (x509_name_constraints_from_der(&permitted_subtrees, &permitted_subtrees_len,
		&excluded_subtrees, &excluded_subtrees_len, &p, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}

	if (x509_cert_get_subject(cert, certlen, &subject, &subject_len) != 1) {
		error_print();
		return -1;
	}
	if (subject_len) {
		if ((ret = x509_general_name_check_name_constraints(X509_gn_directory_name,
			subject, subject_len, permitted_subtrees, permitted_subtrees_len,
			excluded_subtrees, excluded_subtrees_len)) < 0) {
			error_print();
			return -1;
		}
		if (ret == 0) {
			return 0;
		}
	}

	if ((ret = x509_cert_subject_alt_name_check_name_constraints(cert, certlen,
		permitted_subtrees, permitted_subtrees_len,
		excluded_subtrees, excluded_subtrees_len)) < 0) {
		error_print();
		return -1;
	}
	return ret;
}

static int x509_cert_get_name_constraints(const uint8_t *cert, size_t certlen,
	const uint8_t **name_constraints, size_t *name_constraints_len)
{
	int ret;
	int critical;
	const uint8_t *exts;
	size_t extslen;

	if (!cert || !certlen || !name_constraints || !name_constraints_len) {
		error_print();
		return -1;
	}
	*name_constraints = NULL;
	*name_constraints_len = 0;

	if ((ret = x509_cert_get_exts(cert, certlen, &exts, &extslen)) < 0) {
		error_print();
		return -1;
	}
	if (ret == 0) {
		return 0;
	}
	if ((ret = x509_exts_get_ext_by_oid(exts, extslen, OID_ce_name_constraints,
		&critical, name_constraints, name_constraints_len)) < 0) {
		error_print();
		return -1;
	}
	return ret;
}

static int x509_certs_check_name_constraints_by_name_constraints(
	const uint8_t *cert_chain, size_t cert_chain_len,
	const uint8_t *name_constraints, size_t name_constraints_len)
{
	int ret;
	const uint8_t *cert;
	size_t certlen;

	if (!name_constraints || !name_constraints_len) {
		error_print();
		return -1;
	}
	while (cert_chain_len) {
		if (x509_cert_from_der(&cert, &certlen, &cert_chain, &cert_chain_len) != 1) {
			error_print();
			return -1;
		}
		if ((ret = x509_cert_check_name_constraints(cert, certlen,
			name_constraints, name_constraints_len)) < 0) {
			error_print();
			return -1;
		}
		if (ret == 0) {
			return 0;
		}
	}
	return 1;
}

int x509_cert_is_self_issued(const uint8_t *cert, size_t certlen)
{
	int ret;
	const uint8_t *issuer;
	size_t issuer_len;
	const uint8_t *subject;
	size_t subject_len;

	if (!cert || !certlen) {
		error_print();
		return -1;
	}
	if (x509_cert_get_issuer(cert, certlen, &issuer, &issuer_len) != 1
		|| x509_cert_get_subject(cert, certlen, &subject, &subject_len) != 1) {
		error_print();
		return -1;
	}
	if ((ret = x509_name_normalized_equ(issuer, issuer_len, subject, subject_len)) < 0) {
		error_print();
		return -1;
	}
	return ret;
}

int x509_certs_check_name_constraints(const uint8_t *cert_chain, size_t cert_chain_len,
	const uint8_t *rootcacert, size_t rootcacertlen)
{
	int ret;
	const uint8_t *chain;
	size_t chain_len;
	const uint8_t *cert;
	size_t certlen;
	const uint8_t *name_constraints;
	size_t name_constraints_len;
	size_t checked_certs_len = 0;

	if (!cert_chain || !cert_chain_len
		|| (!rootcacert && rootcacertlen)
		|| (rootcacert && !rootcacertlen)) {
		error_print();
		return -1;
	}

	if (rootcacert) {
		if ((ret = x509_cert_get_name_constraints(rootcacert, rootcacertlen,
			&name_constraints, &name_constraints_len)) < 0) {
			error_print();
			return -1;
		}
		if (ret) {
			/*
			根 CA 不在 cert_chain 中。传入根 CA 时，它的 NameConstraints
			只在这里额外约束 cert_chain 中最靠近根的那张下级证书。
			*/
			if (x509_certs_get_last(cert_chain, cert_chain_len, &cert, &certlen) != 1) {
				error_print();
				return -1;
			}
			if ((ret = x509_cert_check_name_constraints(cert, certlen,
				name_constraints, name_constraints_len)) < 0) {
				error_print();
				return -1;
			}
			if (ret == 0) {
				return 0;
			}
		}
	}

	chain = cert_chain;
	chain_len = cert_chain_len;
	while (chain_len) {
		if (x509_cert_from_der(&cert, &certlen, &chain, &chain_len) != 1) {
			error_print();
			return -1;
		}

		/*
		证书链按被验证证书到上级 CA 的顺序排列。当前证书中的
		NameConstraints 只约束它之前已经出现的下级证书，不约束自己。
		*/
		if (checked_certs_len) {
			if ((ret = x509_cert_get_name_constraints(cert, certlen,
				&name_constraints, &name_constraints_len)) < 0) {
				error_print();
				return -1;
			}
			if (ret) {
				if ((ret = x509_certs_check_name_constraints_by_name_constraints(
					cert_chain, checked_certs_len,
					name_constraints, name_constraints_len)) < 0) {
					error_print();
					return -1;
				}
				if (ret == 0) {
					return 0;
				}
			}
		}
		checked_certs_len += certlen;
	}
	return 1;
}

static int x509_cert_get_basic_constraints(const uint8_t *cert, size_t certlen,
	int *critical, int *ca, int *path_len_constraint)
{
	int ret;
	const uint8_t *exts;
	size_t extslen;
	const uint8_t *val;
	size_t vlen;

	if (!cert || !certlen || !critical || !ca || !path_len_constraint) {
		error_print();
		return -1;
	}
	*critical = -1;
	*ca = -1;
	*path_len_constraint = -1;

	if ((ret = x509_cert_get_exts(cert, certlen, &exts, &extslen)) < 0) {
		error_print();
		return -1;
	}
	if (ret == 0) {
		return 0;
	}
	if ((ret = x509_exts_get_ext_by_oid(exts, extslen, OID_ce_basic_constraints,
		critical, &val, &vlen)) < 0) {
		error_print();
		return -1;
	}
	if (ret == 0) {
		return 0;
	}
	if (x509_basic_constraints_from_der(ca, path_len_constraint, &val, &vlen) != 1
		|| asn1_length_is_zero(vlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

static int x509_cert_check_basic_constraints_by_type(const uint8_t *cert, size_t certlen,
	int cert_type, int *path_len_constraint)
{
	int has_basic_constraints;
	int is_ca;
	int critical;
	int ca;

	if (!cert || !certlen || !path_len_constraint) {
		error_print();
		return -1;
	}
	*path_len_constraint = -1;

	switch (cert_type) {
	case X509_cert_server_auth:
	case X509_cert_client_auth:
	case X509_cert_server_key_encipher:
	case X509_cert_client_key_encipher:
	case X509_cert_ocsp_signing:
		is_ca = 0;
		break;
	case X509_cert_ca:
	case X509_cert_root_ca:
	case X509_cert_crl_sign:
		is_ca = 1;
		break;
	default:
		error_print();
		return -1;
	}

	if ((has_basic_constraints = x509_cert_get_basic_constraints(cert, certlen,
		&critical, &ca, path_len_constraint)) < 0) {
		error_print();
		return -1;
	}
	if (!has_basic_constraints) {
		if (is_ca) {
			error_print();
			return -1;
		}
	} else {
		if (x509_ext_check_critical(OID_ce_basic_constraints, is_ca, critical) != 1
			|| x509_basic_constraints_check(ca, *path_len_constraint, cert_type) != 1) {
			error_print();
			return -1;
		}
	}
	return 1;
}

static int x509_certs_count_non_self_issued_ca_certs(const uint8_t *cert_chain,
	size_t cert_chain_len, size_t *count)
{
	int ret;
	int is_first_cert = 1;
	const uint8_t *cert;
	size_t certlen;

	if (!cert_chain || !cert_chain_len || !count) {
		error_print();
		return -1;
	}
	*count = 0;

	while (cert_chain_len) {
		if (x509_cert_from_der(&cert, &certlen, &cert_chain, &cert_chain_len) != 1) {
			error_print();
			return -1;
		}
		if (is_first_cert) {
			is_first_cert = 0;
			continue;
		}

		/*
		pathLenConstraint 统计的是当前 CA 之下的非 self-issued 中间 CA 数量。
		链中第一张证书是实体证书，不计入；self-issued CA 也不计入。
		*/
		if ((ret = x509_cert_is_self_issued(cert, certlen)) < 0) {
			error_print();
			return -1;
		}
		if (ret == 0) {
			(*count)++;
		}
	}
	return 1;
}

int x509_certs_check_basic_constraints(const uint8_t *cert_chain, size_t cert_chain_len,
	const uint8_t *rootcacert, size_t rootcacertlen)
{
	const uint8_t *chain;
	size_t chain_len;
	const uint8_t *cert;
	size_t certlen;
	size_t checked_certs_len;
	size_t path_len;
	int path_len_constraint;

	if (!cert_chain || !cert_chain_len
		|| (!rootcacert && rootcacertlen)
		|| (rootcacert && !rootcacertlen)) {
		error_print();
		return -1;
	}

	chain = cert_chain;
	chain_len = cert_chain_len;

	if (x509_cert_from_der(&cert, &certlen, &chain, &chain_len) != 1) {
		error_print();
		return -1;
	}
	if (x509_cert_check_basic_constraints_by_type(cert, certlen,
		X509_cert_server_auth, &path_len_constraint) != 1) {
		error_print();
		return -1;
	}
	checked_certs_len = certlen;

	while (chain_len) {
		if (x509_cert_from_der(&cert, &certlen, &chain, &chain_len) != 1) {
			error_print();
			return -1;
		}
		if (x509_cert_check_basic_constraints_by_type(cert, certlen,
			X509_cert_ca, &path_len_constraint) != 1) {
			error_print();
			return -1;
		}
		if (x509_certs_count_non_self_issued_ca_certs(cert_chain,
			checked_certs_len, &path_len) != 1) {
			error_print();
			return -1;
		}
		if (path_len_constraint >= 0 && path_len > (size_t)path_len_constraint) {
			error_print();
			return -1;
		}
		checked_certs_len += certlen;
	}

	if (rootcacert) {
		if (x509_cert_check_basic_constraints_by_type(rootcacert, rootcacertlen,
			X509_cert_root_ca, &path_len_constraint) != 1) {
			error_print();
			return -1;
		}
		if (x509_certs_count_non_self_issued_ca_certs(cert_chain,
			cert_chain_len, &path_len) != 1) {
			error_print();
			return -1;
		}
		if (path_len_constraint >= 0 && path_len > (size_t)path_len_constraint) {
			error_print();
			return -1;
		}
	}

	return 1;
}

int x509_cert_chain_find_root_ca_cert(const uint8_t *cert_chain, size_t cert_chain_len,
	const uint8_t *rootcacerts, size_t rootcacertslen,
	const uint8_t **rootcacert, size_t *rootcacertlen,
	const char *signer_id, size_t signer_id_len)
{
	int ret;
	const uint8_t *cert;
	size_t certlen;
	const uint8_t *cacert;
	size_t cacertlen;
	int found_root = 0;

	if (!cert_chain || !cert_chain_len
		|| (!rootcacerts && rootcacertslen)
		|| !rootcacert || !rootcacertlen
		|| (!signer_id && signer_id_len)) {
		error_print();
		return -1;
	}
	*rootcacert = NULL;
	*rootcacertlen = 0;

	if (x509_certs_get_last(cert_chain, cert_chain_len, &cert, &certlen) != 1) {
		error_print();
		return -1;
	}

	while (rootcacertslen) {
		if (x509_cert_from_der(&cacert, &cacertlen, &rootcacerts, &rootcacertslen) != 1) {
			error_print();
			return -1;
		}
		if ((ret = x509_cert_is_signed_by_root_ca_cert(cert, certlen, cacert, cacertlen,
			signer_id, signer_id_len)) < 0) {
			error_print();
			return -1;
		}
		if (ret) {
			*rootcacert = cacert;
			*rootcacertlen = cacertlen;
			found_root = 1;
			break;
		}
	}
	return found_root;
}

static int x509_tlcp_certs_get_ca_certs(const uint8_t *cert_chain, size_t cert_chain_len,
	const uint8_t **ca_certs, size_t *ca_certs_len)
{
	const uint8_t *cert;
	size_t certlen;

	if (!cert_chain || !cert_chain_len || !ca_certs || !ca_certs_len) {
		error_print();
		return -1;
	}

	if (x509_cert_from_der(&cert, &certlen, &cert_chain, &cert_chain_len) != 1
		|| x509_cert_from_der(&cert, &certlen, &cert_chain, &cert_chain_len) != 1) {
		error_print();
		return -1;
	}
	*ca_certs = cert_chain;
	*ca_certs_len = cert_chain_len;
	return 1;
}

static int x509_tlcp_certs_count_non_self_issued_ca_certs(const uint8_t *cert_chain,
	size_t cert_chain_len, size_t *count)
{
	int ret;
	const uint8_t *ca_certs;
	size_t ca_certs_len;
	const uint8_t *cert;
	size_t certlen;

	if (!cert_chain || !cert_chain_len || !count) {
		error_print();
		return -1;
	}
	*count = 0;

	if (x509_tlcp_certs_get_ca_certs(cert_chain, cert_chain_len,
		&ca_certs, &ca_certs_len) != 1) {
		error_print();
		return -1;
	}
	while (ca_certs_len) {
		if (x509_cert_from_der(&cert, &certlen, &ca_certs, &ca_certs_len) != 1) {
			error_print();
			return -1;
		}
		if ((ret = x509_cert_is_self_issued(cert, certlen)) < 0) {
			error_print();
			return -1;
		}
		if (ret == 0) {
			(*count)++;
		}
	}
	return 1;
}

int x509_certs_check_basic_constraints_tlcp(const uint8_t *cert_chain, size_t cert_chain_len,
	const uint8_t *rootcacert, size_t rootcacertlen)
{
	const uint8_t *chain;
	size_t chain_len;
	const uint8_t *cert;
	size_t certlen;
	size_t checked_certs_len;
	size_t path_len;
	int path_len_constraint;

	if (!cert_chain || !cert_chain_len
		|| (!rootcacert && rootcacertlen)
		|| (rootcacert && !rootcacertlen)) {
		error_print();
		return -1;
	}

	chain = cert_chain;
	chain_len = cert_chain_len;

	if (x509_cert_from_der(&cert, &certlen, &chain, &chain_len) != 1) {
		error_print();
		return -1;
	}
	if (x509_cert_check_basic_constraints_by_type(cert, certlen,
		X509_cert_server_auth, &path_len_constraint) != 1) {
		error_print();
		return -1;
	}
	checked_certs_len = certlen;

	if (x509_cert_from_der(&cert, &certlen, &chain, &chain_len) != 1) {
		error_print();
		return -1;
	}
	if (x509_cert_check_basic_constraints_by_type(cert, certlen,
		X509_cert_server_key_encipher, &path_len_constraint) != 1) {
		error_print();
		return -1;
	}
	checked_certs_len += certlen;

	while (chain_len) {
		if (x509_cert_from_der(&cert, &certlen, &chain, &chain_len) != 1) {
			error_print();
			return -1;
		}
		if (x509_cert_check_basic_constraints_by_type(cert, certlen,
			X509_cert_ca, &path_len_constraint) != 1) {
			error_print();
			return -1;
		}
		if (x509_tlcp_certs_count_non_self_issued_ca_certs(cert_chain,
			checked_certs_len, &path_len) != 1) {
			error_print();
			return -1;
		}
		if (path_len_constraint >= 0 && path_len > (size_t)path_len_constraint) {
			error_print();
			return -1;
		}
		checked_certs_len += certlen;
	}

	if (rootcacert) {
		if (x509_cert_check_basic_constraints_by_type(rootcacert, rootcacertlen,
			X509_cert_root_ca, &path_len_constraint) != 1) {
			error_print();
			return -1;
		}
		if (x509_tlcp_certs_count_non_self_issued_ca_certs(cert_chain,
			cert_chain_len, &path_len) != 1) {
			error_print();
			return -1;
		}
		if (path_len_constraint >= 0 && path_len > (size_t)path_len_constraint) {
			error_print();
			return -1;
		}
	}

	return 1;
}

int x509_certs_check_name_constraints_tlcp(const uint8_t *cert_chain, size_t cert_chain_len,
	const uint8_t *rootcacert, size_t rootcacertlen)
{
	int ret;
	const uint8_t *chain;
	size_t chain_len;
	const uint8_t *cert;
	size_t certlen;
	const uint8_t *sign_cert;
	size_t sign_certlen;
	const uint8_t *kenc_cert;
	size_t kenc_certlen;
	const uint8_t *name_constraints;
	size_t name_constraints_len;
	size_t checked_certs_len;

	if (!cert_chain || !cert_chain_len
		|| (!rootcacert && rootcacertlen)
		|| (rootcacert && !rootcacertlen)) {
		error_print();
		return -1;
	}

	chain = cert_chain;
	chain_len = cert_chain_len;
	if (x509_cert_from_der(&sign_cert, &sign_certlen, &chain, &chain_len) != 1
		|| x509_cert_from_der(&kenc_cert, &kenc_certlen, &chain, &chain_len) != 1) {
		error_print();
		return -1;
	}

	if (rootcacert) {
		if ((ret = x509_cert_get_name_constraints(rootcacert, rootcacertlen,
			&name_constraints, &name_constraints_len)) < 0) {
			error_print();
			return -1;
		}
		if (ret) {
			if (chain_len) {
				if (x509_certs_get_last(chain, chain_len, &cert, &certlen) != 1) {
					error_print();
					return -1;
				}
				if ((ret = x509_cert_check_name_constraints(cert, certlen,
					name_constraints, name_constraints_len)) < 0) {
					error_print();
					return -1;
				}
				if (ret == 0) {
					return 0;
				}
			} else {
				if ((ret = x509_cert_check_name_constraints(sign_cert, sign_certlen,
					name_constraints, name_constraints_len)) < 0) {
					error_print();
					return -1;
				}
				if (ret == 0) {
					return 0;
				}
				if ((ret = x509_cert_check_name_constraints(kenc_cert, kenc_certlen,
					name_constraints, name_constraints_len)) < 0) {
					error_print();
					return -1;
				}
				if (ret == 0) {
					return 0;
				}
			}
		}
	}

	checked_certs_len = sign_certlen + kenc_certlen;
	while (chain_len) {
		if (x509_cert_from_der(&cert, &certlen, &chain, &chain_len) != 1) {
			error_print();
			return -1;
		}
		if ((ret = x509_cert_get_name_constraints(cert, certlen,
			&name_constraints, &name_constraints_len)) < 0) {
			error_print();
			return -1;
		}
		if (ret) {
			if ((ret = x509_certs_check_name_constraints_by_name_constraints(
				cert_chain, checked_certs_len,
				name_constraints, name_constraints_len)) < 0) {
				error_print();
				return -1;
			}
			if (ret == 0) {
				return 0;
			}
		}
		checked_certs_len += certlen;
	}
	return 1;
}

static int x509_cert_get_subject_alt_name_der(const uint8_t *cert, size_t certlen,
	int *critical, const uint8_t **subject_alt_name, size_t *subject_alt_name_len)
{
	int has_exts;
	int has_subject_alt_name;
	const uint8_t *exts;
	size_t extslen;

	if (!cert || !certlen || !critical || !subject_alt_name || !subject_alt_name_len) {
		error_print();
		return -1;
	}
	*critical = -1;
	*subject_alt_name = NULL;
	*subject_alt_name_len = 0;

	if ((has_exts = x509_cert_get_exts(cert, certlen, &exts, &extslen)) < 0) {
		error_print();
		return -1;
	}
	if (!has_exts) {
		return 0;
	}
	if ((has_subject_alt_name = x509_exts_get_ext_by_oid(exts, extslen,
		OID_ce_subject_alt_name, critical, subject_alt_name, subject_alt_name_len)) < 0) {
		error_print();
		return -1;
	}
	return has_subject_alt_name;
}

// TLCP 双证书的名字和算法要求严格匹配，不做 normalized 匹配。
int x509_tlcp_cert_pair_entity_match(const uint8_t *sign_cert, size_t sign_certlen,
	const uint8_t *kenc_cert, size_t kenc_certlen)
{
	int sign_has_subject_alt_name;
	int kenc_has_subject_alt_name;
	const uint8_t *sign_subject;
	size_t sign_subject_len;
	const uint8_t *kenc_subject;
	size_t kenc_subject_len;
	const uint8_t *sign_subject_alt_name;
	size_t sign_subject_alt_name_len;
	int sign_subject_alt_name_critical;
	const uint8_t *kenc_subject_alt_name;
	size_t kenc_subject_alt_name_len;
	int kenc_subject_alt_name_critical;
	const uint8_t *sign_issuer;
	size_t sign_issuer_len;
	const uint8_t *kenc_issuer;
	size_t kenc_issuer_len;
	X509_KEY sign_public_key;
	X509_KEY kenc_public_key;
	int sign_signature_algor;
	int kenc_signature_algor;
	int match = 0;

	if (!sign_cert || !sign_certlen || !kenc_cert || !kenc_certlen) {
		error_print();
		return -1;
	}

	if (x509_cert_get_subject(sign_cert, sign_certlen, &sign_subject, &sign_subject_len) != 1
		|| x509_cert_get_subject(kenc_cert, kenc_certlen, &kenc_subject, &kenc_subject_len) != 1) {
		error_print();
		return -1;
	}
	if (sign_subject_len != kenc_subject_len) {
		return 0;
	}
	if (sign_subject_len && memcmp(sign_subject, kenc_subject, sign_subject_len) != 0) {
		return 0;
	}

	if ((sign_has_subject_alt_name = x509_cert_get_subject_alt_name_der(sign_cert, sign_certlen,
		&sign_subject_alt_name_critical,
		&sign_subject_alt_name, &sign_subject_alt_name_len)) < 0) {
		error_print();
		return -1;
	}
	if ((kenc_has_subject_alt_name = x509_cert_get_subject_alt_name_der(kenc_cert, kenc_certlen,
		&kenc_subject_alt_name_critical,
		&kenc_subject_alt_name, &kenc_subject_alt_name_len)) < 0) {
		error_print();
		return -1;
	}
	if (sign_has_subject_alt_name != kenc_has_subject_alt_name) {
		return 0;
	}
	if (sign_has_subject_alt_name) {
		if (sign_subject_alt_name_critical != kenc_subject_alt_name_critical) {
			return 0;
		}
		if (sign_subject_alt_name_len != kenc_subject_alt_name_len) {
			return 0;
		}
		if (sign_subject_alt_name_len
			&& memcmp(sign_subject_alt_name, kenc_subject_alt_name,
				sign_subject_alt_name_len) != 0) {
			return 0;
		}
	}

	if (x509_cert_get_issuer(sign_cert, sign_certlen, &sign_issuer, &sign_issuer_len) != 1
		|| x509_cert_get_issuer(kenc_cert, kenc_certlen, &kenc_issuer, &kenc_issuer_len) != 1) {
		error_print();
		return -1;
	}
	if (sign_issuer_len != kenc_issuer_len) {
		return 0;
	}
	if (sign_issuer_len && memcmp(sign_issuer, kenc_issuer, sign_issuer_len) != 0) {
		return 0;
	}

	if (x509_cert_get_subject_public_key(sign_cert, sign_certlen, &sign_public_key) != 1
		|| x509_cert_get_subject_public_key(kenc_cert, kenc_certlen, &kenc_public_key) != 1) {
		error_print();
		return -1;
	}
	if (sign_public_key.algor != kenc_public_key.algor
		|| sign_public_key.algor_param != kenc_public_key.algor_param) {
		return 0;
	}

	if (x509_cert_get_signature_algor(sign_cert, sign_certlen, &sign_signature_algor) != 1
		|| x509_cert_get_signature_algor(kenc_cert, kenc_certlen, &kenc_signature_algor) != 1) {
		error_print();
		return -1;
	}
	if (sign_signature_algor != kenc_signature_algor) {
		return 0;
	}

	match = 1;
	return match;
}

int x509_cert_is_revoked_by_crl(const uint8_t *cert, size_t certlen,
	const uint8_t *crl, size_t crl_len)
{
	const uint8_t *issuer;
	size_t issuer_len;
	const uint8_t *serial;
	size_t serial_len;
	const uint8_t *crl_issuer;
	size_t crl_issuer_len;
	time_t revoke_date;
	const uint8_t *crl_entry_exts;
	size_t crl_entry_exts_len;
	int ret;

	if (!cert || !certlen || !crl || !crl_len) {
		error_print();
		return -1;
	}
	if (x509_cert_get_issuer_and_serial_number(cert, certlen,
			&issuer, &issuer_len, &serial, &serial_len) != 1
		|| x509_crl_get_issuer(crl, crl_len, &crl_issuer, &crl_issuer_len) != 1) {
		error_print();
		return -1;
	}
	if ((ret = x509_name_equ(issuer, issuer_len, crl_issuer, crl_issuer_len)) != 1) {
		if (ret < 0) error_print();
		else error_print();
		return -1;
	}
	if (x509_crl_check(crl, crl_len, time(NULL)) != 1) {
		error_print();
		return -1;
	}
	if ((ret = x509_crl_find_revoked_cert_by_serial_number(crl, crl_len,
			serial, serial_len, &revoke_date,
			&crl_entry_exts, &crl_entry_exts_len)) < 0) {
		error_print();
		return -1;
	}
	return ret;
}

int x509_cert_verify_by_ocsp_response(const uint8_t *cert, size_t certlen,
	const uint8_t *issuer_cert, size_t issuer_certlen,
	const uint8_t *ocsp, size_t ocsp_len)
{
	uint8_t req[OCSP_MAX_REQUEST_SIZE];
	size_t reqlen;
	OCSP_SIGN_CTX ctx;
	const uint8_t *signer_cert;
	size_t signer_certlen;
	int signer_is_issuer;
	int reason;
	int ret;

	if (!cert || !certlen || !issuer_cert || !issuer_certlen || !ocsp || !ocsp_len) {
		error_print();
		return -1;
	}
	if (ocsp_request_generate(req, &reqlen, sizeof(req),
			cert, certlen, issuer_cert, issuer_certlen, DIGEST_sm3()) != 1
		|| ocsp_verify_init(&ctx, req, reqlen, issuer_cert, issuer_certlen) != 1) {
		error_print();
		return -1;
	}
	if ((ret = ocsp_response_get_signer_cert(ocsp, ocsp_len,
			issuer_cert, issuer_certlen, &signer_cert, &signer_certlen)) < 0) {
		error_print();
		return 0;
	}
	if (ret == 0) {
		return 0;
	}

	signer_is_issuer = (signer_certlen == issuer_certlen
		&& memcmp(signer_cert, issuer_cert, issuer_certlen) == 0);
	if (!signer_is_issuer) {
		if (x509_cert_verify_by_ca_cert(signer_cert, signer_certlen,
				issuer_cert, issuer_certlen,
				SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1) {
			error_print();
			return 0;
		}
		if (x509_cert_check(signer_cert, signer_certlen, X509_cert_ocsp_signing) != 1) {
			error_print();
			return 0;
		}
	}

	ret = ocsp_verify(&ctx, ocsp, ocsp_len,
		signer_cert, signer_certlen,
		NULL, 0, &reason);
	if (ret != 1) {
		return 0;
	}
	return 1;
}
