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
#include <stdint.h>
#include <gmssl/asn1.h>
#include <gmssl/endian.h>
#include <gmssl/oid.h>
#include <gmssl/x509_ext.h>
#include <gmssl/x509_cer.h>
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
	int key_sig_alg;
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

	// FIXME: 改为 x509_key_support_algor
	if (x509_key_get_sign_algor(key, &key_sig_alg) != 1) {
		error_print();
		return -1;
	}
	if (sig_alg != key_sig_alg) {
		return 0;
	}


	// X509_sign/verify 还是默认就使用SM2的默认ID吧
	if (key->algor == OID_ec_public_key && key->algor_param == OID_sm2) {
		sign_args = (uint8_t *)signer_id;
		sign_argslen = signer_id_len;
	}
	if (x509_verify_init(&verify_ctx, key, sign_args, sign_argslen, sig, siglen) != 1
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
	return x509_signed_is_verified_by_key(cert, certlen, &public_key, signer_id, signer_id_len);
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
