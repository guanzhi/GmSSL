/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/oid.h>
#include <gmssl/x509_alg.h>
#include <gmssl/x509_ext.h>
#include <gmssl/x509.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>

#define cnt(nodes) (sizeof(nodes)/sizeof(int))

static int test_x509_other_name(void)
{
	const uint32_t oid[] = { 1,3,5 };
	const uint8_t value[] = { 0x30,0x01,0x00 };
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	const uint8_t *d;
	size_t dlen;

	uint32_t nodes[32];
	size_t nodes_cnt;
	const uint8_t *val;
	size_t vlen;

	if (x509_other_name_to_der(oid, sizeof(oid)/sizeof(int), value, sizeof(value), &p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	x509_other_name_print(stderr, 0, 0, "OtherName", d, dlen);

	p = buf;
	cp = buf;
	len = 0;

	if (x509_other_name_to_der(oid, sizeof(oid)/sizeof(int), value, sizeof(value), &p, &len) != 1
		|| x509_other_name_from_der(nodes, &nodes_cnt, &val, &vlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	asn1_object_identifier_print(stderr, 0, 4, "type-id", NULL, nodes, nodes_cnt);
	format_bytes(stderr, 0, 4, "value", val, vlen);
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_edi_party_name(void)
{
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	const uint8_t *d;
	size_t dlen;

	int assigner_tag;
	const uint8_t *assigner;
	size_t assigner_len;
	int party_name_tag;
	const uint8_t *party_name;
	size_t party_name_len;

	if (x509_edi_party_name_to_der(
			ASN1_TAG_PrintableString, (uint8_t *)"Hello", 5,
			ASN1_TAG_PrintableString, (uint8_t *)"World", 5,
			&p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	x509_edi_party_name_print(stderr, 0, 0, "EDIPartyName", d, dlen);

	p = buf;
	cp = buf;
	len = 0;

	if (x509_edi_party_name_to_der(
			ASN1_TAG_PrintableString, (uint8_t *)"Hello", 5,
			ASN1_TAG_PrintableString, (uint8_t *)"World", 5,
			&p, &len) != 1
		|| x509_edi_party_name_from_der(
			&assigner_tag, &assigner, &assigner_len,
			&party_name_tag, &party_name, &party_name_len,
			&cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	x509_directory_name_print(stderr, 0, 4, "nameAssigner", assigner_tag, assigner, assigner_len);
	x509_directory_name_print(stderr, 0, 4, "partyName", party_name_tag,  party_name, party_name_len);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_general_name(void)
{
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	const uint8_t *d;
	size_t dlen;

	uint8_t gns[512];
	size_t gnslen;
	uint32_t other_id[] = { 1,3,5,7 };
	uint8_t value[] = { ASN1_TAG_OCTET_STRING, 0x02, 0x05, 0x05 };
	uint8_t x400[] = { ASN1_TAG_SEQUENCE, 0x00 };
	uint8_t name[512];
	size_t namelen;
	uint32_t reg_id[] = { 2,4,6,8 };

	if (x509_name_set(name, &namelen, sizeof(name),
		"CN", "Beijing", "Haidian", "PKU", "CS", "CA") != 1) {
		error_print();
		return -1;
	}
	gnslen = 0;
	if (0
		|| x509_general_names_add_other_name(gns, &gnslen, sizeof(gns), other_id, cnt(other_id), value, sizeof(value)) != 1
		|| x509_general_names_add_rfc822_name(gns, &gnslen, sizeof(gns), "guan@pku.edu.cn") != 1
		|| x509_general_names_add_dns_name(gns, &gnslen, sizeof(gns), "www.pku.edu.cn") != 1
		|| x509_general_names_add_x400_address(gns, &gnslen, sizeof(gns), x400, sizeof(x400)) != 1
		|| x509_general_names_add_directory_name(gns, &gnslen, sizeof(gns), name, namelen) != 1
		|| x509_general_names_add_edi_party_name(gns, &gnslen, sizeof(gns),
			ASN1_TAG_PrintableString, (uint8_t *)"Assigner", strlen("Assigner"),
			ASN1_TAG_PrintableString, (uint8_t *)"PartyName", strlen("PartyName")) != 1
		|| x509_general_names_add_uniform_resource_identifier(gns, &gnslen, sizeof(gns), "http://localhost") != 1
		|| x509_general_names_add_ip_address(gns, &gnslen, sizeof(gns), "127.0.0.1") != 1
		|| x509_general_names_add_registered_id(gns, &gnslen, sizeof(gns), reg_id, cnt(reg_id)) != 1
		|| x509_general_names_to_der(gns, gnslen, &p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	x509_general_names_print(stderr, 0, 0, "GeneralNames", d, dlen);
	{
		size_t i;
		printf("uint8_t general_names[%zu] = {", dlen);
		for (i = 0; i < dlen; i++) {
			if (i % 16 == 0) {
				printf("\n\t");
			}
			printf("0x%02x,", d[i]);
		}
		printf("\n};\n");
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

uint8_t general_names[202] = {
	0x80,0x0b,0x06,0x03,0x2b,0x05,0x07,0xa0,0x04,0x04,0x02,0x05,0x05,0x81,0x0f,0x67,
	0x75,0x61,0x6e,0x40,0x70,0x6b,0x75,0x2e,0x65,0x64,0x75,0x2e,0x63,0x6e,0x82,0x0e,
	0x77,0x77,0x77,0x2e,0x70,0x6b,0x75,0x2e,0x65,0x64,0x75,0x2e,0x63,0x6e,0x83,0x02,
	0x30,0x00,0x84,0x59,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x06,0x13,0x02,0x43,
	0x4e,0x31,0x10,0x30,0x0e,0x06,0x03,0x55,0x04,0x08,0x13,0x07,0x42,0x65,0x69,0x6a,
	0x69,0x6e,0x67,0x31,0x10,0x30,0x0e,0x06,0x03,0x55,0x04,0x07,0x13,0x07,0x48,0x61,
	0x69,0x64,0x69,0x61,0x6e,0x31,0x0c,0x30,0x0a,0x06,0x03,0x55,0x04,0x0a,0x13,0x03,
	0x50,0x4b,0x55,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x0b,0x13,0x02,0x43,0x53,
	0x31,0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x03,0x13,0x02,0x43,0x41,0x85,0x19,0xa0,
	0x0a,0x13,0x08,0x41,0x73,0x73,0x69,0x67,0x6e,0x65,0x72,0xa1,0x0b,0x13,0x09,0x50,
	0x61,0x72,0x74,0x79,0x4e,0x61,0x6d,0x65,0x86,0x10,0x68,0x74,0x74,0x70,0x3a,0x2f,
	0x2f,0x6c,0x6f,0x63,0x61,0x6c,0x68,0x6f,0x73,0x74,0x87,0x09,0x31,0x32,0x37,0x2e,
	0x30,0x2e,0x30,0x2e,0x31,0x88,0x03,0x54,0x06,0x08,
};

static int test_x509_authority_key_identifier(void)
{
	uint8_t buf[512];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	const uint8_t *d;
	size_t dlen;

	uint8_t keyid[32];
	uint8_t serial[20];

	const uint8_t *keyidp;
	size_t keyidlen;
	const uint8_t *issuerp;
	size_t issuerlen;
	const uint8_t *serialp;
	size_t seriallen;

	sm3_digest((uint8_t *)"abc", 3, keyid);
	rand_bytes(serial, sizeof(serial));

	if (x509_authority_key_identifier_to_der(
			keyid, sizeof(keyid),
			general_names, sizeof(general_names),
			serial, sizeof(serial),
			&p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	x509_authority_key_identifier_print(stderr, 0, 0, "AuthorityKeyIdentifier", d, dlen);

	p = buf;
	cp = buf;
	len = 0;
	if (x509_authority_key_identifier_to_der(
			keyid, sizeof(keyid),
			general_names, sizeof(general_names),
			serial, sizeof(serial),
			&p, &len) != 1
		|| x509_authority_key_identifier_from_der(
			&keyidp, &keyidlen,
			&issuerp, &issuerlen,
			&serialp, &seriallen,
			&cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_key_usage(void)
{
	int tests[] = {
		0,
		1,
		2,
		X509_KU_NON_REPUDIATION|X509_KU_CRL_SIGN,
		7,
		8,
		X509_KU_DIGITAL_SIGNATURE|X509_KU_NON_REPUDIATION|X509_KU_DECIPHER_ONLY,
		0x1ff,
	//	0x3ff, // this should return error
	};

	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	int usage;
	int i;

	for (i = 0; i <= 8; i++) {
		format_print(stderr, 0, 4, "%d %s\n", i, x509_key_usage_name(1 << i));
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (x509_key_usage_to_der(tests[i], &p, &len) != 1) {
			error_print();
			return -1;
		}
		format_bytes(stderr, 0, 4, "", buf, len);
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (x509_key_usage_from_der(&usage, &cp, &len) != 1
			|| asn1_check(usage == tests[i]) != 1) {
			error_print();
			return -1;
		}
		x509_key_usage_print(stderr, 0, 4, "KeyUsage", usage);
	}
	(void)asn1_length_is_zero(len);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_notice_reference(void)
{
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	const uint8_t *d;
	size_t dlen;

	int notice_nums[] = { 1,2,3,4,5 };

	int org_tag;
	const uint8_t *org;
	size_t orglen;
	int nums[32];
	size_t nums_cnt;

	if (x509_notice_reference_to_der(
			ASN1_TAG_IA5String, (uint8_t *)"Hello", 5,
			notice_nums, sizeof(notice_nums)/sizeof(notice_nums[0]),
			&p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	x509_notice_reference_print(stderr, 0, 0, "NoticeReference", d, dlen);

	p = buf;
	cp = buf;
	len = 0;

	if (x509_notice_reference_to_der(
			ASN1_TAG_IA5String, (uint8_t *)"Hello", 5,
			notice_nums, sizeof(notice_nums)/sizeof(notice_nums[0]),
			&p, &len) != 1
		|| x509_notice_reference_from_der(
			&org_tag, &org, &orglen,
			nums, &nums_cnt, sizeof(nums)/sizeof(nums[0]),
			&cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_user_notice(void)
{
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	const uint8_t *d;
	size_t dlen;

	int notice_nums[] = { 1,2,3,4,5 };

	int org_tag;
	const uint8_t *org;
	size_t orglen;
	int nums[32];
	size_t nums_cnt;
	int text_tag;
	const uint8_t *text;
	size_t textlen;

	if (x509_user_notice_to_der(
			ASN1_TAG_IA5String, (uint8_t *)"Hello", 5,
			notice_nums, sizeof(notice_nums)/sizeof(notice_nums[0]),
			ASN1_TAG_IA5String, (uint8_t *)"World", 5,
			&p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	x509_user_notice_print(stderr, 0, 0, "UserNotice", d, dlen);

	p = buf;
	cp = buf;
	len = 0;

	if (x509_user_notice_to_der(
			ASN1_TAG_IA5String, (uint8_t *)"Hello", 5,
			notice_nums, sizeof(notice_nums)/sizeof(notice_nums[0]),
			ASN1_TAG_IA5String, (uint8_t *)"World", 5,
			&p, &len) != 1
		|| x509_user_notice_from_der(
			&org_tag, &org, &orglen,
			nums, &nums_cnt, sizeof(nums)/sizeof(nums[0]),
			&text_tag, &text, &textlen,
			&cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_policy_qualifier_info(void)
{
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	const uint8_t *d;
	size_t dlen;


	if (x509_policy_qualifier_info_to_der(
			OID_qt_cps,
			(uint8_t *)"Qualifier", strlen("Qualifier"),
			&p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	x509_policy_qualifier_info_print(stderr, 0, 0, "PolicyQualifierInfo", d, dlen);


	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_policy_mapping(void)
{
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	const uint8_t *d;
	size_t dlen;

	int issuer_policy_oid;
	uint32_t issuer_policy_nodes[32];
	size_t issuer_policy_nodes_cnt;
	int subject_policy_oid;
	uint32_t subject_policy_nodes[32];
	size_t subject_policy_nodes_cnt;

	if (x509_policy_mapping_to_der(
			OID_any_policy, NULL, 0,
			OID_any_policy, NULL, 0,
			&p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	x509_policy_mapping_print(stderr, 0, 0, "PolicyMapping", d, dlen);

	p = buf;
	cp = buf;
	len = 0;

	if (x509_policy_mapping_to_der(
			OID_any_policy, NULL, 0,
			OID_any_policy, NULL, 0,
			&p, &len) != 1
		|| x509_policy_mapping_from_der(
			&issuer_policy_oid, issuer_policy_nodes, &issuer_policy_nodes_cnt,
			&subject_policy_oid, subject_policy_nodes, &subject_policy_nodes_cnt,
			&cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

// 这里的一些OID应该在RFC中有，但是我们不实现
static int test_x509_attribute(void)
{
	// TODO
	return 1;
}

static int test_x509_basic_constraints(void)
{
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	const uint8_t *d;
	size_t dlen;

	int ca;
	int path;

	if (x509_basic_constraints_to_der(1, 4, &p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	x509_basic_constraints_print(stderr, 0, 0, "BasicConstraints", d, dlen);

	cp = p = buf; len = 0;
	if (x509_basic_constraints_to_der(-1, 4, &p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	x509_basic_constraints_print(stderr, 0, 0, "BasicConstraints", d, dlen);


	cp = p = buf; len = 0;
	if (x509_basic_constraints_to_der(-1, -1, &p, &len) != -1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 0 // empty sequence is not allowed
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	x509_basic_constraints_print(stderr, 0, 0, "BasicConstraints", d, dlen);

	cp = p = buf; len = 0;
	if (x509_basic_constraints_to_der(1, 4, &p, &len) != 1
		|| x509_basic_constraints_from_der(&ca, &path, &cp, &len) != 1
		|| asn1_check(ca == 1) != 1
		|| asn1_check(path == 4) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}

	cp = p = buf; len = 0;
	if (x509_basic_constraints_to_der(-1, 4, &p, &len) != 1
		|| x509_basic_constraints_from_der(&ca, &path, &cp, &len) != 1
		|| asn1_check(ca == -1) != 1
		|| asn1_check(path == 4) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}

	cp = p = buf; len = 0;
	if (x509_basic_constraints_to_der(-1, -1, &p, &len) != -1 // should return error
		|| x509_basic_constraints_from_der(&ca, &path, &cp, &len) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_general_subtree(void)
{
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	const uint8_t *d;
	size_t dlen;

	uint8_t *dns = (uint8_t *)"www.pku.edu.cn";
	size_t dnslen = strlen((char *)dns);

	int choice;
	const uint8_t *dns_name;
	size_t dns_name_len;
	int min_dis;
	int max_dis;

	if (x509_general_subtree_to_der(X509_gn_dns_name, dns, dnslen, 1, 5, &p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	x509_general_subtree_print(stderr, 0, 0, "GeneralSubtree", d, dlen);

	cp = p = buf; len = 0;
	min_dis = max_dis = 99;
	if (x509_general_subtree_to_der(X509_gn_dns_name, dns, dnslen, -1, 5, &p, &len) != 1
		|| x509_general_subtree_from_der(&choice, &dns_name, &dns_name_len, &min_dis, &max_dis, &cp, &len) != 1
		|| asn1_check(choice == X509_gn_dns_name) != 1
		|| asn1_check(dns_name_len == dnslen && memcmp(dns_name, dns, dnslen) == 0) != 1
		|| asn1_check(min_dis == 0) != 1
		|| asn1_check(max_dis == 5) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}

	cp = p = buf; len = 0;
	min_dis = max_dis = 99;
	if (x509_general_subtree_to_der(X509_gn_dns_name, dns, dnslen, 1, -1, &p, &len) != 1
		|| x509_general_subtree_from_der(&choice, &dns_name, &dns_name_len, &min_dis, &max_dis, &cp, &len) != 1
		|| asn1_check(choice == X509_gn_dns_name) != 1
		|| asn1_check(dns_name_len == dnslen && memcmp(dns_name, dns, dnslen) == 0) != 1
		|| asn1_check(min_dis == 1) != 1
		|| asn1_check(max_dis == -1) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_policy_constraints(void)
{
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	const uint8_t *d;
	size_t dlen;

	int val1;
	int val2;

	if (x509_policy_constraints_to_der(2, 5, &p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	x509_policy_constraints_print(stderr, 0, 0, "PolicyConstraints", d, dlen);

	cp = p = buf; len = 0;
	if (x509_policy_constraints_to_der(2, -1, &p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	x509_policy_constraints_print(stderr, 0, 0, "PolicyConstraints", d, dlen);

	cp = p = buf; len = 0;
	if (x509_policy_constraints_to_der(-1, 5, &p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	x509_policy_constraints_print(stderr, 0, 0, "PolicyConstraints", d, dlen);

	cp = p = buf; len = 0;
	val1 = val2 = 99;
	if (x509_policy_constraints_to_der(2, 5, &p, &len) != 1
		|| x509_policy_constraints_from_der(&val1, &val2, &cp, &len) != 1
		|| asn1_check(val1 == 2) != 1
		|| asn1_check(val2 == 5) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}

	cp = p = buf; len = 0;
	val1 = val2 = 99;
	if (x509_policy_constraints_to_der(-1, -1, &p, &len) != -1
		|| x509_policy_constraints_from_der(&val1, &val2, &cp, &len) != 0 // empty sequence is not allowed
		|| asn1_check(val1 == -1) != 1
		|| asn1_check(val2 == -1) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_ext_key_usage(void)
{
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	const uint8_t *d;
	size_t dlen;

	int kp[] = {
		OID_kp_server_auth,
		OID_kp_client_auth,
		OID_kp_code_signing,
		OID_kp_email_protection,
		OID_kp_time_stamping,
		OID_kp_ocsp_signing,
	};
	int oids[16]  = {0};
	size_t oids_cnt;

	if (x509_ext_key_usage_to_der(kp, sizeof(kp)/sizeof(int), &p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	x509_ext_key_usage_print(stderr, 0, 0, "ExtKeyUsageSyntax", d, dlen);

	if (x509_ext_key_usage_to_der(kp, sizeof(kp)/sizeof(int), &p, &len) != 1
		|| x509_ext_key_usage_from_der(oids, &oids_cnt, sizeof(oids)/sizeof(oids[0]), &cp, &len) != 1
		|| asn1_check(oids_cnt == sizeof(kp)/sizeof(int)) != 1
		|| asn1_check(memcmp(oids, kp, sizeof(kp)) == 0) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_revoke_reasons(void)
{
	int tests[] = {
		0,
		1,
		2,
		X509_RF_SUPERSEDED|X509_RF_PRIVILEGE_WITHDRAWN|X509_RF_AA_COMPROMISE,
		0x1ff,
	};
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	int bits;
	int i;

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (x509_revoke_reason_flags_to_der(tests[i], &p, &len) != 1) {
			error_print();
			return -1;
		}
		format_bytes(stderr, 0, 4, "", buf, len);
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (x509_revoke_reason_flags_from_der(&bits, &cp, &len) != 1
			|| asn1_check(bits == tests[i]) != 1) {
			error_print();
			return -1;
		}
		x509_revoke_reason_flags_print(stderr, 0, 4, "ReasonFlags", bits);
	}
	(void)asn1_length_is_zero(len);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_exts(void)
{
	uint8_t buf[1024];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	const uint8_t *d;
	size_t dlen;

	uint8_t exts[512];
	size_t extslen = 0;
	uint8_t keyid[32] = {1};
	uint8_t serial[20] = {2};

	if (0
		|| x509_exts_add_authority_key_identifier(exts, &extslen, sizeof(exts), 1,
			keyid, sizeof(keyid),
			general_names, sizeof(general_names),
			serial, sizeof(serial)) != 1
		|| x509_exts_add_subject_key_identifier(exts, &extslen, sizeof(exts), 0,
			keyid, sizeof(keyid)) != 1
		|| x509_exts_add_key_usage(exts, &extslen, sizeof(exts), 0,
			X509_KU_NON_REPUDIATION|X509_KU_CRL_SIGN) != 1
		|| x509_exts_to_der(exts, extslen, &p, &len) != 1
		|| x509_exts_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	x509_exts_print(stderr, 0, 0, "Extensions", d, dlen);


	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_x509_cert_with_exts(void)
{
	uint8_t cert[1024];
	size_t certlen = 0;
	uint8_t *p = cert;
	uint8_t serial[20];
	uint8_t name[256];
	size_t namelen;
	time_t not_before, not_after;
	SM2_KEY sm2_key;
	uint8_t uniq_id[32];
	uint8_t exts[512];
	size_t extslen = 0;
	uint8_t keyid[32] = {1};


	rand_bytes(serial, sizeof(serial));
	x509_name_set(name, &namelen, sizeof(name), "CN", "Beijing", "Haidian", "PKU", "CS", "CA");
	time(&not_before);
	x509_validity_add_days(&not_after, not_before, 365);
	sm2_key_generate(&sm2_key);
	sm3_digest((uint8_t *)&(sm2_key.public_key), sizeof(SM2_POINT), uniq_id);

	if (x509_exts_add_authority_key_identifier(exts, &extslen, sizeof(exts), 1,
			keyid, sizeof(keyid),
			general_names, sizeof(general_names),
			serial, sizeof(serial)) != 1
		|| x509_exts_add_subject_key_identifier(exts, &extslen, sizeof(exts), 0,
			keyid, sizeof(keyid)) != 1
		|| x509_exts_add_key_usage(exts, &extslen, sizeof(exts), 0,
			X509_KU_NON_REPUDIATION|X509_KU_CRL_SIGN) != 1) {
		error_print();
		return -1;
	}

	if (x509_cert_sign_to_der(
		X509_version_v3,
		serial, sizeof(serial),
		OID_sm2sign_with_sm3,
		name, namelen,
		not_before, not_after,
		name, namelen,
		&sm2_key,
		uniq_id, sizeof(uniq_id),
		uniq_id, sizeof(uniq_id),
		exts, extslen,
		&sm2_key,
		SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID),
		&p, &certlen) != 1) {
		error_print();
		return -1;
	}
	if (certlen > sizeof(cert)) {
		error_print();
		return -1;
	}

	x509_cert_print(stderr, 0, 0, "Certificate", cert, certlen);


	return 1;
}

static int test_x509_distribution_point_name(void)
{
	uint8_t buf[512];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;


	x509_general_name_to_der(X509_gn_uniform_resource_identifier, (uint8_t *)"http://", 7, &p, &len);

//	x509_uri_as_general_names_to_der_ex(0x80, "http://", 7, &p, &len);

	format_bytes(stderr, 0, 0, "GeneralNames", buf, len);

	return 1;
}



int main(int argc, char **argv)
{
	if (test_x509_other_name() != 1) goto err;
	if (test_x509_edi_party_name() != 1) goto err;
	if (test_x509_general_name() != 1) goto err;
	if (test_x509_authority_key_identifier() != 1) goto err;
	if (test_x509_key_usage() != 1) goto err;
	if (test_x509_notice_reference() != 1) goto err;
	if (test_x509_user_notice() != 1) goto err;
	if (test_x509_policy_qualifier_info() != 1) goto err;
	if (test_x509_policy_mapping() != 1) goto err;
	if (test_x509_basic_constraints() != 1) goto err;
	if (test_x509_general_subtree() != 1) goto err;
	if (test_x509_policy_constraints() != 1) goto err;
	if (test_x509_ext_key_usage() != 1) goto err;
	if (test_x509_revoke_reasons() != 1) goto err;
	if (test_x509_exts() != 1) goto err;
	if (test_x509_cert_with_exts() != 1) goto err;
	if (test_x509_distribution_point_name() != 1) goto err;

	printf("%s all tests passed!\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
