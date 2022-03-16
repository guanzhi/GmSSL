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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/oid.h>
#include <gmssl/x509_alg.h>
#include <gmssl/x509_oid.h>
#include <gmssl/x509_str.h>
#include <gmssl/x509_ext.h>
#include <gmssl/x509.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>



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
	return 0;
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
	return 0;
}

static int test_x509_general_name(void)
{

	uint8_t gns[512];
	size_t gnslen = 0;

	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	const uint8_t *d;
	size_t dlen;

	if (x509_general_names_add_general_name(gns, &gnslen, sizeof(gns), X509_gn_rfc822_name, (uint8_t *)"guan@pku.edu.cn", 15) != 1
		|| format_bytes(stderr, 0, 0, "", gns, gnslen) > 2
		|| x509_general_names_add_general_name(gns, &gnslen, sizeof(gns), X509_gn_dns_name, (uint8_t *)"www.pku.edu.cn", 14) != 1
		|| format_bytes(stderr, 0, 0, "", gns, gnslen) > 2
		|| x509_general_names_add_general_name(gns, &gnslen, sizeof(gns), X509_gn_uniform_resource_identifier, (uint8_t *)"http://localhost", 14) != 1
		|| format_bytes(stderr, 0, 0, "", gns, gnslen) > 2
		|| x509_general_names_add_general_name(gns, &gnslen, sizeof(gns), X509_gn_ip_address, (uint8_t *)"10.0.0.1", 8) != 1
		|| format_bytes(stderr, 0, 0, "", gns, gnslen) > 2
		|| x509_general_names_to_der(gns, gnslen, &p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	x509_general_names_print(stderr, 0, 0, "GeneralNames", d, dlen);

	printf("%s() ok\n", __FUNCTION__);
	return 0;
}

static int test_x509_authority_key_identifier(void)
{
	return 0;
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
	return 0;
}

static int test_x509_notice_reference(void)
{
	int notice_nums[] = { 1,2,3,4,5 };

	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	const uint8_t *d;
	size_t dlen;

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
	return 0;
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
		if (x509_revoke_reasons_to_der(tests[i], &p, &len) != 1) {
			error_print();
			return -1;
		}
		format_bytes(stderr, 0, 4, "", buf, len);
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (x509_revoke_reasons_from_der(&bits, &cp, &len) != 1
			|| asn1_check(bits == tests[i]) != 1) {
			error_print();
			return -1;
		}
		x509_revoke_reasons_print(stderr, 0, 4, "ReasonFlags", bits);
	}
	(void)asn1_length_is_zero(len);

	printf("%s() ok\n", __FUNCTION__);
	return 0;
}





int main(int argc, char **argv)
{
	int err = 0;
	err += test_x509_other_name();
	err += test_x509_edi_party_name();
	err += test_x509_general_name();
	err += test_x509_key_usage();
	err += test_x509_notice_reference();
	err += test_x509_revoke_reasons();
	return err;
}
