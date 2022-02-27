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


int x509_other_name_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	uint32_t nodes[32];
	size_t nodes_count;
	const uint8_t *value;
	size_t valuelen;

	format_print(fp, fmt, ind, "%s:\n", label);
	ind += 4;
	if (asn1_object_identifier_from_der(nodes, &nodes_count, &d, &dlen) != 1
		|| asn1_explicit_from_der(0, &value, &valuelen, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	asn1_oid_nodes_print(fp, fmt, ind, "type-id", "unknown", nodes, nodes_count);
	format_bytes(fp, fmt, ind, "value: ", value, valuelen);
	return 1;
}

int x509_edi_party_name_print(FILE *fp, int fmt, int ind, const char *label,const uint8_t *d, size_t dlen)
{
	const uint8_t *name_assigner;
	const uint8_t *party_name;
	size_t name_assigner_len, party_name_len;

	format_print(fp, fmt, ind, "%s:\n", label);
	ind += 4;
	if (asn1_explicit_from_der(0, &name_assigner, &name_assigner_len, &d, &dlen) < 0
		|| asn1_explicit_from_der(1, &party_name, &party_name_len, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	if (name_assigner) {
		if (x509_directory_string_print(fp, fmt, ind, "nameAssigner",
			name_assigner, name_assigner_len) != 1) {
			error_print();
			return -1;
		}
	}
	if (x509_directory_string_print(fp, fmt, ind, "partyName", party_name, party_name_len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_general_name_print(FILE *fp, int fmt, int ind, const char *label, int tag, const uint8_t *d, size_t dlen)
{
	if (label) {
		format_print(fp, fmt, ind, "%s\n", label);
		ind += 4;
	}
	switch (tag) {
	case ASN1_TAG_IMPLICIT(0): return x509_other_name_print(fp, fmt, ind, "otherName", d, dlen);
	case ASN1_TAG_IMPLICIT(1): return asn1_string_print(fp, fmt, ind, "rfc822Name", (char *)d, dlen);
	case ASN1_TAG_IMPLICIT(2): return asn1_string_print(fp, fmt, ind, "DNSName", (char *)d, dlen);
	case ASN1_TAG_IMPLICIT(3): return format_bytes(fp, fmt, ind, "x400Address", d, dlen);
	case ASN1_TAG_IMPLICIT(4): return x509_name_print(fp, fmt, ind, "directoryName", d, dlen);
	case ASN1_TAG_IMPLICIT(5): return x509_edi_party_name_print(fp, fmt, ind, "ediPartyName", d, dlen);
	case ASN1_TAG_IMPLICIT(6): return asn1_string_print(fp, fmt, ind, "URI", (char *)d, dlen);
	case ASN1_TAG_IMPLICIT(7): return format_bytes(fp, fmt, ind, "IPAddress", d, dlen);
	case ASN1_TAG_IMPLICIT(8): return asn1_object_identifier_print(fp, fmt, ind, "registeredID", d, dlen);
	default:
		error_print();
		return -1;
	}
	return 1;
}

int x509_general_names_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	while (dlen) {
		int tag;
		const uint8_t *p;
		size_t len;
		if (asn1_any_type_from_der(&tag, &p, &len, &d, &dlen) != 1
			|| x509_general_name_print(fp, fmt, ind, NULL, tag, p, len) != 1) {
			error_print();
			return -1;
		}
	}
	return 1;
}

int x509_key_usage_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int usage;
	if (asn1_bits_from_der(&usage, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, fmt, ind, "keyUsage:\n");
	ind += 4;

	if (usage & X509_KU_DIGITAL_SIGNATURE)
		format_print(fp, fmt, ind, "DigitalSignature\n");
	if (usage & X509_KU_NON_REPUDIATION)
		format_print(fp, fmt, ind, "NonRepudiation\n");
	if (usage & X509_KU_KEY_ENCIPHERMENT)
		format_print(fp, fmt, ind, "KeyEncipherment\n");
	if (usage & X509_KU_DATA_ENCIPHERMENT)
		format_print(fp, fmt, ind, "DataEncipherment\n");
	if (usage & X509_KU_KEY_AGREEMENT)
		format_print(fp, fmt, ind, "KeyAgreement\n");
	if (usage & X509_KU_KEY_CERT_SIGN)
		format_print(fp, fmt, ind, "KeyCertSign\n");
	if (usage & X509_KU_CRL_SIGN)
		format_print(fp, fmt, ind, "CRLSign\n");
	if (usage & X509_KU_ENCIPHER_ONLY)
		format_print(fp, fmt, ind, "EncipherOnly\n");
	if (usage & X509_KU_DECIPHER_ONLY)
		format_print(fp, fmt, ind, "DecipherOnly\n");


	return 1;
}

int x509_authority_key_identifier_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	const uint8_t *keyid, *issuer, *serial;
	size_t keyid_len, issuer_len, serial_len;

	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;

	if (asn1_implicit_octet_string_from_der(0, &keyid, &keyid_len, &d, &dlen) < 0
		|| asn1_implicit_sequence_from_der(1, &issuer, &issuer_len, &d, &dlen) < 0
		|| asn1_implicit_integer_from_der(2, &serial, &serial_len, &d, &dlen) < 0
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	if (keyid) {
		format_bytes(fp, fmt, ind, "keyIdentifier : ", keyid, keyid_len);
	}
	if (issuer) {
		x509_general_names_print(fp, fmt, ind, "authorityCertIssuer", issuer, issuer_len);
	}
	if (serial) {
		format_bytes(fp, fmt, ind, "authorityCertSerialNumber", serial, serial_len);
	}
	return 1;
}



int x509_policy_information_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	if (label) {
		format_print(fp, fmt, ind, "%s\n", label);
		ind += 4;
	}
	if (asn1_object_identifier_from_der(nodes, &nodes_cnt, &d, &dlen) != 1) goto err;
				

	return 1;
}

int x509_certificate_policies_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	if (label) {
		format_print(fp, fmt, ind, "%s\n", label);
		ind += 4;
	}
	while (dlen) {
		const uint8_t *p;
		size_t len;
		if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		if (x509_policy_information_print(fp, fmt, ind, "PolicyInformation", p, len) != 1) {
			error_print();
			return -1;
		}
	}
	return 1;
}

int x509_policy_mapping_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	return 1;
}

int x509_policy_mappings_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	if (label) {
		format_print(fp, fmt, ind, "%s\n", label);
		ind += 4;
	}
	while (dlen) {
		const uint8_t *p;
		size_t len;
		if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1
			|| x509_policy_mapping_print(fp, fmt, ind, "PolicyMapping", p, len) != 1) {
			error_print();
			return -1;
		}
	}
	return 1;
}

int x509_attribute_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	return 1;
}

int x509_attributes_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	if (label) {
		format_print(fp, fmt, ind, "%s\n", label);
		ind += 4;
	}
	while (dlen) {
		const uint8_t *p;
		size_t len;
		if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1
			|| x509_attribute_print(fp, fmt, ind, "Attribute", p, len) != 1) {
			error_print();
			return -1;
		}
	}
	return 1;
}

int x509_basic_constraints_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int ret;
	int val;

	if (label) {
		format_print(fp, fmt, ind, "%s\n", label);
		ind += 4;
	}

	if ((ret = asn1_boolean_from_der(&val, &d, &dlen)) < 0) goto err;
	else if (ret)
		format_print(fp, fmt, ind, "cA: %s\n", val ? "true" : "false");

	if ((ret = asn1_int_from_der(&val, &d, &dlen)) < 0) goto err;
	else if (ret)
		format_print(fp, fmt, ind, "pathLenConstraint: %d\n", val);

	return 1;
err:
	error_print();
	return -1;
}

int x509_general_subtree_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int ret;
	int val;
	const uint8_t *p;
	size_t len;

	if (label) {
		format_print(fp, fmt, ind, "%s\n", label);
		ind += 4;
	}
	if (asn1_any_type_from_der(&val, &p, &len, &d, &dlen) != 1) goto err;
	if (x509_general_name_print(fp, fmt, ind, "base", val, p, len) != 1) goto err;
	if ((ret = asn1_implicit_int_from_der(0, &val, &d, &dlen)) < 0) goto err;
	if (ret) format_print(fp, fmt, ind, "minimum: %d\n", val);
	if ((ret = asn1_implicit_int_from_der(0, &val, &d, &dlen)) < 0) goto err;
	if (ret) format_print(fp, fmt, ind, "maximum: %d\n", val);
	if (dlen) {
		format_bytes(fp, fmt, ind, "", d, dlen);
		goto err;
	}
	return 1;
err:
	error_print();
	return -1;
}

int x509_general_subtrees_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	if (label) {
		format_print(fp, fmt, ind, "%s\n", label);
		ind += 4;
	}
	while (dlen) {
		const uint8_t *p;
		size_t len;

		if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1
			|| x509_general_subtree_print(fp, fmt, ind, "GeneralSubtree", p, len) != 1) {
			error_print();
			return -1;
		}
	}
	return 1;
}

int x509_name_constraints_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int ret;
	const uint8_t *p;
	size_t len;

	if (label) {
		format_print(fp, fmt, ind, "%s\n", label);
		ind += 4;
	}

	if ((ret = asn1_sequence_from_der(&p, &len, &d, &dlen)) < 0) goto err;
	if (ret) {
		x509_general_subtrees_print(fp, fmt, ind, "permittedSubtrees", p, len);
	}

	if ((ret = asn1_sequence_from_der(&p, &len, &d, &dlen)) < 0) goto err;
	if (ret) {
		x509_general_subtrees_print(fp, fmt, ind, "excludedSubtrees", p, len);
	}
	if (dlen) {
	}

	return 1;
err:
	error_print();
	return -1;
}

int x509_policy_constraints_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int ret;
	int val;

	if (label) {
		format_print(fp, fmt, ind, "%s\n", label);
		ind += 4;
	}

	if ((ret = asn1_implicit_int_from_der(0, &val, &d, &dlen)) < 0) goto err;
	if (ret) format_print(fp, fmt, ind, "requireExplicitPolicy: %d\n", val);
	if ((ret = asn1_implicit_int_from_der(0, &val, &d, &dlen)) < 0) goto err;
	if (ret) format_print(fp, fmt, ind, "inhibitPolicyMapping: %d\n", val);
	if (dlen) {
		format_bytes(fp, fmt, ind, "", d, dlen);
		goto err;
	}
	return 1;
err:
	error_print();
	return -1;
}

int x509_ext_key_usage_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	if (label) {
		format_print(fp, fmt, ind, "%s\n", label);
		ind += 4;
	}
	while (dlen) {
		int oid;
		if (x509_key_purpose_from_der(&oid, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		format_print(fp, fmt, ind, "%s\n", x509_key_purpose_name(oid));
	}
	return 1;
}

int x509_distribution_point_name_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	return -1;
}

int x509_reason_flags_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	return -1;
}

int x509_distribution_point_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	int ret;
	int val;
	const uint8_t *p;
	size_t len;

	if (label) {
		format_print(fp, fmt, ind, "%s\n", label);
		ind += 4;
	}
	if ((ret = asn1_explicit_from_der(0, &p, &len, &d, &dlen)) < 0) goto err;
	if (ret) {
		if (x509_distribution_point_name_print(fp, fmt, ind, "distributionPoint", p, len) != 1) {
			error_print();
			return -1;
		}
	}

	if ((ret = asn1_implicit_bits_from_der(1, &val, &d, &dlen)) < 0) goto err;
	if (ret) {
		x509_reason_flags_print(fp, fmt, ind, "reasons", p, len);
	}

	if ((ret = asn1_implicit_sequence_from_der(2, &p, &len, &d, &dlen)) < 0) goto err;
	if (ret) {
		x509_general_names_print(fp, fmt, ind, "cRLIssuer", p, len);
	}
	if (dlen) {
		format_bytes(fp, fmt, ind, "", d, dlen);
		goto err;
	}
	return 1;

err:
	error_print();
	return -1;
}

int x509_crl_distribution_points_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen)
{
	if (label) {
		format_print(fp, fmt, ind, "%s\n", label);
		ind += 4;
	}
	while (dlen) {
		const uint8_t *p;
		size_t len;
		if (asn1_sequence_from_der(&p, &len, &d, &dlen) != 1) {
			error_print();
			return -1;
		}
		if (x509_distribution_point_print(fp, fmt, ind, "DistributionPoint", p, len) != 1) {
			error_print();
			return -1;
		}
	}
	return 1;
}


int x509_directory_string_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *a, size_t alen)
{
	if (label) {
		format_print(fp, fmt, ind, "%s\n", label);
		ind += 4;
	}
	return -1;
}
