/*
 * Copyright (c) 2021 - 2021 The GmSSL Project.  All rights reserved.
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
#include <gmssl/crl.h>


const char *crl_reason_text(int reason)
{
	switch (reason) {
	case X509_cr_unspecified: return "unspecified";
	case X509_cr_key_compromise: return "keyCompromise";
	case X509_cr_ca_compromise: return "cACompromise";
	case X509_cr_affiliation_changed: return "affiliationChanged";
	case X509_cr_superseded: return "superseded";
	case X509_cr_cessation_of_operation: return "cessationOfOperation";
	case X509_cr_certificate_hold: return "certificateHold";
	case X509_cr_remove_from_crl: return "removeFromCRL";
	case X509_cr_privilege_withdrawn: return "privilegeWithdrawn";
	case X509_cr_aa_compromise: return "aACompromise";
	}
	return NULL;
}

 84 typedef struct {
 85         uint8_t serial_number[20];
 86         size_t serial_number_len;
 87         time_t revoke_date;
 88         CRL_EXTENSIONS crlEntryExtensions;
 89 } CRL_REVOKED_CERT;


int crl_revoked_cert_to_der(const CRL_REVOKED_CERT *a, uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (asn1_integer_to_der(a->serial_number, a->serial_number_len, NULL, &len) != 1
		|| x509_time_to_der(a->revoke_date, NULL, &len) != 1
		|| x509_extension_to_der(a->exts, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_integer_to_der(a->serial_number, a->serial_number_len, out, outlen) != 1
		|| x509_time_to_der(a->revoke_date, out, outlen) != 1
		|| x509_extension_to_der(a->exts, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int crl_revoked_cert_from_der(CRL_REVOKED_CERT *a, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_integer_from_der(a->serial_number, &a->serial_number_len, &data, &datalen) != 1
		|| x509_time_from_der(&a->revoke_date, &data, &datalen) != 1
		|| x509_extensions_from_der(&a->exts, &data, &datalen) != 1
		|| datalen) {
		error_print();
		return -1;
	}
	return 1;
}

int crl_revoked_cert_print(FILE *fp, const CRL_REVOKED_CERT *a, int format, int indent)
{

	return 1;
}

int crl_tbs_cert_list_to_der(const CRL_TBS_CERT_LIST *a, uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (asn1_int_to_der(a->version, NULL, &len) != 1
		|| x509_algorithm_id_to_der(a->signature_algor, NULL, &len) != 1
		|| x509_name_to_der(&a->issuer, NULL, &len) != 1
		|| x509_time_to_der(a->this_update, NULL, &len) != 1
		|| x509_time_to_der(a->next_update, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(a->version, out, outlen) != 1
		|| x509_algorithm_id_to_der(a->signature_algor, out, outlen) != 1
		|| x509_name_to_der(&a->issuer, out, outlen) != 1
		|| x509_time_to_der(a->next_update, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int crl_tbs_cert_list_from_der(CRL_TBS_CERT_LIST *a, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_int_from_der(&a->version, &data, &datalen) != 1
		|| x509_algorithm_id_from_der(&a->signature_algor, &data, &datalen) != 1
		|| x509_name_from_der(&a->issuer, &data, &datalen) != 1
		|| x509_time_from_der(&a->this_update, &data, &datalen) != 1
		|| x509_time_from_der(&a->next_update, &data, &datalen) != 1) {
		error_print();
		return -1;
	}
}

int x509_cert_list_to_der(const X509_CERT_LIST *a, uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (x509_tbs_cert_list_to_der(&a->tbs_cert_list, NULL, &len) != 1
		|| x509_signature_algor_to_der(a->signature_algor, NULL, &len) != 1
		|| asn1_bit_string_to_der(a->signature, a->signature_len, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| x509_tbs_cert_list_to_der(&a->tbs_cert_list, out, outlen) != 1
		|| x509_signature_algor_to_der(a->signature_algor, out, outlen) != 1
		|| asn1_bit_string_to_der(a->signature, a->signature_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int x509_cert_list_from_der(X509_CERT_LIST *a, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t datalen;
	const uint8_t *sig;

	if ((ret = asn1_sequence_from_der(&data, &datalen, in, inlen)) != 1) {
		if (ret < 0)
			error_print();
		return ret;
	}
	if (x509_tbs_cert_list_from_der(&a->tbs_cert_list, in, inlen) != 1
		|| x509_signature_algor_from_der(&a->signature_algor, in, inlen) != 1
		|| asn1_bit_string_from_der(&sig, &a->signature_len, in, inlen) != 1
		|| a->signature_len <= 0
		|| a->signature_len >= X509_MAX_SIGNATURE_SIZE) {
		error_print();
		return -1;
	}

	memcpy(a->signature, sig, a->signature_len);
	return 1;
}


static const int X509_CRLExtensionOIDs[7] = {
	OID_id_ce_authorityKeyIdentifier,
	OID_id_ce_issuerAltName,
	OID_id_ce_cRLNumber,
	OID_id_ce_deltaCRLIndicator,
	OID_id_ce_issuingDistributionPoint,
	OID_id_ce_freshestCRL,
	OID_pe_authorityInfoAccess,
};



void X509_CRLExtensionValue_to_der(const X509_CRLExtensionValue *a, int type, uint8_t **out, size_t *outlen)
{
	switch (type) {
	case OID_id_ce_authorityKeyIdentifier: AuthorityKeyIdentifier_to_der(&a->u.authorityKeyIdentifier, out, outlen); break;
	case OID_id_ce_issuerAltName: X509_GeneralNames_to_der(&a->u.issuerAltName, out, outlen); break;
	case OID_id_ce_cRLNumber: ASN1_INTEGER_to_der(&a->u.cRLNumber, out, outlen); break;
	case OID_id_ce_deltaCRLIndicator: ASN1_INTEGER_to_der(&a->u.deltaCRLIndicator, out, outlen);
	case OID_id_ce_issuingDistributionPoint: X509_IssuingDistributionPoint_to_der(&a->u.issuingDistributionPoint, out, outlen);
	case OID_id_ce_freshestCRL: X509_CRLDistributionPoints_to_der(&a->u.freshestCRL, out, outlen);
	case OID_pe_authorityInfoAccess: X509_AuthorityInfoAccessSyntax_to_der(&a->u.authorityInfoAccess, out, outlen);
	}
}

int X509_CRLExtensionValue_from_der(X509_CRLExtensionValue *a, int type, const uint8_t **in, size_t *inlen)
{
	switch (type) {
	case OID_id_ce_authorityKeyIdentifier: return AuthorityKeyIdentifier_from_der(&a->u.authorityKeyIdentifier, in, inlen);
	case OID_id_ce_issuerAltName: return X509_GeneralNames_from_der(&a->u.issuerAltName, in, inlen);
	case OID_id_ce_cRLNumber: return ASN1_INTEGER_from_der(&a->u.cRLNumber, in, inlen);
	case OID_id_ce_deltaCRLIndicator: return ASN1_INTEGER_from_der(&a->u.deltaCRLIndicator, in, inlen);
	case OID_id_ce_issuingDistributionPoint: return X509_IssuingDistributionPoint_from_der(&a->u.issuingDistributionPoint, in, inlen);
	case OID_id_ce_freshestCRL: return X509_CRLDistributionPoints_from_der(&a->u.freshestCRL, in, inlen);
	case OID_pe_authorityInfoAccess: return X509_AuthorityInfoAccessSyntax_from_der(&a->u.authorityInfoAccess, in, inlen);
	}
}



void X509_CRLExtension_to_der(const X509_CRLExtension *a, uint8_t **out, size_t *outlen)
{
	ASN1_SEQUENCE_tag_length_to_der((ASN1_SEQUENCE *)a, out, outlen);
	ASN1_OBJECT_IDENTIFIER_to_der(&a->extnID, out, outlen);
	ASN1_BOOLEAN_to_der(&a->critical, out, outlen);
	ASN1_OCTET_STRING_tag_length_to_der(&a->extnValue, out, outlen);
	X509_CRLExtensionValue_to_der(&a->extnValue_data, out, outlen);
}

int X509_CRLExtension_from_der(X509_CRLExtension *a, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t length;

	if ((ret = ASN1_SEQUENCE_from_der((ASN1_SEQUENCE *)a, in, inlen)) <= 0) {
		return ret;
	}
	data = ((ASN1_SEQUENCE *)a)->data;
	length = ((ASN1_SEQUENCE *)a)->length;
	if (ASN1_OBJECT_IDENTIFIER_from_der(&a->extnID, &data, &length) <= 0
		|| ASN1_BOOLEAN_from_der(&a->critical, &data, &length) < 0
		|| ASN1_OCTET_STRING_from_der(&a->extnValue, &data, &length) <= 0
		|| length > 0) {
		return -1;
	}
	data = a->extnValue.data;
	length = a->extnValue.length;
	if (X509_CRLExtensionValue_from_der(&a->extnValue_data, &data, &length) < 0
		|| length > 0) {
		return -1;
	}

	return 1;
}





void X509_CRLExtensions_add(X509_CRLExtensions *a, const X509_CRLExtension *value)
{
	size_t length = ((ASN1_SEQUENCE *)a)->length;
	assert(a->count < 16);
	X509_CRLExtension_copy(&a->values[a->count], value);
	X509_CRLExtension_to_der(&a->values[a->count], NULL, &length);
	ASN1_SEQUENCE_set((ASN1_SEQUENCE *)a, NULL, length);
	a->count++;
}

void X509_CRLExtensions_to_der(const X509_CRLExtensions *a, uint8_t **out, size_t *outlen)
{
	int i;
	ASN1_SEQUENCE_tag_length_to_der((ASN1_SEQUENCE *)a, out, outlen);
	for (i = 0; i < a->count; i++) {
		X509_CRLExtension_to_der(&a->value[i], out, outlen);
	}
}

int X509_CRLExtensions_from_der(X509_CRLExtensions *a, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t length;

	if ((ret = ASN1_SEQUENCE_from_der((ASN1_SEQUENCE *)a, in, inlen)) <= 0) {
		return ret;
	}
	data = ((ASN1_SEQUENCE *)a)->data;
	length = ((ASN1_SEQUENCE *)a)->length;
	while (length > 0) {
		if (a->count >= 16
			|| X509_CRLExtension_from_der(&a->values[a->count], &data, &length) <= 0) {
			return -1;
		}
	}
	return 1;
}




// 5.2.5.  Issuing Distribution Point
/*
-- issuing distribution point extension OID and syntax

id-ce-issuingDistributionPoint OBJECT IDENTIFIER ::= { id-ce 28 }

IssuingDistributionPoint ::= SEQUENCE {
     distributionPoint          [0] IMPLICIT DistributionPointName OPTIONAL,
     onlyContainsUserCerts      [1] IMPLICIT BOOLEAN DEFAULT FALSE,
     onlyContainsCACerts        [2] IMPLICIT BOOLEAN DEFAULT FALSE,
     onlySomeReasons            [3] IMPLICIT ReasonFlags OPTIONAL,
     indirectCRL                [4] IMPLICIT BOOLEAN DEFAULT FALSE,
     onlyContainsAttributeCerts [5] IMPLICIT BOOLEAN DEFAULT FALSE }
     -- at most one of onlyContainsUserCerts, onlyContainsCACerts,
     -- and onlyContainsAttributeCerts may be set to TRUE.
*/










void X509_CRLEntryExtension_to_der(const X509_CRLEntryExtension *a, uint8_t **out, size_t *outlen)
{
	ASN1_SEQUENCE_tag_length_to_der((ASN1_SEQUENCE *)a, out, outlen);
	ASN1_OBJECT_IDENTIFIER_to_der(&a->extnID, out, outlen);
	ASN1_BOOLEAN_to_der(&a->critical, out, outlen);
	ASN1_OCTET_STRING_tag_length_to_der(&a->extnValue, out, outlen);
	X509_CRLEntryExtensionValue_to_der(&a->extnValue_data, out, outlen);
}

int X509_CRLEntryExtension_from_der(X509_CRLEntryExtension *a, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t length;

	if ((ret = ASN1_SEQUENCE_from_der((ASN1_SEQUENCE *)a, in, inlen)) <= 0) {
		return ret;
	}
	data = ((ASN1_SEQUENCE *)a)->data;
	length = ((ASN1_SEQUENCE *)a)->length;
	if (ASN1_OBJECT_IDENTIFIER_from_der(&a->extnID, &data, &length) <= 0
		|| ASN1_BOOLEAN_from_der(&a->critical, &data, &length) < 0
		|| ASN1_OCTET_STRING_from_der(&a->extnValue, &data, &length) <= 0
		|| length > 0) {
		return -1;
	}
	data = a->extnValue.data;
	length = a->extnValue.length;
	if (X509_CRLEntryExtensionValue_from_der(&a->extnValue_data, &data, &length) < 0
		|| length > 0) {
		return -1;
	}

	return 1;
}


	

// CRL Entry Extensions
//***********************************************************************************************************

static const int X509_CRLEntryExtensionOIDs[3] = {
	OID_id_ce_cRLReasons,
	OID_id_ce_invalidityDate,
	OID_id_ce_certificateIssuer,
};



void X509_CRLEntryExtensionValue_to_der(const X509_CRLEntryExtensionValue *a, int type, uint8_t **out, size_t *outlen)
{
	switch (type) {
	case OID_id_ce_cRLReasons: ASN1_ENUMERATED_to_der(&a->u.reasonCode, out, outlen); break;
	case OID_id_ce_invalidityDate: X509_GeneralizedTime_to_der(&a->u.invalidityDate, out, outlen); break;
	case OID_id_ce_certificateIssuer: X509_GeneralNames_to_der(&a->u.certificateIssuer, out, outlen); break;
	}
}

int X509_CRLEntryExtensionValue_from_der(X509_CRLEntryExtensionValue *a, int type, const uint8_t **in, size_t *inlen)
{
	switch (type) {
	case OID_id_ce_cRLReasons: return ASN1_ENUMERATED_to_der(&a->u.reasonCode, in, inlen);
	case OID_id_ce_invalidityDate: return X509_GeneralizedTime_to_der(&a->u.invalidityDate, in, inlen);
	case OID_id_ce_certificateIssuer: return X509_GeneralNames_to_der(&a->u.certificateIssuer, in, inlen);
	}
}

void X509_CRLEntryExtensions_add(X509_CRLEntryExtensions *a, const X509_CRLEntryExtension *value)
{
	size_t length = ((ASN1_SEQUENCE *)a)->length;
	assert(a->count < 16);
	X509_CRLEntryExtension_copy(&a->values[a->count], value);
	X509_CRLEntryExtension_to_der(&a->values[a->count], NULL, &length);
	ASN1_SEQUENCE_set((ASN1_SEQUENCE *)a, NULL, length);
	a->count++;
}

void X509_CRLEntryExtensions_to_der(const X509_CRLEntryExtensions *a, uint8_t **out, size_t *outlen)
{
	int i;
	ASN1_SEQUENCE_tag_length_to_der((ASN1_SEQUENCE *)a, out, outlen);
	for (i = 0; i < a->count; i++) {
		X509_CRLEntryExtension_to_der(&a->value[i], out, outlen);
	}
}

int X509_CRLEntryExtensions_from_der(X509_CRLExtensions *a, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *data;
	size_t length;

	if ((ret = ASN1_SEQUENCE_from_der((ASN1_SEQUENCE *)a, in, inlen)) <= 0) {
		return ret;
	}
	data = ((ASN1_SEQUENCE *)a)->data;
	length = ((ASN1_SEQUENCE *)a)->length;
	while (length > 0) {
		if (a->count >= 16
			|| X509_CRLEntryExtension_from_der(&a->values[a->count], &data, &length) <= 0) {
			return -1;
		}
	}
	return 1;
}







