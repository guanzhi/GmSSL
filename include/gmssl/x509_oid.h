/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#ifndef GMSSL_X509_OID_H
#define GMSSL_X509_OID_H


#include <time.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <gmssl/sm2.h>
#include <gmssl/oid.h>
#include <gmssl/asn1.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
id-at:
	OID_at_name
	OID_at_surname
	OID_at_given_name
	OID_at_initials
	OID_at_generation_qualifier
	OID_at_common_name
	OID_at_locality_name
	OID_at_state_or_province_name
	OID_at_organization_name
	OID_at_organizational_unit_name
	OID_at_title
	OID_at_dn_qualifier
	OID_at_country_name
	OID_at_serial_number
	OID_at_pseudonym
	OID_domain_component
*/
const char *x509_name_type_name(int oid);
int x509_name_type_from_name(const char *name);
int x509_name_type_from_der(int *oid, const uint8_t **in, size_t *inlen);
int x509_name_type_to_der(int oid, uint8_t **out, size_t *outlen);

/*
id-ce:
	OID_ce_authority_key_identifier
	OID_ce_subject_key_identifier
	OID_ce_key_usage
	OID_ce_certificate_policies
	OID_ce_policy_mappings
	OID_ce_subject_alt_name
	OID_ce_issuer_alt_name
	OID_ce_subject_directory_attributes
	OID_ce_basic_constraints
	OID_ce_name_constraints
	OID_ce_policy_constraints
	OID_ce_ext_key_usage
	OID_ce_crl_distribution_points
	OID_ce_inhibit_any_policy
	OID_ce_freshest_crl
	OID_netscape_cert_comment
*/
const char *x509_ext_id_name(int oid);
int x509_ext_id_from_name(const char *name);
int x509_ext_id_from_der(int *oid, uint32_t *nodes, size_t *nodes_count, const uint8_t **in, size_t *inlen);
int x509_ext_id_to_der(int oid, uint8_t **out, size_t *outlen);

/*
id-qt
	OID_qt_cps
	OID_qt_unotice
*/
const char *x509_qualifier_id_name(int oid);
int x509_qualifier_id_from_name(const char *name);
int x509_qualifier_id_from_der(int *oid, const uint8_t **in, size_t *inlen);
int x509_qualifier_id_to_der(int oid, uint8_t **out, size_t *outlen);

/*
	OID_any_policy
*/
char *x509_cert_policy_id_name(int oid);
int x509_cert_policy_id_from_name(const char *name);
int x509_cert_policy_id_from_der(int *oid, uint32_t *nodes, size_t *nodes_cnt, const uint8_t **in, size_t *inlen);
int x509_cert_policy_id_to_der(int oid, const uint32_t *nodes, size_t nodes_cnt, uint8_t **out, size_t *outlen);

/*
id-kp
	OID_kp_server_auth
	OID_kp_client_auth
	OID_kp_code_signing
	OID_kp_email_protection
	OID_kp_time_stamping
	OID_kp_ocsp_signing
*/
const char *x509_key_purpose_name(int oid);
const char *x509_key_purpose_text(int oid);
int x509_key_purpose_from_name(const char *name);
int x509_key_purpose_from_der(int *oid, const uint8_t **in, size_t *inlen);
int x509_key_purpose_to_der(int oid, uint8_t **out, size_t *outlen);

#ifdef __cplusplus
}
#endif
#endif
