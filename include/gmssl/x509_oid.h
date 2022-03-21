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
