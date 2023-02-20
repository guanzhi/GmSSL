/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#ifndef GMSSL_OID_H
#define GMSSL_OID_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
	OID_undef = 0,

	// ShangMi schemes in GM/T 0006-2012
	OID_sm1,
	OID_ssf33,
	OID_sm4,
	OID_zuc,
	OID_sm2,
	OID_sm2sign,
	OID_sm2keyagreement,
	OID_sm2encrypt,
	OID_sm9,
	OID_sm9sign,
	OID_sm9keyagreement,
	OID_sm9encrypt,
	OID_sm3,
	OID_sm3_keyless,
	OID_hmac_sm3,
	OID_sm2sign_with_sm3,
	OID_rsasign_with_sm3,
	OID_ec_public_key, // X9.62 ecPublicKey
	OID_prime192v1,
	OID_prime256v1,
	OID_secp256k1,
	OID_secp192k1,
	OID_secp224k1,
	OID_secp224r1,
	OID_secp384r1,
	OID_secp521r1,

	OID_at_name,
	OID_at_surname,
	OID_at_given_name,
	OID_at_initials,
	OID_at_generation_qualifier,
	OID_at_common_name,
	OID_at_locality_name,
	OID_at_state_or_province_name,
	OID_at_organization_name,
	OID_at_organizational_unit_name,
	OID_at_title,
	OID_at_dn_qualifier,
	OID_at_country_name,
	OID_at_serial_number,
	OID_at_pseudonym,
	OID_domain_component,
	OID_email_address,

	// Cert Extensions
	OID_ce_authority_key_identifier,
	OID_ce_subject_key_identifier,
	OID_ce_key_usage,
	OID_ce_certificate_policies,
	OID_ce_policy_mappings,
	OID_ce_subject_alt_name,
	OID_ce_issuer_alt_name,
	OID_ce_subject_directory_attributes,
	OID_ce_basic_constraints,
	OID_ce_name_constraints,
	OID_ce_policy_constraints,
	OID_ce_ext_key_usage,
	OID_ce_crl_distribution_points,
	OID_ce_inhibit_any_policy,
	OID_ce_freshest_crl,
	OID_netscape_cert_type,
	OID_netscape_cert_comment,
	OID_ct_precertificate_scts,

	OID_ad_ca_issuers,
	OID_ad_ocsp,

	// CRL Extensions
	//OID_ce_authority_key_identifier,
	//OID_ce_issuer_alt_name,
	OID_ce_crl_number,
	OID_ce_delta_crl_indicator,
	OID_ce_issuing_distribution_point,
	//OID_ce_freshest_crl,
	OID_pe_authority_info_access,

	// CRL Entry Extensions
	OID_ce_crl_reasons,
	OID_ce_invalidity_date,
	OID_ce_certificate_issuer,

	// X.509 KeyPropuseID
	OID_any_extended_key_usage,
	OID_kp_server_auth,
	OID_kp_client_auth,
	OID_kp_code_signing,
	OID_kp_email_protection,
	OID_kp_time_stamping,
	OID_kp_ocsp_signing,

	OID_qt_cps,
	OID_qt_unotice,

	OID_md5,
	OID_sha1,
	OID_sha224,
	OID_sha256,
	OID_sha384,
	OID_sha512,
	OID_sha512_224,
	OID_sha512_256,


	OID_hmac_sha1,
	OID_hmac_sha224,
	OID_hmac_sha256,
	OID_hmac_sha384,
	OID_hmac_sha512,
	OID_hmac_sha512_224,
	OID_hmac_sha512_256,

	OID_pbkdf2, // {pkcs-5 12}
	OID_pbes2,  // {pkcs-5 13}



	OID_sm4_ecb, // 1 2 156 10197 1 104 1
	OID_sm4_cbc, // 1 2 156 10197 1 104 2

	OID_aes,
	OID_aes128_cbc,
	OID_aes192_cbc,
	OID_aes256_cbc,

	OID_aes128, // 没有OID

	OID_ecdsa_with_sha1,
	OID_ecdsa_with_sha224,
	OID_ecdsa_with_sha256,
	OID_ecdsa_with_sha384,
	OID_ecdsa_with_sha512,

	OID_rsasign_with_md5,
	OID_rsasign_with_sha1,
	OID_rsasign_with_sha224,
	OID_rsasign_with_sha256,
	OID_rsasign_with_sha384,
	OID_rsasign_with_sha512,

	OID_rsa_encryption,
	OID_rsaes_oaep,

	OID_any_policy,

	OID_cms_data,
	OID_cms_signed_data,
	OID_cms_enveloped_data,
	OID_cms_signed_and_enveloped_data,
	OID_cms_encrypted_data,
	OID_cms_key_agreement_info,
};

// {iso(1) org(3) dod(6) internet(1) security(5) mechanisms(5) pkix(7)}
#define oid_pkix	1,3,6,1,5,5,7

#define oid_pe		oid_pkix,1
#define oid_qt		oid_pkix,2
#define oid_kp		oid_pkix,3
#define oid_ad		oid_pkix,48

// {iso(1) member-body(2) us(840) rsadsi(113549)}
#define oid_rsadsi	1,2,840,113549
#define oid_pkcs	oid_rsadsi,1
#define oid_pkcs5	oid_pkcs,5

// {iso(1) member-body(2) us(840) ansi-x962(10045)}
#define oid_x9_62	1,2,840,10045



#define oid_at	2,5,4
#define oid_ce	2,5,29


#define oid_sm		1,2,156,10197
#define oid_sm_algors	oid_sm,1
#define oid_sm2_cms	oid_sm,6,1,4,2





#define oid_cnt(nodes)	(sizeof(nodes)/sizeof((nodes)[0]))



#ifdef __cplusplus
}
#endif
#endif
