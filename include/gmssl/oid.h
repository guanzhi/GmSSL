/*
 * Copyright (c) 2014 - 2021 The GmSSL Project.  All rights reserved.
 *
OCSPSigning * Redistribution and use in source and binary forms, with or without
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


#ifndef GMSSL_OID_H
#define GMSSL_OID_H


#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif


enum {
	OID_undef = 0,
	//OID_aes,







































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
	OID_x9_62_ecPublicKey, // start of X9.62 curves
	OID_prime192v1,
	OID_prime192v2,
	OID_prime192v3,
	OID_prime239v1,
	OID_prime239v2,
	OID_prime239v3,
	OID_prime256v1,
	OID_secp256k1, // start of SECG curves (secure curves only!)
	OID_secp192k1,
	OID_secp224k1,
	OID_secp224r1,
	OID_secp384r1,
	OID_secp521r1,
	OID_at_commonName, // start of X.509 Attributes
	OID_at_surname,
	OID_at_serialNumber,
	OID_at_countryName,
	OID_at_localityName,
	OID_at_stateOrProvinceName,
	OID_at_streetAddress,
	OID_at_organizationName,
	OID_at_organizationalUnitName,
	OID_at_title,
	OID_at_description,
	OID_at_searchGuide,
	OID_at_businessCategory,
	OID_at_postalAddress,
	OID_at_postalCode,
	OID_at_postOfficeBox,
	OID_at_physicalDeliveryOfficeName,
	OID_at_telephoneNumber,
	OID_at_telexNumber,
	OID_at_teletexTerminalIdentifier,
	OID_at_facsimileTelephoneNumber,
	OID_at_x121Address,
	OID_at_internationaliSDNNumber,
	OID_at_registeredAddress,
	OID_at_destinationIndicator,
	OID_at_preferredDeliveryMethod,
	OID_at_presentationAddress,
	OID_at_supportedApplicationContext,
	OID_at_member,
	OID_at_owner,
	OID_at_roleOccupant,
	OID_at_seeAlso,
	OID_at_userPassword,
	OID_at_userCertificate,
	OID_at_caCertificate,
	OID_at_authorityRevocationList,
	OID_at_certificateRevocationList,
	OID_at_crossCertificatePair,
	OID_at_name,
	OID_at_givenName,
	OID_at_initials,
	OID_at_generationQualifier,
	OID_at_x500UniqueIdentifier,
	OID_at_dnQualifier,
	OID_at_enhancedSearchGuide,
	OID_at_protocolInformation,
	OID_at_distinguishedName,
	OID_at_uniqueMember,
	OID_at_houseIdentifier,
	OID_at_supportedAlgorithms,
	OID_at_deltaRevocationList,
	OID_at_dmdName,
	OID_at_pseudonym,
	OID_at_role,

	/* ext  1 */ OID_ce_authorityKeyIdentifier,
	/* ext  2 */ OID_ce_subjectKeyIdentifier,
	/* ext  3 */ OID_ce_keyUsage,
	/* ext  4 */ OID_ce_certificatePolicies, // start of X.500v3 Certificate Extensions
	/* ext  5 */ OID_ce_policyMappings, // start of OID_ce_certificatePolicies,
	/* ext  6 */ OID_ce_subjectAltName,
	/* ext  7 */ OID_ce_issuerAltName,
	/* ext  8 */ OID_ce_subjectDirectoryAttributes,
	/* ext  9 */ OID_ce_basicConstraints,
	/* ext 10 */ OID_ce_nameConstraints,
	/* ext 11 */ OID_ce_policyConstraints,
	/* ext 12 */ OID_ce_extKeyUsage,
	/* ext 13 */ OID_ce_crlDistributionPoints,
	/* ext 14 */ OID_ce_inhibitAnyPolicy,
	/* ext 15 */ OID_ce_freshestCRL,

	OID_ce_primaryKeyUsageRestriction,
	
	
	
	OID_ce_privateKeyUsagePeriod,
	
	
	
	OID_ce_crlNumber,
	OID_ce_reasonCode,
	OID_ce_instructionCode,
	OID_ce_invalidityDate,
	OID_ce_deltaCRLIndicator,
	OID_ce_issuingDistributionPoint,
	OID_ce_certificateIssuer,
	
	
	
	
	
	
	
	


	OID_kp_serverAuth, // start of X.509 KeyPropuseID
	OID_kp_clientAuth,
	OID_kp_codeSigning,
	OID_kp_emailProtection,
	OID_kp_timeStamping,
	OID_kp_OCSPSigning,


	OID_qt_cps,
	OID_qt_unotice,

	OID_MAX,

	OID_md5,
	OID_sha1,
	OID_sha224,
	OID_sha256,
	OID_sha384,
	OID_sha512,
	OID_sha512_224,
	OID_sha512_256,


	OID_pbkdf2, // {pkcs-5 12}
	OID_pbes2,  // {pkcs-5 13}
	OID_hmacWithSHA1,
	OID_hmacWithSHA224,

	OID_sm4_ecb, // 1 2 156 10197 1 104 1
	OID_sm4_cbc, // 1 2 156 10197 1 104 2


	OID_aes,
	OID_aes128_cbc,
	OID_aes192_cbc,
	OID_aes256_cbc,

	OID_ecdsa_with_sha1,
	OID_ecdsa_with_sha224,
	OID_ecdsa_with_sha256,
	OID_ecdsa_with_sha384,
	OID_ecdsa_with_sha512,

	OID_rsasign_with_sha1,
	OID_rsasign_with_sha224,
	OID_rsasign_with_sha256,
	OID_rsasign_with_sha384,
	OID_rsasign_with_sha512,

	OID_rsa_encryption,
	OID_rsaes_oaep,


};

typedef struct {
	int oid;
	uint32_t nodes[32];
	int nodes_count;
} ASN1_OBJECT_IDENTIFIER;




const char *asn1_sm_oid_name(int oid);
const char *asn1_sm_oid_description(int oid);
void asn1_sm_oid_to_octets(int oid, uint8_t *out, size_t *outlen);
int asn1_sm_oid_from_octets(const uint8_t *in, size_t inlen);
int asn1_sm_oid_from_name(const char *name);

const char *asn1_x9_62_curve_oid_name(int oid);
const char *asn1_x9_62_curve_oid_description(int oid);
void asn1_x9_62_curve_oid_to_octets(int oid, uint8_t *out, size_t *outlen);
int asn1_x9_62_curve_oid_from_octets(const uint8_t *in, size_t inlen);
int asn1_x9_62_curve_oid_from_name(const char *name);

const char *asn1_secg_curve_oid_name(int oid);
const char *asn1_secg_curve_oid_description(int oid);
void asn1_secg_curve_oid_to_octets(int oid, uint8_t *out, size_t *outlen);
int asn1_secg_curve_oid_from_octets(const uint8_t *in, size_t inlen);
int asn1_secg_curve_oid_from_name(const char *name);

const char *asn1_x509_oid_name(int oid);
const char *asn1_x509_oid_description(int oid);
void asn1_x509_oid_to_octets(int oid, uint8_t *out, size_t *outlen);
int asn1_x509_oid_from_octets(const uint8_t *in, size_t inlen);
int asn1_x509_oid_from_name(const char *name);


const char *asn1_x509_kp_oid_name(int oid);
const char *asn1_x509_kp_oid_description(int oid);
void asn1_x509_kp_oid_to_octets(int oid, uint8_t *out, size_t *outlen);
int asn1_x509_kp_oid_from_octets(const uint8_t *in, size_t inlen);
int asn1_x509_kp_oid_from_name(const char *name);


void asn1_oid_to_octets(int oid, uint8_t *out, size_t *outlen);
int asn1_oid_from_octets(const uint8_t *in, size_t inlen);
int asn1_oid_nodes_to_octets(const uint32_t *nodes, size_t nodes_count, uint8_t *out, size_t *outlen);
int asn1_oid_nodes_from_octets(uint32_t *nodes, size_t *nodes_count, const uint8_t *in, size_t inlen);

int test_asn1_oid(void);
int test_asn1_object_identifier(void);

#ifdef __cplusplus
}
#endif
#endif
