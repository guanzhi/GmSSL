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

#ifndef GMSSL_X509_H
#define GMSSL_X509_H


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
 ASN.1 API 规则

	* SEQUENCE OF/SET OF 类型是存储类型
	* 如果一个CHOICE类型可选项中有存储类型，那么这个CHOICE也设置为存储类型

*/


enum X509_Version {
	X509_version_v1 = 0,
	X509_version_v2 = 1,
	X509_version_v3 = 2,
};

int x509_time_to_der(time_t a, uint8_t **out, size_t *outlen);
int x509_time_from_der(time_t *a, const uint8_t **in, size_t *inlen);

typedef struct {
	time_t not_before;
	time_t not_after;
} X509_VALIDITY;

int x509_validity_set_days(X509_VALIDITY *a, time_t not_before, int days);
int x509_validity_to_der(const X509_VALIDITY *a, uint8_t **out, size_t *outlen);
int x509_validity_from_der(X509_VALIDITY *a, const uint8_t **in, size_t *inlen);
int x509_validity_print(FILE *fp, const X509_VALIDITY *validity, int format, int indent);

/*
DirectoryString ::= CHOICE {
	teletexString		TeletexString  (SIZE (1..MAX)),
	printableString		PrintableString (SIZE (1..MAX)),
	universalString		UniversalString  (SIZE (1..MAX)),
	utf8String		UTF8String (SIZE (1..MAX)),
	bmpString		BMPString (SIZE (1..MAX)),
}
DirectoryString 实际上就是一个 Universal 类型，因此提供和 asn1.h 中基本类型一致的接口
*/
int x509_directory_string_to_der(int tag, const char *a, size_t alen, uint8_t **out, size_t *outlen);
int x509_directory_string_from_der(int *tag, const char **a, size_t *alen, const uint8_t **in, size_t *inlen);


/*
Name ::= SEQUENCE OF RelativeDistinguishedName

RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
	-- 我们只支持 SIZE == 1 的情况

AttributeTypeAndValue ::= SEQUENCE {
	type OBJECT IDENTIFIER,
	value ANY -- DEFINED BY AttributeType
                  -- mostly DirectoryString or PrintableString
}

	type == domainComponent 可能出现多次，因此目前X509_NAME并不支持这种情况
	这个在实际中出现的多吗？

*/

typedef struct {
	size_t datalen;
	uint8_t data[256];
} X509_RDN;

int x509_rdn_to_der(int oid, int tag, const char *str, uint8_t **out, size_t *outlen);
int x509_rdn_from_der(int *oid, int *tag, const char **str, size_t *slen, const uint8_t **in, size_t *inlen);

typedef struct {
	int count;
	int oids[8];
	int tags[8];

	char country[3]; // printableString
	char state_or_province[129];
	char locality[129];
	char org[65];
	char org_unit[65];
	char common_name[65];
	char serial_number[65]; // printableString
	char dn_qualifier[65]; // printableString
} X509_NAME;

int x509_name_add_rdn_ex(X509_NAME *a, int oid, int tag, const char *str, size_t len);
int x509_name_equ(const X509_NAME *a, const X509_NAME *b);
int x509_name_from_der(X509_NAME *a, const uint8_t **in, size_t *inlen);
int x509_name_to_der(const X509_NAME *a, uint8_t **out, size_t *outlen);
int x509_name_print(FILE *fp, const X509_NAME *a, int format, int indent);


#define x509_name_add_rdn(a,oid,tag,s)		x509_name_add_rdn_ex((a),(oid),(tag),(s),strlen(s))
#define x509_name_set_country(a,s)		x509_name_add_rdn((a),OID_at_countryName,ASN1_TAG_PrintableString,(s))
#define x509_name_set_state_or_province(a,s)	x509_name_add_rdn((a),OID_at_stateOrProvinceName,ASN1_TAG_PrintableString,(s))
#define x509_name_set_organization(a,s)		x509_name_add_rdn((a),OID_at_organizationName,ASN1_TAG_PrintableString,(s))
#define x509_name_set_organizational_unit(a,s)	x509_name_add_rdn((a),OID_at_organizationalUnitName,ASN1_TAG_PrintableString,(s))
#define x509_name_set_common_name(a,s)		x509_name_add_rdn((a),OID_at_commonName,ASN1_TAG_PrintableString,(s))

/*
AlgorithmIdentifier  ::=  SEQUENCE  {
        algorithm               OBJECT IDENTIFIER,
        parameters              ANY DEFINED BY algorithm OPTIONAL  }

	SignatureAlgorithm 是特殊的 AlgorithmIdentifier
	当 algorithm 为 ECDSA/SM2 时，parameters 为空
	当 algorithm 为 RSA 时，parameters 为 ASN1_NULL 对象
*/

const char *x509_digest_algor_name(int algor);
int x509_digest_algor_from_name(const char *name);
int x509_digest_algor_to_der(int algor, uint8_t **out, size_t *outlen);
int x509_digest_algor_from_der(int *algor, uint32_t *nodes, size_t *nodes_count,
	const uint8_t **in, size_t *inlen);

const char *x509_encryption_algor_name(int algor);
int x509_encryption_algor_from_name(const char *name);
int x509_encryption_algor_to_der(int algor, const uint8_t *iv, size_t ivlen,
	uint8_t **out, size_t *outlen);
int x509_encryption_algor_from_der(int *algor, uint32_t *nodes, size_t *nodes_count,
	const uint8_t **iv, size_t *ivlen,
	const uint8_t **in, size_t *inlen);

const char *x509_signature_algor_name(int algor);
int x509_signature_algor_from_name(const char *name);
int x509_signature_algor_to_der(int algor, uint8_t **out, size_t *outlen);
int x509_signature_algor_from_der(int *algor, uint32_t *nodes, size_t *nodes_count,
	const uint8_t **in, size_t *inlen);

const char *x509_public_key_encryption_algor_name(int algor);
int x509_public_key_encryption_algor_from_name(const char *name);
int x509_public_key_encryption_algor_to_der(int algor, uint8_t **out, size_t *outlen);
int x509_public_key_encryption_algor_from_der(int *algor, uint32_t *nodes, size_t *nodes_count,
	const uint8_t **params, size_t *params_len,
	const uint8_t **in, size_t *inlen);



/*
SubjectPublicKeyInfo  ::=  SEQUENCE  {
	algorithm            AlgorithmIdentifier,
	subjectPublicKey     BIT STRING  }

	algorithm.algorithm = OID_x9_62_ecPublicKey;
	algorithm.parameters = OID_sm2p256v1;
	subjectPublicKey = ECPoint
*/
typedef struct {
	int algor_oid;
	int curve_oid;
	SM2_KEY sm2_key;
} X509_PUBLIC_KEY_INFO;

int x509_public_key_info_set_sm2(X509_PUBLIC_KEY_INFO *a, const SM2_KEY *sm2_key);
#define x509_public_key_info_set(a,pk)  x509_public_key_info_set_sm2((a),(pk))
int x509_public_key_info_to_der(const X509_PUBLIC_KEY_INFO *a, uint8_t **out, size_t *outlen);
int x509_public_key_info_from_der(X509_PUBLIC_KEY_INFO *a, const uint8_t **in, size_t *inlen);
int x509_public_key_info_print(FILE *fp, const X509_PUBLIC_KEY_INFO *a, int format, int indent);

/*
Extension  ::=  SEQUENCE  {
	extnID OBJECT IDENTIFIER,
	critical BOOLEAN DEFAULT FALSE,
	extnValue OCTET STRING -- contains the DER encoding of an ASN.1 value
*/
const char *x509_extension_oid_name(int oid);
int x509_extension_oid_to_der(int oid, uint8_t **out, size_t *outlen);
int x509_extension_oid_from_der(int *oid, uint32_t *nodes, size_t *nodes_count, const uint8_t **in, size_t *inlen);

int x509_extension_to_der(int oid,
	int is_critical, const uint8_t *data, size_t datalen,
	uint8_t **out, size_t *outlen);
int x509_extension_from_der(int *oid, uint32_t *nodes, size_t *nodes_count,
	int *is_critical, const uint8_t **data, size_t *datalen,
	const uint8_t **in, size_t *inlen);
int x509_extension_print(FILE *fp, int oid, const uint32_t *nodes, size_t nodes_count,
	int is_critical, const uint8_t *data, size_t datalen,
	int format, int indent);

typedef struct {
	size_t datalen;
	uint8_t data[2048];
} X509_EXTENSIONS;

int x509_extensions_add_item(X509_EXTENSIONS *a,
	int oid, int is_critical, const uint8_t *data, size_t datalen);
int x509_extensions_get_next_item(const X509_EXTENSIONS *a, const uint8_t **next,
	int *oid, uint32_t *nodes, size_t *nodes_count,
	int *is_critical, const uint8_t **data, size_t *datalen);
int x509_extensions_print(FILE *fp, const X509_EXTENSIONS *a, int format, int indent);






typedef struct {
	int version;			// [0] EXPLICIT INTEGER DEFAULT v1
	uint8_t serial_number[20];	// INTEGER
	size_t serial_number_len;
	int signature_algor;		// AlgorithmIdentifier
	X509_NAME issuer;
	X509_VALIDITY validity;
	X509_NAME subject;
	X509_PUBLIC_KEY_INFO subject_public_key_info;
	uint8_t issuer_unique_id[64];	// [1] IMPLICIT BIT STRING OPTIONAL
	size_t issuer_unique_id_len;
	uint8_t subject_unique_id[64];	// [2] IMPLICIT BIT STRING OPTIONAL
	size_t subject_unique_id_len;
	X509_EXTENSIONS extensions;	// [3]  EXPLICIT, If present, version MUST be v3
} X509_TBS_CERTIFICATE;

int x509_tbs_certificate_to_der(const X509_TBS_CERTIFICATE *a, uint8_t **out, size_t *outlen);
int x509_tbs_certificate_from_der(X509_TBS_CERTIFICATE *a, const uint8_t **in, size_t *inlen);



/*
Certificate  ::=  SEQUENCE  {
	tbsCertificate       TBSCertificate,
	signatureAlgorithm   AlgorithmIdentifier,
	signatureValue       BIT STRING }
*/
typedef struct {
	X509_TBS_CERTIFICATE tbs_certificate;
	int signature_algor;
	uint8_t signature[256];
	size_t signature_len;
} X509_CERTIFICATE;


int x509_certificate_set_version(X509_CERTIFICATE *cert, int version);
int x509_certificate_set_serial_number(X509_CERTIFICATE *cert, const uint8_t *sn, size_t snlen);
int x509_certificate_set_signature_algor(X509_CERTIFICATE *cert, int oid); // 这个应该直接指定SM2吗？
int x509_certificate_set_issuer(X509_CERTIFICATE *cert, const X509_NAME *name);
int x509_certificate_set_subject(X509_CERTIFICATE *cert, const X509_NAME *name);
int x509_certificate_set_validity(X509_CERTIFICATE *cert, time_t not_before, int days);
int x509_certificate_set_subject_public_key_info_sm2(X509_CERTIFICATE *cert, const SM2_KEY *sm2_key);
int x509_certificate_set_issuer_unique_id(X509_CERTIFICATE *cert, const uint8_t *id, size_t idlen);
int x509_certificate_set_subject_unique_id(X509_CERTIFICATE *cert, const uint8_t *id, size_t idlen);
int x509_certificate_set_issuer_unique_id_from_public_key_sm2(X509_CERTIFICATE *cert, const SM2_KEY *sm2_key);
int x509_certificate_set_subject_unique_id_from_public_key_sm2(X509_CERTIFICATE *cert, const SM2_KEY *sm2_key);
#define x509_certificate_set_subject_public_key_info(c,pk)  x509_certificate_set_subject_public_key_info_sm2((c),(pk))
#define x509_certificate_set_issuer_unique_id_from_public_key(c,pk) x509_certificate_set_issuer_unique_id_from_public_key_sm2((c),(pk))
#define x509_certificate_set_subject_unique_id_from_public_key(c,pk) x509_certificate_set_subject_unique_id_from_public_key_sm2((c),(pk))


int x509_certificate_add_extension(X509_CERTIFICATE *a, int oid, int is_critical,
	const uint8_t *data, size_t datalen);
int x509_certificate_get_extension_from_oid(const X509_CERTIFICATE *a, int oid,
	int *is_critical, const uint8_t **data, size_t *datalen);

int x509_certificate_sign_sm2(X509_CERTIFICATE *cert, const SM2_KEY *key);
int x509_certificate_verify_sm2(const X509_CERTIFICATE *cert, const SM2_KEY *sm2_key);
int x509_certificate_get_public_key_sm2(const X509_CERTIFICATE *cert, SM2_KEY *sm2_key);
#define x509_certificate_sign(c,sk)  x509_certificate_sign_sm2((c),(sk))
#define x509_certificate_verify(c,pk)  x509_certificate_verify_sm2((c),(pk))
#define x509_certificate_get_public_key(c,pk)  x509_certificate_get_public_key_sm2((c),(pk))

int x509_certificate_to_der(const X509_CERTIFICATE *a, uint8_t **out, size_t *outlen);
int x509_certificate_to_pem(const X509_CERTIFICATE *a, FILE *fp);
int x509_certificate_from_der(X509_CERTIFICATE *a, const uint8_t **in, size_t *inlen);
int x509_certificate_from_pem(X509_CERTIFICATE *a, FILE *fp);
int x509_certificate_print(FILE *fp, const X509_CERTIFICATE *a, int format, int indent);

int x509_certificate_from_pem_by_name(X509_CERTIFICATE *cert, FILE *certs_fp, const X509_NAME *issuer);

int x509_certificate_verify_by_certificate(const X509_CERTIFICATE *cert, const X509_CERTIFICATE *cacert);







// Extension 1 AuthorityKeyIdentifier

/*
OtherName ::= SEQUENCE {
        type-id    OBJECT IDENTIFIER,
        value      [0] EXPLICIT ANY DEFINED BY type-id }
*/
int x509_other_name_to_der_ex(int tag,
	int oid, const uint32_t *nodes, size_t nodes_count,
	const uint8_t *value, size_t valuelen,
	uint8_t **out, size_t *outlen);

int x509_other_name_from_der_ex(int tag,
	int *oid, uint32_t *nodes, size_t *nodes_count,
	const uint8_t **value, size_t *valuelen,
	const uint8_t **in, size_t *inlen);

/*
EDIPartyName ::= SEQUENCE {
        nameAssigner            [0]     DirectoryString OPTIONAL,
        partyName               [1]     DirectoryString }
*/
int x509_edi_party_name_to_der_ex(
	int tag,
	int assigner_tag, const char *assigner, size_t assigner_len,
	int party_name_tag, const char *party_name, size_t party_name_len,
	uint8_t **out, size_t *outlen);

int x509_edi_party_name_from_der_ex(
	int tag,
	int *assigner_tag, const char **assigner, size_t *assigner_len,
	int *party_name_tag, const char **party_name, size_t *party_name_len,
	const uint8_t **in, size_t *inlen);

/*
GeneralName ::= CHOICE {
        otherName                       [0]     OtherName,
        rfc822Name                      [1]     IA5String,
        dNSName                         [2]     IA5String,
        x400Address                     [3]     ORAddress,
        directoryName                   [4]     Name,
        ediPartyName                    [5]     EDIPartyName,
        uniformResourceIdentifier       [6]     IA5String,
        iPAddress                       [7]     OCTET STRING,
        registeredID                    [8]     OBJECT IDENTIFIER
 }
*/
enum {
	X509_gn_otherName = 0,
	X509_gn_rfc822Name,
	X509_gn_dnsName,
	X509_gn_x400Address,
	X509_gn_directoryName,
	X509_gn_ediPartyName,
	X509_gn_uniformResourceIdentifier,
	X509_gn_ipAddress,
	X509_gn_registeredID,
};

int x509_general_name_to_der(int choice, const uint8_t *data, size_t datalen, uint8_t **out, size_t *outlen);
int x509_general_name_from_der(int *choice, const uint8_t **data, size_t *datalen, const uint8_t **in, size_t *inlen);


typedef struct {
	size_t datalen;
	uint8_t data[256];
} X509_GENERAL_NAMES;

int x509_general_names_add_item(X509_GENERAL_NAMES *a, int choice, const uint8_t *data, size_t datalen);
int x509_general_names_get_next_item(const X509_GENERAL_NAMES *a, const uint8_t **next,
	int *choice, const uint8_t **data, size_t *datalen);

#define x509_general_names_to_der(a,d,dl) \
	asn1_sequence_to_der((a)->data,(a)->datalen,d,dl)

#define x509_general_names_from_der(a,d,dl) \
	asn1_sequence_copy_from_der((a)->data,&((a)->datalen),d,dl)

#define x509_implicit_general_names_to_der(i,a,d,dl) \
	asn1_type_to_der(ASN1_TAG_EXPLICIT(i),(a)->data,(a)->datalen,d,dl)

#define x509_implicit_general_names_from_der(i,a,d,dl) \
	asn1_type_copy_from_der(ASN1_TAG_EXPLICIT(i),256,(a)->data,&((a)->datalen),d,dl)


/*
Extension 1
AuthorityKeyIdentifier ::= SEQUENCE {
	keyIdentifier             [0] IMPLICIT OCTET STRING OPTIONAL,
	authorityCertIssuer       [1] IMPLICIT GeneralNames OPTIONAL,
	authorityCertSerialNumber [2] IMPLICIT INTEGER OPTIONAL
}
	在验证证书时，签名方公钥是通过 issuer 在备选的CA证书列表中检索得到的
	但是某些CA可能存在一个同一个名字对应了多个证书，因此需要一个格外的公钥ID
	也许我们可以对所有这种SEQUENCE OF类型的都支持一个IMPLICIT

用于从多个subject同名的CA证书中挑选出需要的证书

 * 如果这些同名CA证书中使用的公钥不同，那么这些公钥的key_id不同
 * 如果这些同名CA证书（不是根CA证书）是由不同的上级CA签发，那么可以由issuer来区分
 * 如果这些同名CA证书的序列号


AuthorityKeyIdentifier 扩展中包含签发该证书的上级CA证书的部分信息
*/

int x509_authority_key_identifier_to_der(
	const uint8_t *keyid, size_t keyid_len,
	const X509_GENERAL_NAMES *issuer,
	const uint8_t *serial_number, size_t serial_number_len,
	uint8_t **out, size_t *outlen);

int x509_authority_key_identifier_from_der(
	const uint8_t **keyid, size_t *keyid_len,
	X509_GENERAL_NAMES *issuer,
	const uint8_t **serial_number, size_t *serial_number_len,
	const uint8_t **in, size_t *inlen);

int x509_certificate_set_authority_key_identifier(X509_CERTIFICATE *cert,
	int is_critical,
	const uint8_t *keyid, size_t keyid_len,
	const X509_GENERAL_NAMES *issuer,
	const uint8_t *serial_number, size_t serial_number_len);

int x509_certificate_get_authority_key_identifier(const X509_CERTIFICATE *cert,
	int *is_critical,
	const uint8_t **keyid, size_t *keyid_len,
	X509_GENERAL_NAMES *issuer,
	const uint8_t **serial_number, size_t *serial_number_len);

/*
Extension 2
SubjectKeyIdentifier ::= OCTET STRING
*/
int x509_certificate_set_subject_key_identifier(X509_CERTIFICATE *cert,
	int is_critical,
	const uint8_t *keyid, size_t keyid_len);

// keyid = sm3(uncompressed_sm2_public_key_point)
int x509_certificate_generate_subject_key_identifier(X509_CERTIFICATE *cert,
	int is_critical);

int x509_certificate_get_subject_key_identifier(const X509_CERTIFICATE *cert,
	int *is_critical,
	const uint8_t **keyid, size_t *keyid_len);


int x509_subject_key_identifier_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent);


/*
Extension 3 KeyUsage

KeyUsage ::= BIT STRING {
           digitalSignature        (0),
           nonRepudiation          (1), -- recent editions of X.509 have
                                -- renamed this bit to contentCommitment
           keyEncipherment         (2),
           dataEncipherment        (3),
           keyAgreement            (4),
           keyCertSign             (5),
           cRLSign                 (6),
           encipherOnly            (7),
           decipherOnly            (8) }
*/
enum X509_KeyUsage {
	X509_ku_digital_signature = 0,
	X509_ku_non_repudiation, // -- renamed this bit to contentCommitment
	X509_ku_key_encipherment,
	X509_ku_data_encipherment,
	X509_ku_key_agreement,
	X509_ku_key_cert_sign,
	X509_ku_crl_sign,
	X509_ku_encipher_only,
	X509_ku_decipher_only,
};

int x509_certificate_set_key_usage(X509_CERTIFICATE *cert,
	int is_critical,
	int usage_bits);

int x509_certificate_get_key_usage(const X509_CERTIFICATE *cert,
	int *is_critical,
	int *usage_bits);


// Extension 4 CertificatePolicies

/*
   DisplayText ::= CHOICE {
        ia5String        IA5String      (SIZE (1..200)),
        visibleString    VisibleString  (SIZE (1..200)),
        bmpString        BMPString      (SIZE (1..200)),
        utf8String       UTF8String     (SIZE (1..200)) }
*/
int x509_display_text_to_der(int tag, const char *text, size_t textlen, uint8_t **out, size_t *outlen);
int x509_display_text_from_der(int *tag, const char **text, size_t *textlen, const uint8_t **in, size_t *inlen);


/*
NoticeReference ::= SEQUENCE {
        organization     DisplayText,
        noticeNumbers    SEQUENCE OF INTEGER }
*/
int x509_notice_reference_to_der(
	int organization_tag, const char *organization, size_t organization_len,
	const int *notice_numbers, size_t notice_numbers_count,
	uint8_t **out, size_t *outlen);

int x509_notice_reference_from_der(
	int *organization_tag, const char **organization, size_t *organization_len,
	int *notice_numbers, size_t *notice_numbers_count,
	const uint8_t **in, size_t *inlen);

/*
UserNotice ::= SEQUENCE {
        noticeRef        NoticeReference OPTIONAL,
        explicitText     DisplayText OPTIONAL }
*/
int x509_user_notice_to_der(
	const uint8_t *notice_ref_der, size_t notice_ref_der_len,
	int explicit_text_tag, const char *explicit_text, size_t explicit_text_len,
	uint8_t **out, size_t *outlen);

int x509_user_notice_from_der(
	const uint8_t **notice_ref_der, size_t *notice_ref_der_len,
	int *explicit_text_tag, const char **explicit_text, size_t *explicit_text_len,
	const uint8_t **in, size_t *inlen);

/*
PolicyQualifierInfo ::= SEQUENCE {
        policyQualifierId  PolicyQualifierId,
        qualifier          ANY DEFINED BY policyQualifierId }

	switch(policyQualifierId)
	case id-qt-cps		: qualifier ::= IA5String
	case id-qt-unotice	: qualifier ::= UserNotice
*/
int x509_policy_qualifier_info_to_der(int oid,
	const uint8_t *qualifier, size_t qualifier_len,
	uint8_t **out, size_t *outlen);

int x509_policy_qualifier_info_from_der(int *oid,
	const uint8_t **qualifier, size_t *qualifier_len,
	const uint8_t **in, size_t *inlen);

/*
PolicyInformation ::= SEQUENCE {
        policyIdentifier   CertPolicyId,
        policyQualifiers   SEQUENCE SIZE (1..MAX) OF
                                PolicyQualifierInfo OPTIONAL }

CertPolicyId ::= OBJECT IDENTIFIER
*/
typedef struct {
	size_t datalen;
	uint8_t data[256];
} X509_POLICY_QUALIFIER_INFOS;

int x509_policy_qualifier_infos_add_item(X509_POLICY_QUALIFIER_INFOS *a,
	int oid, const uint8_t *qualifier, size_t qualifier_len);

int x509_policy_qualifier_infos_get_next_item(const X509_POLICY_QUALIFIER_INFOS *a, const uint8_t **next,
	int *oid, const uint8_t **qualifier, size_t *qualifier_len);

#define x509_policy_qualifier_infos_to_der(a,d,dl) \
	asn1_sequence_to_der((a)->data,(a)->datalen,d,dl)

#define x509_policy_qualifier_infos_from_der(a,d,dl) \
	asn1_sequence_copy_from_der(256, (a)->data,&((a)->datalen),d,dl)

int x509_policy_information_to_der(
	int oid, const uint32_t *nodes, size_t nodes_count,
	const X509_POLICY_QUALIFIER_INFOS *qualifiers,
	uint8_t **out, size_t *outlen);

int x509_policy_information_from_der(
	int *oid, uint32_t *nodes, size_t *nodes_count,
	X509_POLICY_QUALIFIER_INFOS *qualifiers,
	const uint8_t **in, size_t *inlen);

/*
Extension 4 Certificate Policies
CertificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
*/
typedef struct {
	size_t datalen;
	uint8_t data[1024];
} X509_CERTIFICATE_POLICIES;

int x509_certificate_policies_add_item(X509_CERTIFICATE_POLICIES *a,
	int oid, const uint32_t *nodes, size_t nodes_count,
	const X509_POLICY_QUALIFIER_INFOS *qualifiers);

int x509_certificate_policies_get_next_item(const X509_CERTIFICATE_POLICIES *a, const uint8_t **next,
	int *oid, const uint32_t *nodes, size_t *nodes_count,
	X509_POLICY_QUALIFIER_INFOS *qualifiers);

#define x509_certificate_policies_to_der(a,d,dl) \
	asn1_sequence_to_der((a)->data,(a)->datalen,d,dl)

#define x509_certificate_policies_from_der(a,d,dl) \
	asn1_sequence_copy_from_der(1024, (a)->data,&((a)->datalen),d,dl)



int x509_certificate_set_certificate_policies(X509_CERTIFICATE *cert,
	int is_critical,
	const X509_CERTIFICATE_POLICIES *policies);

int x509_certificate_get_certificate_policies(const X509_CERTIFICATE *cert,
	int *is_critical,
	X509_CERTIFICATE_POLICIES *policies);



// Extension 5.  Policy Mappings

/*
   PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
        issuerDomainPolicy      CertPolicyId,
        subjectDomainPolicy     CertPolicyId }
*/
int x509_policy_mapping_to_der(
	int issuer_policy_oid, const uint32_t *issuer_policy_nodes, size_t issuer_policy_nodes_count,
	int subject_policy_oid, const uint32_t *subject_policy_nodes, size_t subject_policy_nodes_count,
	uint8_t **out, size_t *outlen);

int x509_policy_mapping_from_der(
	int *issuer_policy_oid, uint32_t *issuer_policy_nodes, size_t *issuer_policy_nodes_count,
	int *subject_policy_oid, uint32_t *subject_policy_nodes, size_t *subject_policy_nodes_count,
	const uint8_t **in, size_t *inlen);

typedef struct {
	size_t datalen;
	uint8_t data[1024];
} X509_POLICY_MAPPINGS;

int x509_policy_mappings_add_item(X509_POLICY_MAPPINGS *a,
	int issuer_policy_oid, const uint32_t *issuer_policy_nodes, size_t issuer_policy_nodes_count,
	int subject_policy_oid, const uint32_t *subject_policy_nodes, size_t subject_policy_nodes_count);
int x509_policy_mappings_get_next_item(const X509_POLICY_MAPPINGS *a, const uint8_t **next,
	uint32_t *issuer_policy_nodes, size_t *issuer_policy_nodes_count,
	uint32_t *subject_policy_nodes, size_t *subject_policy_nodes_count);

#define x509_policy_mappings_to_der(a,d,dl) \
	asn1_sequence_to_der((a)->data,(a)->datalen,d,dl)

#define x509_policy_mappings_from_der(a,d,dl) \
	asn1_sequence_copy_from_der(1024,(a)->data,&((a)->datalen),d,dl)


int x509_certificate_set_policy_mappings(X509_CERTIFICATE *cert,
	int is_critical,
	const X509_POLICY_MAPPINGS *mappings);

int x509_certificate_get_policy_mappings(const X509_CERTIFICATE *cert,
	int *is_critical,
	X509_POLICY_MAPPINGS *mappings);


// Extension 6 Subject Alternative Names
// SubjectAltName ::= GeneralNames

int x509_certificate_set_subject_alt_name(X509_CERTIFICATE *a,
	int is_critical,
	const X509_GENERAL_NAMES *name);

int x509_certificate_get_subject_alt_name(const X509_CERTIFICATE *a,
	int *is_critical,
	X509_GENERAL_NAMES *name);


// Extension 7  Issuer Alternative Name
// IssuerAltName ::= GeneralNames

int x509_certificate_set_issuer_alt_name(X509_CERTIFICATE *a,
	int is_critical,
	const X509_GENERAL_NAMES *name);

int x509_certificate_get_issuer_alt_name(X509_CERTIFICATE *a,
	int *is_critical,
	X509_GENERAL_NAMES *name);

// Extension 8.  Subject Directory Attributes
/*
SubjectDirectoryAttributes ::= SEQUENCE SIZE (1..MAX) OF Attribute

Attribute       ::=     SEQUENCE {
      type              OBJECT IDENTIFIER,
      values    SET OF AttributeValue }
            -- at least one value is required

	AttributeValue          ::=  ANY

 Conforming CAs MUST mark this extension as non-critical.
*/
int x509_attribute_to_der(
	int oid, const uint32_t *nodes, size_t nodes_count,
	const uint8_t *values, size_t valueslen,
	uint8_t **out, size_t *outlen);
int x509_attribute_from_der(
	int *oid, uint32_t *nodes, size_t *nodes_count,
	const uint8_t **values, size_t *valueslen,
	const uint8_t **in, size_t *inlen);

typedef struct {
	size_t datalen;
	uint8_t data[128];
} X509_ATTRIBUTES;

int x509_attributes_add_item(X509_ATTRIBUTES *a,
	int oid, const uint32_t *nodes, size_t nodes_count,
	const uint8_t *values, size_t valueslen);

int x509_attributes_get_next_item(const X509_ATTRIBUTES *a, const uint8_t **next,
	int *oid, uint32_t *nodes, size_t *nodes_count,
	const uint8_t **data, size_t *datalen);

#define x509_attributes_to_der(a,d,dl) \
	asn1_sequence_to_der((a)->data,(a)->datalen,d,dl)

#define x509_attributes_from_der(a,d,dl) \
	asn1_sequence_copy_from_der(128,(a)->data,&((a)->datalen),d,dl)


int x509_certificate_set_subject_directory_attributes(X509_CERTIFICATE *cert,
	int is_critical,
	const X509_ATTRIBUTES *attrs);

int x509_certificate_get_subject_directory_attributes(const X509_CERTIFICATE *cert,
	int *is_critical,
	X509_ATTRIBUTES *attrs);




// Extension 9.  Basic Constraints
/*
BasicConstraints ::= SEQUENCE {
        cA                      BOOLEAN DEFAULT FALSE,
        pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
*/

int x509_basic_constraints_to_der(int is_ca_cert, // 必须设置为 0 或 1，如果设为 0 那么不编码
	int cert_chain_maxlen, // -1 means omitted，FIXME: 应该设置一个最大值
	uint8_t **out, size_t *outlen);

int x509_basic_constraints_from_der(int *is_ca_cert, int *cert_chain_maxlen, const uint8_t **in, size_t *inlen);

int x509_certificate_set_basic_constraints(X509_CERTIFICATE *cert,
	int is_critical,
	int is_ca_cert,
	int cert_chain_maxlen);

int x509_certificate_get_basic_constraints(const X509_CERTIFICATE *cert,
	int *is_critical,
	int *is_ca_cert,
	int *cert_chain_maxlen);

int x509_basic_constraints_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent);
int x509_key_usage_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent);
int x509_ext_key_usage_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent);
int x509_authority_key_identifier_print(FILE *fp, const uint8_t *data, size_t datalen, int format, int indent);
int x509_policy_constraints_print(FILE *fp, const uint8_t *p, size_t len, int format, int indent);


// Extension 10.  Name Constraints
/*
      NameConstraints ::= SEQUENCE {
           permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
           excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }

      GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree

      GeneralSubtree ::= SEQUENCE {
           base                    GeneralName,
           minimum         [0]     BaseDistance DEFAULT 0,
           maximum         [1]     BaseDistance OPTIONAL }

      BaseDistance ::= INTEGER (0..MAX)
*/
int x509_general_subtree_to_der(
	int base_choise, const uint8_t *base_data, size_t base_datalen,
	int minimum,
	int maximum,
	uint8_t **out, size_t *outlen);
int x509_general_subtree_from_der(
	int *base_choise, const uint8_t **base_data, size_t *base_datalen,
	int *minimum,
	int *maximum,
	const uint8_t **in, size_t *inlen);

typedef struct {
	size_t datalen;
	uint8_t data[128];
} X509_GENERAL_SUBTREES;

int x509_general_subtrees_add_item(X509_GENERAL_SUBTREES *a,
	int base_choise, const uint8_t *base_data, size_t base_datalen,
	int minimum,
	int maximum);
int x509_general_subtrees_get_next_item(const X509_GENERAL_SUBTREES *a, const uint8_t **next,
	int *base_choise, const uint8_t **base_data, size_t *base_datalen,
	int *minimum,
	int *maximum);

int x509_general_subtrees_to_der_ex(int tag, const X509_GENERAL_SUBTREES *a, uint8_t **out, size_t *outlen);
int x509_general_subtrees_from_der_ex(int tag, X509_GENERAL_SUBTREES *a, const uint8_t **in, size_t *inlen);

#define x509_general_subtrees_to_der(a,d,dl) \
	asn1_sequence_to_der((a)->data,(a)->datalen,d,dl)

#define x509_general_subtrees_from_der(a,d,dl) \
	asn1_sequence_copy_from_der(128,(a)->data,&((a)->datalen),d,dl)

int x509_name_constraints_to_der(
	const X509_GENERAL_SUBTREES *permitted_subtrees,
	const X509_GENERAL_SUBTREES *excluded_subtrees,
	uint8_t **out, size_t *outlen);

int x509_name_constraints_from_der(
	X509_GENERAL_SUBTREES *permitted_subtrees,
	X509_GENERAL_SUBTREES *excluded_subtrees,
	const uint8_t **in, size_t *inlen);

int x509_certificate_set_name_constraints(X509_CERTIFICATE *cert,
	int is_critical,
	const X509_GENERAL_SUBTREES *permitted_subtrees,
	const X509_GENERAL_SUBTREES *excluded_subtrees);

int x509_certificate_get_name_constraints(X509_CERTIFICATE *cert,
	int *is_critical,
	X509_GENERAL_SUBTREES *permitted_subtrees,
	X509_GENERAL_SUBTREES *excluded_subtrees);



// Extension 11. Policy Constraints
/*
   PolicyConstraints ::= SEQUENCE {
        requireExplicitPolicy           [0] SkipCerts OPTIONAL,
        inhibitPolicyMapping            [1] SkipCerts OPTIONAL }

   SkipCerts ::= INTEGER (0..MAX)
*/

int x509_policy_constraints_to_der(
	int require_explicit_policy,
	int inhibit_policy_mapping,
	uint8_t **out, size_t *outlen);

int x509_policy_constraints_from_der(
	int *require_explicit_policy,
	int *inhibit_policy_mapping,
	const uint8_t **in, size_t *inlen);

int x509_certificate_set_policy_constraints(X509_CERTIFICATE *cert,
	int is_critical,
	int require_explicit_policy,
	int inhibit_policy_mapping);

int x509_certificate_get_policy_constraints(const X509_CERTIFICATE *cert,
	int *is_critical,
	int *requireExplicitPolicy,
	int *inhibitPolicyMapping);


/*
12.  Extended Key Usage

   ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
   KeyPurposeId ::= OBJECT IDENTIFIER

*/
int x509_key_purpose_from_name(int *oid, const char *name);
const char *x509_key_purpose_name(int oid);
const char *x509_key_purpose_text(int oid);
int x509_key_purpose_to_der(int oid, uint8_t **out, size_t *outlen);
int x509_key_purpose_from_der(int *oid, const uint8_t **in, size_t *inlen);
int x509_ext_key_usage_to_der(const int *oids, size_t oids_count, uint8_t **out, size_t *outlen);
int x509_ext_key_usage_from_der(int *oids, size_t *oids_count, const uint8_t **in, size_t *inlen);

int x509_certificate_set_ext_key_usage(X509_CERTIFICATE *cert,
	int is_critical,
	const int *key_purpose_oids, size_t key_purpose_oids_count);

int x509_certificate_get_ext_key_usage(const X509_CERTIFICATE *cert,
	int *is_critical,
	int *key_purpose_oids, size_t *key_purpose_oids_count);

/*

13. CRL Distribution Points

   CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint

   DistributionPoint ::= SEQUENCE {
        distributionPoint       [0]     DistributionPointName OPTIONAL,
        reasons                 [1]     ReasonFlags OPTIONAL,
        cRLIssuer               [2]     GeneralNames OPTIONAL }

   DistributionPointName ::= CHOICE {
        fullName                [0]     GeneralNames,
        nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }

	由于 GeneralNames 是存储类型，因此 DistributionPointName 也是存储类型

   ReasonFlags ::= BIT STRING {
        unused                  (0),
        keyCompromise           (1),
        cACompromise            (2),
        affiliationChanged      (3),
        superseded              (4),
        cessationOfOperation    (5),
        certificateHold         (6),
        privilegeWithdrawn      (7),
        aACompromise            (8) }
*/
enum {
	X509_rf_unused = 0,
	X509_rf_keyCompromise,
	X509_rf_caCompromise,
	X509_rf_affiliationChanged,
	X509_rf_superseded,
	X509_rf_cessationOfOperation,
	X509_rf_certificateHold,
	X509_rf_privilegeWithdrawn,
	X509_rf_aaCompromise,
};

typedef struct {
	int choice;
	union {
		X509_GENERAL_NAMES full_name;	// [0] IMPLICIT
		X509_RDN relative_name;		// [1] IMPLICIT
	} u;
} X509_DISTRIBUTION_POINT_NAME;

int x509_distribution_point_name_to_der_ex(
	int tag,
	const X509_DISTRIBUTION_POINT_NAME *a,
	uint8_t **out, size_t *outlen);

int x509_distribution_point_name_from_der_ex(
	int tag,
	X509_DISTRIBUTION_POINT_NAME *a,
	const uint8_t **in, size_t *inlen);


int x509_distribution_point_to_der(				// DistributionPoint
	const X509_DISTRIBUTION_POINT_NAME *dist_point_name,	// [0] EXPLICIT OPTIONAL
	int reason_bits,					// [1] IMPLICIT OPTIONAL
	const X509_GENERAL_NAMES *crl_issuer,			// [2] IMPLICIT OPTIONAL
	uint8_t **out, size_t *outlen);

int x509_distribution_point_from_der(
	X509_DISTRIBUTION_POINT_NAME *dist_point_name,
	int *reason_bits,
	X509_GENERAL_NAMES *crl_issuer,
	const uint8_t **in, size_t *inlen);

typedef struct {
	size_t datalen;
	uint8_t data[128];
} X509_CRL_DISTRIBUTION_POINTS;

int x509_crl_distribution_points_add_item(X509_CRL_DISTRIBUTION_POINTS *a,
	const X509_DISTRIBUTION_POINT_NAME *dist_point_name,
	int reason_bits,
	const X509_GENERAL_NAMES *crl_issuer);
int x509_crl_distribution_points_get_next_item(const X509_CRL_DISTRIBUTION_POINTS *a,
	const uint8_t **next,
	X509_DISTRIBUTION_POINT_NAME *distribution_point,
	int *reasons,
	X509_GENERAL_NAMES *crl_issuer);
int x509_crl_distribution_points_to_der(const X509_CRL_DISTRIBUTION_POINTS *a, uint8_t **out, size_t *outlen);
int x509_crl_distribution_points_from_der(X509_CRL_DISTRIBUTION_POINTS *a, const uint8_t **in, size_t *inlen);

int x509_certificate_set_crl_distribution_points(X509_CERTIFICATE *cert,
	int is_critical,
	const X509_CRL_DISTRIBUTION_POINTS *crl_dist_points);

int x509_certificate_get_crl_distribution_points(const X509_CERTIFICATE *cert,
	int *is_critical,
	X509_CRL_DISTRIBUTION_POINTS *crl_dist_points);


/*
14.  Inhibit anyPolicy

   id-ce-inhibitAnyPolicy OBJECT IDENTIFIER ::=  { id-ce 54 }

   InhibitAnyPolicy ::= SkipCerts

   SkipCerts ::= INTEGER (0..MAX)
*/
int x509_certificate_set_inhibit_any_policy(X509_CERTIFICATE *cert,
	int is_critical,
	int skip_certs);
int x509_certificate_get_inhibit_any_policy(const X509_CERTIFICATE *cert,
	int *is_critical,
	int *skip_certs);

/*
15. Freshest CRL (a.k.a. Delta CRL Distribution Point)
FreshestCRL ::= CRLDistributionPoints
*/
int x509_certificate_set_freshest_crl(X509_CERTIFICATE *cert,
	int is_critical,
	const X509_CRL_DISTRIBUTION_POINTS *crl_dist_points);
int x509_certificate_get_freshest_crl(const X509_CERTIFICATE *cert,
	int *is_critical,
	X509_CRL_DISTRIBUTION_POINTS *crl_dist_points);


#define X509_ub_name 32768
#define X509_ub_common_name 64
#define X509_ub_locality_name 128
#define X509_ub_state_name 128
#define X509_ub_organization_name 64
#define X509_ub_organizational_unit_name 64
#define X509_ub_title 64
#define X509_ub_serial_number 64
#define X509_ub_match 128
#define X509_ub_emailaddress_length 255
#define X509_ub_common_name_length 64
#define X509_ub_country_name_alpha_length 2
#define X509_ub_country_name_numeric_length 3
#define X509_ub_domain_defined_attributes 4
#define X509_ub_domain_defined_attribute_type_length 8
#define X509_ub_domain_defined_attribute_value_length 128
#define X509_ub_domain_name_length 16
#define X509_ub_extension_attributes 256
#define X509_ub_e163_4_number_length 15
#define X509_ub_e163_4_sub_address_length 40
#define X509_ub_generation_qualifier_length 3
#define X509_ub_given_name_length 16
#define X509_ub_initials_length 5
#define X509_ub_integer_options 256
#define X509_ub_numeric_user_id_length 32
#define X509_ub_organization_name_length 64
#define X509_ub_organizational_unit_name_length 32
#define X509_ub_organizational_units 4
#define X509_ub_pds_name_length 16
#define X509_ub_pds_parameter_length 30
#define X509_ub_pds_physical_address_lines 6
#define X509_ub_postal_code_length 16
#define X509_ub_pseudonym 128
#define X509_ub_surname_length 40
#define X509_ub_terminal_id_length 24
#define X509_ub_unformatted_address_length 180
#define X509_ub_x121_address_length 16


typedef struct {
	int version;
	X509_NAME subject;
	X509_PUBLIC_KEY_INFO subject_public_key_info;
} X509_CERT_REQUEST_INFO;

int x509_cert_request_info_to_der(const X509_CERT_REQUEST_INFO *a, uint8_t **out, size_t *outlen);
int x509_cert_request_info_from_der(X509_CERT_REQUEST_INFO *a, const uint8_t **in, size_t *inlen);
int x509_cert_request_info_print(FILE *fp, const X509_CERT_REQUEST_INFO *a, int format, int indent);

typedef struct {
	X509_CERT_REQUEST_INFO req_info;
	int signature_algor;
	uint8_t signature[SM2_MAX_SIGNATURE_SIZE];
	size_t signature_len;
} X509_CERT_REQUEST;

int x509_cert_request_set_sm2(X509_CERT_REQUEST *a, const X509_NAME *subject, const SM2_KEY *sm2_key);
int x509_cert_request_sign_sm2(X509_CERT_REQUEST *a, const SM2_KEY *sm2_key);
int x509_cert_request_verify(const X509_CERT_REQUEST *a);
#define x509_cert_request_set(a,subj,pk)  x509_cert_request_set_sm2((a),(subj),(pk))
#define x509_cert_request_sign(a,sk)  x509_cert_request_sign_sm2((a),(sk))

int x509_cert_request_to_der(const X509_CERT_REQUEST *a, uint8_t **out, size_t *outlen);
int x509_cert_request_to_pem(const X509_CERT_REQUEST *a, FILE *fp);
int x509_cert_request_from_der(X509_CERT_REQUEST *a, const uint8_t **in, size_t *inlen);
int x509_cert_request_from_pem(X509_CERT_REQUEST *a, FILE *fp);
int x509_cert_request_print(FILE *fp, const X509_CERT_REQUEST *a, int format, int indent);


#ifdef __cplusplus
}
#endif
#endif
