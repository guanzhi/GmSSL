/*
GM/T 0081-2020 ASN.1 definitions

IdentifierRevocationLists ::= SET OF IdentifierRevocationList

ContentEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier

DigestAlgorithmIdentifier ::= AlgorithmIdentifier

DigestEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier

KeyEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier

Version ::= INTEGER(1)

ContentInfo ::= SEQUENCE {
	contentType	ContentType,
	content		[0] EXPLICIT contentType OPTIONAL
}

ContentType ::= OBJECT IDENTIFIER

Identifier ::= SEQUENCE {
	version		EXPLICIT VERSION DEFAULT v1,
	ibcType		OBJECT IDENTIFIER,
	ibcTypeAlias	[0] OCTET STRING OPTIONAL,
	identityData	OCTET STRING,
	validStart	UTCTIME,
	validEnd	[1] UTCTIME OPTIONAL,
	extensions	[2] Extensions OPTIONAL
}

Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension

Extension ::= SEQUENCE {
	extnID		OBJECT IDENTIFIER,
	critical	BOOLEAN DEFAULT FALSE,
	extnValue	OCTET STRING
}

DistricInfo ::= SEQUENCE {
	district	IA5String,
	districtNo	INTEGER,
}

Validity ::= SEQUENCE {
	notBefore	Time,
	notAfter	Time,
	Time ::= CHOICE {
		utcTime		UTCTime,
		generalTime	GeneralizedTime
	}
}

IBCSysParamsPublishInfo ::= SEQUENCE {
	ibcSysParams		IBCSysParams,
	signatureAlgorithm	OBJECT IDENTIFIER,
	signatureValue		BIT STRING
}

AlgorithmIdentifier ::= SEQUENCE {
	Algorithm	OBJECT IDENTIFIER,
	Parameters	ANY DEFINED BY algorithm OPTIONAL
}

BeSignParamsPubInfo ::= SEQUENCE {
	ibcSysParams		IBCSysParams,
	signatureAlgorithm	OBJECT IDENTIFIER
}

IDAppAttr ::= SEQUENCE {
	versoin			Version DEFAULT v1,
	serialNumber		IdentifierSerialNumber,
	subjectId		Identifier,
	sysParamsPublishInfo	IBCSysParamsPublishInfo,
	extensions		[0] EXPLICIT Externsions OPTIONAL
}

version ::= INTEGER { v1(0) }

IdentifierSerialNumber ::= INTEGER

Externsions ::= SEQUENCE SIZE (1..MAX) OF Extension

Data ::= OCTET STRING

SignedData ::= SEQUENCE {
	version				Version,
	digestAlgorithms		DigestAlgorithmIdentifiers,
	contentInfo			ContentInfo,
	ibcSysParamsPublishInfos	[0] IMPLICIT IBCSysParamsPublishInfos OPTIONAL,
	irls				[1] IMPLICIT IdentifierRevocationLists OPTIONAL,
	signerInfos			SignerInfos
}

IBCSysParamsPublishInfos ::= SET OF IBCSysParamsPublishInfo

DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier

SignerInfos ::= SET OF SignerInfo

SignerInfo ::= SEQUENCE {
	version				Version,
	issuerIdentifier		Identifier,
	digestAlgorithm			DigestAlgorithmIdentifier,
	authenticatedAttributes		[0] IMPLICIT Attributes OPTIONAL,
	digestEncryptionAlgorithm	DigestEncryptionAlgorithmIdentifier,
	encryptedDigest			SM9Signature,
	unauthenticatedAttributes	[1] IMPLICIT Attributes OPTIONAL
}

EnvelopedData ::= SEQUENCE {
	version			Version,
	recipientInfos		RecipientInfos,
	encryptedContentInfo	EncryptedContentInfo
}

RecipientInfos ::= SET OF RecipientInfo

EncryptedContentInfo ::= SEQUENCE {
	contentType			ContentType,
	contentEncryptionAlgorithm	ContentEncryptionAlgorithmIdentifier,
	sharedInfo			[0] OCTET STRING OPTIONAL,
	sharedInfo2			[1] OCTET STRING OPTIONAL,
	encryptedContent		[2] IMPLICIT EncryptedContent OPTIONAL
}

EncryptedContent ::= OCTET STRING

RecipientInfo ::= SEQUENCE {
	Version			Version,
	issuerIdentifier	Identifier,
	keyEncryptionAlgorithm	KeyEncryptionAlgorithmIdentifier,
	encryptedKey		SM9cipher
}

SignedAndEnvelopedData ::= SEQUENCE {
	version			Version,
	recipientInfos		RecipientInfos,
	digestAlgorithms	DigestAlgorithmIdentifiers,
	encryptedContentInfo	EncryptedContentInfo,
	idAppAttrInfos		[0] IMPLICIT IDAppAttrInfos OPTIONAL,
	irls			[1] IMPLICIT IdentifierRevocationLists OPTIONAL,
	signerInfos		SignerInfos
}

EncryptedData ::= SEQUENCE {
	Version			Version,
	encryptedContentInfo	EncryptedContentInfo
}

//-- 这之后的类型都需要实现
KeyAgreementInfo ::= SEQUENCE {						
	version	Version(1),
	tempKey	SM9MastEncryptPublicKey,
	userIDA	OCTET STRING
	userIDB	OCTET STRING
	hid	OCTET STRING
}

IdentifierRevocationList ::= SEQUENCE {					
	tbsIdList	TBSIdList,
	signInfos	SignerInfos
}

TBSIdList ::= SEQUENCE {						
	Version(1)		Version,
	signatureOID		AlgorithmIdentifier,
	issuerIdentifier	Identifier,
	thisUpdate		GeneralizedTime,
	nextUpdate		[0] GeneralizedTime OPTIONAL,
	revokedIds		RevokedIds,
	irlExtensions		[1] EXPLICIT Extensions OPTIONAL
}

Version ::= INTEGER(1)

RevokedIds ::= SEQUENCE OF RevokedId

RevokedId ::= SEQUENCE {
	id			OCTET STRING,
	revocationDate		GeneralizedTime,
	IrlEntryExtensions	[0] Extensions OPTIONAL
}

IBCSysParams ::= SEQUENCE {							
	version			INTEGER { v2(2) },
	districtName		IA5String,
	districtSerial		INTEGER,
	validity		ValidityPeriod,
	ibcPublicParameters	IBCPublicParameters,
	ibcIdentityType		OBJECT IDENTIFIER,
	issuerID		Identifier,
	ibcParamExtensions	IBCParamExtensions OPTIONAL
}

IBCPublicParameters ::= SEQUENCE (1..MAX) OF IBCPublicParameter		

IBCPublicParameter ::= SEQUENCE {
	ibcAlgorithm		OBJECT IDENTIFIER,
	publicParameterData	OCTET STRING
}

SM9PublicParameterData ::= SEQUENCE {
	pkgID			OCTET STRING,
	encMastPublicKey	SM9EncryptMasterPublicKey,
	signMastPublicKey	SM9SignMasterPublicKey
}

IBCParamExtensions ::= SEQUENCE OF IBCParamExtension

IBCParamExtension ::= SEQUENCE {
	ibcParamExtensionOID	OBJECT IDENTIFIER,
	ibcParamExtensionValue	OCTET STRING
}

IbcParamExt OBJECT IDENTIFIER ::= {
	ibcs	ibcs3(3)	parameter-extensions(2)
}
*/

#include <time.h>
#include <stdint.h>
#include <stdio.h>
#include <gmssl/asn1.h>
#include <gmssl/sm9.h>
#include <gmssl/x509.h>
#include <gmssl/error.h>


int sm9_cms_algorithm_identifier_to_der(
	const uint32_t *algorithm, size_t algorithm_cnt,
	const uint8_t *parameters, size_t parameters_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (asn1_object_identifier_to_der(algorithm, algorithm_cnt, NULL, &len) != 1
		|| asn1_any_to_der(parameters, parameters_len, NULL, &len) < 0
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_object_identifier_to_der(algorithm, algorithm_cnt, out, outlen) != 1
		|| asn1_any_to_der(parameters, parameters_len, out, outlen) < 0) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_cms_algorithm_identifier_from_der(
	uint32_t *algorithm, size_t *algorithm_cnt,
	const uint8_t **parameters, size_t *parameters_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	*parameters = NULL;
	*parameters_len = 0;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_object_identifier_from_der(algorithm, algorithm_cnt, &d, &dlen) != 1
		|| asn1_any_from_der(parameters, parameters_len, &d, &dlen) < 0
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_cms_extensions_to_der(const uint8_t *extensions, size_t extensions_len,
	uint8_t **out, size_t *outlen)
{
	if (asn1_sequence_of_to_der(extensions, extensions_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_cms_extensions_from_der(const uint8_t **extensions, size_t *extensions_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;

	if ((ret = asn1_sequence_of_from_der(extensions, extensions_len, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	return 1;
}

int sm9_cms_explicit_extensions_to_der(int index,
	const uint8_t *extensions, size_t extensions_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (!extensions) {
		return 0;
	}
	if (sm9_cms_extensions_to_der(extensions, extensions_len, NULL, &len) != 1
		|| asn1_explicit_header_to_der(index, len, out, outlen) != 1
		|| sm9_cms_extensions_to_der(extensions, extensions_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_cms_explicit_extensions_from_der(int index,
	const uint8_t **extensions, size_t *extensions_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_explicit_from_der(index, &d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		else {
			*extensions = NULL;
			*extensions_len = 0;
		}
		return ret;
	}
	if (sm9_cms_extensions_from_der(extensions, extensions_len, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_cms_implicit_extensions_to_der(int index,
	const uint8_t *extensions, size_t extensions_len,
	uint8_t **out, size_t *outlen)
{
	if (!extensions) {
		return 0;
	}
	if (asn1_implicit_sequence_to_der(index, extensions, extensions_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_cms_implicit_extensions_from_der(int index,
	const uint8_t **extensions, size_t *extensions_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;

	if ((ret = asn1_implicit_sequence_from_der(index, extensions, extensions_len, in, inlen)) < 0) {
		error_print();
		return -1;
	}
	return ret;
}

int sm9_cms_key_agreement_info_to_der(
	int version,
	const SM9_ENC_MASTER_KEY *temp_key,
	const uint8_t *user_id_a, size_t user_id_a_len,
	const uint8_t *user_id_b, size_t user_id_b_len,
	const uint8_t *hid, size_t hid_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (version != 1) {
		error_print();
		return -1;
	}
	if (asn1_int_to_der(version, NULL, &len) != 1
		|| sm9_enc_master_public_key_to_der(temp_key, NULL, &len) != 1
		|| asn1_octet_string_to_der(user_id_a, user_id_a_len, NULL, &len) != 1
		|| asn1_octet_string_to_der(user_id_b, user_id_b_len, NULL, &len) != 1
		|| asn1_octet_string_to_der(hid, hid_len, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(version, out, outlen) != 1
		|| sm9_enc_master_public_key_to_der(temp_key, out, outlen) != 1
		|| asn1_octet_string_to_der(user_id_a, user_id_a_len, out, outlen) != 1
		|| asn1_octet_string_to_der(user_id_b, user_id_b_len, out, outlen) != 1
		|| asn1_octet_string_to_der(hid, hid_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_cms_key_agreement_info_from_der(
	int *version,
	SM9_ENC_MASTER_KEY *temp_key,
	const uint8_t **user_id_a, size_t *user_id_a_len,
	const uint8_t **user_id_b, size_t *user_id_b_len,
	const uint8_t **hid, size_t *hid_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_int_from_der(version, &d, &dlen) != 1
		|| sm9_enc_master_public_key_from_der(temp_key, &d, &dlen) != 1
		|| asn1_octet_string_from_der(user_id_a, user_id_a_len, &d, &dlen) != 1
		|| asn1_octet_string_from_der(user_id_b, user_id_b_len, &d, &dlen) != 1
		|| asn1_octet_string_from_der(hid, hid_len, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	if (*version != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_cms_revoked_id_to_der(
	const uint8_t *id, size_t id_len,
	time_t revocation_date,
	const uint8_t *irl_entry_extensions, size_t irl_entry_extensions_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (asn1_octet_string_to_der(id, id_len, NULL, &len) != 1
		|| asn1_generalized_time_to_der(revocation_date, NULL, &len) != 1
		|| sm9_cms_implicit_extensions_to_der(0, irl_entry_extensions, irl_entry_extensions_len, NULL, &len) < 0
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_octet_string_to_der(id, id_len, out, outlen) != 1
		|| asn1_generalized_time_to_der(revocation_date, out, outlen) != 1
		|| sm9_cms_implicit_extensions_to_der(0, irl_entry_extensions, irl_entry_extensions_len, out, outlen) < 0) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_cms_revoked_id_from_der(
	const uint8_t **id, size_t *id_len,
	time_t *revocation_date,
	const uint8_t **irl_entry_extensions, size_t *irl_entry_extensions_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_octet_string_from_der(id, id_len, &d, &dlen) != 1
		|| asn1_generalized_time_from_der(revocation_date, &d, &dlen) != 1
		|| sm9_cms_implicit_extensions_from_der(0, irl_entry_extensions, irl_entry_extensions_len, &d, &dlen) < 0
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_cms_revoked_ids_to_der(const uint8_t *revoked_ids, size_t revoked_ids_len,
	uint8_t **out, size_t *outlen)
{
	if (asn1_sequence_of_to_der(revoked_ids, revoked_ids_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_cms_revoked_ids_from_der(const uint8_t **revoked_ids, size_t *revoked_ids_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;

	if ((ret = asn1_sequence_of_from_der(revoked_ids, revoked_ids_len, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	return 1;
}

int sm9_cms_tbs_id_list_to_der(
	int version,
	const uint32_t *signature_oid, size_t signature_oid_cnt,
	const uint8_t *signature_params, size_t signature_params_len,
	const uint8_t *issuer_identifier, size_t issuer_identifier_len,
	time_t this_update, time_t next_update,
	const uint8_t *revoked_ids, size_t revoked_ids_len,
	const uint8_t *irl_extensions, size_t irl_extensions_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (version != 1) {
		error_print();
		return -1;
	}
	if (asn1_int_to_der(version, NULL, &len) != 1
		|| sm9_cms_algorithm_identifier_to_der(signature_oid, signature_oid_cnt,
			signature_params, signature_params_len, NULL, &len) != 1
		|| asn1_any_to_der(issuer_identifier, issuer_identifier_len, NULL, &len) != 1
		|| asn1_generalized_time_to_der(this_update, NULL, &len) != 1
		|| asn1_implicit_generalized_time_to_der(0, next_update, NULL, &len) < 0
		|| sm9_cms_revoked_ids_to_der(revoked_ids, revoked_ids_len, NULL, &len) != 1
		|| sm9_cms_explicit_extensions_to_der(1, irl_extensions, irl_extensions_len, NULL, &len) < 0
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(version, out, outlen) != 1
		|| sm9_cms_algorithm_identifier_to_der(signature_oid, signature_oid_cnt,
			signature_params, signature_params_len, out, outlen) != 1
		|| asn1_any_to_der(issuer_identifier, issuer_identifier_len, out, outlen) != 1
		|| asn1_generalized_time_to_der(this_update, out, outlen) != 1
		|| asn1_implicit_generalized_time_to_der(0, next_update, out, outlen) < 0
		|| sm9_cms_revoked_ids_to_der(revoked_ids, revoked_ids_len, out, outlen) != 1
		|| sm9_cms_explicit_extensions_to_der(1, irl_extensions, irl_extensions_len, out, outlen) < 0) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_cms_tbs_id_list_from_der(
	int *version,
	uint32_t *signature_oid, size_t *signature_oid_cnt,
	const uint8_t **signature_params, size_t *signature_params_len,
	const uint8_t **issuer_identifier, size_t *issuer_identifier_len,
	time_t *this_update, time_t *next_update,
	const uint8_t **revoked_ids, size_t *revoked_ids_len,
	const uint8_t **irl_extensions, size_t *irl_extensions_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_int_from_der(version, &d, &dlen) != 1
		|| sm9_cms_algorithm_identifier_from_der(signature_oid, signature_oid_cnt,
			signature_params, signature_params_len, &d, &dlen) != 1
		|| asn1_any_from_der(issuer_identifier, issuer_identifier_len, &d, &dlen) != 1
		|| asn1_generalized_time_from_der(this_update, &d, &dlen) != 1
		|| asn1_implicit_generalized_time_from_der(0, next_update, &d, &dlen) < 0
		|| sm9_cms_revoked_ids_from_der(revoked_ids, revoked_ids_len, &d, &dlen) != 1
		|| sm9_cms_explicit_extensions_from_der(1, irl_extensions, irl_extensions_len, &d, &dlen) < 0
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	if (*version != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_cms_signer_infos_to_der(const uint8_t *signer_infos, size_t signer_infos_len,
	uint8_t **out, size_t *outlen)
{
	if (asn1_set_of_to_der(signer_infos, signer_infos_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_cms_signer_infos_from_der(const uint8_t **signer_infos, size_t *signer_infos_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;

	if ((ret = asn1_set_of_from_der(signer_infos, signer_infos_len, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	return 1;
}

int sm9_cms_identifier_revocation_list_to_der(
	const uint8_t *tbs_id_list, size_t tbs_id_list_len,
	const uint8_t *signer_infos, size_t signer_infos_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (asn1_any_to_der(tbs_id_list, tbs_id_list_len, NULL, &len) != 1
		|| sm9_cms_signer_infos_to_der(signer_infos, signer_infos_len, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_any_to_der(tbs_id_list, tbs_id_list_len, out, outlen) != 1
		|| sm9_cms_signer_infos_to_der(signer_infos, signer_infos_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_cms_identifier_revocation_list_from_der(
	const uint8_t **tbs_id_list, size_t *tbs_id_list_len,
	const uint8_t **signer_infos, size_t *signer_infos_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_any_from_der(tbs_id_list, tbs_id_list_len, &d, &dlen) != 1
		|| sm9_cms_signer_infos_from_der(signer_infos, signer_infos_len, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_cms_validity_period_to_der(time_t not_before, time_t not_after,
	uint8_t **out, size_t *outlen)
{
	return x509_validity_to_der(not_before, not_after, out, outlen);
}

int sm9_cms_validity_period_from_der(time_t *not_before, time_t *not_after,
	const uint8_t **in, size_t *inlen)
{
	return x509_validity_from_der(not_before, not_after, in, inlen);
}

int sm9_cms_ibc_public_parameter_to_der(
	const uint32_t *ibc_algorithm, size_t ibc_algorithm_cnt,
	const uint8_t *public_parameter_data, size_t public_parameter_data_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (asn1_object_identifier_to_der(ibc_algorithm, ibc_algorithm_cnt, NULL, &len) != 1
		|| asn1_octet_string_to_der(public_parameter_data, public_parameter_data_len, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_object_identifier_to_der(ibc_algorithm, ibc_algorithm_cnt, out, outlen) != 1
		|| asn1_octet_string_to_der(public_parameter_data, public_parameter_data_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_cms_ibc_public_parameter_from_der(
	uint32_t *ibc_algorithm, size_t *ibc_algorithm_cnt,
	const uint8_t **public_parameter_data, size_t *public_parameter_data_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_object_identifier_from_der(ibc_algorithm, ibc_algorithm_cnt, &d, &dlen) != 1
		|| asn1_octet_string_from_der(public_parameter_data, public_parameter_data_len, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_cms_ibc_public_parameters_to_der(
	const uint8_t *ibc_public_parameters, size_t ibc_public_parameters_len,
	uint8_t **out, size_t *outlen)
{
	if (asn1_sequence_of_to_der(ibc_public_parameters, ibc_public_parameters_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_cms_ibc_public_parameters_from_der(
	const uint8_t **ibc_public_parameters, size_t *ibc_public_parameters_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;

	if ((ret = asn1_sequence_of_from_der(ibc_public_parameters, ibc_public_parameters_len, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	return 1;
}

int sm9_cms_sm9_public_parameter_data_to_der(
	const uint8_t *pkg_id, size_t pkg_id_len,
	const SM9_ENC_MASTER_KEY *enc_mast_public_key,
	const SM9_SIGN_MASTER_KEY *sign_mast_public_key,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (asn1_octet_string_to_der(pkg_id, pkg_id_len, NULL, &len) != 1
		|| sm9_enc_master_public_key_to_der(enc_mast_public_key, NULL, &len) != 1
		|| sm9_sign_master_public_key_to_der(sign_mast_public_key, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_octet_string_to_der(pkg_id, pkg_id_len, out, outlen) != 1
		|| sm9_enc_master_public_key_to_der(enc_mast_public_key, out, outlen) != 1
		|| sm9_sign_master_public_key_to_der(sign_mast_public_key, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_cms_sm9_public_parameter_data_from_der(
	const uint8_t **pkg_id, size_t *pkg_id_len,
	SM9_ENC_MASTER_KEY *enc_mast_public_key,
	SM9_SIGN_MASTER_KEY *sign_mast_public_key,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_octet_string_from_der(pkg_id, pkg_id_len, &d, &dlen) != 1
		|| sm9_enc_master_public_key_from_der(enc_mast_public_key, &d, &dlen) != 1
		|| sm9_sign_master_public_key_from_der(sign_mast_public_key, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_cms_ibc_param_extension_to_der(
	const uint32_t *ibc_param_extension_oid, size_t ibc_param_extension_oid_cnt,
	const uint8_t *ibc_param_extension_value, size_t ibc_param_extension_value_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (asn1_object_identifier_to_der(ibc_param_extension_oid, ibc_param_extension_oid_cnt, NULL, &len) != 1
		|| asn1_octet_string_to_der(ibc_param_extension_value, ibc_param_extension_value_len, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_object_identifier_to_der(ibc_param_extension_oid, ibc_param_extension_oid_cnt, out, outlen) != 1
		|| asn1_octet_string_to_der(ibc_param_extension_value, ibc_param_extension_value_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_cms_ibc_param_extension_from_der(
	uint32_t *ibc_param_extension_oid, size_t *ibc_param_extension_oid_cnt,
	const uint8_t **ibc_param_extension_value, size_t *ibc_param_extension_value_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_object_identifier_from_der(ibc_param_extension_oid, ibc_param_extension_oid_cnt, &d, &dlen) != 1
		|| asn1_octet_string_from_der(ibc_param_extension_value, ibc_param_extension_value_len, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_cms_ibc_param_extensions_to_der(
	const uint8_t *ibc_param_extensions, size_t ibc_param_extensions_len,
	uint8_t **out, size_t *outlen)
{
	if (!ibc_param_extensions) {
		return 0;
	}
	if (asn1_sequence_of_to_der(ibc_param_extensions, ibc_param_extensions_len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_cms_ibc_param_extensions_from_der(
	const uint8_t **ibc_param_extensions, size_t *ibc_param_extensions_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;

	if ((ret = asn1_sequence_of_from_der(ibc_param_extensions, ibc_param_extensions_len, in, inlen)) < 0) {
		error_print();
		return -1;
	}
	return ret;
}

int sm9_cms_ibc_sys_params_to_der(
	int version,
	const char *district_name, size_t district_name_len,
	int district_serial,
	time_t not_before, time_t not_after,
	const uint8_t *ibc_public_parameters, size_t ibc_public_parameters_len,
	const uint32_t *ibc_identity_type, size_t ibc_identity_type_cnt,
	const uint8_t *issuer_id, size_t issuer_id_len,
	const uint8_t *ibc_param_extensions, size_t ibc_param_extensions_len,
	uint8_t **out, size_t *outlen)
{
	size_t len = 0;

	if (version != 2) {
		error_print();
		return -1;
	}
	if (asn1_int_to_der(version, NULL, &len) != 1
		|| asn1_ia5_string_to_der(district_name, district_name_len, NULL, &len) != 1
		|| asn1_int_to_der(district_serial, NULL, &len) != 1
		|| sm9_cms_validity_period_to_der(not_before, not_after, NULL, &len) != 1
		|| sm9_cms_ibc_public_parameters_to_der(ibc_public_parameters, ibc_public_parameters_len, NULL, &len) != 1
		|| asn1_object_identifier_to_der(ibc_identity_type, ibc_identity_type_cnt, NULL, &len) != 1
		|| asn1_any_to_der(issuer_id, issuer_id_len, NULL, &len) != 1
		|| sm9_cms_ibc_param_extensions_to_der(ibc_param_extensions, ibc_param_extensions_len, NULL, &len) < 0
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(version, out, outlen) != 1
		|| asn1_ia5_string_to_der(district_name, district_name_len, out, outlen) != 1
		|| asn1_int_to_der(district_serial, out, outlen) != 1
		|| sm9_cms_validity_period_to_der(not_before, not_after, out, outlen) != 1
		|| sm9_cms_ibc_public_parameters_to_der(ibc_public_parameters, ibc_public_parameters_len, out, outlen) != 1
		|| asn1_object_identifier_to_der(ibc_identity_type, ibc_identity_type_cnt, out, outlen) != 1
		|| asn1_any_to_der(issuer_id, issuer_id_len, out, outlen) != 1
		|| sm9_cms_ibc_param_extensions_to_der(ibc_param_extensions, ibc_param_extensions_len, out, outlen) < 0) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_cms_ibc_sys_params_from_der(
	int *version,
	const char **district_name, size_t *district_name_len,
	int *district_serial,
	time_t *not_before, time_t *not_after,
	const uint8_t **ibc_public_parameters, size_t *ibc_public_parameters_len,
	uint32_t *ibc_identity_type, size_t *ibc_identity_type_cnt,
	const uint8_t **issuer_id, size_t *issuer_id_len,
	const uint8_t **ibc_param_extensions, size_t *ibc_param_extensions_len,
	const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_int_from_der(version, &d, &dlen) != 1
		|| asn1_ia5_string_from_der(district_name, district_name_len, &d, &dlen) != 1
		|| asn1_int_from_der(district_serial, &d, &dlen) != 1
		|| sm9_cms_validity_period_from_der(not_before, not_after, &d, &dlen) != 1
		|| sm9_cms_ibc_public_parameters_from_der(ibc_public_parameters, ibc_public_parameters_len, &d, &dlen) != 1
		|| asn1_object_identifier_from_der(ibc_identity_type, ibc_identity_type_cnt, &d, &dlen) != 1
		|| asn1_any_from_der(issuer_id, issuer_id_len, &d, &dlen) != 1
		|| sm9_cms_ibc_param_extensions_from_der(ibc_param_extensions, ibc_param_extensions_len, &d, &dlen) < 0
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	if (*version != 2) {
		error_print();
		return -1;
	}
	return 1;
}
