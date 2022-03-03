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

/*
References:
  1. GM/T 0010-2012 SM2 Cryptography Message Syntax Specification
  2. RFC 2315 PKCS #7 Cryptographic Message Syntax Version 1.5
  3. RFC 5652 Cryptographic Message Syntax (CMS)
*/

#ifndef GMSSL_CMS_H
#define GMSSL_CMS_H


#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <gmssl/x509.h>


#ifdef __cplusplus
extern "C" {
#endif


/*
ContentType:
	OID_cms_data
	OID_cms_signed_data
	OID_cms_enveloped_data
	OID_cms_signed_and_enveloped_data
	OID_cms_encrypted_data
	OID_cms_key_agreement_info
*/
const char *cms_content_type_name(int oid);
int cms_content_type_from_name(const char *name);
int cms_content_type_to_der(int oid, uint8_t **out, size_t *outlen);
int cms_content_type_from_der(int *oid, const uint8_t **in, size_t *inlen);

/*
ContentInfo ::= SEQUENCE {
	contentType	OBJECT IDENTIFIER,
	content		[0] EXPLICIT ANY OPTIONAL }
*/
int cms_content_info_to_der(
	int content_type,
	const uint8_t *content, size_t content_len,
	uint8_t **out, size_t *outlen);
int cms_content_info_from_der(
	int *content_type,
	const uint8_t **content, size_t *content_len, // 这里获得的是完整的TLV
	const uint8_t **in, size_t *inlen);
int cms_content_info_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

/*
Data ::= OCTET STRING
*/
#define cms_data_to_der(d,dlen,out,outlen) asn1_octet_string_to_der(d,dlen,out,outlen)
#define cms_data_from_der(d,dlen,in,inlen) asn1_octet_string_from_der(d,dlen,in,inlen)
#define cms_data_print(fp,fmt,ind,label,d,dlen) format_bytes(fp,fmt,ind,label,d,dlen)

/*
EncryptedContentInfo ::= SEQUENCE {
	contentType			OBJECT IDENTIFIER,
	contentEncryptionAlgorithm	AlgorithmIdentifier,
	encryptedContent		[0] IMPLICIT OCTET STRING OPTIONAL,
	sharedInfo1			[1] IMPLICIT OCTET STRING OPTIONAL,
	sharedInfo2			[2] IMPLICIT OCTET STRING OPTIONAL }
*/
int cms_enced_content_info_to_der(
	int content_type,
	int enc_algor, const uint8_t *enc_iv, size_t enc_iv_len,
	const uint8_t *enced_content, size_t enced_content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	uint8_t **out, size_t *outlen);
int cms_enced_content_info_from_der(
	int *content_type,
	int *enc_algor, const uint8_t **enc_iv, size_t *enc_iv_len,
	const uint8_t **enced_content, size_t *enced_content_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len,
	const uint8_t **in, size_t *inlen);
int cms_enced_content_info_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

int cms_enced_content_info_encrypt_to_der(
	int content_type,
	int enc_algor, const uint8_t *iv, size_t ivlen,
	const uint8_t *content, size_t content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	const uint8_t *key, size_t keylen,
	uint8_t **out, size_t *outlen);
int cms_enced_content_info_decrypt_from_der(
	int *content_type,
	int *enc_algor, const uint8_t **iv, size_t *ivlen,
	uint8_t *content, size_t *content_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len,
	const uint8_t *key, size_t keylen,
	const uint8_t **in, size_t *inlen);

/*
EncryptedData ::= SEQUENCE {
	version			INTEGER (1),
	encryptedContentInfo	EncryptedContentInfo }
*/
int cms_encrypted_data_to_der(
	int version,
	int content_type,
	int enc_algor, const uint8_t *iv, size_t ivlen,
	const uint8_t *enced_content, size_t enced_content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	uint8_t **out, size_t *outlen);
int cms_encrypted_data_from_der(
	int *version,
	int *content_type,
	int *enc_algor, const uint8_t **iv, size_t *ivlen,
	const uint8_t **enced_content, size_t *enced_content_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len,
	const uint8_t **in, size_t *inlen);
int cms_encrypted_data_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

int cms_encrypted_data_encrypt_to_der(
	int version,
	int content_type,
	int enc_algor, const uint8_t *iv, size_t ivlen,
	const uint8_t *content, size_t content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	const uint8_t *key, size_t keylen,
	uint8_t **out, size_t *outlen);
int cms_encrypted_data_decrypt_from_der(
	int *version,
	int *content_type,
	int *enc_algor, const uint8_t **iv, size_t *ivlen,
	uint8_t *content, size_t *content_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len,
	const uint8_t *key, size_t keylen,
	const uint8_t **in, size_t *inlen);

/*
IssuerAndSerialNumber ::= SEQUENCE {
	isser		Name,
	serialNumber	INTEGER }
*/
int cms_issuer_and_serial_number_to_der(
	const uint8_t *issuer, size_t issuer_len,
	const uint8_t *serial_number, size_t serial_number_len,
	uint8_t **out, size_t *outlen);
int cms_issuer_and_serial_number_from_der(
	const uint8_t **issuer, size_t *issuer_len,
	const uint8_t **serial_number, size_t *serial_number_len,
	const uint8_t **in, size_t *inlen);
int cms_issuer_and_serial_number_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

/*
SignerInfo ::= SEQUENCE {
	version				INTEGER (1),
	issuerAndSerialNumber		IssuerAndSerialNumber,
	digestAlgorithm			AlgorithmIdentifier,
	authenticatedAttributes		[0] IMPLICIT SET OF Attribute OPTINOAL,
	digestEncryptionAlgorithm	AlgorithmIdentifier,
	encryptedDigest			OCTET STRING,
	unauthenticatedAttributes       [1] IMPLICIT SET OF Attribute OPTINOAL, }
*/
int cms_signer_info_to_der(
	int version,
	const uint8_t *issuer, size_t issuer_len,
	const uint8_t *serial_number, size_t serial_number_len,
	int digest_algor,
	const uint8_t *authed_attrs, size_t authed_attrs_len,
	int signature_algor,
	const uint8_t *enced_digest, size_t enced_digest_len,
	const uint8_t *unauthed_attrs, size_t unauthed_attrs_len,
	uint8_t **out, size_t *outlen);
int cms_signer_info_from_der(
	int *version,
	const uint8_t **issuer, size_t *issuer_len,
	const uint8_t **serial_number, size_t *serial_number_len,
	int *digest_algor,
	const uint8_t **authed_attrs, size_t *authed_attrs_len,
	int *signature_algor,
	const uint8_t **enced_digest, size_t *enced_digest_len,
	const uint8_t **unauthed_attrs, size_t *unauthed_attrs_len,
	const uint8_t **in, size_t *inlen);
int cms_signer_info_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

int cms_signer_info_sign_to_der(
	int version,
	const uint8_t *issuer, size_t issuer_len,
	const uint8_t *serial_number, size_t serial_number_len,
	const uint8_t *authed_attrs, size_t authed_attrs_len,
	const uint8_t *unauthed_attrs, size_t unauthed_attrs_len,
	const SM3_CTX *sm3_ctx, const SM2_KEY *sign_key,
	uint8_t **out, size_t *outlen);
int cms_signer_info_verify_from_der(
	int *version,
	const uint8_t **issuer, size_t *issuer_len,
	const uint8_t **serial_number, size_t *serial_number_len,
	int *digest_algor,
	const uint8_t **authed_attrs, size_t *authed_attrs_len,
	int *signature_algor,
	const uint8_t **enced_digest, size_t *enced_digest_len,
	const uint8_t **unauthed_attrs, size_t *unauthed_attrs_len,
	const SM3_CTX *sm3_ctx, const SM2_KEY *sign_pub_key,
	const uint8_t **in, size_t *inlen);

/*
SignerInfos ::= SET OF SignerInfo;
*/
int cms_signer_infos_add_signer_info(
	uint8_t *d, size_t *dlen, size_t maxlen,
	int version,
	const uint8_t *issuer, size_t issuer_len,
	const uint8_t *serial_number, size_t serial_number_len,
	const uint8_t *authed_attrs, size_t authed_attrs_len,
	const uint8_t *unauthed_attrs, size_t unauthed_attrs_len,
	const SM3_CTX *sm3_ctx, const SM2_KEY *sign_key);

#define cms_signer_infos_to_der(d,dlen,out,outlen) asn1_set_to_der(d,dlen,out,outlen)
#define cms_signer_infos_from_der(d,dlen,in,inlen) asn1_set_from_der(d,dlen,in,inlen)
int cms_signer_infos_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

/*
CertificateRevocationLists ::= SET OF CertificateRevocationList
*/
int cms_crls_add_crl(uint8_t *d, size_t *dlen, size_t maxlen, const uint8_t *crl, size_t crllen);
#define cms_crls_to_der(d,dlen,out,outlen) asn1_set_to_der(d,dlen,out,outlen)
#define cms_crls_from_der(d,dlen,in,inlen) asn1_set_from_der(d,dlen,in,inlen)
int cms_crls_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

/*
ExtendedCertificateAndCertificate ::= CHOICE {
	certificate		Certificate,
	extendedCertificate	[0] IMPLICIT ExtendedCertificate }

ExtendedCertificatesAndCertificates ::= SET OF
	ExtendedCertificateOrCertificate

ExtendedCertificate is supported in print, not in add/to/from
*/
int cms_extened_certs_add_cert(uint8_t *d, size_t *dlen, size_t maxlen, const uint8_t *cert, size_t certlen);
#define cms_extened_certs_to_der(d,dlen,out,outlen) asn1_set_to_der(d,dlen,out,outlen)
#define cms_extened_certs_from_der(d,dlen,in,inlen) asn1_set_from_der(d,dlen,in,inlen)
int cms_extended_certs_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

int cms_digest_algors_to_der(const int *digest_algors, size_t digest_algors_cnt, uint8_t **out, size_t *outlen);
int cms_digest_algors_from_der(int *digest_algors, size_t *digest_algors_cnt, size_t max_digest_algors,
	const uint8_t **in, size_t *inlen);
int cms_digest_algors_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

/*
SignedData ::= SEQUENCE {
	version			INTEGER (1),
	digestAlgorithms	SET OF AlgorithmIdentifier,
	contentInfo		ContentInfo,
	certificates		[0] IMPLICIT SET OF Certificate OPTIONAL,
	crls			[1] IMPLICIT SET OF CertificateRevocationList OPTIONAL,
	signerInfos		SET OF SignerInfo }
*/
int cms_signed_data_to_der(
	int version,
	const int *digest_algors, size_t digest_algors_cnt,
	const int content_type, const uint8_t *content, const size_t content_len,
	const uint8_t *certs, size_t certs_len,
	const uint8_t *crls, const size_t crls_len,
	const uint8_t *signer_infos, size_t signer_infos_len,
	uint8_t **out, size_t *outlen);
int cms_signed_data_from_der(
	int *version,
	int *digest_algors, size_t *digest_algors_cnt, size_t max_digest_algors,
	int *content_type, const uint8_t **content, size_t *content_len,
	const uint8_t **certs, size_t *certs_len,
	const uint8_t **crls, size_t *crls_len,
	const uint8_t **signer_infos, size_t *signer_infos_len,
	const uint8_t **in, size_t *inlen);
int cms_signed_data_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);


typedef struct {
	uint8_t *certs;
	size_t certs_len;
	SM2_KEY *sm2_key;
	char *signer_id;
	size_t signer_id_len;
} CMS_CERT_AND_KEY;

int cms_signed_data_sign_to_der(
	int version,
	int content_type, const uint8_t *content, size_t content_len,
	const CMS_CERT_AND_KEY *signers, size_t signers_cnt,
	const uint8_t *crls, size_t crls_len,
	uint8_t **out, size_t *outlen);
int cms_signed_data_verify_from_der(
	int *version,
	const uint8_t *digest_algors, size_t *digest_algors_cnt, size_t max_digest_algors,
	int *content_type, const uint8_t **content, size_t *content_len,
	const uint8_t **certs, size_t *certs_len,
	const uint8_t **crls, size_t *crls_len,
	const uint8_t **signer_infos, size_t *signer_infos_len,
	const uint8_t *extra_certs, size_t extra_certs_len,
	const uint8_t *extra_crls, size_t extra_crls_len,
	const uint8_t **in, size_t *inlen);

/*
RecipientInfo ::= SEQUENCE {
	version				INTEGER (1),
	issuerAndSerialNumber		IssuerAndSerialNumber,
	keyEncryptionAlgorithm		AlgorithmIdentifier,
	encryptedKey			OCTET STRING -- DER-encoding of SM2Cipher
}
*/
int cms_recipient_info_to_der(
	int version,
	const uint8_t *issuer, size_t issuer_len,
	const uint8_t *serial_number, size_t serial_number_len,
	int public_key_enc_algor,
	const uint8_t *enced_key, size_t enced_key_len,
	uint8_t **out, size_t *outlen);
int cms_recipient_info_from_der(
	int *version,
	const uint8_t **issuer, size_t *issuer_len,
	const uint8_t **serial_number, size_t *serial_number_len,
	int *pke_algor, const uint8_t **params, size_t *paramslen,// SM2加密只使用SM3，没有默认参数，但是ECIES可能有
	const uint8_t **enced_key, size_t *enced_key_len,
	const uint8_t **in, size_t *inlen);
int cms_recipient_info_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

int cms_recipient_info_encrypt_to_der(
	int version,
	const uint8_t *issuer, size_t issuer_len,
	const uint8_t *serial_number, size_t serial_number_len,
	int public_key_enc_algor,
	const uint8_t *in, size_t inlen,
	const SM2_KEY *public_key,
	uint8_t **out, size_t *outlen);
int cms_recipient_info_decrypt_from_der(
	int *version,
	const uint8_t **issuer, size_t *issuer_len,
	const uint8_t **serial_number, size_t *serial_number_len,
	int *pke_algor, const uint8_t **params, size_t *paramslen,
	const uint8_t **decrypted_key, size_t *decrypted_key_len,
	const SM2_KEY *sm2_key,
	const uint8_t **in, size_t *inlen);

/*
EnvelopedData ::= SEQUENCE {
	version			Version,
	recipientInfos		SET OF RecipientInfo,
	encryptedContentInfo	EncryptedContentInfo }
*/
int cms_enveloped_data_to_der(
	int version,
	const uint8_t *rcpt_infos, size_t rcpt_infos_len,
	int content_type,
	int enc_algor, const uint8_t *enc_iv, size_t enc_iv_len,
	const uint8_t *enced_content, size_t enced_content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	uint8_t **out, size_t *outlen);
int cms_enveloped_data_from_der(
	int *version,
	const uint8_t **rcpt_infos, size_t *rcpt_infos_len,
	int *content_type,
	int *enc_algor, const uint8_t **enc_iv, size_t *enc_iv_len,
	const uint8_t **enced_content, size_t *enced_content_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len,
	const uint8_t **in, size_t *inlen);
int cms_enveloped_data_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

int cms_enveloped_data_encrypt_to_der(
	int version,
	const uint8_t *rcpt_certs, size_t rcpt_certs_len, // 当只有一个接收者的时候，这个参数类型非常方便
	int enc_algor, const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen,
	int content_type, const uint8_t *content, size_t content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	uint8_t **out, size_t *outlen);
int cms_enveloped_data_decrypt_from_der(
	int *version,
	const uint8_t **rcpt_infos, size_t *rcpt_infos_len,
	int *content_type, uint8_t *content, size_t *content_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len,
	const SM2_KEY *sm2_key,
	const uint8_t *issuer, size_t issuer_len,
	const uint8_t *serial_number, size_t serial_number_len,
	const uint8_t **in, size_t *inlen);

/*
SignedAndEnvelopedData ::= SEQUENCE {
	version			INTEGER (1),
	recipientInfos		SET OF RecipientInfo,
	digestAlgorithms	SET OF AlgorithmIdentifier,
	encryptedContentInfo	EncryptedContentInfo,
	certificates		[0] IMPLICIT SET OF Certificate OPTIONAL,
	crls			[1] IMPLICIT SET OF CertificateRevocationList OPTIONAL,
	signerInfos		SET OF SignerInfo }
*/
int cms_signed_and_enveloped_data_to_der(
	int version,
	const uint8_t *rcpt_infos, size_t rcpt_infos_len,
	const int *digest_algors, size_t digest_algors_cnt,
	int content_type,
	int enc_algor, const uint8_t *iv, size_t ivlen,
	const uint8_t *enced_content, size_t enced_content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	const uint8_t *certs, size_t certs_len,
	const uint8_t *crls, size_t crls_len,
	const uint8_t *signer_infos, size_t signer_infos_len,
	uint8_t **out, size_t *outlen);
int cms_signed_and_enveloped_data_from_der(
	int *version,
	const uint8_t **rcpt_infos, size_t *rcpt_infos_len,
	int *digest_algors, size_t *digest_algors_cnt, size_t max_digest_algors,
	int *content_type,
	int *enc_algor, const uint8_t **enc_iv, size_t *enc_iv_len,
	const uint8_t **enced_content, size_t *enced_content_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len,
	const uint8_t **certs, size_t *certs_len,
	const uint8_t **crls, size_t *crls_len,
	const uint8_t **signer_infos, size_t *signer_infos_len,
	const uint8_t **in, size_t *inlen);
int cms_signed_and_enveloped_data_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

int cms_signed_and_enveloped_encipher_to_der(
	const CMS_CERT_AND_KEY *signers, size_t signers_cnt,
	const uint8_t *rcpt_certs, size_t rcpt_certs_len,
	int content_type, const uint8_t *content, size_t content_len,
	const uint8_t *signer_crls, size_t signer_crls_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	uint8_t **out, size_t *outlen);

int cms_deenvelop_and_verify_decipher_from_der(
	int *version,
	const uint8_t **rcpt_infos, size_t *rcpt_infos_len,
	const uint8_t **digest_algors, size_t *digest_algors_len,
	int *enc_algor, uint8_t *key, size_t *keylen, const uint8_t **iv, size_t *ivlen,
	int *content_type, uint8_t *content, size_t *content_len,
	const uint8_t **enced_content, size_t *enced_content_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len,
	const uint8_t **certs, size_t *certs_len,
	const uint8_t **crls, size_t *crls_len,
	const uint8_t **signer_infos, size_t *signer_infos_len,

	const SM2_KEY *rcpt_key,
	const uint8_t *rcpt_issuer, size_t rcpt_issuer_len,
	const uint8_t *rcpt_serial_number, size_t rcpt_serial_number_len,
	const uint8_t *extra_verify_certs, size_t extra_verify_certs_len,
	const uint8_t *extra_verify_crls, size_t extra_verify_crls_len,

	const uint8_t **in, size_t *inlen);


/*
KeyAgreementInfo ::= SEQUENCE {
	version			INTEGER (1),
	tempPublicKeyR		SM2PublicKey,
	userCertificate		Certificate,
	userID			OCTET STRING }
*/
int cms_key_agreement_info_to_der(
	int version,
	const SM2_KEY *temp_public_key_r,
	const uint8_t *user_cert, size_t user_cert_len,
	const uint8_t *user_id, size_t user_id_len,
	uint8_t **out, size_t *outlen);
int cms_key_agreement_info_from_der(
	int *version,
	SM2_KEY *temp_public_key_r,
	const uint8_t **user_cert, size_t *user_cert_len,
	const uint8_t **user_id, size_t *user_id_len,
	const uint8_t **in, size_t *inlen);
int cms_key_agreement_info_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);



// 下面是公开API


// 生成ContentInfo, type == data
int cms_set_data(uint8_t *cms, size_t *cmslen, size_t maxlen, const uint8_t *d, size_t dlen);

int cms_encrypt(
	int enc_algor, const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen, // 对称加密算法、密钥和IV
	int content_type, const uint8_t *content, size_t content_len, // 待加密的输入数据
	const uint8_t *shared_info1, size_t shared_info1_len, // 附加信息
	const uint8_t *shared_info2, size_t shared_info2_len, // 附加信息
	uint8_t *cms, size_t *cmslen, size_t maxlen); // 输出的ContentInfo (type encryptedData)

int cms_decrypt(
	const uint8_t *key, size_t keylen, // 解密密钥（我们不知道解密算法）
	const uint8_t *cms, size_t cms_len, // 输入的ContentInfo (type encryptedData)
	const uint8_t *extra_enced_content, size_t extra_enced_content_len, // EncryptedContentInfo的密文数据为空时显示提供输入密文
	int *content_type, uint8_t *content, size_t *content_len, // 输出的解密数据类型及数据
	int *enc_algor, const uint8_t **iv, size_t *ivlen, // 解析EncryptedContentInfo得到的对称加密算法及参数
	const uint8_t **shared_info1, size_t *shared_info1_len, // 附加信息
	const uint8_t **shared_info2, size_t *shared_info2_len);

int cms_sign(
	const CMS_CERT_AND_KEY *signers, size_t signers_cnt, // 签名者的签名私钥和证书
	int content_type, const uint8_t *content, size_t content_len, // 待签名的输入数据
	const uint8_t *crls, size_t crls_len, // 签名者证书的CRL
	uint8_t *cms, size_t *cms_len); // 输出的ContentInfo (type signedData)

int cms_verify(
	const uint8_t *cms, size_t cms_len, // 输入的ContentInfo (type signedData)
	const uint8_t *extra_content, size_t extra_content_len, // ContentInfo的数据为空时显示提供输入
	const uint8_t *extra_certs, size_t extra_certs_len, // 当SignedData中未提供证书时显示输入
	const uint8_t *extra_crls, size_t extra_crls_len, // 当SignedData中未提供CRL时显示输入
	int *content_type, const uint8_t **content, size_t *content_len, // 从SignedData解析得到的被签名数据
	const uint8_t **certs, size_t *certs_len, // 从SignedData解析得到的签名证书
	const uint8_t **crls, size_t *crls_len, // 从SignedData解析得到的CRL
	const uint8_t **signer_infos, size_t *signer_infos_len); // 从SignedData解析得到的SignerInfos，可用于显示验证结果

int cms_envelop(
	const uint8_t *rcpt_certs, size_t rcpt_certs_len, // 接收方证书，注意这个参数的类型可以容纳多个证书，但是只有在一个接受者时对调用方最方便
	int enc_algor, const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen, // 对称加密算法及参数
	int content_type, const uint8_t *content, size_t content_len, // 待加密的输入数据
	const uint8_t *shared_info1, size_t shared_info1_len, // 附加输入信息
	const uint8_t *shared_info2, size_t shared_info2_len, // 附加输入信息
	uint8_t *cms, size_t *cms_len); // 输出ContentInfo

int cms_deenvelop(
	const SM2_KEY *rcpt_key, const uint8_t *rcpt_cert, size_t rcpt_cert_len, // 接收方的解密私钥和对应的证书，注意只需要一个解密方
	const uint8_t *cms, size_t cms_len,
	const uint8_t *extra_enced_content, size_t extra_enced_content_len, // 显式输入的密文
	int *content_type, uint8_t *content, size_t *content_len,
	int *enc_algor, const uint8_t **iv, size_t *ivlen, // 注意，对称加密的密钥就不输出了
	const uint8_t **rcpt_infos, size_t *rcpt_infos_len, // 解析得到，用于显示
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len);

int cms_sign_and_envelop( // 参考cms_sign, cms_envelop
	const CMS_CERT_AND_KEY *signers, size_t signers_cnt,
	const uint8_t *rcpt_certs, size_t rcpt_certs_len,
	int enc_algor, const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen,
	int content_type, const uint8_t *content, size_t content_len,
	const uint8_t *signer_crls, size_t signer_crls_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	uint8_t *cms, size_t *cms_len);

int cms_deenvelop_and_verify( // 参考cms_deenvelop, cms_verify
	const SM2_KEY *rcpt_key, const uint8_t *rcpt_cert, size_t rcpt_cert_len,
	// 输入
	const uint8_t *cms, size_t cms_len,
	const uint8_t *extra_enced_content, size_t extra_enced_content_len,
	const uint8_t *extra_signer_certs, size_t extra_signer_certs_len,
	const uint8_t *extra_signer_crls, size_t extra_signer_crls_len,
	// 输出
	int *content_type, uint8_t *content, size_t *content_len,
	// 格外的解析内容输出，均为可选
	int *enc_algor, const uint8_t **iv, size_t *ivlen,
	const uint8_t **rcpt_infos, size_t rcpt_infos_len,
	const uint8_t **signer_infos, size_t *signer_infos_len,
	const uint8_t **signer_certs, size_t *signer_certs_len,
	const uint8_t **signer_crls, size_t *signer_crls_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len);

// 生成ContentInfo, type == keyAgreementInfo
int cms_set_key_agreement_info(
	uint8_t *cms, size_t *cms_len,
	const SM2_KEY *temp_public_key_r,
	const uint8_t *user_cert, size_t user_cert_len,
	const uint8_t *user_id, size_t user_id_len);

int cms_print(FILE *fp, int fmt, int ind, const uint8_t *a, size_t alen);


#ifdef __cplusplus
}
#endif
#endif
