/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
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

enum {
	CMS_version_v1 = 1,
};


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
int cms_content_info_header_to_der(
	int content_type, size_t content_len,
	uint8_t **out, size_t *outlen);
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
	int enc_algor,
	const uint8_t *key, size_t keylen,
	const uint8_t *iv, size_t ivlen,
	int content_type, const uint8_t *content, size_t content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	uint8_t **out, size_t *outlen);
int cms_enced_content_info_decrypt_from_der(
	int *enc_algor,
	const uint8_t *key, size_t keylen,
	int *content_type, uint8_t *content, size_t *content_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len,
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
	int enc_algor,
	const uint8_t *key, size_t keylen,
	const uint8_t *iv, size_t ivlen,
	int content_type, const uint8_t *content, size_t content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	uint8_t **out, size_t *outlen);
int cms_encrypted_data_decrypt_from_der(
	int *enc_algor,
	const uint8_t *key, size_t keylen,
	int *content_type, uint8_t *content, size_t *content_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len,
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
	const SM3_CTX *sm3_ctx, const SM2_KEY *sm2_key,
	const uint8_t *issuer, size_t issuer_len,
	const uint8_t *serial_number, size_t serial_number_len,
	const uint8_t *authed_attrs, size_t authed_attrs_len,
	const uint8_t *unauthed_attrs, size_t unauthed_attrs_len,
	uint8_t **out, size_t *outlen);
int cms_signer_info_verify_from_der(
	const SM3_CTX *sm3_ctx, const uint8_t *certs, size_t certslen,
	const uint8_t **cert, size_t *certlen,
	const uint8_t **issuer, size_t *issuer_len,
	const uint8_t **serial, size_t *serial_len,
	const uint8_t **authed_attrs, size_t *authed_attrs_len,
	const uint8_t **unauthed_attrs, size_t *unauthed_attrs_len,
	const uint8_t **in, size_t *inlen);
/*
SignerInfos ::= SET OF SignerInfo;
*/
int cms_signer_infos_add_signer_info(
	uint8_t *d, size_t *dlen, size_t maxlen,
	const SM3_CTX *sm3_ctx, const SM2_KEY *sign_key,
	const uint8_t *issuer, size_t issuer_len,
	const uint8_t *serial_number, size_t serial_number_len,
	const uint8_t *authed_attrs, size_t authed_attrs_len,
	const uint8_t *unauthed_attrs, size_t unauthed_attrs_len);
#define cms_signer_infos_to_der(d,dlen,out,outlen) asn1_set_to_der(d,dlen,out,outlen)
#define cms_signer_infos_from_der(d,dlen,in,inlen) asn1_set_from_der(d,dlen,in,inlen)
int cms_signer_infos_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

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
	SM2_KEY *sign_key;
} CMS_CERTS_AND_KEY;

int cms_signed_data_sign_to_der(
	const CMS_CERTS_AND_KEY *signers, size_t signers_cnt,
	int content_type, const uint8_t *data, size_t datalen, // 当OID_cms_data时为raw data
	const uint8_t *crls, size_t crls_len, // 可以为空
	uint8_t **out, size_t *outlen);
int cms_signed_data_verify_from_der(
	const uint8_t *extra_certs, size_t extra_certs_len,
	const uint8_t *extra_crls, size_t extra_crls_len,
	int *content_type, const uint8_t **content, size_t *content_len, // 是否应该返回raw data呢？			
	const uint8_t **certs, size_t *certs_len,
	const uint8_t **crls, size_t *crls_len,
	const uint8_t **signer_infos, size_t *signer_infos_len,
	const uint8_t **in, size_t *inlen);


/*
RecipientInfo ::= SEQUENCE {
	version				INTEGER (1),
	issuerAndSerialNumber		IssuerAndSerialNumber,
	keyEncryptionAlgorithm		AlgorithmIdentifier,
	encryptedKey			OCTET STRING -- DER-encoding of SM2Cipher
}
由于encryptedKey的类型为SM2Cipher, 而SM2Cipher中有2个INTEGER，因此长度是不固定的。
因此不能预先确定输出长度
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
	int *pke_algor, const uint8_t **params, size_t *params_len,// SM2加密只使用SM3，没有默认参数，但是ECIES可能有
	const uint8_t **enced_key, size_t *enced_key_len,
	const uint8_t **in, size_t *inlen);
int cms_recipient_info_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);


int cms_recipient_info_encrypt_to_der(
	const SM2_KEY *public_key,
	const uint8_t *issuer, size_t issuer_len,
	const uint8_t *serial, size_t serial_len,
	const uint8_t *in, size_t inlen,
	uint8_t **out, size_t *outlen);
int cms_recipient_info_decrypt_from_der(
	const SM2_KEY *sm2_key,
	const uint8_t *rcpt_issuer, size_t rcpt_issuer_len,
	const uint8_t *rcpt_serial, size_t rcpt_serial_len,
	uint8_t *out, size_t *outlen, size_t maxlen,
	const uint8_t **in, size_t *inlen);

int cms_recipient_infos_add_recipient_info(
	uint8_t *d, size_t *dlen, size_t maxlen,
	const SM2_KEY *public_key,
	const uint8_t *issuer, size_t issuer_len,
	const uint8_t *serial, size_t serial_len,
	const uint8_t *in, size_t inlen);
#define cms_recipient_infos_to_der(d,dlen,out,outlen) asn1_set_to_der(d,dlen,out,outlen)
#define cms_recipient_infos_from_der(d,dlen,in,inlen) asn1_set_from_der(d,dlen,in,inlen)
int cms_recipient_infos_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

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
	const uint8_t **enced_content_info, size_t *enced_content_info_len,
	const uint8_t **in, size_t *inlen);
int cms_enveloped_data_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

int cms_enveloped_data_encrypt_to_der(
	const uint8_t *rcpt_certs, size_t rcpt_certs_len,
	int enc_algor, const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen,
	int content_type, const uint8_t *content, size_t content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	uint8_t **out, size_t *outlen);
int cms_enveloped_data_decrypt_from_der(
	const SM2_KEY *sm2_key,
	const uint8_t *issuer, size_t issuer_len,
	const uint8_t *serial_number, size_t serial_number_len,
	int *content_type, uint8_t *content, size_t *content_len,
	const uint8_t **rcpt_infos, size_t *rcpt_infos_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len,
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
	const uint8_t **enced_content_info, size_t *enced_content_info_len,
	const uint8_t **certs, size_t *certs_len,
	const uint8_t **crls, size_t *crls_len,
	const uint8_t **signer_infos, size_t *signer_infos_len,
	const uint8_t **in, size_t *inlen);
int cms_signed_and_enveloped_data_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *d, size_t dlen);

int cms_signed_and_enveloped_data_encipher_to_der(
	const CMS_CERTS_AND_KEY *signers, size_t signers_cnt,
	const uint8_t *rcpt_certs, size_t rcpt_certs_len,
	int enc_algor, const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen,
	int content_type, const uint8_t *content, size_t content_len,
	const uint8_t *signers_crls, size_t signers_crls_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	uint8_t **out, size_t *outlen);
int cms_signed_and_enveloped_data_decipher_from_der(
	const SM2_KEY *rcpt_key,
	const uint8_t *rcpt_issuer, size_t rcpt_issuer_len,
	const uint8_t *rcpt_serial, size_t rcpt_serial_len,
	int *content_type, uint8_t *content, size_t *content_len,
	const uint8_t **prcpt_infos, size_t *prcpt_infos_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len,
	const uint8_t **certs, size_t *certs_len,
	const uint8_t **crls, size_t *crls_len,
	const uint8_t **psigner_infos, size_t *psigner_infos_len,
	const uint8_t *extra_certs, size_t extra_certs_len,
	const uint8_t *extra_crls, size_t extra_crls_len,
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
// 公开API的设计考虑：
// 1. 不需要调用其他函数
// 2. 在逻辑上容易理解
// 3. 将cms,cmslen看做对象


// 生成ContentInfo, type == data
int cms_set_data(uint8_t *cms, size_t *cmslen,
	const uint8_t *d, size_t dlen);

int cms_encrypt(
	uint8_t *cms, size_t *cmslen, // 输出的ContentInfo (type encryptedData)
	int enc_algor, const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen, // 对称加密算法、密钥和IV
	int content_type, const uint8_t *content, size_t content_len, // 待加密的输入数据
	const uint8_t *shared_info1, size_t shared_info1_len, // 附加信息
	const uint8_t *shared_info2, size_t shared_info2_len);

int cms_decrypt(
	const uint8_t *cms, size_t cmslen, // 输入的ContentInfo (type encryptedData)
	int *enc_algor, const uint8_t *key, size_t keylen, // 解密密钥（我们不知道解密算法）
	int *content_type, uint8_t *content, size_t *content_len, // 输出的解密数据类型及数据
	const uint8_t **shared_info1, size_t *shared_info1_len, // 附加信息
	const uint8_t **shared_info2, size_t *shared_info2_len);

int cms_sign(
	uint8_t *cms, size_t *cms_len,
	const CMS_CERTS_AND_KEY *signers, size_t signers_cnt, // 签名者的签名私钥和证书
	int content_type, const uint8_t *content, size_t content_len, // 待签名的输入数据
	const uint8_t *crls, size_t crls_len);

int cms_verify(
	const uint8_t *cms, size_t cms_len,
	const uint8_t *extra_certs, size_t extra_certs_len,
	const uint8_t *extra_crls, size_t extra_crls_len,
	int *content_type, const uint8_t **content, size_t *content_len,
	const uint8_t **certs, size_t *certs_len,
	const uint8_t **crls, size_t *crls_len,
	const uint8_t **signer_infos, size_t *signer_infos_len);

int cms_envelop(
	uint8_t *cms, size_t *cms_len,
	const uint8_t *rcpt_certs, size_t rcpt_certs_len, // 接收方证书，注意这个参数的类型可以容纳多个证书，但是只有在一个接受者时对调用方最方便
	int enc_algor, const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen, // 对称加密算法及参数
	int content_type, const uint8_t *content, size_t content_len, // 待加密的输入数据
	const uint8_t *shared_info1, size_t shared_info1_len, // 附加输入信息
	const uint8_t *shared_info2, size_t shared_info2_len);

int cms_deenvelop(
	const uint8_t *cms, size_t cms_len,
	const SM2_KEY *rcpt_key, const uint8_t *rcpt_cert, size_t rcpt_cert_len, // 接收方的解密私钥和对应的证书，注意只需要一个解密方
	int *content_type, uint8_t *content, size_t *content_len,
	const uint8_t **rcpt_infos, size_t *rcpt_infos_len, // 解析得到，用于显示
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len);

int cms_sign_and_envelop(
	uint8_t *cms, size_t *cms_len,
	const CMS_CERTS_AND_KEY *signers, size_t signers_cnt,
	const uint8_t *rcpt_certs, size_t rcpt_certs_len,
	int enc_algor, const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen,
	int content_type, const uint8_t *content, size_t content_len,
	const uint8_t *signers_crls, size_t signers_crls_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len);

int cms_deenvelop_and_verify(
	const uint8_t *cms, size_t cms_len,
	const SM2_KEY *rcpt_key, const uint8_t *rcpt_cert, size_t rcpt_cert_len,
	const uint8_t *extra_signer_certs, size_t extra_signer_certs_len,
	const uint8_t *extra_signer_crls, size_t extra_signer_crls_len,
	int *content_type, uint8_t *content, size_t *content_len,
	const uint8_t **rcpt_infos, size_t *rcpt_infos_len,
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

#define PEM_CMS "CMS"
int cms_to_pem(const uint8_t *cms, size_t cms_len, FILE *fp);
int cms_from_pem(uint8_t *cms, size_t *cms_len, size_t maxlen, FILE *fp);


int cms_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *a, size_t alen);


#ifdef __cplusplus
}
#endif
#endif
