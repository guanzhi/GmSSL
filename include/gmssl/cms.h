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



ContentInfo ::= SEQUENCE {
	contentType			OBJECT IDENTIFIER,
	content				[0] EXPLICIT ANY OPTIONAL
}


data 1.2.156.10197.6.1.4.2.1





data ::= OCTET STRING

SignedData ::= SEQUENCE {
	version			INTEGER (1),
	digestAlgorithms	SET OF AlgorithmIdentifier,
	contentInfo		ContentInfo,
	certificates		[0] IMPLICIT SET OF Certificate OPTIONAL,
	crls			[1] IMPLICIT SET OF CertificateRevocationList OPTIONAL,
	signerInfos		SET OF SignerInfo
}

SignerInfo ::= SEQUENCE {
	version				INTEGER (1),
	issuerAndSerialNumber		IssuerAndSerialNumber,
	digestAlgorithm			AlgorithmIdentifier,
	authenticatedAttributes		[0] IMPLICIT SET OF Attribute OPTINOAL,
	digestEncryptionAlgorithm	AlgorithmIdentifier,
	encryptedDigest			OCTET STRING,
	unauthenticatedAttributes       [1] IMPLICIT SET OF Attribute OPTINOAL,
}

EnvelopedData ::= SEQUENCE {
	version				INTEGER (1),
	recipientInfos			SET OF RecipientInfo,
	encryptedContentInfo		EncryptedContentInfo
}

EncryptedContentInfo ::= SEQUENCE {
	contentType			OBJECT IDENTIFIER,
	contentEncryptionAlgorithm	AlgorithmIdentifier,
	encryptedContent		[0] IMPLICIT OCTET STRING OPTIONAL,
	sharedInfo1			[1] IMPLICIT OCTET STRING OPTIONAL,
	sharedInfo2			[2] IMPLICIT OCTET STRING OPTIONAL,
}

RecipientInfo ::= SEQUENCE {
	version				INTEGER (1),
	issuerAndSerialNumber		IssuerAndSerialNumber,
	keyEncryptionAlgorithm		AlgorithmIdentifier,
	encryptedKey			OCTET STRING
}

SignedAndEnvelopedData ::= SEQUENCE {
	version			INTEGER (1),
	recipientInfos		SET OF RecipientInfo,
	digestAlgorithms	SET OF AlgorithmIdentifier,
	encryptedContentInfo	EncryptedContentInfo,
	certificates		[0] IMPLICIT SET OF Certificate OPTIONAL,
	crls			[1] IMPLICIT SET OF CertificateRevocationList OPTIONAL,
	signerInfos		SET OF SignerInfo
}

EncryptedData ::= SEQUENCE {
	version			INTEGER (1),
	encryptedContentInfo	EncryptedContentInfo
}

KeyAgreementInfo ::= SEQUENCE {
	version			INTEGER (1),
	tempPublicKeyR		SM2PublicKey,
	userCertificate		Certificate,
	userID			OCTET STRING
}
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
	CMS_version = 1,
};



typedef enum {
	CMS_data 			= 1,
	CMS_signed_data			= 2,
	CMS_enveloped_data		= 3,
	CMS_signed_and_enveloped_data	= 4,
	CMS_encrypted_data		= 5,
	CMS_key_agreement_info		= 6,
} CMS_CONTENT_TYPE;




/*
IssuerAndSerialNumber ::= SEQUENCE {
	issuer				Name,
	serialNumber			INTEGER }
*/
int cms_issuer_and_serial_number_from_certificate(const X509_NAME **issuer,
	const uint8_t **serial_number, size_t *serial_number_len,
	const X509_CERTIFICATE *cert);
int cms_public_key_from_certificate(const SM2_KEY **pub_key,
	const X509_CERTIFICATE *cert);
int cms_issuer_and_serial_number_to_der(const X509_NAME *issuer,
	const uint8_t *serial_number, size_t serial_number_len,
	uint8_t **out, size_t *outlen);
int cms_issuer_and_serial_number_from_der(X509_NAME *issuer,
	const uint8_t **serial_number, size_t *serial_number_len,
	const uint8_t **in, size_t *inlen);


const char *cms_content_type_name(int type);
int cms_content_type_to_der(int type, uint8_t **out, size_t *outlen);
int cms_content_type_from_der(int *type, const uint8_t **in, size_t *inlen);



int cms_content_info_print(FILE *fp, const uint8_t *a, size_t alen, int format, int indent);


int cms_content_info_set_data(uint8_t *content_info, size_t *content_info_len,
	const uint8_t *data, size_t datalen);
int cms_content_info_get_data(const uint8_t *content_info, size_t content_info_len,
	const uint8_t **data, size_t *datalen);




int cms_data_print(FILE *fp, const uint8_t *in, size_t inlen, int format, int indent);



int cms_signer_info_to_der(const X509_NAME *issuer,
	const uint8_t *serial_number, size_t serial_number_len, int digest_algor,
	const uint8_t *authed_attrs, size_t authed_attrs_len,
	const uint8_t *enced_digest, size_t enced_digest_len,
	const uint8_t *unauthed_attrs, size_t unauthed_attrs_len,
	uint8_t **out, size_t *outlen);

int cms_signer_info_from_der(X509_NAME *issuer,
	const uint8_t **serial_number, size_t *serial_number_len,
	int *digest_algor, uint32_t *nodes, size_t *nodes_count,
	const uint8_t **authed_attrs, size_t *authed_attrs_len,
	int *sign_algor, uint32_t *sign_algor_nodes, size_t *sign_algor_nodes_count,
	const uint8_t **enced_digest, size_t *enced_digest_len,
	const uint8_t **unauthed_attrs, size_t *unauthed_attrs_len,
	const uint8_t **in, size_t *inlen);

int cms_signer_info_print(FILE *fp, const uint8_t *a, size_t alen, int format, int indent);

int cms_signer_info_sign_to_der(const SM2_KEY *sm2_key, const SM3_CTX *sm3_ctx,
	const X509_NAME *issuer, const uint8_t *serial_number, size_t serial_number_len,
	const uint8_t *authed_attrs, size_t authed_attrs_len,
	const uint8_t *unauthed_attrs, size_t unauthed_attrs_len,
	uint8_t **out, size_t *outlen);

int cms_signer_info_verify_from_der(
	const SM2_KEY *sm2_key, const SM3_CTX *sm3_ctx,
	X509_NAME *issuer, const uint8_t **serial_number, size_t *serial_number_len,
	int *digest_algor, uint32_t *digest_nodes, size_t *digest_algor_nodes_count,
	const uint8_t **authed_attrs, size_t *authed_attrs_len,
	int *sign_algor, uint32_t *sign_algor_nodes, size_t *sign_algor_nodes_count,
	const uint8_t **unauthed_attrs, size_t *unauthed_attrs_len,
	const uint8_t **in, size_t *inlen);

int cms_signed_data_to_der(
	const int *digest_algors, const size_t digset_algors_count,
	const int content_type, const uint8_t *content, const size_t content_len,
	const X509_CERTIFICATE *certs, size_t certs_count,
	const uint8_t **crls, const size_t *crls_lens, const size_t crls_count,
	const uint8_t **signer_infos, size_t *signer_infos_lens, size_t signer_infos_count,
	uint8_t **out, size_t *outlen);

int cms_signed_data_from_der(
	const uint8_t **digest_algors, size_t *digest_algors_len,
	int *content_type, const uint8_t **content, size_t *content_len,
	const uint8_t **certs, size_t *certs_len,
	const uint8_t **crls, size_t *crls_len,
	const uint8_t **signer_infos, size_t *signer_infos_len,
	const uint8_t **in, size_t *inlen);

int cms_signed_data_print(FILE *fp, const uint8_t *in, size_t inlen, int format, int indent);

int cms_signed_data_sign_to_der(const SM2_KEY *sign_keys, const X509_CERTIFICATE *sign_certs, size_t sign_count,
	int content_type, const uint8_t *content, size_t content_len,
	const uint8_t **crls, size_t *crls_lens, size_t crls_count,
	uint8_t **out, size_t *outlen);

int cms_signed_data_verify_from_der(const uint8_t *signed_data, size_t signed_data_len);


int cms_sign(const SM2_KEY *sign_keys,
	const X509_CERTIFICATE *sign_certs, size_t sign_count,
	int content_type, const uint8_t *content, size_t content_len,
	const uint8_t **crls, size_t *crls_lens, size_t crls_count,
	uint8_t *content_info, size_t *content_info_len);




#ifdef __cplusplus
}
#endif
#endif
