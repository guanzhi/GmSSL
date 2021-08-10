/* 
 *   Copyright 2014-2021 The GmSSL Project Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
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
	int *digest_algor,
	const uint8_t **authed_attrs, size_t *authed_attrs_len,
	int *sign_algor,
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

int cms_encrypt(const uint8_t key[16], const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen);

int cms_decrypt(const uint8_t key[16], const uint8_t *in, size_t inlen,
	int *content_type, uint8_t *out, size_t *outlen,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len);

int cms_enced_content_info_to_der(int enc_algor, const uint8_t *enc_iv, size_t enc_iv_len,
	int content_type, const uint8_t *enced_content, size_t enced_content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	uint8_t **out, size_t *outlen);

int cms_enced_content_info_from_der(int *content_type,
	int *enc_algor, const uint8_t **enc_iv, size_t *enc_iv_len,
	const uint8_t **enced_content, size_t *enced_content_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len,
	const uint8_t **in, size_t *inlen);


#ifdef __cplusplus
}
#endif
#endif
