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






int cms_data_print(FILE *fp, const uint8_t *a, size_t alen, int format, int indent);

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

int cms_enced_content_info_print(FILE *fp,
	int content_type,
	int enc_algor, const uint8_t *enc_iv, size_t enc_iv_len,
	const uint8_t *enced_content, size_t enced_content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	int format, int indent);

int cms_enced_content_info_encrypt_to_der(const SM4_KEY *sm4_key, const uint8_t iv[16],
	int content_type, const uint8_t *content, size_t content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	uint8_t **out, size_t *outlen);

int cms_enced_content_info_decrypt_from_der(const SM4_KEY *key,
	int *content_type, uint8_t *content, size_t *content_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len,
	const uint8_t **in, size_t *inlen);

int cms_encrypted_data_to_der(int enc_algor, const uint8_t *enc_iv, size_t enc_iv_len,
	int content_type, const uint8_t *enced_content, size_t enced_content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	uint8_t **out, size_t *outlen);

int cms_encrypted_data_from_der(int *content_type,
	int *enc_algor, const uint8_t **enc_iv, size_t *enc_iv_len,
	const uint8_t **enced_content, size_t *enced_content_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len,
	const uint8_t **in, size_t *inlen);

int cms_encrypted_data_print(FILE *fp, const uint8_t *a, size_t alen, int format, int indent);

int cms_encrypted_data_encrypt_to_der(const SM4_KEY *sm4_key, const uint8_t iv[16],
	int content_type, const uint8_t *content, size_t content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	uint8_t **out, size_t *outlen);

int cms_encrypted_data_decrypt_from_der(const SM4_KEY *key,
	int *content_type, uint8_t *content, size_t *content_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len,
	const uint8_t **in, size_t *inlen);


int cms_key_agreement_info_to_der(const SM2_KEY *pub_key, const X509_CERTIFICATE *cert,
	const uint8_t *user_id, size_t user_id_len, uint8_t **out, size_t *outlen);

int cms_key_agreement_info_from_der(SM2_KEY *pub_key, X509_CERTIFICATE *cert,
	const uint8_t **user_id, size_t *user_id_len, const uint8_t **in, size_t *inlen);

int cms_key_agreement_info_print(FILE *fp, const uint8_t *a, size_t alen, int format, int indent);


int cms_issuer_and_serial_number_from_certificate(const X509_NAME **issuer,
	const uint8_t **serial_number, size_t *serial_number_len,
	const X509_CERTIFICATE *cert);

int cms_public_key_from_certificate(const SM2_KEY **sm2_key,
	const X509_CERTIFICATE *cert);

int cms_issuer_and_serial_number_to_der(const X509_NAME *issuer,
	const uint8_t *serial_number, size_t serial_number_len,
	uint8_t **out, size_t *outlen);

int cms_issuer_and_serial_number_from_der(X509_NAME *issuer,
	const uint8_t **serial_number, size_t *serial_number_len,
	const uint8_t **in, size_t *inlen);

int cms_issuer_and_serial_number_print(FILE *fp,
	const X509_NAME *issuer,
	const uint8_t *serial_number, size_t serial_number_len,
	int format, int indent);



int cms_recipient_info_from_x509_certificate(
	const SM2_KEY **key,
	const X509_NAME **issuer,
	const uint8_t **serial_number, size_t *serial_number_len,
	const X509_CERTIFICATE *cert);

int cms_recipient_info_to_der(const X509_NAME *issuer,
	const uint8_t *serial_number, size_t serial_number_len,
	const uint8_t *enced_key, size_t enced_key_len,
	uint8_t **out, size_t *outlen);

int cms_recipient_info_from_der(
	int *version,
	X509_NAME *issuer,
	const uint8_t **serial_number, size_t *serial_number_len,
	int *pke_algor, const uint8_t **params, size_t *paramslen,
	const uint8_t **enced_key, size_t *enced_key_len,
	const uint8_t **in, size_t *inlen);

int cms_recipient_info_print(FILE *fp,
	int version,
	const X509_NAME *issuer, const uint8_t *serial_number, size_t serial_number_len,
	int pke_algor, const uint8_t *params, size_t paramslen,
	const uint8_t *enced_key, size_t enced_key_len,
	int format, int indent);

int cms_recipient_info_encrypt_to_der(const SM2_KEY *sm2_key,
	const X509_NAME *issuer, const uint8_t *serial_number, size_t serial_number_len,
	const uint8_t *key, size_t keylen,
	uint8_t **out, size_t *outlen);

int cms_recipient_info_decrypt_from_der(const SM2_KEY *sm2_key,
	X509_NAME *issuer, const uint8_t **serial_number, size_t *serial_number_len,
	uint8_t *key, size_t *keylen,
	const uint8_t **in, size_t *inlen);


int cms_enveloped_data_to_der(const uint8_t *rcpt_infos, size_t rcpt_infos_len,
	int content_type,
	int enc_algor,
	const uint8_t *enc_iv, size_t enc_iv_len,
	const uint8_t *enced_content, size_t enced_content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	const uint8_t **out, size_t *outlen);

int cms_enveloped_data_from_der(const uint8_t **rcpt_infos, size_t *rcpt_infos_len,
	int *content_type,
	int *enc_algor, const uint8_t **enc_iv, size_t *enc_iv_len,
	const uint8_t **enced_content, size_t *enced_content_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len,
	const uint8_t **in, size_t *inlen);

int cms_enveloped_data_print(FILE *fp, const uint8_t *a, size_t alen, int format, int indent);

int cms_enveloped_data_encrypt_to_der(const X509_CERTIFICATE *rcpt_certs, size_t rcpt_count,
	int content_type, const uint8_t *content, size_t content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	uint8_t **out, size_t *outlen);

int cms_enveloped_data_decrypt_from_der(
	const SM2_KEY *sm2_key, const X509_CERTIFICATE *cert, // 应该用证书还是issuer_and_serial_number?
	int *content_type, uint8_t *content, size_t *content_len,
	const uint8_t **shared_info1, size_t *shared_info1_len,
	const uint8_t **shared_info2, size_t *shared_info2_len,
	const uint8_t **in, size_t *inlen);


const char *cms_content_type_name(int type);
int cms_content_type_to_der(int type, uint8_t **out, size_t *outlen);
int cms_content_type_from_der(int *type, const uint8_t **in, size_t *inlen);

int cms_content_info_to_der(int content_type, const uint8_t *content, size_t content_len,
	uint8_t **out, size_t *outlen);

int cms_content_info_from_der(int *content_type, const uint8_t **content, size_t *content_len,
	const uint8_t **in, size_t *inlen);




int cms_signer_info_to_der(
	const X509_NAME *issuer,
	const uint8_t *serial_number, size_t serial_number_len,
	int digest_algor,
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

int cms_signer_info_print(FILE *fp,
	int version,
	const X509_NAME *issuer, const uint8_t *serial_number, size_t serial_number_len,
	int digest_algor, const uint8_t *digest_params, size_t digest_params_len,
	const uint8_t *authed_attrs, size_t authed_attrs_len,
	int sign_algor, const uint8_t *sign_params, size_t sign_params_len,
	const uint8_t *sig, size_t siglen,
	const uint8_t *unauthed_attrs, size_t unauthed_attrs_len,
	int format, int indent);

int cms_signer_info_sign_to_der(const SM2_KEY *sm2_key, const SM3_CTX *sm3_ctx,
	const X509_NAME *issuer, const uint8_t *serial_number, size_t serial_number_len,
	const uint8_t *authed_attrs, size_t authed_attrs_len,
	const uint8_t *unauthed_attrs, size_t unauthed_attrs_len,
	uint8_t **out, size_t *outlen);

int cms_signer_info_verify(
	const SM2_KEY *sm2_key, const SM3_CTX *sm3_ctx,
	const uint8_t *authed_attrs, size_t authed_attrs_len,
	const uint8_t *sig, size_t siglen);


int cms_signed_data_to_der(
	const int *digest_algors, const size_t digest_algors_count,
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

int cms_signed_data_print(FILE *fp, const uint8_t *a, size_t alen, int format, int indent);

int cms_signed_data_sign_to_der(const SM2_KEY *sign_keys,
	const X509_CERTIFICATE *sign_certs, size_t sign_count,
	int content_type, const uint8_t *content, size_t content_len,
	const uint8_t *crls, size_t crls_len,
	uint8_t **out, size_t *outlen);

int cms_signed_data_verify_from_der(
	const uint8_t **digest_algors, size_t *digest_algors_len,
	int *content_type, const uint8_t **content, size_t *content_len,
	const uint8_t **certs, size_t *certs_len,
	const uint8_t **crls, size_t *crls_len,
	const uint8_t **signer_infos, size_t *signer_infos_len,
	const uint8_t **in, size_t *inlen);

int cms_signed_data_verify(
	int content_type, const uint8_t *content, size_t content_len, // 被签名的到底是什么数据？
	const uint8_t *certs, size_t certs_len,
	const uint8_t *signer_infos, size_t signer_infos_len);


int cms_signed_and_enveloped_data_to_der(
	int version,
	const uint8_t *rcpt_infos, size_t rcpt_infos_len,
	const int *digest_algors, size_t digest_algors_count,
	int content_type,
		int enc_algor, const uint8_t *enc_iv, size_t enc_iv_len,
		const uint8_t *enced_content, size_t enced_content_len,
		const uint8_t *shared_info1, size_t shared_info1_len,
		const uint8_t *shared_info2, size_t shared_info2_len,
	const X509_CERTIFICATE *certs, size_t certs_count,
	const uint8_t *crls, size_t crls_count,
	const uint8_t signer_infos, size_t signer_infos_len);

int cms_signed_and_enveloped_data_from_der(
	int *version,
	const uint8_t **rcpt_infos, size_t *rcpt_infos_len,
	const uint8_t **dgst_algors, size_t *dgst_algors_len,
	int *content_type,
		int *enc_algor, const uint8_t **enc_iv, size_t *enc_iv_len,
		const uint8_t **enced_content, size_t *enced_content_len,
		const uint8_t **shared_info1, size_t *shared_info1_len,
		const uint8_t **shared_info2, size_t *shared_info2_len,
	const uint8_t **certs, size_t *certs_len,
	const uint8_t **crls, size_t *crls_len,
	const uint8_t **signer_infos, size_t *signer_infos_len,
	const uint8_t **in, size_t *inlen);

int cms_signed_and_enveloped_data_print(FILE *fp, const uint8_t *a, size_t alen,
	int format, int indent);




int cms_signed_and_enveloped_data_sign_encrypt_to_der(
	const SM2_KEY *sign_keys, const X509_CERTIFICATE *sign_certs, size_t sign_count,
	const uint8_t *sign_crls, const size_t sign_crls_len,
	const X509_CERTIFICATE *rcpt_certs, size_t rcpt_count,
	int content_type, const uint8_t *content, size_t content_len,
	const uint8_t *shared_info1, size_t shared_info1_len,
	const uint8_t *shared_info2, size_t shared_info2_len,
	uint8_t **out, size_t *outlen);


int cms_signed_and_enveloped_data_decrypt_verify_from_der(
	const SM2_KEY *dec_key, const X509_CERTIFICATE *dec_cert,
	const uint8_t **rcpt_infos, size_t *rcpt_infos_len,
	const uint8_t **dgst_algors, size_t *dgst_algors_len,
	int *content_type,
		int *enc_algor, const uint8_t **enc_iv, size_t *enc_iv_len,
		const uint8_t **enced_content, size_t *enced_content_len,
		const uint8_t **shared_info1, size_t *shared_info1_len,
		const uint8_t **shared_info2, size_t *shared_info2_len,
	const uint8_t **certs, size_t *certs_len,
	const uint8_t **crls, size_t *crls_len,
	const uint8_t **signer_infos, size_t *signer_infos_len);


/*
下面是预计export的函数
*/

int cms_content_info_print(FILE *fp, const uint8_t *a, size_t alen, int format, int indent);


int cms_encrypt(const uint8_t key[16], const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen);

int cms_decrypt(const uint8_t key[16], const uint8_t *in, size_t inlen,
	int *content_type, uint8_t *out, size_t *outlen);

int cms_seal(const X509_CERTIFICATE *rcpt_certs, size_t rcpt_count,
	const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen);

int cms_open(const SM2_KEY *sm2_key, const X509_CERTIFICATE *cert,
	const uint8_t *in, size_t inlen,
	int *content_type, uint8_t *out, size_t *outlen);

int cms_sign(const SM2_KEY *sign_keys, const X509_CERTIFICATE *sign_certs, size_t sign_count,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);

int cms_verify(int *content_type, const uint8_t **content, size_t *content_len,
	const uint8_t **certs, size_t *certs_len,
	const uint8_t **crls, size_t *crls_len,
	const uint8_t **signer_infos, size_t *signer_infos_len,
	const uint8_t *cms, size_t cmslen);

int cms_sign_and_seal(const SM2_KEY *sign_keys,
	const X509_CERTIFICATE *sign_certs, size_t sign_count,
	const X509_CERTIFICATE *rcpt_certs, size_t rcpt_count,
	const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen);

int cms_open_and_verify(
	const SM2_KEY *sm2_key, const X509_CERTIFICATE *cert,
	const uint8_t *in, size_t inlen,
	int *content_type, uint8_t *out, size_t *outlen);



#ifdef __cplusplus
}
#endif
#endif
