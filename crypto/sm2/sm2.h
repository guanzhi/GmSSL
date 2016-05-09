/* crypto/sm2/sm2.h */
/* ====================================================================
 * Copyright (c) 2015 The GmSSL Project.  All rights reserved.
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
 * ====================================================================
 *
 */


#ifndef HEADER_SM2_H
#define HEADER_SM2_H

#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/ecdsa.h>

#ifdef __cplusplus
extern "C" {
#endif


#define SM2_MAX_ID_BITS				65535
#define SM2_MAX_ID_LENGTH			(SM2_MAX_ID_BITS/8)
#define SM2_DEFAULT_ID				"1234567812345678" 
#define SM2_DEFAULT_POINT_CONVERSION_FORM	POINT_CONVERSION_UNCOMPRESSED


char *SM2_get0_id(EC_KEY *ec_key);
int SM2_set_id(EC_KEY *ec_key, const char *id);
int SM2_compute_id_digest(const EVP_MD *md, unsigned char *dgst,
	unsigned int *dgstlen, EC_KEY *ec_key);


typedef struct sm2_ciphertext_value_st {
	EC_POINT *ephem_point;
	unsigned char *ciphertext;
	size_t ciphertext_size;
	unsigned char mactag[EVP_MAX_MD_SIZE];
	unsigned int mactag_size;
} SM2_CIPHERTEXT_VALUE;

int SM2_CIPHERTEXT_VALUE_size(const EC_GROUP *ec_group,
	point_conversion_form_t point_form, size_t mlen,
	const EVP_MD *mac_md);
void SM2_CIPHERTEXT_VALUE_free(SM2_CIPHERTEXT_VALUE *cv);
int SM2_CIPHERTEXT_VALUE_encode(const SM2_CIPHERTEXT_VALUE *cv,
	const EC_GROUP *ec_group, point_conversion_form_t point_form,
	unsigned char *buf, size_t *buflen);
SM2_CIPHERTEXT_VALUE *SM2_CIPHERTEXT_VALUE_decode(const EC_GROUP *ec_group,
	point_conversion_form_t point_form, const EVP_MD *mac_md,
	const unsigned char *buf, size_t buflen);
int i2d_SM2_CIPHERTEXT_VALUE(const SM2_CIPHERTEXT_VALUE *c, unsigned char **out);
SM2_CIPHERTEXT_VALUE *d2i_SM2_CIPHERTEXT_VALUE(SM2_CIPHERTEXT_VALUE **c,
	const unsigned char **in, long len);
int SM2_CIPHERTEXT_VALUE_print(BIO *out, const EC_GROUP *ec_group,
	const SM2_CIPHERTEXT_VALUE *cv, int indent, unsigned long flags);

/* FIXME: we should provide optional return value */
SM2_CIPHERTEXT_VALUE *SM2_do_encrypt(const EVP_MD *kdf_md, const EVP_MD *mac_md,
	const unsigned char *in, size_t inlen, EC_KEY *ec_key);
int SM2_do_decrypt(const EVP_MD *kdf_md, const EVP_MD *mac_md,
	const SM2_CIPHERTEXT_VALUE *cv, unsigned char *out, size_t *outlen,
	EC_KEY *ec_key);

int SM2_encrypt_ex(const EVP_MD *kdf_md, const EVP_MD *mac_md,
	point_conversion_form_t point_form,
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key);
int SM2_decrypt_ex(const EVP_MD *kdf_md, const EVP_MD *mac_md,
	point_conversion_form_t point_form,
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key);

int SM2_encrypt(const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key);
int SM2_decrypt(const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key);


int SM2_compute_message_digest(const EVP_MD *id_md, const EVP_MD *msg_md,
	const void *msg, size_t msglen, unsigned char *dgst,
	unsigned int *dgstlen, EC_KEY *ec_key);
int SM2_digest(const void *msg, size_t msglen, unsigned char *dgst,
	unsigned int *dgstlen, EC_KEY *ec_key);


#define SM2_signature_size(ec_key)	ECDSA_size(ec_key)
int SM2_sign_setup(EC_KEY *ec_key, BN_CTX *ctx, BIGNUM **a, BIGNUM **b);
ECDSA_SIG *SM2_do_sign_ex(const unsigned char *dgst, int dgstlen,
	const BIGNUM *a, const BIGNUM *b, EC_KEY *ec_key);
ECDSA_SIG *SM2_do_sign(const unsigned char *dgst, int dgst_len,
	EC_KEY *ec_key);
int SM2_do_verify(const unsigned char *dgst, int dgstlen,
	const ECDSA_SIG *sig, EC_KEY *ec_key);
int SM2_sign_ex(int type, const unsigned char *dgst, int dgstlen,
	unsigned char *sig, unsigned int *siglen,
	const BIGNUM *k, const BIGNUM *x, EC_KEY *ec_key);
int SM2_sign(int type, const unsigned char *dgst, int dgstlen,
	unsigned char *sig, unsigned int *siglen, EC_KEY *eckey);
#define SM2_VERIFY_SUCCESS	 1
#define SM2_VERIFY_FAILED	 0
#define SM2_VERIFY_INNER_ERROR	-1
int SM2_verify(int type, const unsigned char *dgst, int dgstlen,
	const unsigned char *sig, int siglen, EC_KEY *ec_key);



typedef struct sm2_kap_ctx_st {

	const EVP_MD *id_dgst_md;
	const EVP_MD *kdf_md;
	const EVP_MD *checksum_md;
	point_conversion_form_t point_form;
	KDF_FUNC kdf;
	
	int is_initiator;
	int do_checksum;

	EC_KEY *ec_key;
	unsigned char id_dgst[EVP_MAX_MD_SIZE];
	unsigned int id_dgstlen;
	
	EC_KEY *remote_pubkey;
	unsigned char remote_id_dgst[EVP_MAX_MD_SIZE];
	unsigned int remote_id_dgstlen;

	const EC_GROUP *group;
	BN_CTX *bn_ctx;
	BIGNUM *order;
	BIGNUM *two_pow_w;
	
	BIGNUM *t;
	EC_POINT *point;
	unsigned char pt_buf[1 + (OPENSSL_ECC_MAX_FIELD_BITS+7)/4];
	unsigned char checksum[EVP_MAX_MD_SIZE];

} SM2_KAP_CTX;



int SM2_KAP_CTX_init(SM2_KAP_CTX *ctx, EC_KEY *ec_key,
	EC_KEY *remote_pubkey, int is_initiator, int do_checksum);
int SM2_KAP_prepare(SM2_KAP_CTX *ctx, unsigned char *ephem_point,
	size_t *ephem_point_len);
int SM2_KAP_compute_key(SM2_KAP_CTX *ctx, const unsigned char *remote_ephem_point,
	size_t remote_ephem_point_len, unsigned char *key, size_t keylen,
	unsigned char *checksum, size_t *checksumlen);
int SM2_KAP_final_check(SM2_KAP_CTX *ctx, const unsigned char *checksum,
	size_t checksumlen);
void SM2_KAP_CTX_cleanup(SM2_KAP_CTX *ctx);




void ERR_load_SM2_strings(void);

/* Function codes. */
#define SM2_F_SM2_SET_ID			100
#define SM2_F_SM2_GET_ID			101
#define SM2_F_SM2_COMPUTE_ID_DIGEST		102
#define SM2_F_SM2_CIPHERTEXT_VALUE_SIZE		103
#define SM2_F_SM2_CIPHERTEXT_VALUE_FREE		104
#define SM2_F_SM2_CIPHERTEXT_VALUE_ENCODE	105
#define SM2_F_SM2_CIPHERTEXT_VALUE_DECODE	106
#define SM2_F_SM2_CIPHERTEXT_VALUE_PRINT	107
#define SM2_F_SM2_DO_ENCRYPT			108
#define SM2_F_SM2_DO_DECRYPT			109
#define SM2_F_SM2_ENCRYPT			110
#define SM2_F_SM2_DECRYPT			111
#define SM2_F_SM2_SIGNATURE_SIZE		112
#define SM2_F_SM2_SIGN_SETUP			113
#define SM2_F_SM2_DO_SIGN_EX			114
#define SM2_F_SM2_DO_SIGN			115
#define SM2_F_SM2_DO_VERIFY			116
#define SM2_F_SM2_SIGN_EX			117
#define SM2_F_SM2_SIGN				118
#define SM2_F_SM2_VERIFY			119
#define SM2_F_SM2_KAP_CTX_INIT			120
#define SM2_F_SM2_KAP_CTX_CLEANUP		121
#define SM2_F_SM2_KAP_PREPARE			122
#define SM2_F_SM2_KAP_COMPUTE_KEY		123
#define SM2_F_SM2_KAP_FINAL_CHECK		124	


/* Reason codes. */
#define SM2_R_BAD_DATA				100
#define SM2_R_UNKNOWN_CIPHER_TYPE		101
#define SM2_R_ENCRYPT_FAILED			102
#define SM2_R_DECRYPT_FAILED			103
#define SM2_R_UNKNOWN_MAC_TYPE			104
#define SM2_R_GEN_MAC_FAILED			105
#define SM2_R_VERIFY_MAC_FAILED			106
#define SM2_R_ECDH_FAILED			107
#define SM2_R_BUFFER_TOO_SMALL			108
#define SM2_R_SM2_KAP_NOT_INITED		109
#define SM2_R_RANDOM_NUMBER_GENERATION_FAILED	110

#ifdef __cplusplus
}
#endif
#endif

