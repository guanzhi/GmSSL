/* ====================================================================
 * Copyright (c) 2015 - 2016 The GmSSL Project.  All rights reserved.
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
 */

#ifndef HEADER_SM2_H
#define HEADER_SM2_H

#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf2.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/ecies.h>
#include <openssl/sm3.h>

#ifdef __cplusplus
extern "C" {
#endif


#define SM2_MAX_ID_BITS				65535
#define SM2_MAX_ID_LENGTH			(SM2_MAX_ID_BITS/8)

#define SM2_DEFAULT_ID_GMT09			"1234567812345678"
#define SM2_DEFAULT_ID_GMSSL			"anonym@gmssl.org"
#define SM2_DEFAULT_ID				SM2_DEFAULT_ID_GMSSL
#define SM2_DEFAULT_ID_LENGTH			(sizeof(SM2_DEFAULT_ID) - 1)
#define SM2_DEFAULT_ID_BITS			(SM2_DEFAULT_ID_LENGTH * 8)
#define SM2_ID_DIGEST_LENGTH			SM3_DIGEST_LENGTH

#define SM2_DEFAULT_POINT_CONVERSION_FORM	POINT_CONVERSION_UNCOMPRESSED

#define SM2_MAX_PKEY_DATA_LENGTH		((EC_MAX_NBYTES + 1) * 6)



int SM2_get_public_key_data(EC_KEY *ec_key, unsigned char *out, size_t *outlen);

int SM2_compute_id_digest(const EVP_MD *md, const char *id, size_t idlen,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key);

/*
 * Generate GM/T 0003.2-2012 message digest for SM2 signature scheme.
 * Return dgst = msg_md( id_md(id, ec_key) || msg )
 */
int SM2_compute_message_digest(const EVP_MD *id_md, const EVP_MD *msg_md,
	const unsigned char *msg, size_t msglen, const char *id, size_t idlen,
	unsigned char *out, size_t *outlen,
	EC_KEY *ec_key);


typedef struct sm2_enc_params_st {
	const EVP_MD *kdf_md;
	const EVP_MD *mac_md;
	point_conversion_form_t point_form;
} SM2_ENC_PARAMS;


/* SM2_ENC_PARAMS_dup() is used by ec_pmeth.c,
 * so the SM2_ENC_PARAMS_new() and SM2_ENC_PARAMS_free() is also provided
 */
SM2_ENC_PARAMS *SM2_ENC_PARAMS_new(void);
SM2_ENC_PARAMS *SM2_ENC_PARAMS_dup(const SM2_ENC_PARAMS *param);
void SM2_ENC_PARAMS_free(SM2_ENC_PARAMS *param);

int SM2_ENC_PARAMS_init_with_recommended(SM2_ENC_PARAMS *param);


typedef struct sm2_ciphertext_value_st {
	EC_POINT *ephem_point;
	unsigned char *ciphertext;
	size_t ciphertext_size;
	unsigned char mactag[EVP_MAX_MD_SIZE];
	unsigned int mactag_size;
} SM2_CIPHERTEXT_VALUE;

int SM2_CIPHERTEXT_VALUE_size(const EC_GROUP *ec_group,
	const SM2_ENC_PARAMS *params, size_t mlen);

SM2_CIPHERTEXT_VALUE *SM2_CIPHERTEXT_VALUE_new(const EC_GROUP *group);
void SM2_CIPHERTEXT_VALUE_free(SM2_CIPHERTEXT_VALUE *cv);
int SM2_CIPHERTEXT_VALUE_encode(const SM2_CIPHERTEXT_VALUE *cv,
	const EC_GROUP *ec_group, const SM2_ENC_PARAMS *params,
	unsigned char *buf, size_t *buflen);
SM2_CIPHERTEXT_VALUE *SM2_CIPHERTEXT_VALUE_decode(const EC_GROUP *ec_group,
	const SM2_ENC_PARAMS *params, const unsigned char *buf, size_t buflen);

int i2d_SM2_CIPHERTEXT_VALUE(const EC_GROUP *group,
	const SM2_CIPHERTEXT_VALUE *c, unsigned char **out);
SM2_CIPHERTEXT_VALUE *d2i_SM2_CIPHERTEXT_VALUE(const EC_GROUP *group,
	SM2_CIPHERTEXT_VALUE **c, const unsigned char **in, long len);

int SM2_CIPHERTEXT_VALUE_print(BIO *out, const EC_GROUP *ec_group,
	const SM2_CIPHERTEXT_VALUE *cv, int indent, unsigned long flags);

SM2_CIPHERTEXT_VALUE *SM2_do_encrypt(const SM2_ENC_PARAMS *params,
	const unsigned char *in, size_t inlen, EC_KEY *ec_key);
int SM2_do_decrypt(const SM2_ENC_PARAMS *params,
	const SM2_CIPHERTEXT_VALUE *in, unsigned char *out, size_t *outlen,
	EC_KEY *ec_key);
int SM2_encrypt(const SM2_ENC_PARAMS *params,
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen,
	EC_KEY *ec_key);
int SM2_decrypt(const SM2_ENC_PARAMS *params,
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen,
	EC_KEY *ec_key);


int SM2_encrypt_with_recommended(const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key);
int SM2_decrypt_with_recommended(const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key);


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

int SM2_KAP_CTX_init(SM2_KAP_CTX *ctx,
	EC_KEY *ec_key, const char *id, size_t idlen,
	EC_KEY *remote_pubkey, const char *rid, size_t ridlen,
	int is_initiator, int do_checksum);
int SM2_KAP_prepare(SM2_KAP_CTX *ctx, unsigned char *ephem_point,
	size_t *ephem_point_len);
int SM2_KAP_compute_key(SM2_KAP_CTX *ctx, const unsigned char *remote_ephem_point,
	size_t remote_ephem_point_len, unsigned char *key, size_t keylen,
	unsigned char *checksum, size_t *checksumlen);
int SM2_KAP_final_check(SM2_KAP_CTX *ctx, const unsigned char *checksum,
	size_t checksumlen);
void SM2_KAP_CTX_cleanup(SM2_KAP_CTX *ctx);


const EC_KEY_METHOD *EC_KEY_GmSSL(void);
void EC_KEY_set_default_secg_method(void);
void EC_KEY_set_default_sm_method(void);


int EC_KEY_METHOD_type(const EC_KEY_METHOD *meth);

void EC_KEY_METHOD_set_encrypt(EC_KEY_METHOD *meth,
	int (*encrypt)(int type, const unsigned char *in, size_t inlen,
		unsigned char *out, size_t *outlen, EC_KEY *ec_key),
	ECIES_CIPHERTEXT_VALUE *(*do_encrypt)(int type,
		const unsigned char *in, size_t inlen, EC_KEY *ec_key));

void EC_KEY_METHOD_set_decrypt(EC_KEY_METHOD *meth,
	int (*decrypt)(int type, const unsigned char *in, size_t inlen,
		unsigned char *out, size_t *outlen, EC_KEY *ec_key),
	int (do_decrypt)(int type, const ECIES_CIPHERTEXT_VALUE *in,
		unsigned char *out, size_t *outlen, EC_KEY *ec_key));

void EC_KEY_METHOD_get_encrypt(EC_KEY_METHOD *meth,
	int (**pencrypt)(int type, const unsigned char *in, size_t inlen,
		unsigned char *out, size_t *outlen, EC_KEY *ec_key),
	ECIES_CIPHERTEXT_VALUE *(**pdo_encrypt)(int type,
		const unsigned char *in, size_t inlen, EC_KEY *ec_key));

void EC_KEY_METHOD_get_decrypt(EC_KEY_METHOD *meth,
	int (**pdecrypt)(int type, const unsigned char *in, size_t inlen,
		unsigned char *out, size_t *outlen, EC_KEY *ec_key),
	int (**pdo_decrypt)(int type, const ECIES_CIPHERTEXT_VALUE *in,
		unsigned char *out, size_t *outlen, EC_KEY *ec_key));

#ifdef  __cplusplus
}
#endif
#endif
