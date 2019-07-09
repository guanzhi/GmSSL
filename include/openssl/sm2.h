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

#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_SM2

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
#define SM2_DEFAULT_ID				SM2_DEFAULT_ID_GMT09
#define SM2_DEFAULT_ID_LENGTH			(sizeof(SM2_DEFAULT_ID) - 1)
#define SM2_DEFAULT_ID_BITS			(SM2_DEFAULT_ID_LENGTH * 8)
#define SM2_DEFAULT_ID_DIGEST_LENGTH		SM3_DIGEST_LENGTH


int EC_KEY_is_sm2p256v1(const EC_KEY *ec_key);

/* compute identity digest Z */
int SM2_compute_id_digest(const EVP_MD *md, const char *id, size_t idlen,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key);
int SM2_compute_message_digest(const EVP_MD *id_md, const EVP_MD *msg_md,
	const unsigned char *msg, size_t msglen, const char *id, size_t idlen,
	unsigned char *out, size_t *outlen,
	EC_KEY *ec_key);


/* SM2 digital signature */

#define SM2_MAX_SIGNATURE_LENGTH	96

int SM2_sign_setup(EC_KEY *ec_key, BN_CTX *ctx, BIGNUM **a, BIGNUM **b);
ECDSA_SIG *SM2_do_sign_ex(const unsigned char *dgst, int dgstlen,
	const BIGNUM *k, const BIGNUM *x, EC_KEY *ec_key);
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

/* SM2 Public Key Encryption */

typedef struct SM2CiphertextValue_st SM2CiphertextValue;
DECLARE_ASN1_FUNCTIONS(SM2CiphertextValue)

int i2d_SM2CiphertextValue_bio(BIO *bp, SM2CiphertextValue *a);
SM2CiphertextValue *d2i_SM2CiphertextValue_bio(BIO *bp, SM2CiphertextValue **a);
#ifndef OPENSSL_NO_STDIO
SM2CiphertextValue *d2i_SM2CiphertextValue_fp(FILE *fp, SM2CiphertextValue **a);
int i2d_SM2CiphertextValue_fp(FILE *fp, SM2CiphertextValue *a);
#endif

int i2o_SM2CiphertextValue(const EC_GROUP *group, const SM2CiphertextValue *cv,
	unsigned char **pout);
SM2CiphertextValue *o2i_SM2CiphertextValue(const EC_GROUP *group, const EVP_MD *md,
	SM2CiphertextValue **cv, const unsigned char **pin, long len);

SM2CiphertextValue *SM2_do_encrypt(const EVP_MD *md,
	const unsigned char *in, size_t inlen, EC_KEY *ec_key);
int SM2_do_decrypt(const EVP_MD *md, const SM2CiphertextValue *in,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key);
int SM2_encrypt(int type, const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key);
int SM2_decrypt(int type, const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key);
#define SM2_encrypt_with_recommended(in,inlen,out,outlen,ec_key) \
	SM2_encrypt(NID_sm3,in,inlen,out,outlen,ec_key)
#define SM2_decrypt_with_recommended(in,inlen,out,outlen,ec_key) \
	SM2_decrypt(NID_sm3,in,inlen,out,outlen,ec_key)

/* SM2 Key Exchange */

int SM2_compute_share_key(unsigned char *out, size_t *outlen,
	const EC_POINT *peer_ephem, EC_KEY *ephem,
	const EC_POINT *peer_pk, const unsigned char *peer_z, size_t peer_zlen,
	const unsigned char *z, size_t zlen, EC_KEY *sk, int initiator);

typedef struct sm2_kap_ctx_st SM2_KAP_CTX;

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


/* EC_KEY_METHOD */
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


#define EVP_PKEY_CTRL_EC_SCHEME	    	(EVP_PKEY_ALG_CTRL + 11)
#define EVP_PKEY_CTRL_SIGNER_ID		(EVP_PKEY_ALG_CTRL + 12)
#define EVP_PKEY_CTRL_GET_SIGNER_ID	(EVP_PKEY_ALG_CTRL + 13)
#define EVP_PKEY_CTRL_GET_SIGNER_ZID    (EVP_PKEY_ALG_CTRL + 14)
#define EVP_PKEY_CTRL_EC_ENCRYPT_PARAM  (EVP_PKEY_ALG_CTRL + 15)

#define EVP_PKEY_CTX_set_ec_scheme(ctx, scheme) \
	EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, \
		EVP_PKEY_OP_SIGN|EVP_PKEY_OP_SIGNCTX| \
		EVP_PKEY_OP_VERIFY|EVP_PKEY_OP_VERIFYCTX| \
		EVP_PKEY_OP_ENCRYPT|EVP_PKEY_OP_DECRYPT| \
		EVP_PKEY_OP_DERIVE, \
		EVP_PKEY_CTRL_EC_SCHEME, scheme, NULL)

#define EVP_PKEY_CTX_get_ec_scheme(ctx) \
	EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, \
		EVP_PKEY_OP_SIGN|EVP_PKEY_OP_SIGNCTX| \
		EVP_PKEY_OP_VERIFY|EVP_PKEY_OP_VERIFYCTX| \
		EVP_PKEY_OP_ENCRYPT|EVP_PKEY_OP_DECRYPT| \
		EVP_PKEY_OP_DERIVE, \
		EVP_PKEY_CTRL_EC_SCHEME, -2, NULL)

#define EVP_PKEY_CTX_set_signer_id(ctx, id) \
	EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, \
		EVP_PKEY_OP_SIGN|EVP_PKEY_OP_SIGNCTX| \
		EVP_PKEY_OP_VERIFY|EVP_PKEY_OP_VERIFYCTX| \
		EVP_PKEY_OP_DERIVE, \
		EVP_PKEY_CTRL_SIGNER_ID, 0, (void *)id)

#define EVP_PKEY_CTX_get_signer_id(ctx, pid) \
	EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, \
		EVP_PKEY_OP_SIGN|EVP_PKEY_OP_SIGNCTX| \
		EVP_PKEY_OP_VERIFY|EVP_PKEY_OP_VERIFYCTX| \
		EVP_PKEY_OP_DERIVE, \
		EVP_PKEY_CTRL_GET_SIGNER_ID, 0, (void *)pid)

#define EVP_PKEY_CTX_get_signer_zid(ctx, pzid) \
	EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, \
		EVP_PKEY_OP_SIGN|EVP_PKEY_OP_SIGNCTX| \
		EVP_PKEY_OP_VERIFY|EVP_PKEY_OP_VERIFYCTX| \
		EVP_PKEY_OP_DERIVE, \
		EVP_PKEY_CTRL_GET_SIGNER_ZID, 0, (void *)pzid)

#define EVP_PKEY_CTX_set_ec_encrypt_param(ctx, param) \
	EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, \
		EVP_PKEY_OP_ENCRYPT|EVP_PKEY_OP_DECRYPT, \
		EVP_PKEY_CTRL_EC_ENCRYPT_PARAM, param, NULL)

#define EVP_PKEY_CTX_get_ec_encrypt_param(ctx) \
	EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, \
		EVP_PKEY_OP_ENCRYPT|EVP_PKEY_OP_DECRYPT, \
		EVP_PKEY_CTRL_EC_ENCRYPT_PARAM, -2, NULL)


/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */

int ERR_load_SM2_strings(void);

/* Error codes for the SM2 functions. */

/* Function codes. */
# define SM2_F_I2O_SM2CIPHERTEXTVALUE                     107
# define SM2_F_O2I_SM2CIPHERTEXTVALUE                     108
# define SM2_F_SM2CIPHERTEXTVALUE_SIZE                    109
# define SM2_F_SM2_CIPHERTEXT_SIZE                        110
# define SM2_F_SM2_COSIGNER1_GENERATE_PROOF               111
# define SM2_F_SM2_COSIGNER1_GENERATE_SIGNATURE           112
# define SM2_F_SM2_COSIGNER1_SETUP                        113
# define SM2_F_SM2_COSIGNER2_GENERATE_PROOF               114
# define SM2_F_SM2_COSIGNER2_SETUP                        115
# define SM2_F_SM2_DECRYPT                                100
# define SM2_F_SM2_DO_DECRYPT                             101
# define SM2_F_SM2_DO_ENCRYPT                             102
# define SM2_F_SM2_DO_SIGN                                104
# define SM2_F_SM2_DO_VERIFY                              105
# define SM2_F_SM2_ENCRYPT                                103
# define SM2_F_SM2_SIGN_SETUP                             106

/* Reason codes. */
# define SM2_R_BAD_SIGNATURE                              110
# define SM2_R_BUFFER_TOO_SMALL                           100
# define SM2_R_DECRYPT_FAILURE                            101
# define SM2_R_ENCRYPT_FAILURE                            102
# define SM2_R_INVALID_CIPHERTEXT                         103
# define SM2_R_INVALID_DIGEST_ALGOR                       104
# define SM2_R_INVALID_EC_KEY                             105
# define SM2_R_INVALID_INPUT_LENGTH                       106
# define SM2_R_INVALID_PLAINTEXT_LENGTH                   107
# define SM2_R_INVALID_PUBLIC_KEY                         108
# define SM2_R_KDF_FAILURE                                109
# define SM2_R_MISSING_PARAMETERS                         111
# define SM2_R_NEED_NEW_SETUP_VALUES                      112
# define SM2_R_NOT_IMPLEMENTED                            115
# define SM2_R_PLAINTEXT_TOO_LONG                         114
# define SM2_R_RANDOM_NUMBER_GENERATION_FAILED            113

#  ifdef  __cplusplus
}
#  endif
# endif
#endif
