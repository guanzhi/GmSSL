/* ====================================================================
 * Copyright (c) 2016 - 2018 The GmSSL Project.  All rights reserved.
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

#ifndef HEADER_SM9_H
#define HEADER_SM9_H

#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_SM9

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>

/* set the same value as sm2 */
#define SM9_MAX_ID_BITS		65535
#define SM9_MAX_ID_LENGTH	(SM9_MAX_ID_BITS/8)

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SM9_MASTER_KEY_st SM9_MASTER_KEY;
typedef struct SM9_KEY_st SM9_KEY;
typedef struct SM9Signature_st SM9Signature;
typedef struct SM9Ciphertext_st SM9Ciphertext;

typedef SM9_MASTER_KEY SM9MasterSecret;
typedef SM9_MASTER_KEY SM9PublicParameters;
typedef SM9_KEY SM9PrivateKey;
typedef SM9_KEY SM9PublicKey;

SM9_MASTER_KEY *SM9_MASTER_KEY_new(void);
void SM9_MASTER_KEY_free(SM9_MASTER_KEY *a);
SM9_KEY *SM9_KEY_new(void);
void SM9_KEY_free(SM9_KEY *a);

int SM9_MASTER_KEY_up_ref(SM9_MASTER_KEY *msk);
int SM9_KEY_up_ref(SM9_KEY *sk);

int SM9_setup(int pairing, /* NID_sm9bn256v1 */
	int scheme, /* NID_[sm9sign | sm9encrypt | sm9keyagreement] */
	int hash1, /* NID_sm9hash1_with_[sm3 | sha256] */
	SM9PublicParameters **mpk,
	SM9MasterSecret **msk);

SM9MasterSecret *SM9_generate_master_secret(int pairing, int scheme, int hash1);
SM9PublicParameters *SM9_extract_public_parameters(SM9MasterSecret *msk);
SM9PrivateKey *SM9_extract_private_key(SM9MasterSecret *msk,
	const char *id, size_t idlen);
SM9PublicKey *SM9_extract_public_key(SM9PublicParameters *mpk,
	const char *id, size_t idlen);

SM9PublicKey *SM9PrivateKey_get_public_key(SM9PrivateKey *sk);

int SM9PrivateKey_get_gmtls_public_key(SM9PublicParameters *mpk,
	SM9PrivateKey *sk, unsigned char pub_key[1024]);

int SM9PublicKey_get_gmtls_encoded(SM9PublicParameters *mpk,
	SM9PublicKey *pk, unsigned char encoded[1024]);

int SM9_signature_size(const SM9PublicParameters *mpk);

SM9Signature *SM9_do_sign(const unsigned char *dgst, int dgstlen, SM9_KEY *sm9);
int SM9_do_verify(const unsigned char *dgst, int dgstlen,
	const SM9Signature *sig, SM9_KEY *sm9);

int SM9_sign(int type,
	const unsigned char *data, size_t datalen,
	unsigned char *sig, size_t *siglen,
	SM9PrivateKey *sk);

int SM9_verify(int type,
	const unsigned char *data, size_t datalen,
	const unsigned char *sig, size_t siglen,
	SM9PublicParameters *mpk, const char *id, size_t idlen);

int SM9_SignInit(EVP_MD_CTX *ctx, const EVP_MD *md, ENGINE *engine);
#define SM9_SignUpdate(ctx,d,l) EVP_DigestUpdate(ctx,d,l)
SM9Signature *SM9_SignFinal(EVP_MD_CTX *ctx, SM9PrivateKey *sk);

int SM9_VerifyInit(EVP_MD_CTX *ctx, const EVP_MD *md, ENGINE *engine);
#define SM9_VerifyUpdate(ctx,d,l) EVP_DigestUpdate(ctx,d,l)
int SM9_VerifyFinal(EVP_MD_CTX *ctx, const SM9Signature *sig, SM9PublicKey *pk);

int SM9_wrap_key(int type, /* NID_sm9kdf_with_sm3 */
	unsigned char *key, size_t keylen,
	unsigned char *enced_key, size_t *enced_len,
	SM9PublicParameters *mpk, const char *id, size_t idlen);

int SM9_unwrap_key(int type,
	unsigned char *key, size_t keylen,
	const unsigned char *enced_key, size_t enced_len,
	SM9PrivateKey *sk);

int SM9_ciphertext_size(const SM9_MASTER_KEY *params, size_t inlen);

int SM9_encrypt(int type, /* NID_sm9encrypt_with_sm3_xor */
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen,
	SM9PublicParameters *mpk, const char *id, size_t idlen);

int SM9_decrypt(int type,
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen,
	SM9PrivateKey *sk);

/* the key agreement API might be changed */
int SM9_generate_key_exchange(unsigned char *R, size_t *Rlen, /* R = r * Q_ID */
	BIGNUM *r, unsigned char *gr, size_t *grlen, /* gr = e(Ppube, P2)^r */
	const char *peer_id, size_t peer_idlen, /* peer's identity */
	SM9PrivateKey *sk, int initiator);

int SM9_compute_share_key_A(int type,
	unsigned char *SKA, size_t SKAlen,
	unsigned char SA[32], /* optional, send to B */
	const unsigned char SB[32], /* optional, recv from B */
	const BIGNUM *rA,
	const unsigned char RA[65],
	const unsigned char RB[65],
	const unsigned char g1[384],
	const char *IDB, size_t IDBlen,
	SM9PrivateKey *skA);

int SM9_compute_share_key_B(int type,
	unsigned char *SKB, size_t SKBlen,
	unsigned char SB[32], /* optional, send to A */
	unsigned char S2[32], /* optional, to be compared with recved SA */
	const BIGNUM *rB,
	const unsigned char RB[65],
	const unsigned char RA[65],
	const unsigned char g2[384],
	const char *IDA, size_t IDAlen,
	SM9PrivateKey *skB);

int SM9_MASTER_KEY_print(BIO *bp, const SM9_MASTER_KEY *x, int off);
int SM9_KEY_print(BIO *bp, const SM9_KEY *x, int off);

SM9Ciphertext *d2i_SM9Ciphertext_bio(BIO *bp, SM9Ciphertext **a);
int i2d_SM9MasterSecret_bio(BIO *bp, SM9MasterSecret *a);
SM9MasterSecret *d2i_SM9MasterSecret_bio(BIO *bp, SM9MasterSecret **a);
int i2d_SM9PublicParameters_bio(BIO *bp, SM9PublicParameters *a);
SM9PublicParameters *d2i_SM9PublicParameters_bio(BIO *bp, SM9PublicParameters **a);
int i2d_SM9PrivateKey_bio(BIO *bp, SM9PrivateKey *a);
SM9PrivateKey *d2i_SM9PrivateKey_bio(BIO *bp, SM9PrivateKey **a);
int i2d_SM9Signature_bio(BIO *bp, SM9Signature *a);
SM9Signature *d2i_SM9Signature_bio(BIO *bp, SM9Signature **a);
int i2d_SM9Ciphertext_bio(BIO *bp, SM9Ciphertext *a);

#ifndef OPENSSL_NO_STDIO
SM9MasterSecret *d2i_SM9MasterSecret_fp(FILE *fp, SM9MasterSecret **pp);
SM9PublicParameters *d2i_SM9PublicParameters_fp(FILE *fp, SM9PublicParameters **pp);
SM9PrivateKey *d2i_SM9PrivateKey_fp(FILE *fp, SM9PrivateKey **pp);
SM9Signature *d2i_SM9Signature_fp(FILE *fp, SM9Signature **pp);
SM9Ciphertext *d2i_SM9Ciphertext_fp(FILE *fp, SM9Ciphertext **pp);

int i2d_SM9MasterSecret_fp(FILE *fp, SM9MasterSecret *a);
int i2d_SM9PublicParameters_fp(FILE *fp, SM9PublicParameters *a);
int i2d_SM9PrivateKey_fp(FILE *fp, SM9PrivateKey *a);
int i2d_SM9Signature_fp(FILE *fp, SM9Signature *a);
int i2d_SM9Ciphertext_fp(FILE *fp, SM9Ciphertext *a);
#endif

DECLARE_ASN1_ENCODE_FUNCTIONS_const(SM9_MASTER_KEY,SM9MasterSecret)
DECLARE_ASN1_ENCODE_FUNCTIONS_const(SM9_MASTER_KEY,SM9PublicParameters)
DECLARE_ASN1_ENCODE_FUNCTIONS_const(SM9_KEY,SM9PrivateKey)
DECLARE_ASN1_ENCODE_FUNCTIONS_const(SM9_KEY,SM9PublicKey)
DECLARE_ASN1_FUNCTIONS(SM9Signature)
DECLARE_ASN1_FUNCTIONS(SM9Ciphertext)

#define SM9MasterSecret_new() SM9_MASTER_KEY_new()
#define SM9MasterSecret_free(a) SM9_MASTER_KEY_free(a)
#define SM9PublicParameters_new() SM9_MASTER_KEY_new()
#define SM9PublicParameters_free(a) SM9_MASTER_KEY_free(a)
#define SM9PrivateKey_new() SM9_KEY_new()
#define SM9PrivateKey_free(a) SM9_KEY_free(a)
#define SM9PublicKey_new() SM9_KEY_new()
#define SM9PublicKey_free(a) SM9_KEY_free(a)

# define EVP_PKEY_CTRL_SM9_PAIRING		(EVP_PKEY_ALG_CTRL + 1)
# define EVP_PKEY_CTRL_SM9_SCHEME		(EVP_PKEY_ALG_CTRL + 2)
# define EVP_PKEY_CTRL_SM9_HASH1		(EVP_PKEY_ALG_CTRL + 3)
# define EVP_PKEY_CTRL_SM9_SIGN_SCHEME		(EVP_PKEY_ALG_CTRL + 4)
# define EVP_PKEY_CTRL_SM9_ENCRYPT_SCHEME	(EVP_PKEY_ALG_CTRL + 5)
# define EVP_PKEY_CTRL_SM9_ID			(EVP_PKEY_ALG_CTRL + 6)
# define EVP_PKEY_CTRL_GET_SM9_ID		(EVP_PKEY_ALG_CTRL + 7)

# define EVP_PKEY_CTX_set_sm9_pairing(ctx, nid) \
	EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_SM9_MASTER, \
		EVP_PKEY_OP_KEYGEN, \
		EVP_PKEY_CTRL_SM9_PAIRING, nid, NULL)

# define EVP_PKEY_CTX_get_sm9_pairing(ctx) \
	EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_SM9_MASTER, \
		EVP_PKEY_OP_KEYGEN, \
		EVP_PKEY_CTRL_SM9_PAIRING, -2, NULL)

# define EVP_PKEY_CTX_set_sm9_scheme(ctx, nid) \
	EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_SM9_MASTER, \
		EVP_PKEY_OP_KEYGEN, \
		EVP_PKEY_CTRL_SM9_SCHEME, nid, NULL)

# define EVP_PKEY_CTX_get_sm9_scheme(ctx) \
	EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_SM9_MASTER, \
		EVP_PKEY_OP_KEYGEN, \
		EVP_PKEY_CTRL_SM9_SCHEME, -2, NULL)

# define EVP_PKEY_CTX_set_sm9_hash1(ctx, nid) \
	EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_SM9_MASTER, \
		EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_SM9_HASH1, nid, NULL)

# define EVP_PKEY_CTX_get_sm9_hash1(ctx) \
	EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_SM9_MASTER, \
		EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_SM9_HASH1, -2, NULL)

# define EVP_PKEY_CTX_set_sm9_encrypt_scheme(ctx, nid) \
	EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_SM9_MASTER, \
		EVP_PKEY_OP_ENCRYPT, \
		EVP_PKEY_CTRL_SM9_ENCRYPT_SCHEME, nid, NULL)

# define EVP_PKEY_CTX_set_sm9_decrypt_scheme(ctx, nid) \
	EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_SM9, \
		EVP_PKEY_OP_DECRYPT|EVP_PKEY_OP_ENCRYPT, \
		EVP_PKEY_CTRL_SM9_ENCRYPT_SCHEME, nid, NULL)

# define EVP_PKEY_CTX_set_sm9_sign_scheme(ctx, nid) \
	EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_SM9, \
		EVP_PKEY_OP_SIGN|EVP_PKEY_OP_SIGNCTX| \
		EVP_PKEY_OP_VERIFY|EVP_PKEY_OP_VERIFYCTX, \
		EVP_PKEY_CTRL_SM9_SIGN_SCHEME, nid, NULL)

# define EVP_PKEY_CTX_set_sm9_verify_scheme(ctx, nid) \
	EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_SM9_MASTER, \
		EVP_PKEY_OP_VERIFY|EVP_PKEY_OP_VERIFYCTX, \
		EVP_PKEY_CTRL_SM9_SIGN_SCHEME, nid, NULL)

# define EVP_PKEY_CTX_set_sm9_id(ctx, id) \
	EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_SM9_MASTER, \
		EVP_PKEY_OP_ENCRYPT| \
		EVP_PKEY_OP_VERIFY|EVP_PKEY_OP_VERIFYCTX, \
		EVP_PKEY_CTRL_SM9_ID, 0, (void *)id)

# define EVP_PKEY_CTX_get_sm9_id(ctx, pid) \
	EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_SM9_MASTER, \
		EVP_PKEY_OP_ENCRYPT| \
		EVP_PKEY_OP_VERIFY|EVP_PKEY_OP_VERIFYCTX, \
		EVP_PKEY_CTRL_GET_SM9_ID, 0, (void *)pid)

/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */

int ERR_load_SM9_strings(void);

/* Error codes for the SM9 functions. */

/* Function codes. */
# define SM9_F_DO_SM9_KEY_PRINT                           100
# define SM9_F_DO_SM9_MASTER_KEY_PRINT                    101
# define SM9_F_PKEY_SM9_COPY                              102
# define SM9_F_PKEY_SM9_CTRL                              103
# define SM9_F_PKEY_SM9_CTRL_STR                          104
# define SM9_F_PKEY_SM9_DECRYPT                           105
# define SM9_F_PKEY_SM9_INIT                              106
# define SM9_F_PKEY_SM9_MASTER_COPY                       107
# define SM9_F_PKEY_SM9_MASTER_CTRL                       108
# define SM9_F_PKEY_SM9_MASTER_CTRL_STR                   109
# define SM9_F_PKEY_SM9_MASTER_ENCRYPT                    110
# define SM9_F_PKEY_SM9_MASTER_INIT                       111
# define SM9_F_PKEY_SM9_MASTER_KEYGEN                     112
# define SM9_F_PKEY_SM9_MASTER_VERIFY                     113
# define SM9_F_PKEY_SM9_SIGN                              114
# define SM9_F_SM9_CIPHERTEXT_SIZE                        141
# define SM9_F_SM9_COMPUTE_SHARE_KEY_A                    115
# define SM9_F_SM9_COMPUTE_SHARE_KEY_B                    116
# define SM9_F_SM9_DECRYPT                                117
# define SM9_F_SM9_ENCRYPT                                118
# define SM9_F_SM9_EXTRACT_PUBLIC_PARAMETERS              119
# define SM9_F_SM9_GENERATE_KEY_EXCHANGE                  120
# define SM9_F_SM9_GENERATE_MASTER_SECRET                 121
# define SM9_F_SM9_KEY_NEW                                122
# define SM9_F_SM9_MASTER_KEY_EXTRACT_KEY                 123
# define SM9_F_SM9_MASTER_KEY_NEW                         124
# define SM9_F_SM9_MASTER_OLD_PRIV_DECODE                 125
# define SM9_F_SM9_MASTER_PRIV_DECODE                     126
# define SM9_F_SM9_MASTER_PRIV_ENCODE                     127
# define SM9_F_SM9_MASTER_PUB_DECODE                      128
# define SM9_F_SM9_OLD_PRIV_DECODE                        129
# define SM9_F_SM9_PRIV_DECODE                            130
# define SM9_F_SM9_PRIV_ENCODE                            131
# define SM9_F_SM9_PUB_DECODE                             132
# define SM9_F_SM9_SIGN                                   133
# define SM9_F_SM9_SIGNFINAL                              134
# define SM9_F_SM9_SIGNINIT                               135
# define SM9_F_SM9_UNWRAP_KEY                             136
# define SM9_F_SM9_VERIFY                                 137
# define SM9_F_SM9_VERIFYFINAL                            138
# define SM9_F_SM9_VERIFYINIT                             139
# define SM9_F_SM9_WRAP_KEY                               140

/* Reason codes. */
# define SM9_R_BUFFER_TOO_SMALL                           100
# define SM9_R_DECODE_ERROR                               101
# define SM9_R_DIGEST_FAILURE                             102
# define SM9_R_EC_LIB                                     103
# define SM9_R_EXTENSION_FIELD_ERROR                      104
# define SM9_R_IDENTITY_REQUIRED                          105
# define SM9_R_INVALID_DIGEST_TYPE                        106
# define SM9_R_INVALID_ENCRYPT_SCHEME                     107
# define SM9_R_INVALID_HASH1                              108
# define SM9_R_INVALID_HASH2_DIGEST                       109
# define SM9_R_INVALID_ID                                 110
# define SM9_R_INVALID_KEM_KEY_LENGTH                     111
# define SM9_R_INVALID_KEY_AGREEMENT_CHECKSUM             112
# define SM9_R_INVALID_KEY_USAGE                          113
# define SM9_R_INVALID_PAIRING                            114
# define SM9_R_INVALID_PAIRING_TYPE                       115
# define SM9_R_INVALID_POINTPPUB                          116
# define SM9_R_INVALID_PRIVATE_POINT                      117
# define SM9_R_INVALID_SCHEME                             118
# define SM9_R_INVALID_SIGNATURE                          119
# define SM9_R_INVALID_SIGNATURE_FORMAT                   120
# define SM9_R_INVALID_SIGN_MD                            121
# define SM9_R_INVALID_SIGN_SCHEME                        122
# define SM9_R_INVALID_SM9_SCHEME                         123
# define SM9_R_NO_MASTER_SECRET                           124
# define SM9_R_PAIRING_ERROR                              125
# define SM9_R_PLAINTEXT_TOO_LONG                         131
# define SM9_R_RATE_PAIRING_ERROR                         126
# define SM9_R_SIGNER_ID_REQUIRED                         127
# define SM9_R_TWIST_CURVE_ERROR                          128
# define SM9_R_VERIFY_FAILURE                             129
# define SM9_R_ZERO_ID                                    130

#  ifdef  __cplusplus
}
#  endif
# endif
#endif
