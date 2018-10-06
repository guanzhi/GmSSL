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

/* private key extract algorithms */
#define SM9_HID_SIGN		0x01
#define SM9_HID_EXCH		0x02
#define SM9_HID_ENC		0x03

#define SM9_HASH1		0x01
#define SM9_HASH2		0x02

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SM9MasterSecret_st SM9MasterSecret;
typedef struct SM9PublicParameters_st SM9PublicParameters;
typedef struct SM9PrivateKey_st SM9PrivateKey;
typedef struct SM9PublicKey_st SM9PublicKey;
typedef struct SM9Signature_st SM9Signature;
typedef struct SM9Ciphertext_st SM9Ciphertext;


int SM9_setup(int pairing, /* NID_sm9bn256v1 */
	int scheme, /* NID_[sm9sign | sm9encrypt | sm9keyagreement] */
	int hash1, /* NID_sm9hash1_with_[sm3 | sha256] */
	SM9PublicParameters **mpk,
	SM9MasterSecret **msk);

SM9PrivateKey *SM9_extract_private_key(SM9MasterSecret *msk,
	const char *id, size_t idlen);

SM9MasterSecret *SM9_generate_master_secret(int pairing, int scheme, int hash1);

SM9PublicParameters *SM9_extract_public_parameters(SM9MasterSecret *msk);

SM9PublicKey *SM9_extract_public_key(SM9PublicParameters *mpk,
	const char *id, size_t idlen);

SM9PublicKey *SM9PrivateKey_get_public_key(SM9PrivateKey *sk);

int SM9PrivateKey_get_gmtls_public_key(SM9PublicParameters *mpk,
	SM9PrivateKey *sk, unsigned char pub_key[1024]);

int SM9PublicKey_get_gmtls_encoded(SM9PublicParameters *mpk,
	SM9PublicKey *pk, unsigned char encoded[1024]);

int SM9_signature_size(SM9PublicParameters *mpk);

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

int SM9_encrypt(int type, /* NID_sm9encrypt_with_sm3_xor */
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen,
	SM9PublicParameters *mpk, const char *id, size_t idlen);

int SM9_decrypt(int type,
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen,
	SM9PrivateKey *sk);

DECLARE_ASN1_FUNCTIONS(SM9MasterSecret)
DECLARE_ASN1_FUNCTIONS(SM9PublicParameters)
DECLARE_ASN1_FUNCTIONS(SM9PrivateKey)
DECLARE_ASN1_FUNCTIONS(SM9PublicKey)
DECLARE_ASN1_FUNCTIONS(SM9Signature)
DECLARE_ASN1_FUNCTIONS(SM9Ciphertext)


/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */

int ERR_load_SM9_strings(void);

/* Error codes for the SM9 functions. */

/* Function codes. */
# define SM9_F_SM9CIPHERTEXT_CHECK                        100
# define SM9_F_SM9ENCPARAMETERS_DECRYPT                   101
# define SM9_F_SM9ENCPARAMETERS_ENCRYPT                   102
# define SM9_F_SM9ENCPARAMETERS_GENERATE_MAC              103
# define SM9_F_SM9ENCPARAMETERS_GET_KEY_LENGTH            104
# define SM9_F_SM9PUBLICPARAMETERS_GET_POINT_SIZE         105
# define SM9_F_SM9_DECRYPT                                106
# define SM9_F_SM9_DO_DECRYPT                             107
# define SM9_F_SM9_DO_ENCRYPT                             108
# define SM9_F_SM9_ENCRYPT                                109
# define SM9_F_SM9_EXTRACT_PRIVATE_KEY                    110
# define SM9_F_SM9_EXTRACT_PUBLIC_PARAMETERS              111
# define SM9_F_SM9_GENERATE_MASTER_SECRET                 112
# define SM9_F_SM9_SIGN                                   119
# define SM9_F_SM9_SIGNFINAL                              115
# define SM9_F_SM9_SIGNINIT                               116
# define SM9_F_SM9_UNWRAP_KEY                             113
# define SM9_F_SM9_VERIFY                                 120
# define SM9_F_SM9_VERIFYFINAL                            117
# define SM9_F_SM9_VERIFYINIT                             118
# define SM9_F_SM9_WRAP_KEY                               114

/* Reason codes. */
# define SM9_R_BUFFER_TOO_SMALL                           100
# define SM9_R_DIGEST_FAILURE                             119
# define SM9_R_EC_LIB                                     101
# define SM9_R_EXTENSION_FIELD_ERROR                      120
# define SM9_R_GENERATE_MAC_FAILURE                       102
# define SM9_R_HASH_FAILURE                               103
# define SM9_R_INVALID_CIPHERTEXT                         104
# define SM9_R_INVALID_DIGEST_TYPE                        130
# define SM9_R_INVALID_ENCPARAMETERS                      105
# define SM9_R_INVALID_HASH1                              106
# define SM9_R_INVALID_HASH2_DIGEST                       126
# define SM9_R_INVALID_ID                                 107
# define SM9_R_INVALID_ID_LENGTH                          108
# define SM9_R_INVALID_INPUT                              109
# define SM9_R_INVALID_KEM_KEY_LENGTH                     128
# define SM9_R_INVALID_KEY_LENGTH                         110
# define SM9_R_INVALID_MD                                 111
# define SM9_R_INVALID_PAIRING_TYPE                       112
# define SM9_R_INVALID_PARAMETER                          113
# define SM9_R_INVALID_POINTPPUB                          121
# define SM9_R_INVALID_PRIVATE_POINT                      122
# define SM9_R_INVALID_SCHEME                             114
# define SM9_R_INVALID_SIGNATURE                          123
# define SM9_R_INVALID_SIGNATURE_FORMAT                   127
# define SM9_R_INVALID_TYPE1CURVE                         115
# define SM9_R_KDF_FAILURE                                116
# define SM9_R_PAIRING_ERROR                              124
# define SM9_R_RATE_PAIRING_ERROR                         129
# define SM9_R_TWIST_CURVE_ERROR                          117
# define SM9_R_VERIFY_FAILURE                             125
# define SM9_R_ZERO_ID                                    118

#  ifdef  __cplusplus
}
#  endif
# endif
#endif
