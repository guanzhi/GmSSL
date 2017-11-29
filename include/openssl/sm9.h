/* ====================================================================
 * Copyright (c) 2016 The GmSSL Project.  All rights reserved.
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

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SM9PublicParameters_st SM9PublicParameters;
typedef struct SM9MasterSecret_st SM9MasterSecret;
typedef struct SM9PublicKey_st SM9PublicKey;
typedef struct SM9PrivateKey_st SM9PrivateKey;
typedef struct SM9Ciphertext_st SM9Ciphertext;
typedef struct SM9Signature_st SM9Signature;

int SM9_setup_by_pairing_name(int nid, int hid,
	SM9PublicParameters **mpk, SM9MasterSecret **msk);

SM9PrivateKey *SM9_extract_private_key(SM9PublicParameters *mpk,
	SM9MasterSecret *msk, const char *id, size_t idlen);

SM9PublicKey *SM9_extract_public_key(SM9PublicParameters *mpk,
	const char *id, size_t idlen);

SM9PublicKey *SM9PrivateKey_get_public_key(SM9PublicParameters *mpk,
	SM9PrivateKey *sk);

int SM9PrivateKey_get_gmtls_public_key(SM9PublicParameters *mpk,
	SM9PrivateKey *sk, unsigned char pub_key[1024]);

int SM9PublicKey_get_gmtls_encoded(SM9PublicParameters *mpk,
	SM9PublicKey *pk, unsigned char encoded[1024]);

typedef struct {
	const EVP_MD *kdf_md;
	const EVP_CIPHER *enc_cipher;
	const EVP_CIPHER *cmac_cipher;
	const EVP_CIPHER *cbcmac_cipher;
	const EVP_MD *hmac_md;
} SM9EncParameters;

SM9Ciphertext *SM9_do_encrypt_ex(SM9PublicParameters *mpk,
	const SM9EncParameters *encparams,
	const unsigned char *in, size_t inlen,
	SM9PublicKey *pk);

SM9Ciphertext *SM9_do_encrypt(SM9PublicParameters *mpk,
	const SM9EncParameters *encparams,
	const unsigned char *in, size_t inlen,
	const char *id, size_t idlen);

int SM9_do_decrypt(SM9PublicParameters *mpk,
	const SM9EncParameters *encparams,
	const SM9Ciphertext *in,
	unsigned char *out, size_t *outlen,
	SM9PrivateKey *sk,
	const char *id, size_t idlen);

int SM9_encrypt_ex(SM9PublicParameters *mpk,
	const SM9EncParameters *encparams,
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen,
	SM9PublicKey *pk);

int SM9_encrypt(SM9PublicParameters *mpk,
	const SM9EncParameters *encparams,
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen,
	const char *id, size_t idlen);

int SM9_decrypt(SM9PublicParameters *mpk,
	const SM9EncParameters *encparams,
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen,
	SM9PrivateKey *sk,
	const char *id, size_t idlen);

int SM9_encrypt_with_recommended_ex(SM9PublicParameters *mpk,
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen,
	SM9PublicKey *pk);

int SM9_encrypt_with_recommended(SM9PublicParameters *mpk,
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen,
	const char *id, size_t idlen);

int SM9_decrypt_with_recommended(SM9PublicParameters *mpk,
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen,
	SM9PrivateKey *sk,
	const char *id, size_t idlen);

int SM9_signature_size(SM9PublicParameters *mpk);

SM9Signature *SM9_do_sign(SM9PublicParameters *mpk,
	const unsigned char *dgst, size_t dgstlen,
	SM9PrivateKey *sk);

int SM9_do_verify_ex(SM9PublicParameters *mpk,
	const unsigned char *dgst, size_t dgstlen,
	const SM9Signature *sig,
	SM9PublicKey *pk);

int SM9_do_verify(SM9PublicParameters *mpk,
	const unsigned char *dgst, size_t dgstlen,
	const SM9Signature *sig,
	const char *id, size_t idlen);

int SM9_sign(SM9PublicParameters *mpk,
	const unsigned char *dgst, size_t dgstlen,
	unsigned char *sig, size_t *siglen,
	SM9PrivateKey *sk);

int SM9_verify_ex(SM9PublicParameters *mpk,
	const unsigned char *dgst, size_t dgstlen,
	const unsigned char *sig, size_t siglen,
	SM9PublicKey *pk);

int SM9_verify(SM9PublicParameters *mpk,
	const unsigned char *dgst, size_t dgstlen,
	const unsigned char *sig, size_t siglen,
	const char *id, size_t idlen);

SM9PublicKey *SM9_generate_key_exchange(SM9PublicParameters *mpk,
	const char *peer_id, size_t peer_idlen, BIGNUM **r);

int SM9_compute_share_key(SM9PublicParameters *mpk,
	unsigned char *out, size_t *outlen,
	const char *peer_id, size_t peer_idlen, SM9PublicKey *peer_exch,
	const char *id, size_t idlen, SM9PublicKey *exch,
	SM9PrivateKey *sk, int initiator);


DECLARE_ASN1_FUNCTIONS(SM9PublicParameters)
DECLARE_ASN1_FUNCTIONS(SM9MasterSecret)
DECLARE_ASN1_FUNCTIONS(SM9PrivateKey)
DECLARE_ASN1_FUNCTIONS(SM9PublicKey)
DECLARE_ASN1_FUNCTIONS(SM9Ciphertext)
DECLARE_ASN1_FUNCTIONS(SM9Signature)


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
# define SM9_F_SM9_DO_SIGN                                109
# define SM9_F_SM9_DO_SIGN_TYPE1CURVE                     110
# define SM9_F_SM9_DO_VERIFY                              111
# define SM9_F_SM9_DO_VERIFY_TYPE1CURVE                   112
# define SM9_F_SM9_ENCRYPT                                113
# define SM9_F_SM9_EXTRACT_PRIVATE_KEY                    114
# define SM9_F_SM9_SETUP_TYPE1CURVE                       115
# define SM9_F_SM9_SIGN                                   116
# define SM9_F_SM9_UNWRAP_KEY                             117
# define SM9_F_SM9_VERIFY                                 118
# define SM9_F_SM9_WRAP_KEY                               119

/* Reason codes. */
# define SM9_R_BUFFER_TOO_SMALL                           100
# define SM9_R_COMPUTE_PAIRING_FAILURE                    101
# define SM9_R_GENERATE_MAC_FAILURE                       102
# define SM9_R_HASH_FAILURE                               103
# define SM9_R_INVALID_CIPHERTEXT                         104
# define SM9_R_INVALID_CURVE                              105
# define SM9_R_INVALID_DIGEST                             106
# define SM9_R_INVALID_DIGEST_LENGTH                      107
# define SM9_R_INVALID_ENCPARAMETERS                      108
# define SM9_R_INVALID_ID                                 109
# define SM9_R_INVALID_ID_LENGTH                          110
# define SM9_R_INVALID_INPUT                              111
# define SM9_R_INVALID_KEY_LENGTH                         112
# define SM9_R_INVALID_MD                                 113
# define SM9_R_INVALID_PARAMETER                          114
# define SM9_R_INVALID_SIGNATURE                          115
# define SM9_R_INVALID_TYPE1CURVE                         116
# define SM9_R_KDF_FAILURE                                117
# define SM9_R_NOT_NAMED_CURVE                            118
# define SM9_R_PARSE_PAIRING                              119
# define SM9_R_ZERO_ID                                    120

# ifdef  __cplusplus
}
# endif
#endif
#endif
