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
/*
 * Converting types between native types and GM API types
 */

#ifndef HEADER_GMAPI_H
#define HEADER_GMAPI_H

#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_GMAPI

#ifndef OPENSSL_NO_EC
# include <openssl/ec.h>
# ifndef OPENSSL_NO_SM2
#  include <openssl/sm2.h>
# endif
#endif
#ifndef OPENSSL_NO_RSA
# include <openssl/rsa.h>
#endif
#include <openssl/evp.h>
#include <openssl/sgd.h>
#include <openssl/sdf.h>
#include <openssl/skf.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SGD */
const EVP_CIPHER *EVP_get_cipherbysgd(ULONG ulAlgId, ULONG ulFeedBitLen);
int EVP_CIPHER_get_sgd(const EVP_CIPHER *cipher, ULONG *pulAlgId, ULONG *pulFeedBits);
int EVP_CIPHER_CTX_get_sgd(const EVP_CIPHER_CTX *ctx, ULONG *pulAlgId, ULONG *pulFeedBits);
const EVP_MD *EVP_get_digestbysgd(ULONG ulAlgId);
int EVP_MD_get_sgd(const EVP_MD *md, ULONG *ulAlgId);
int EVP_MD_CTX_get_sgd(const EVP_MD_CTX *ctx, ULONG *ulAlgId);
//convert sgd to pkey type					
int EVP_PKEY_get_sgd(const EVP_PKEY *pkey, ULONG *ulAlgId);
int EVP_PKEY_CTX_get_sgd(const EVP_PKEY_CTX *ctx, ULONG *ulAlgId);

/* SDF */
#ifndef OPENSSL_NO_SDF
# ifndef OPENSSL_NO_RSA
RSA *RSA_new_from_RSArefPublicKey(const RSArefPublicKey *ref);
int RSA_set_RSArefPublicKey(RSA *rsa, const RSArefPublicKey *ref);
int RSA_get_RSArefPublicKey(RSA *rsa, RSArefPublicKey *ref);
RSA *RSA_new_from_RSArefPrivateKey(const RSArefPrivateKey *ref);
int RSA_set_RSArefPrivateKey(RSA *rsa, const RSArefPrivateKey *ref);
int RSA_get_RSArefPrivateKey(RSA *rsa, RSArefPrivateKey *ref);
# endif
# ifndef OPENSSL_NO_EC
EC_KEY *EC_KEY_new_from_ECCrefPublicKey(const ECCrefPublicKey *ref);
int EC_KEY_set_ECCrefPublicKey(EC_KEY *ec_key, const ECCrefPublicKey *ref);
int EC_KEY_get_ECCrefPublicKey(EC_KEY *ec_key, ECCrefPublicKey *ref);
EC_KEY *EC_KEY_new_from_ECCrefPrivateKey(const ECCrefPrivateKey *ref);
int EC_KEY_set_ECCrefPrivateKey(EC_KEY *ec_key, const ECCrefPrivateKey *ref);
int EC_KEY_get_ECCrefPrivateKey(EC_KEY *ec_key, ECCrefPrivateKey *ref);
#  ifndef OPENSSL_NO_SM2
SM2CiphertextValue *SM2CiphertextValue_new_from_ECCCipher(const ECCCipher *ref);
int SM2CiphertextValue_set_ECCCipher(SM2CiphertextValue *cv, const ECCCipher *ref);
int SM2CiphertextValue_get_ECCCipher(const SM2CiphertextValue *cv, ECCCipher *ref);
#  endif
#  ifndef OPENSSL_NO_ECIES
ECIES_CIPHERTEXT_VALUE *ECIES_CIPHERTEXT_VALUE_new_from_ECCCipher(const ECCCipher *ref);
int ECIES_CIPHERTEXT_VALUE_set_ECCCipher(ECIES_CIPHERTEXT_VALUE *cv, const ECCCipher *ref);
int ECIES_CIPHERTEXT_VALUE_get_ECCCipher(const ECIES_CIPHERTEXT_VALUE *cv, ECCCipher *ref);
#  endif
ECDSA_SIG *ECDSA_SIG_new_from_ECCSignature(const ECCSignature *ref);
int ECDSA_SIG_set_ECCSignature(ECDSA_SIG *sig, const ECCSignature *ref);
int ECDSA_SIG_get_ECCSignature(const ECDSA_SIG *sig, ECCSignature *ref);
ECCCipher *d2i_ECCCipher(ECCCipher **a, const unsigned char **pp, long length);
int i2d_ECCCipher(ECCCipher *a, unsigned char **pp);
ECCSignature *d2i_ECCSignature(ECCSignature **a, const unsigned char **pp, long length);
int i2d_ECCSignature(ECCSignature *a, unsigned char **pp);
# endif
#endif


/* SKF */
#ifndef OPENSSL_NO_SKF
# ifndef OPENSSL_NO_RSA
RSA *RSA_new_from_RSAPUBLICKEYBLOB(const RSAPUBLICKEYBLOB *blob);
int RSA_set_RSAPUBLICKEYBLOB(RSA *rsa, const RSAPUBLICKEYBLOB *blob);
int RSA_get_RSAPUBLICKEYBLOB(RSA *rsa, RSAPUBLICKEYBLOB *blob);
RSA *RSA_new_from_RSAPRIVATEKEYBLOB(const RSAPRIVATEKEYBLOB *blob);
int RSA_set_RSAPRIVATEKEYBLOB(RSA *rsa, const RSAPRIVATEKEYBLOB *blob);
int RSA_get_RSAPRIVATEKEYBLOB(RSA *rsa, RSAPRIVATEKEYBLOB *blob);
# endif
# ifndef OPENSSL_NO_EC
EC_KEY *EC_KEY_new_from_ECCPUBLICKEYBLOB(const ECCPUBLICKEYBLOB *blob);
int EC_KEY_set_ECCPUBLICKEYBLOB(EC_KEY *ec_key, const ECCPUBLICKEYBLOB *blob);
int EC_KEY_get_ECCPUBLICKEYBLOB(EC_KEY *ec_key, ECCPUBLICKEYBLOB *blob);
EC_KEY *EC_KEY_new_from_ECCPRIVATEKEYBLOB(const ECCPRIVATEKEYBLOB *blob);
int EC_KEY_set_ECCPRIVATEKEYBLOB(EC_KEY *ec_key, const ECCPRIVATEKEYBLOB *blob);
int EC_KEY_get_ECCPRIVATEKEYBLOB(EC_KEY *ec_key, ECCPRIVATEKEYBLOB *blob);
#  ifndef OPENSSL_NO_SM2
SM2CiphertextValue *SM2CiphertextValue_new_from_ECCCIPHERBLOB(const ECCCIPHERBLOB *blob);
int SM2CiphertextValue_set_ECCCIPHERBLOB(SM2CiphertextValue *cv, const ECCCIPHERBLOB *blob);
int SM2CiphertextValue_get_ECCCIPHERBLOB(const SM2CiphertextValue *cv, ECCCIPHERBLOB *blob);
#  endif
#  ifndef OPENSSL_NO_ECIES
ECIES_CIPHERTEXT_VALUE *ECIES_CIPHERTEXT_VALUE_new_from_ECCCIPHERBLOB(const ECCCIPHERBLOB *blob);
int ECIES_CIPHERTEXT_VALUE_set_ECCCIPHERBLOB(ECIES_CIPHERTEXT_VALUE *cv, const ECCCIPHERBLOB *blob);
int ECIES_CIPHERTEXT_VALUE_get_ECCCIPHERBLOB(const ECIES_CIPHERTEXT_VALUE *cv, ECCCIPHERBLOB *blob);
#  endif
ECDSA_SIG *ECDSA_SIG_new_from_ECCSIGNATUREBLOB(const ECCSIGNATUREBLOB *blob);
int ECDSA_SIG_get_ECCSIGNATUREBLOB(const ECDSA_SIG *sig, ECCSIGNATUREBLOB *blob);
int ECDSA_SIG_set_ECCSIGNATUREBLOB(ECDSA_SIG *sig, const ECCSIGNATUREBLOB *blob);
int ECCPRIVATEKEYBLOB_set_private_key(ECCPRIVATEKEYBLOB *blob, const BIGNUM *priv_key);
ECCCIPHERBLOB *d2i_ECCCIPHERBLOB(ECCCIPHERBLOB **a, const unsigned char **pp, long length);
int i2d_ECCCIPHERBLOB(ECCCIPHERBLOB *a, unsigned char **pp);
ECCSIGNATUREBLOB *d2i_ECCSIGNATUREBLOB(ECCSIGNATUREBLOB **a, const unsigned char **pp, long length);
int i2d_ECCSIGNATUREBLOB(ECCSIGNATUREBLOB *a, unsigned char **pp);
# endif
#endif

/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */

int ERR_load_GMAPI_strings(void);

/* Error codes for the GMAPI functions. */

/* Function codes. */
# define GMAPI_F_D2I_ECCCIPHER                            141
# define GMAPI_F_D2I_ECCCIPHERBLOB                        158
# define GMAPI_F_D2I_ECCCIPHERBLOB_BIO                    151
# define GMAPI_F_D2I_ECCCIPHERBLOB_FP                     152
# define GMAPI_F_D2I_ECCSIGNATURE                         142
# define GMAPI_F_D2I_ECCSIGNATUREBLOB                     159
# define GMAPI_F_D2I_ECCSIGNATUREBLOB_BIO                 160
# define GMAPI_F_D2I_ECCSIGNATUREBLOB_FP                  153
# define GMAPI_F_ECCPRIVATEKEYBLOB_SET_PRIVATE_KEY        100
# define GMAPI_F_ECDSA_SIG_GET_ECCSIGNATURE               101
# define GMAPI_F_ECDSA_SIG_GET_ECCSIGNATUREBLOB           102
# define GMAPI_F_ECDSA_SIG_NEW_FROM_ECCSIGNATURE          103
# define GMAPI_F_ECDSA_SIG_NEW_FROM_ECCSIGNATUREBLOB      104
# define GMAPI_F_ECDSA_SIG_SET_ECCSIGNATURE               105
# define GMAPI_F_ECDSA_SIG_SET_ECCSIGNATUREBLOB           106
# define GMAPI_F_ECIES_CIPHERTEXT_VALUE_GET_ECCCIPHER     145
# define GMAPI_F_ECIES_CIPHERTEXT_VALUE_GET_ECCCIPHERBLOB 150
# define GMAPI_F_ECIES_CIPHERTEXT_VALUE_NEW_FROM_ECCCIPHER 146
# define GMAPI_F_ECIES_CIPHERTEXT_VALUE_NEW_FROM_ECCCIPHERBLOB 148
# define GMAPI_F_ECIES_CIPHERTEXT_VALUE_SET_ECCCIPHER     147
# define GMAPI_F_ECIES_CIPHERTEXT_VALUE_SET_ECCCIPHERBLOB 149
# define GMAPI_F_EC_KEY_GET_ECCPRIVATEKEYBLOB             107
# define GMAPI_F_EC_KEY_GET_ECCPUBLICKEYBLOB              108
# define GMAPI_F_EC_KEY_GET_ECCREFPRIVATEKEY              109
# define GMAPI_F_EC_KEY_GET_ECCREFPUBLICKEY               110
# define GMAPI_F_EC_KEY_NEW_FROM_ECCPRIVATEKEYBLOB        111
# define GMAPI_F_EC_KEY_NEW_FROM_ECCPUBLICKEYBLOB         112
# define GMAPI_F_EC_KEY_NEW_FROM_ECCREFPRIVATEKEY         113
# define GMAPI_F_EC_KEY_NEW_FROM_ECCREFPUBLICKEY          114
# define GMAPI_F_EC_KEY_SET_ECCPRIVATEKEYBLOB             115
# define GMAPI_F_EC_KEY_SET_ECCPUBLICKEYBLOB              116
# define GMAPI_F_EC_KEY_SET_ECCREFPRIVATEKEY              117
# define GMAPI_F_EC_KEY_SET_ECCREFPUBLICKEY               118
# define GMAPI_F_EVP_CIPHER_CTX_GET_SGD                   119
# define GMAPI_F_EVP_CIPHER_GET_SGD                       120
# define GMAPI_F_EVP_MD_GET_SGD                           121
# define GMAPI_F_EVP_PKEY_GET_SGD                         140
# define GMAPI_F_I2D_ECCCIPHER                            143
# define GMAPI_F_I2D_ECCCIPHERBLOB                        154
# define GMAPI_F_I2D_ECCCIPHERBLOB_BIO                    155
# define GMAPI_F_I2D_ECCCIPHERBLOB_FP                     156
# define GMAPI_F_I2D_ECCSIGNATURE                         144
# define GMAPI_F_I2D_ECCSIGNATUREBLOB                     161
# define GMAPI_F_I2D_ECCSIGNATUREBLOB_BIO                 162
# define GMAPI_F_I2D_ECCSIGNATUREBLOB_FP                  157
# define GMAPI_F_RSA_GET_RSAPRIVATEKEYBLOB                122
# define GMAPI_F_RSA_GET_RSAPUBLICKEYBLOB                 123
# define GMAPI_F_RSA_GET_RSAREFPRIVATEKEY                 124
# define GMAPI_F_RSA_GET_RSAREFPUBLICKEY                  125
# define GMAPI_F_RSA_NEW_FROM_RSAPRIVATEKEYBLOB           126
# define GMAPI_F_RSA_NEW_FROM_RSAPUBLICKEYBLOB            127
# define GMAPI_F_RSA_NEW_FROM_RSAREFPRIVATEKEY            128
# define GMAPI_F_RSA_NEW_FROM_RSAREFPUBLICKEY             129
# define GMAPI_F_RSA_SET_RSAPRIVATEKEYBLOB                130
# define GMAPI_F_RSA_SET_RSAPUBLICKEYBLOB                 131
# define GMAPI_F_RSA_SET_RSAREFPRIVATEKEY                 132
# define GMAPI_F_RSA_SET_RSAREFPUBLICKEY                  133
# define GMAPI_F_SM2CIPHERTEXTVALUE_GET_ECCCIPHER         134
# define GMAPI_F_SM2CIPHERTEXTVALUE_GET_ECCCIPHERBLOB     135
# define GMAPI_F_SM2CIPHERTEXTVALUE_NEW_FROM_ECCCIPHER    136
# define GMAPI_F_SM2CIPHERTEXTVALUE_NEW_FROM_ECCCIPHERBLOB 137
# define GMAPI_F_SM2CIPHERTEXTVALUE_SET_ECCCIPHER         138
# define GMAPI_F_SM2CIPHERTEXTVALUE_SET_ECCCIPHERBLOB     139

/* Reason codes. */
# define GMAPI_R_BUFFER_TOO_SMALL                         100
# define GMAPI_R_DECODE_EC_PRIVATE_KEY_FAILED             101
# define GMAPI_R_DECODE_EC_PUBLIC_KEY_FAILED              102
# define GMAPI_R_ENCODE_RSA_PUBLIC_KEY_FAILED             103
# define GMAPI_R_INVALID_ALGOR                            104
# define GMAPI_R_INVALID_BIGNUM_LENGTH                    105
# define GMAPI_R_INVALID_CIPHERTEXT_LENGTH                106
# define GMAPI_R_INVALID_CIPHERTEXT_MAC                   107
# define GMAPI_R_INVALID_CIPHERTEXT_POINT                 108
# define GMAPI_R_INVALID_CIPHETEXT_LENGTH                 109
# define GMAPI_R_INVALID_EC_KEY                           110
# define GMAPI_R_INVALID_EC_PRIVATE_KEY                   111
# define GMAPI_R_INVALID_EC_PUBLIC_KEY                    112
# define GMAPI_R_INVALID_KEY_LENGTH                       113
# define GMAPI_R_INVALID_PRIVATE_KEY                      114
# define GMAPI_R_INVALID_PUBLIC_KEY                       115
# define GMAPI_R_INVALID_RSA_KEY_LENGTH                   116
# define GMAPI_R_INVALID_RSA_PRIVATE_KEY                  117
# define GMAPI_R_INVALID_RSA_PUBLIC_KEY                   118
# define GMAPI_R_INVALID_SIGNATURE                        119
# define GMAPI_R_INVALID_SKF_CIPHERTEXT                   129
# define GMAPI_R_INVALID_SKF_EC_CIPHERTEXT                128
# define GMAPI_R_INVALID_SM2_CIPHERTEXT                   120
# define GMAPI_R_INVALID_SM2_CIPHERTEXT_MAC_LENGTH        127
# define GMAPI_R_INVALID_SM2_PRIVATE_KEY                  121
# define GMAPI_R_INVALID_SM2_SIGNATURE                    122
# define GMAPI_R_MALLOC_FAILED                            123
# define GMAPI_R_NOT_CONVERTABLE                          124
# define GMAPI_R_NOT_IMPLEMENTED                          130
# define GMAPI_R_NOT_SUPPORTED_GMAPI_CIPHER               125
# define GMAPI_R_NOT_SUPPORTED_PKEY                       126

# ifdef  __cplusplus
}
# endif
#endif
#endif
