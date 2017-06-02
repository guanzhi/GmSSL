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

#include <openssl/ec.h>
#include <openssl/sm2.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/sgd.h>
#include <openssl/saf.h>
#include <openssl/sdf.h>
#include <openssl/skf.h>
#include <openssl/sof.h>

#ifdef __cplusplus
extern "C" {
#endif

const char *GMAPI_keyusage2str(int usage);
int GMAPI_sgd2ciphernid(int sgd);
int GMAPI_sgd2mdnid(int sgd);

int EVP_MD_sgd(const EVP_MD *md);
int EVP_CIPHER_sgd(const EVP_CIPHER *cipher);

/* SGD <==> EVP */
const EVP_MD *EVP_get_digestbysgd(int sgd);
const EVP_CIPHER *EVP_get_cipherbysgd(int sgd);

/* SDF types <==> Native types */
RSA *RSA_new_from_RSArefPublicKey(const RSArefPublicKey *ref);
RSA *RSA_new_from_RSArefPrivateKey(const RSArefPrivateKey *ref);
int RSA_set_RSArefPublicKey(RSA *rsa, const RSArefPublicKey *ref);
int RSA_set_RSArefPrivateKey(RSA *rsa, const RSArefPrivateKey *ref);
int RSA_get_RSArefPublicKey(RSA *rsa, RSArefPublicKey *ref);
int RSA_get_RSArefPrivateKey(RSA *rsa, RSArefPrivateKey *ref);
EC_KEY *EC_KEY_new_from_ECCrefPublicKey(const ECCrefPublicKey *ref);
EC_KEY *EC_KEY_new_from_ECCrefPrivateKey(const ECCrefPrivateKey *ref);
int EC_KEY_set_ECCrefPublicKey(EC_KEY *ec_key, const ECCrefPublicKey *ref);
int EC_KEY_set_ECCrefPrivateKey(EC_KEY *ec_key, const ECCrefPrivateKey *ref);
int EC_KEY_get_ECCrefPublicKey(EC_KEY *ec_key, ECCrefPublicKey *ref);
int EC_KEY_get_ECCrefPrivateKey(EC_KEY *ec_key, ECCrefPrivateKey *ref);
SM2CiphertextValue *SM2CiphertextValue_new_from_ECCCipher(const ECCCipher *ref);
int SM2CiphertextValue_set_ECCCipher(SM2CiphertextValue *cv, const ECCCipher *ref);
int SM2CiphertextValue_get_ECCCipher(const SM2CiphertextValue *cv, ECCCipher *ref);
ECDSA_SIG *ECDSA_SIG_new_from_ECCSignature(const ECCSignature *ref);
int ECDSA_SIG_set_ECCSignature(ECDSA_SIG *sig, const ECCSignature *ref);
int ECDSA_SIG_get_ECCSignature(const ECDSA_SIG *sig, ECCSignature *ref);

/* SKF types <==> Native types */
RSA *RSA_new_from_RSAPUBLICKEYBLOB(const RSAPUBLICKEYBLOB *blob);
RSA *RSA_new_from_RSAPRIVATEKEYBLOB(const RSAPRIVATEKEYBLOB *blob);
int RSA_set_RSAPUBLICKEYBLOB(RSA *rsa, const RSAPUBLICKEYBLOB *blob);
int RSA_set_RSAPRIVATEKEYBLOB(RSA *rsa, const RSAPRIVATEKEYBLOB *blob);
int RSA_get_RSAPUBLICKEYBLOB(RSA *rsa, RSAPUBLICKEYBLOB *blob);
int RSA_get_RSAPRIVATEKEYBLOB(RSA *rsa, RSAPRIVATEKEYBLOB *blob);
EC_KEY *EC_KEY_new_from_ECCPUBLICKEYBLOB(const ECCPUBLICKEYBLOB *blob);
EC_KEY *EC_KEY_new_from_ECCPRIVATEKEYBLOB(const ECCPRIVATEKEYBLOB *blob);
int EC_KEY_set_ECCPUBLICKEYBLOB(EC_KEY *ec_key, const ECCPUBLICKEYBLOB *blob);
int EC_KEY_get_ECCPUBLICKEYBLOB(EC_KEY *ec_key, ECCPUBLICKEYBLOB *blob);
int EC_KEY_set_ECCPRIVATEKEYBLOB(EC_KEY *ec_key, const ECCPRIVATEKEYBLOB *blob);
int EC_KEY_get_ECCPRIVATEKEYBLOB(EC_KEY *ec_key, ECCPRIVATEKEYBLOB *blob);
SM2CiphertextValue *SM2CiphertextValue_new_from_ECCCIPHERBLOB(const ECCCIPHERBLOB *blob);
int SM2CiphertextValue_set_ECCCIPHERBLOB(SM2CiphertextValue *cv, const ECCCIPHERBLOB *blob);
int SM2CiphertextValue_get_ECCCIPHERBLOB(const SM2CiphertextValue *cv, ECCCIPHERBLOB *blob);
ECDSA_SIG *ECDSA_SIG_new_from_ECCSIGNATUREBLOB(const ECCSIGNATUREBLOB *blob);
int ECDSA_SIG_get_ECCSIGNATUREBLOB(const ECDSA_SIG *sig, ECCSIGNATUREBLOB *blob);
int ECDSA_SIG_set_ECCSIGNATUREBLOB(ECDSA_SIG *sig, const ECCSIGNATUREBLOB *blob);


/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */

int ERR_load_GMAPI_strings(void);

/* Error codes for the GMAPI functions. */

/* Function codes. */
# define GMAPI_F_ECDSA_SIG_GET_ECCSIGNATURE               100
# define GMAPI_F_ECDSA_SIG_GET_ECCSIGNATUREBLOB           101
# define GMAPI_F_ECDSA_SIG_NEW_FROM_ECCSIGNATURE          102
# define GMAPI_F_ECDSA_SIG_NEW_FROM_ECCSIGNATUREBLOB      103
# define GMAPI_F_ECDSA_SIG_SET_ECCSIGNATURE               104
# define GMAPI_F_ECDSA_SIG_SET_ECCSIGNATUREBLOB           105
# define GMAPI_F_EC_KEY_GET_ECCPRIVATEKEYBLOB             106
# define GMAPI_F_EC_KEY_GET_ECCPUBLICKEYBLOB              107
# define GMAPI_F_EC_KEY_GET_ECCREFPRIVATEKEY              108
# define GMAPI_F_EC_KEY_GET_ECCREFPUBLICKEY               109
# define GMAPI_F_EC_KEY_NEW_FROM_ECCPRIVATEKEYBLOB        110
# define GMAPI_F_EC_KEY_NEW_FROM_ECCPUBLICKEYBLOB         111
# define GMAPI_F_EC_KEY_NEW_FROM_ECCREFPRIVATEKEY         112
# define GMAPI_F_EC_KEY_NEW_FROM_ECCREFPUBLICKEY          113
# define GMAPI_F_EC_KEY_SET_ECCPRIVATEKEYBLOB             114
# define GMAPI_F_EC_KEY_SET_ECCPUBLICKEYBLOB              115
# define GMAPI_F_EC_KEY_SET_ECCREFPRIVATEKEY              116
# define GMAPI_F_EC_KEY_SET_ECCREFPUBLICKEY               117
# define GMAPI_F_RSA_GET_RSAPRIVATEKEYBLOB                118
# define GMAPI_F_RSA_GET_RSAPUBLICKEYBLOB                 119
# define GMAPI_F_RSA_GET_RSAREFPRIVATEKEY                 120
# define GMAPI_F_RSA_GET_RSAREFPUBLICKEY                  121
# define GMAPI_F_RSA_NEW_FROM_RSAPRIVATEKEYBLOB           122
# define GMAPI_F_RSA_NEW_FROM_RSAPUBLICKEYBLOB            123
# define GMAPI_F_RSA_NEW_FROM_RSAREFPRIVATEKEY            124
# define GMAPI_F_RSA_NEW_FROM_RSAREFPUBLICKEY             125
# define GMAPI_F_RSA_SET_RSAPRIVATEKEYBLOB                126
# define GMAPI_F_RSA_SET_RSAPUBLICKEYBLOB                 127
# define GMAPI_F_RSA_SET_RSAREFPRIVATEKEY                 128
# define GMAPI_F_RSA_SET_RSAREFPUBLICKEY                  129
# define GMAPI_F_SAF_BASE64_CREATEBASE64OBJ               130
# define GMAPI_F_SAF_BASE64_DECODE                        131
# define GMAPI_F_SAF_BASE64_DECODEFINAL                   132
# define GMAPI_F_SAF_BASE64_DECODEUPDATE                  133
# define GMAPI_F_SAF_BASE64_ENCODE                        134
# define GMAPI_F_SAF_BASE64_ENCODEFINAL                   135
# define GMAPI_F_SAF_BASE64_ENCODEUPDATE                  136
# define GMAPI_F_SAF_CREATESYMMKEYOBJ                     137
# define GMAPI_F_SAF_ECCPUBLICKEYENC                      138
# define GMAPI_F_SAF_ECCPUBLICKEYENCBYCERT                139
# define GMAPI_F_SAF_ECCSIGN                              140
# define GMAPI_F_SAF_ECCVERIFYSIGN                        141
# define GMAPI_F_SAF_ECCVERIFYSIGNBYCERT                  142
# define GMAPI_F_SAF_GENECCKEYPAIR                        143
# define GMAPI_F_SAF_GENERATEAGREEMENTDATAWITHECC         144
# define GMAPI_F_SAF_GENERATEKEYWITHECC                   145
# define GMAPI_F_SAF_GETECCPUBLICKEY                      146
# define GMAPI_F_SAF_MACFINAL                             147
# define GMAPI_F_SAF_MACUPDATE                            148
# define GMAPI_F_SAF_PKCS7_DECODEDIGESTEDDATA             149
# define GMAPI_F_SAF_PKCS7_ENCODEDIGESTEDDATA             150
# define GMAPI_F_SAF_SYMMDECRYPTUPDATE                    151
# define GMAPI_F_SAF_SYMMENCRYPTUPDATE                    152
# define GMAPI_F_SKF_CLOSEHANDLE                          153
# define GMAPI_F_SKF_DECRYPT                              154
# define GMAPI_F_SKF_DECRYPTFINAL                         155
# define GMAPI_F_SKF_DECRYPTINIT                          156
# define GMAPI_F_SKF_DECRYPTUPDATE                        157
# define GMAPI_F_SKF_DIGEST                               158
# define GMAPI_F_SKF_DIGESTFINAL                          159
# define GMAPI_F_SKF_DIGESTINIT                           160
# define GMAPI_F_SKF_DIGESTUPDATE                         161
# define GMAPI_F_SKF_ENCRYPT                              162
# define GMAPI_F_SKF_ENCRYPTFINAL                         163
# define GMAPI_F_SKF_ENCRYPTINIT                          164
# define GMAPI_F_SKF_ENCRYPTUPDATE                        165
# define GMAPI_F_SKF_EXTECCDECRYPT                        166
# define GMAPI_F_SKF_EXTECCENCRYPT                        167
# define GMAPI_F_SKF_EXTECCSIGN                           168
# define GMAPI_F_SKF_EXTECCVERIFY                         169
# define GMAPI_F_SKF_EXTRSAPRIKEYOPERATION                170
# define GMAPI_F_SKF_EXTRSAPUBKEYOPERATION                171
# define GMAPI_F_SKF_GENEXTECCKEYPAIR                     172
# define GMAPI_F_SKF_GENEXTRSAKEY                         173
# define GMAPI_F_SKF_GENRANDOM                            174
# define GMAPI_F_SKF_GETDEVINFO                           175
# define GMAPI_F_SKF_GETDEVSTATE                          176
# define GMAPI_F_SKF_HANDLE_GET_CBCMAC_CTX                177
# define GMAPI_F_SKF_HANDLE_GET_CIPHER                    178
# define GMAPI_F_SKF_HANDLE_GET_CIPHER_CTX                179
# define GMAPI_F_SKF_HANDLE_GET_KEY                       180
# define GMAPI_F_SKF_HANDLE_GET_MD_CTX                    181
# define GMAPI_F_SKF_MAC                                  182
# define GMAPI_F_SKF_MACFINAL                             183
# define GMAPI_F_SKF_MACINIT                              184
# define GMAPI_F_SKF_MACUPDATE                            185
# define GMAPI_F_SKF_SETSYMMKEY                           186
# define GMAPI_F_SM2CIPHERTEXTVALUE_GET_ECCCIPHER         193
# define GMAPI_F_SM2CIPHERTEXTVALUE_GET_ECCCIPHERBLOB     194
# define GMAPI_F_SM2CIPHERTEXTVALUE_NEW_FROM_ECCCIPHER    195
# define GMAPI_F_SM2CIPHERTEXTVALUE_NEW_FROM_ECCCIPHERBLOB 196
# define GMAPI_F_SM2CIPHERTEXTVALUE_SET_ECCCIPHER         197
# define GMAPI_F_SM2CIPHERTEXTVALUE_SET_ECCCIPHERBLOB     198
# define GMAPI_F_SM2_CIPHERTEXT_VALUE_GET_ECCCIPHER       187
# define GMAPI_F_SM2_CIPHERTEXT_VALUE_GET_ECCCIPHERBLOB   188
# define GMAPI_F_SM2_CIPHERTEXT_VALUE_NEW_FROM_ECCCIPHER  189
# define GMAPI_F_SM2_CIPHERTEXT_VALUE_NEW_FROM_ECCCIPHERBLOB 190
# define GMAPI_F_SM2_CIPHERTEXT_VALUE_SET_ECCCIPHER       191
# define GMAPI_F_SM2_CIPHERTEXT_VALUE_SET_ECCCIPHERBLOB   192

/* Reason codes. */
# define GMAPI_R_BUFFER_TOO_SMALL                         100
# define GMAPI_R_CBCMAC_FAILURE                           101
# define GMAPI_R_CTX_NOT_CREATED                          102
# define GMAPI_R_DECODE_EC_PRIVATE_KEY_FAILED             103
# define GMAPI_R_DECODE_EC_PUBLIC_KEY_FAILED              104
# define GMAPI_R_DECRYPT_FAILED                           105
# define GMAPI_R_ENCODE_CIPHERTEXT_FAILED                 106
# define GMAPI_R_ENCODE_FAILED                            107
# define GMAPI_R_ENCODE_RSA_PUBLIC_KEY_FAILED             108
# define GMAPI_R_ENCODE_SIGNATURE_FAILED                  109
# define GMAPI_R_ENCRYPT_FAILED                           110
# define GMAPI_R_FAIL                                     111
# define GMAPI_R_GEN_RANDOM                               112
# define GMAPI_R_GEN_RSA_FAILED                           113
# define GMAPI_R_GET_PRIVATE_KEY_FAILED                   114
# define GMAPI_R_GET_PUBLIC_KEY_FAILED                    115
# define GMAPI_R_INT_OVERFLOW                             116
# define GMAPI_R_INVALID_ALGID                            117
# define GMAPI_R_INVALID_ALGOR                            118
# define GMAPI_R_INVALID_ARGUMENTS                        119
# define GMAPI_R_INVALID_BIGNUM_LENGTH                    120
# define GMAPI_R_INVALID_BLOB                             121
# define GMAPI_R_INVALID_CIPHERTEXT                       122
# define GMAPI_R_INVALID_CIPHERTEXT_LENGTH                123
# define GMAPI_R_INVALID_CIPHERTEXT_MAC                   124
# define GMAPI_R_INVALID_CIPHERTEXT_POINT                 125
# define GMAPI_R_INVALID_CIPHER_CTX_HANDLE                126
# define GMAPI_R_INVALID_CIPHETEXT_LENGTH                 127
# define GMAPI_R_INVALID_CONTEXT                          128
# define GMAPI_R_INVALID_DIGEST_ALGOR                     129
# define GMAPI_R_INVALID_DIGEST_LENGTH                    130
# define GMAPI_R_INVALID_ECC_PRIVATE_KEY                  131
# define GMAPI_R_INVALID_ECC_PUBLIC_KEY                   132
# define GMAPI_R_INVALID_EC_KEY                           133
# define GMAPI_R_INVALID_EC_PRIVATE_KEY                   134
# define GMAPI_R_INVALID_EC_PUBLIC_KEY                    135
# define GMAPI_R_INVALID_FEED_BIT_LENGTH                  136
# define GMAPI_R_INVALID_HANDLE                           137
# define GMAPI_R_INVALID_HANDLE_ALGOR                     138
# define GMAPI_R_INVALID_HANDLE_MAGIC                     139
# define GMAPI_R_INVALID_HANDLE_TYPE                      140
# define GMAPI_R_INVALID_HASH_HANDLE                      141
# define GMAPI_R_INVALID_ID_LENGTH                        142
# define GMAPI_R_INVALID_INPUT_LENGTH                     143
# define GMAPI_R_INVALID_IV_LENGTH                        144
# define GMAPI_R_INVALID_KEY_HANDLE                       145
# define GMAPI_R_INVALID_KEY_LENGTH                       146
# define GMAPI_R_INVALID_KEY_USAGE                        147
# define GMAPI_R_INVALID_LENGTH                           148
# define GMAPI_R_INVALID_MAC_HANDLE                       149
# define GMAPI_R_INVALID_PLAINTEXT_LENGTH                 150
# define GMAPI_R_INVALID_PRIVATE_KEY                      151
# define GMAPI_R_INVALID_PUBLIC_KEY                       152
# define GMAPI_R_INVALID_RANDOM_LENGTH                    153
# define GMAPI_R_INVALID_RSA_KEY_LENGTH                   154
# define GMAPI_R_INVALID_RSA_PRIVATE_KEY                  155
# define GMAPI_R_INVALID_RSA_PUBLIC_KEY                   156
# define GMAPI_R_INVALID_SIGNATURE                        157
# define GMAPI_R_INVALID_SM2_CIPHERTEXT                   158
# define GMAPI_R_INVALID_SM2_SIGNATURE                    159
# define GMAPI_R_MAC_FAILURE                              160
# define GMAPI_R_MALLOC_FAILED                            161
# define GMAPI_R_NOT_CONVERTABLE                          162
# define GMAPI_R_NO_PUBLIC_KEY                            163
# define GMAPI_R_NULL_ARGUMENT                            164
# define GMAPI_R_OPERATION_NOT_INITIALIZED                165
# define GMAPI_R_SAF_ERROR                                166
# define GMAPI_R_SIGN_FAILED                              167
# define GMAPI_R_VERIFY_NOT_PASS                          168

# ifdef  __cplusplus
}
# endif
#endif
