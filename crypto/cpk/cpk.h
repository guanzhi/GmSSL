/* crypto/cpk/cpk.h */
/* ====================================================================
 * Copyright (c) 2007 - 2015 The GmSSL Project.  All rights reserved.
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

#ifndef HEADER_CPK_H
#define HEADER_CPK_H

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/ossl_typ.h>
#include <openssl/ecies.h>

#ifdef  __cplusplus
extern "C" {
#endif

#define CPK_MAX_ID_LENGTH	64


typedef struct cpk_master_secret_st {
	long version;
	X509_NAME *id;
	X509_ALGOR *pkey_algor;
	X509_ALGOR *map_algor;
	ASN1_OCTET_STRING *secret_factors;
} CPK_MASTER_SECRET;

DECLARE_ASN1_FUNCTIONS(CPK_MASTER_SECRET)

typedef struct cpk_public_params_st {
	long version;
	X509_NAME *id;
	X509_ALGOR *pkey_algor;
	X509_ALGOR *map_algor;
	ASN1_OCTET_STRING *public_factors;
} CPK_PUBLIC_PARAMS;

DECLARE_ASN1_FUNCTIONS(CPK_PUBLIC_PARAMS)

X509_ALGOR *CPK_MAP_new_default(void);
int CPK_MAP_is_valid(const X509_ALGOR *algor);
int CPK_MAP_num_factors(const X509_ALGOR *algor);
int CPK_MAP_num_indexes(const X509_ALGOR *algor);
int CPK_MAP_str2index(const X509_ALGOR *algor, const char *str, int *index);
int CPK_MAP_print(BIO *out, X509_ALGOR *map, int indent, unsigned long flags);

CPK_MASTER_SECRET *CPK_MASTER_SECRET_create(const char *domain_id, EVP_PKEY *pkey, X509_ALGOR *map_algor);
CPK_PUBLIC_PARAMS *CPK_MASTER_SECRET_extract_public_params(CPK_MASTER_SECRET *master);
EVP_PKEY *CPK_MASTER_SECRET_extract_private_key(CPK_MASTER_SECRET *master, const char *id);
EVP_PKEY *CPK_PUBLIC_PARAMS_extract_public_key(CPK_PUBLIC_PARAMS *params, const char *id);


int CPK_PUBLIC_PARAMS_compute_share_key(CPK_PUBLIC_PARAMS *params,
	void *out, size_t outlen, const char *id, EVP_PKEY *priv_key,
	void *(*kdf)(const void *in, size_t inlen, void *out, size_t *outlen));

char *CPK_MASTER_SECRET_get_name(CPK_MASTER_SECRET *master, char *buf, int size);
char *CPK_PUBLIC_PARAMS_get_name(CPK_PUBLIC_PARAMS *params);
int CPK_MASTER_SECRET_digest(CPK_MASTER_SECRET *master, const EVP_MD *type, unsigned char *md, unsigned int *len);
int CPK_PUBLIC_PARAMS_digest(CPK_PUBLIC_PARAMS *params, const EVP_MD *type, unsigned char *md, unsigned int *len);
int CPK_MASTER_SECRET_print(BIO *out, CPK_MASTER_SECRET *master, int indent, unsigned long flags);
int CPK_PUBLIC_PARAMS_print(BIO *out, CPK_PUBLIC_PARAMS *params, int indent, unsigned long flags);
int CPK_MASTER_SECRET_validate_public_params(CPK_MASTER_SECRET *master, CPK_PUBLIC_PARAMS *params);
int CPK_PUBLIC_PARAMS_validate_private_key(CPK_PUBLIC_PARAMS *params, const char *id, const EVP_PKEY *pkey);
CPK_MASTER_SECRET *d2i_CPK_MASTER_SECRET_bio(BIO *bp, CPK_MASTER_SECRET **master);
int i2d_CPK_MASTER_SECRET_bio(BIO *bp, CPK_MASTER_SECRET *master);
CPK_PUBLIC_PARAMS *d2i_CPK_PUBLIC_PARAMS_bio(BIO *bp, CPK_PUBLIC_PARAMS **params);
int i2d_CPK_PUBLIC_PARAMS_bio(BIO *bp, CPK_PUBLIC_PARAMS *params);


/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_CPK_strings(void);

/* Error codes for the CPK functions. */

/* Function codes. */
# define CPK_F_CPK_MAP_NEW_DEFAULT                        100
# define CPK_F_CPK_MAP_NUM_FACTORS                        101
# define CPK_F_CPK_MAP_NUM_INDEXES                        102
# define CPK_F_CPK_MAP_STR2INDEX                          103
# define CPK_F_CPK_MASTER_SECRET_CREATE                   104
# define CPK_F_CPK_MASTER_SECRET_DIGEST                   105
# define CPK_F_CPK_MASTER_SECRET_EXTRACT_PRIVATE_KEY      106
# define CPK_F_CPK_MASTER_SECRET_EXTRACT_PUBLIC_PARAMS    107
# define CPK_F_CPK_MASTER_SECRET_PRINT                    108
# define CPK_F_CPK_MASTER_SECRET_VALIDATE_PUBLIC_PARAMS   109
# define CPK_F_CPK_PUBLIC_PARAMS_COMPUTE_SHARE_KEY        110
# define CPK_F_CPK_PUBLIC_PARAMS_DIGEST                   111
# define CPK_F_CPK_PUBLIC_PARAMS_EXTRACT_PUBLIC_KEY       112
# define CPK_F_CPK_PUBLIC_PARAMS_PRINT                    113
# define CPK_F_CPK_PUBLIC_PARAMS_VALIDATE_PRIVATE_KEY     114
# define CPK_F_X509_ALGOR_GET1_DSA                        115
# define CPK_F_X509_ALGOR_GET1_EC_KEY                     116

/* Reason codes. */
# define CPK_R_ADD_SIGNING_TIME                           100
# define CPK_R_BAD_ARGUMENT                               101
# define CPK_R_BAD_DATA                                   102
# define CPK_R_DERIVE_KEY_FAILED                          103
# define CPK_R_DER_DECODE_FAILED                          104
# define CPK_R_DIGEST_FAILED                              105
# define CPK_R_ECIES_DECRYPT_FAILED                       106
# define CPK_R_ECIES_ENCRYPT_FAILED                       107
# define CPK_R_INVALID_ID_LENGTH                          108
# define CPK_R_INVALID_MAP_ALGOR                          109
# define CPK_R_INVALID_PKEY_TYPE                          110
# define CPK_R_MAP_FAILED                                 111
# define CPK_R_PKEY_TYPE_NOT_MATCH                        112
# define CPK_R_SET_RECIP_INFO                             113
# define CPK_R_SET_SIGNER                                 114
# define CPK_R_STACK_ERROR                                115
# define CPK_R_UNABLE_TO_FIND_MESSAGE_DIGEST              116
# define CPK_R_UNKNOWN_CIPHER_TYPE                        117
# define CPK_R_UNKNOWN_CURVE                              118
# define CPK_R_UNKNOWN_DIGEST_TYPE                        119
# define CPK_R_UNKNOWN_ECDH_TYPE                          120
# define CPK_R_UNKNOWN_MAP_TYPE                           121
# define CPK_R_UNKNOWN_PKCS7_TYPE                         122
# define CPK_R_UNSUPPORTED_PKCS7_CONTENT_TYPE             123
# define CPK_R_VERIFY_FAILED                              124
# define CPK_R_WITHOUT_DECRYPT_KEY                        125

#ifdef  __cplusplus
}
#endif
#endif
