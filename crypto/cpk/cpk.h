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

#define CPK_LIB_VERSION		"0.9"
#define CPK_MAX_ID_LENGTH	64


/**
 * @struct CPK_MASTER_SECRET
 * @brief The in-memory structure to represent a cpk master secret.
 */
typedef struct cpk_master_secret_st {
	long                 version;         /**< The version of the master secret.*/
	X509_NAME           *id;               /**< The id of the master secret.*/
	X509_ALGOR          *pkey_algor;      /**< The public key algorithm used in the master secret.*/
	X509_ALGOR          *map_algor;       /**< The map algorithm used in the master secret.*/
	ASN1_OCTET_STRING   *secret_factors;   /**< The secret factors of the master secret.*/
} CPK_MASTER_SECRET;
/** 
 * @def
 * @brief Declare 4 basic ASN1 functions of CPK_MASTER_SECRET and a pointer
 * to an ASN1_ITEM with detail information of the fields of 
 * CPK_MASTER_SECRET in it.
 *
 * The macro would generate following 4 function declarations and 1 pointer:\n
 * CPK_MASTER_SECRET *CPK_MASTER_SECRET_new(void): alloc a new instance of CPK_MASTER_SECRET.\n
 * void CPK_MASTER_SECRET_free(CPK_MASTER_SECRET* a): free the instance a.\n
 * CPK_MASTER_SECRET *d2i_CPK_MASTER_SECRET(CPK_MASTER_SECRET **a, const unsigned char **in, long len):
 * convert the CPK_MASTER_SECRET instance from the DER format to the internal format.\n
 * int i2d_CPK_MASTER_SECRET(CPK_MASTER_SECRET *a, unsigned char* out): convert an CPK_MASTER_SECRET
 * to the DER format.\n
 * ASN1_ITEM* CPK_MASTER_SECRET_it: a pointer to a instance of ASN1_ITEM struct which contains
 * information on the conversion between DER and internal.\n
 */
DECLARE_ASN1_FUNCTIONS(CPK_MASTER_SECRET)


/**
 * @struct CPK_PUBLIC_PARAMS
 * @brief The in-memory structure to represent a set of cpk public parameters.
 */
typedef struct cpk_public_params_st {
	long                version;       /**< The version of the public parameters.*/
	X509_NAME          *id;            /**< The id of the public parameters.*/
	X509_ALGOR         *pkey_algor;    /**< The public key algorithm used in the public parameters.*/
	X509_ALGOR         *map_algor;     /**< The map algorithm used in the public parameters.*/
	ASN1_OCTET_STRING  *public_factors;/**< The public factors of the public parameters.*/
} CPK_PUBLIC_PARAMS;
/** 
 * @brief Declare 4 basic ASN1 functions of CPK_PUBLIC_PARAMS and a pointer to an ASN1_ITEM
 * with detail information of the fields of CPK_PUBLIC_PARAMS in it.
 *
 * The macro would generate following 4 function declarations and 1 pointer:\n
 * CPK_PUBLIC_PARAMS *CPK_PUBLIC_PARAMS_new(void): alloc a new instance of CPK_PUBLIC_PARAMS.\n
 * void CPK_PUBLIC_PARAMS_free(CPK_PUBLIC_PARAMS* a): free the instance a.\n
 * CPK_PUBLIC_PARAMS *d2i_CPK_PUBLIC_PARAMS(CPK_PUBLIC_PARAMS **a, const unsigned char **in, long len):
 * convert the CPK_PUBLIC_PARAMS instance from the DER format to the internal format.\n
 * int i2d_CPK_PUBLIC_PARAMS(CPK_PUBLIC_PARAMS *a, unsigned char* out): convert a CPK_PUBLIC_PARAMS
 * to the DER format.\n
 * ASN1_ITEM* CPK_PUBLIC_PARAMS_it: a pointer to a instance of ASN1_ITEM struct which contains
 * information on the conversion between DER and internal.\n
 */
DECLARE_ASN1_FUNCTIONS(CPK_PUBLIC_PARAMS)

/**
 * @brief Get a new default map algorithm.
 *
 * @return Returns a pointer to a new instance of the default map algorithm of the type X509_ALGOR.
 */
X509_ALGOR *CPK_MAP_new_default();

/**
 * @brief Check if the given map algorithm is valid.
 *
 * @param[in] algor The pointer to the algorithm to check.
 * @return Returns 1 if the given algorithm is valid.
 */
int CPK_MAP_is_valid(const X509_ALGOR *algor);

/**
 * @brief Get the number of factors of the given algorithm.
 *
 * @param[in] algor The pointer to the algorithm.
 * @return Returns the number of factors of the algorithm.
 */
int CPK_MAP_num_factors(const X509_ALGOR *algor);

/**
 * @brief Get the number of indexes of the given algorithm.
 *
 * @param[in] algor The pointer to the algorithm.
 * @return Returns the number of indexes of the algorithm.
 */
int CPK_MAP_num_indexes(const X509_ALGOR *algor);

/**
 * @brief Convert the string to the index vector.
 * 
 * @param[in] algor The pointer to the algorithm to do the map function.
 * @param[in] str The pointer to a string in the memory, ended by '\0'.
 * @param[out] index The pointer to a array which will receive the index.
 * @return Returns 1 on success.
 */
int CPK_MAP_str2index(const X509_ALGOR *algor, const char *str, int *index);

/**
 * @brief Print the parameters of the map algortihm.
 *
 * @param[out] out A IO abstraction to receive the output stream.
 * @param[in] indent The amount of the indentation in the output stream.
 * @param[in] flags The flag set to control the ouput.
 * @return Returns 1 on success.
 */
int CPK_MAP_print(BIO *out, X509_ALGOR *map, int indent, unsigned long flags);

/**
 * @brief Create a master secret with the given domain id, public key algorithm and map algorithm.
 *
 * @param[in] domain_id The domain identifier of the master secret.
 * @param[in] pkey The pointer to the public key algorithm of the master secret.
 * @param[in] map_algor The pointer to the map algorithm of the master secret.
 * @return Returns a poniter to the created master secret on success, or NULL on failure.
 */
CPK_MASTER_SECRET *CPK_MASTER_SECRET_create(const char *domain_id, EVP_PKEY *pkey, X509_ALGOR *map_algor);

/**
 * @brief Extract the public parameters from the master secret.
 * 
 * @param[in] master The master secret to extract from.
 * @return Returns the pointer to the extracted public parameters on success, or NULL on failure.
 */
CPK_PUBLIC_PARAMS *CPK_MASTER_SECRET_extract_public_params(CPK_MASTER_SECRET *master);

/**
 * @brief Extract the private key of a given identifier from the master secret.
 *
 * @param[in] master The master secret to extract from.
 * @param[in] id The identifier which is used to maps to the private key.
 * @return Returns the pointer to the extracted private key on success, or NULL on failure.
 */
EVP_PKEY *CPK_MASTER_SECRET_extract_private_key(CPK_MASTER_SECRET *master, const char *id);

/**
 * @brief Extract the public key of a given identifier from the public parameters.
 *
 * @param[in] params The public parameters to extract from.
 * @param[in] id The identifier which is used to maps to the public key.
 * @return Returns the pointer to the extracted public key EVP_PKEY on success, or NULL on failure.
 */
EVP_PKEY *CPK_PUBLIC_PARAMS_extract_public_key(CPK_PUBLIC_PARAMS *params, const char *id);


int CPK_PUBLIC_PARAMS_compute_share_key(CPK_PUBLIC_PARAMS *params,
	void *out, size_t outlen, const char *id, EVP_PKEY *priv_key,
	void *(*kdf)(const void *in, size_t inlen, void *out, size_t *outlen));

char *CPK_MASTER_SECRET_get_name(CPK_MASTER_SECRET *master, char *buf, int size);
char *CPK_PUBLIC_PARAMS_get_name(CPK_PUBLIC_PARAMS *params);

/**
 * @brief Generate the message digest of the given master secret with the given parameters.
 *
 * This function takes the secret_factors field of the given parameter of CPK_MASTER_SECRET as 
 * the input and the parameter type of EVP_MD as the message digest
 * algorithm to compute the message digest, and put the result in the parameter md, the length
 * of the result in the paramter len.
 * @param[in] master The master secret to compute the digest.
 * @param[in] type The message digest algorithm to use to comput the digest.
 * @param[out] md The buffer to receive the result of the computation of message digest.
 * @param[out] len If len is not null, the variable it point to will be assigned the length of
 * the message digest.
 * @return Returns 1 on success, 0 on failure.
 */
int CPK_MASTER_SECRET_digest(CPK_MASTER_SECRET *master, const EVP_MD *type, unsigned char *md, unsigned int *len);

/**
 * @brief Generate the message digest of the given public parameters with the given parameters.
 *
 * This function takes the secret_factors field of the given parameter of CPK_PUBLIC_PARAMS as
 * the input and the parameter type of EVP_MD as the message digest
 * algorithm to compute the message digest, and put the result in the parameter md, the length
 * of the result in the paramter len.
 * @param[in] params The public parameters to compute the digest.
 * @param[in] type The message digest algorithm to use to comput the digest.
 * @param[out] md The buffer to receive the result of the computation of message digest.
 * @param[out] len If len is not null, the variable it point to will be assigned the length of
 * the message digest.
 * @return Returns 1 on success, 0 on failure.
 */
int CPK_PUBLIC_PARAMS_digest(CPK_PUBLIC_PARAMS *params, const EVP_MD *type, unsigned char *md, unsigned int *len);

/**
 * @brief Print the master secret to a BIO, including the version, the domain uri, the public
 * algorithm and the map algorithm.
 *
 * @param[out] out A IO abstraction to receive the output stream.
 * @param[in] master The CPK_MASTER_SECRET instance to print.
 * @param[in] indent The amount of the indentation.
 * @param[in] flags The flag set to control the ouput.
 * @return Returns 1 on success, 0 on failure.
 */
int CPK_MASTER_SECRET_print(BIO *out, CPK_MASTER_SECRET *master, int indent, unsigned long flags);

/**
 * @brief Print the public parameters to a BIO.
 *
 * @param[out] out A IO abstraction to receive the output stream.
 * @param[in] params The CPK_PUBLIC_PARAMS instance to print.
 * @param[in] indent The amount of the indentation.
 * @param[in] flags The flag set to control the ouput.
 * @return Returns 1 on success, 0 on failure.
 */
int CPK_PUBLIC_PARAMS_print(BIO *out, CPK_PUBLIC_PARAMS *params, int indent, unsigned long flags);

/**
 * @brief Validate the public parameters with the given master secret.
 *
 * @param[in] master The master secret used for the validation.
 * @param[in] params The public parameters to validate.
 * @return Returns 1 if the public parameter is valid, returns 0 otherwise.
 */
int CPK_MASTER_SECRET_validate_public_params(CPK_MASTER_SECRET *master, CPK_PUBLIC_PARAMS *params);

/**
 * @brief Validate the private key with the given public parameters.
 *
 * @param[in] params The public parameter used for the validation.
 * @param[in] id the identifier of the private key owner.
 * @param[in] pkey pkey The private key to validate.
 * @return Returns 1 if the private key is valid, returns a integer less or equal than 0 otherwise.
 */
int CPK_PUBLIC_PARAMS_validate_private_key(CPK_PUBLIC_PARAMS *params, const char *id, const EVP_PKEY *pkey);

/**
 * @brief Convert the master secret in DER format in the IO abstraction to an instance of CPK_MASTER_SECRET.
 *
 * @param[in] bp A pointer to the IO abstraction which ocntaints the master secret in DER format.
 * @param[out] master A pointer to receive the pointer to the converted master secret of the type CPK_MASTER_SECRET.
 * @return Returns the pointer to the converted master secret of the type CPK_MASTER_SECRET on success, 
 * or null on failure.
 */
CPK_MASTER_SECRET *d2i_CPK_MASTER_SECRET_bio(BIO *bp, CPK_MASTER_SECRET **master);

/**
 * @brief Convert the master key from CPK_MASTER_SECRET to a byte stream in DER format, and write
 * the stream to an IO abstraction.
 *
 * @param[out] bp A pointer to the IO abstraction which receives the stream.
 * @param[in] master A pointer to the master key of the type CPK_MASTER_SECRET.
 * @return Returns the size of the output stream on success, of an integer less or equal than 0
 * indicating an error.
 */
int i2d_CPK_MASTER_SECRET_bio(BIO *bp, CPK_MASTER_SECRET *master);

/**
 * @brief Convert the public parameters in DER format in the IO abstraction to an instance of CPK_PUBLIC_PARAMS.
 *
 * @param[in] bp A pointer to the IO abstraction which ocntaints the public parameters in DER format.
 * @param[out] params A pointer to receive the pointer to the converted public parameters of the type CPK_PUBLIC_PARAMS.
 * @return Returns the pointer to the converted public parameters of the type CPK_PUBLIC_PARAMS on success,
 * or null on failure.
 */
CPK_PUBLIC_PARAMS *d2i_CPK_PUBLIC_PARAMS_bio(BIO *bp, CPK_PUBLIC_PARAMS **params);

/**
 * @brief Convert the public parameters from CPK_PUBLIC_PARAMS to a byte stream in DER format,
 * and write the stream to an IO abstraction.
 *
 * @param[out] bp A pointer to the IO abstraction which receives the stream.
 * @param[in] master A pointer to the public parameters of the type CPK_PUBLIC_PARAMS.
 * @return Returns the size of the output stream on success, of an integer less or equal than 0
 * indicating an error.
 */
int i2d_CPK_PUBLIC_PARAMS_bio(BIO *bp, CPK_PUBLIC_PARAMS *params);


/*
 * SignerInfo ::= SEQUENCE {
 *	version INTEGER {1},
 *	signer IssuerAndSerialNumber,
 *	digestAlgor DigestAlgorithmIdentifier,
 *	signedAttrs [0] IMPLICIT Attributes OPTIONAL,
 *	signingAlgor SigningAlgorithmIdentifier,
 *	signature OCTET STRING {{ECDSASigValue}},
 *	unsignedAttrs [1] IMPLICIT Attributes OPTIONAL
 * }
 */
typedef struct cpk_signer_info_st {
	long				 version;
	X509_NAME			*signer;
	X509_ALGOR			*digest_algor;
	STACK_OF(X509_ATTRIBUTE)	*signed_attr;
	X509_ALGOR			*sign_algor;
	ASN1_OCTET_STRING		*signature;
	STACK_OF(X509_ATTRIBTE)		*unsigned_attr;	
	EVP_PKEY			*_privkey; /* private member */
} CPK_SIGNER_INFO;
DECLARE_STACK_OF(CPK_SIGNER_INFO)
DECLARE_ASN1_SET_OF(CPK_SIGNER_INFO)
DECLARE_ASN1_FUNCTIONS(CPK_SIGNER_INFO)

int CPK_SIGNER_INFO_set(CPK_SIGNER_INFO *si, const EVP_MD *sign_alg, const EVP_PKEY *sign_key);
int CPK_SIGNER_INFO_add_attr(CPK_SIGNER_INFO *si, int nid, int atrtype, void *value);
int CPK_SIGNER_INFO_add_signed_attr(CPK_SIGNER_INFO *si, int nid, int atrtype, void *value);
int CPK_SIGNER_INFO_add_signed_time(CPK_SIGNER_INFO *si);
int CPK_SIGNER_INFO_add_signed_digest(CPK_SIGNER_INFO *si, const EVP_MD_CTX *ctx);
ASN1_TYPE *CPK_SIGNER_INFO_get_attr(CPK_SIGNER_INFO *si, int nid);
ASN1_TYPE *CPK_SIGNER_INFO_get_signed_attr(CPK_SIGNER_INFO *si, int nid);
ASN1_UTCTIME *CPK_SIGNER_INFO_get_signed_time(CPK_SIGNER_INFO *si);

int CPK_SIGNER_INFO_do_sign(CPK_SIGNER_INFO *si, EVP_MD_CTX *md_ctx);
int CPK_SIGNER_INFO_do_verify(const CPK_SIGNER_INFO *si, EVP_MD_CTX *ctx, const CPK_PUBLIC_PARAMS *params);

/*
 * RecipientInfo ::= SEQUENCE {
 *	version INTEGER {0},
 *	recipient IssuerAndSerialNumber,
 *	keyEncryptionAlgor EncryptionAlgorithmIdentifier,
 *	encryptedKey OCTET STRING
 * }
 * RecipientInfos ::= SET OF RecipientInfo
 */
typedef struct cpk_recip_info_st {
	long				 version;
	X509_NAME			*recipient;
	X509_ALGOR			*enc_algor;
	ASN1_OCTET_STRING		*enc_data;
	/* private */
	EVP_PKEY			*_pubkey;
} CPK_RECIP_INFO;
DECLARE_STACK_OF(CPK_RECIP_INFO)
DECLARE_ASN1_SET_OF(CPK_RECIP_INFO)
DECLARE_ASN1_FUNCTIONS(CPK_RECIP_INFO)

int CPK_RECIP_INFO_set(CPK_RECIP_INFO *ri, const X509_NAME *recipient, const ECIES_PARAMS *ecies);
int CPK_RECIP_INFO_do_encrypt(CPK_RECIP_INFO *ri, const unsigned char *in, size_t inlen);
int CPK_RECIP_INFO_do_decrypt(CPK_RECIP_INFO *ri, const EVP_PKEY *pkey, unsigned char *out, size_t *outlen);


/*
 * SingerInfos ::= SET OF SignerInfo
 *
 * SignedData ::= SEQUENCE {
 *	version INTEGER,
 *	digestAlgors DigestAlgorithmIdentifiers,
 *	contentInfo ContentInfo,
 *	signerInfos SignerInfos,
 * }
 */
typedef struct cpk_signed_st {
	long				 version;
	STACK_OF(X509_ALGOR)		*digest_algors;
	STACK_OF(X509)			*cert;	/* [ 0 ] */
	STACK_OF(X509_CRL)		*crl;	/* [ 1 ] */
	STACK_OF(CPK_SIGINFO)		*signer_infos;
	struct CPK_CMS_st		*contents;
} CPK_SIGNED;
DECLARE_ASN1_FUNCTIONS(CPK_SIGNED)

typedef struct cpk_enc_content_st {
	ASN1_OBJECT			*content_type;
	X509_ALGOR			*enc_algor;
	ASN1_OCTET_STRING		*enc_data;	/* [ 0 ] */
	/* private */
	const EVP_CIPHER		*cipher;
} CPK_ENC_CONTENT;
DECLARE_ASN1_FUNCTIONS(CPK_ENC_CONTENT)

typedef struct cpk_envelope_st {
	long				 version;
	STACK_OF(CPK_RECIP_INFO)	*recip_infos;
	CPK_ENC_CONTENT			*enc_data;
} CPK_ENVELOPE;
DECLARE_ASN1_FUNCTIONS(CPK_ENVELOPE)

typedef struct cpk_sign_envelope_st {
	long				 version;
	STACK_OF(X509_ALGOR)		*digest_algors;
	STACK_OF(X509)			*cert;	/* [ 0 ] */
	STACK_OF(X509_CRL)		*crl;	/* [ 1 ] */
	STACK_OF(CPK_SIGNER_INFO)	*signer_infos;
	CPK_ENC_CONTENT			*enc_data;
	STACK_OF(CPK_RECIP_INFO)	*recip_infos;
} CPK_SIGN_ENVELOPE;
DECLARE_ASN1_FUNCTIONS(CPK_SIGN_ENVELOPE)

typedef struct cpk_cms_st {
	int state; /* used during processing */
	int detached;

	ASN1_OBJECT *type;
	union	{
		char *ptr;

		/* NID_pkcs7_data */
		ASN1_OCTET_STRING *data;

		/* NID_pkcs7_signed */
		CPK_SIGNED *sign;

		/* NID_pkcs7_enveloped */
		CPK_ENVELOPE *enveloped;

		/* NID_pkcs7_signedAndEnveloped */
		CPK_SIGN_ENVELOPE *signed_and_enveloped;

		/* Anything else */
		ASN1_TYPE *other;
	} d;
} CPK_CMS;
DECLARE_STACK_OF(CPK_CMS)
DECLARE_ASN1_SET_OF(CPK_CMS)
DECLARE_PKCS12_STACK_OF(CPK_CMS)
DECLARE_ASN1_FUNCTIONS(CPK_CMS)

DECLARE_ASN1_ITEM(CPK_CMS_ATTR_SIGN)
DECLARE_ASN1_ITEM(CPK_CMS_ATTR_VERIFY)
DECLARE_ASN1_NDEF_FUNCTION(CPK_CMS)



#define CPK_CMS_OP_SET_DETACHED_SIGNATURE	1
#define CPK_CMS_OP_GET_DETACHED_SIGNATURE	2

#define CPK_CMS_get_signed_attributes(si)	((si)->auth_attr)
#define CPK_CMS_get_attributes(si)		((si)->unauth_attr)

#define CPK_CMS_type_is_signed(a)			\
	(OBJ_obj2nid((a)->type) == NID_pkcs7_signed)
#define CPK_CMS_type_is_enveloped(a)			\
	(OBJ_obj2nid((a)->type) == NID_pkcs7_enveloped)
#define CPK_CMS_type_is_signedAndEnveloped(a)		\
	(OBJ_obj2nid((a)->type) == NID_pkcs7_signedAndEnveloped)
#define CPK_CMS_type_is_data(a)			\
	(OBJ_obj2nid((a)->type) == NID_pkcs7_data)
#define CPK_CMS_set_detached(p,v)			\
	CPK_CMS_ctrl(p,CPK_CMS_OP_SET_DETACHED_SIGNATURE,v,NULL)
#define CPK_CMS_get_detached(p)			\
	CPK_CMS_ctrl(p,CPK_CMS_OP_GET_DETACHED_SIGNATURE,0,NULL)
#define CPK_CMS_is_detached(p7)			\
	(CPK_CMS_type_is_signed(p7) && CPK_CMS_get_detached(p7))

long CPK_CMS_ctrl(CPK_CMS *p7, int cmd, long larg, char *parg);
int CPK_CMS_set_type(CPK_CMS *p7, int type);
int CPK_CMS_set_cipher(CPK_CMS *p7, const EVP_CIPHER *cipher);
int CPK_CMS_set_content(CPK_CMS *p7, CPK_CMS *p7_data);
int CPK_CMS_content_new(CPK_CMS *p7, int type);
int CPK_CMS_add_signer(CPK_CMS *p7, const EVP_MD *sign_alg, const EVP_PKEY *sign_key);
int CPK_CMS_add_recipient(CPK_CMS *p7, const X509_NAME *id, const ECIES_PARAMS *params);


BIO *CPK_CMS_dataInit(CPK_CMS *p7, BIO *bio);
BIO *CPK_CMS_dataDecode(CPK_CMS *p7, BIO *in_bio, const EVP_PKEY *keyinfo);
int  CPK_CMS_dataUpdate(CPK_CMS *p7, BIO *bio, const unsigned char *data, int len);
int  CPK_CMS_dataFinal(CPK_CMS *p7, BIO *bio);
STACK_OF(CPK_SIGNER_INFO) *CPK_CMS_get_signer_infos(CPK_CMS *p7);
int CPK_CMS_dataVerify(CPK_PUBLIC_PARAMS *params, BIO *bio, CPK_CMS *p7, CPK_SIGNER_INFO *si);



/* ERR function (should in openssl/err.h) begin */
#define ERR_LIB_CPK		130
#define ERR_R_CPK_LIB		ERR_LIB_CPK
#define CPKerr(f,r) ERR_PUT_error(ERR_LIB_CPK,(f),(r),__FILE__,__LINE__)
/* end */


void ERR_load_CPK_strings(void);

/**
 * @defgroup error_cpk Definations to handle errors of cpk runtime.
 * @{
 */
/* Error codes for the ECIES functions. */

/* Function codes. */
#define CPK_F_CPK_MASTER_SECRET_CREATE			100
#define CPK_F_CPK_MASTER_SECRET_EXTRACT_PUBLIC_PARAMS	101
#define CPK_F_CPK_MASTER_SECRET_EXTRACT_PRIVATE_KEY	102
#define CPK_F_CPK_PUBLIC_PARAMS_EXTRACT_PUBLIC_KEY	103
#define CPK_F_CPK_PUBLIC_PARAMS_COMPUTE_SHARE_KEY	116
#define CPK_F_CPK_MASTER_SECRET_DIGEST			104
#define CPK_F_CPK_PUBLIC_PARAMS_DIGEST			105
#define CPK_F_CPK_MASTER_SECRET_PRINT			106
#define CPK_F_CPK_PUBLIC_PARAMS_PRINT			107
#define CPK_F_CPK_MASTER_SECRET_VALIDATE_PUBLIC_PARAMS	108
#define CPK_F_CPK_PUBLIC_PARAMS_VALIDATE_PRIVATE_KEY	109
#define CPK_F_CPK_MAP_NEW_DEFAULT			110
#define CPK_F_CPK_MAP_NUM_FACTORS			111
#define CPK_F_CPK_MAP_NUM_INDEXES			112
#define CPK_F_CPK_MAP_STR2INDEX				113
#define CPK_F_X509_ALGOR_GET1_EC_KEY			114
#define CPK_F_X509_ALGOR_GET1_DSA			115

/* Reason codes. */
#define CPK_R_BAD_ARGUMENT				100
#define CPK_R_UNKNOWN_DIGEST_TYPE			101
#define CPK_R_UNKNOWN_CIPHER_TYPE			102
#define CPK_R_UNKNOWN_MAP_TYPE				103
#define CPK_R_UNKNOWN_CURVE				104
#define CPK_R_STACK_ERROR				105
#define CPK_R_DERIVE_KEY_FAILED				106
#define CPK_R_ECIES_ENCRYPT_FAILED			107
#define CPK_R_ECIES_DECRYPT_FAILED			108
#define CPK_R_DER_DECODE_FAILED				109
#define CPK_R_UNSUPPORTED_PKCS7_CONTENT_TYPE		110
#define CPK_R_SET_SIGNER				111
#define CPK_R_SET_RECIP_INFO				112
#define CPK_R_UNABLE_TO_FIND_MESSAGE_DIGEST		113
#define CPK_R_BAD_DATA					114
#define CPK_R_MAP_FAILED				115
#define CPK_R_ADD_SIGNING_TIME				116
#define CPK_R_VERIFY_FAILED				117
#define	CPK_R_UNKNOWN_ECDH_TYPE				118
#define CPK_R_DIGEST_FAILED				119
#define CPK_R_WITHOUT_DECRYPT_KEY			120
#define CPK_R_UNKNOWN_PKCS7_TYPE			121
#define CPK_R_INVALID_ID_LENGTH				122
#define CPK_R_INVALID_PKEY_TYPE				123
#define CPK_R_INVALID_MAP_ALGOR				124
#define CPK_R_PKEY_TYPE_NOT_MATCH			125

/**
 * @}
 */
 
#ifdef  __cplusplus
}
#endif
#endif
