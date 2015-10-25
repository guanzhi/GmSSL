/* crypto/cpk/cpk_err.c */
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

#include <openssl/err.h>
#include "cpk.h"

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

#define ERR_FUNC(func) ERR_PACK(ERR_LIB_CPK,func,0)
#define ERR_REASON(reason) ERR_PACK(ERR_LIB_CPK,0,reason)

static ERR_STRING_DATA CPK_str_functs[] = 
{
	{ERR_FUNC(CPK_F_CPK_MASTER_SECRET_CREATE),	"CPK_MASTER_SECRET_create"},
	{ERR_FUNC(CPK_F_CPK_MASTER_SECRET_EXTRACT_PUBLIC_PARAMS),	"CPK_MASTER_SECRET_extract_public_params"},
	{ERR_FUNC(CPK_F_CPK_MASTER_SECRET_EXTRACT_PRIVATE_KEY),		"CPK_MASTER_SECRET_extract_private_key"},
	{ERR_FUNC(CPK_F_CPK_PUBLIC_PARAMS_EXTRACT_PUBLIC_KEY),		"CPK_PUBLIC_PARAMS_extract_public_key"},
	{ERR_FUNC(CPK_F_CPK_PUBLIC_PARAMS_COMPUTE_SHARE_KEY),           "CPK_PUBLIC_PARAMS_compute_share_key"},
	{ERR_FUNC(CPK_F_CPK_MASTER_SECRET_DIGEST),	"CPK_F_CPK_MASTER_SECRET_digest"},
	{ERR_FUNC(CPK_F_CPK_PUBLIC_PARAMS_DIGEST),	"CPK_F_CPK_PUBLIC_PARAMS_digest"},
	{ERR_FUNC(CPK_F_CPK_MASTER_SECRET_PRINT),	"CPK_F_CPK_MASTER_SECRET_print"},
	{ERR_FUNC(CPK_F_CPK_PUBLIC_PARAMS_PRINT),	"CPK_F_CPK_PUBLIC_PARAMS_print"},
	{ERR_FUNC(CPK_F_CPK_MASTER_SECRET_VALIDATE_PUBLIC_PARAMS),	"CPK_F_CPK_MASTER_SECRET_validate_public_params"},
	{ERR_FUNC(CPK_F_CPK_PUBLIC_PARAMS_VALIDATE_PRIVATE_KEY),	"CPK_F_CPK_PUBLIC_PARAMS_validate_private_key"},
	{ERR_FUNC(CPK_F_CPK_MAP_NEW_DEFAULT),		"CPK_F_CPK_MAP_new_default"},
	{ERR_FUNC(CPK_F_CPK_MAP_NUM_FACTORS),		"CPK_F_CPK_MAP_num_factors"},
	{ERR_FUNC(CPK_F_CPK_MAP_NUM_INDEXES),		"CPK_F_CPK_MAP_num_indexes"},
	{ERR_FUNC(CPK_F_CPK_MAP_STR2INDEX),		"CPK_F_CPK_MAP_STR2INDEX"},	
	{ERR_FUNC(CPK_F_X509_ALGOR_GET1_EC_KEY),	"X509_ALGOR_get1_ec_key"},
	{ERR_FUNC(CPK_F_X509_ALGOR_GET1_DSA),		"X509_ALGOR_get1_dsa"},
	{0, NULL}
};

static ERR_STRING_DATA CPK_str_reasons[] = 
{
	{ERR_REASON(CPK_R_BAD_ARGUMENT),		"bad argument"},
	{ERR_REASON(CPK_R_UNKNOWN_DIGEST_TYPE),		"unknown digest algorithm"},
	{ERR_REASON(CPK_R_UNKNOWN_CIPHER_TYPE),		"unknown cipher algorithm"},
	{ERR_REASON(CPK_R_UNKNOWN_MAP_TYPE),		"unknown cpk map algorithm"},
	{ERR_REASON(CPK_R_UNKNOWN_CURVE),		"unknown elliptic curve"},
	{ERR_REASON(CPK_R_STACK_ERROR),			"stack error"},
	{ERR_REASON(CPK_R_DERIVE_KEY_FAILED),		"derive key failed"},
	{ERR_REASON(CPK_R_ECIES_ENCRYPT_FAILED),	"ecies encryption failed"},
	{ERR_REASON(CPK_R_ECIES_DECRYPT_FAILED),	"ecies decryption failed"},
	{ERR_REASON(CPK_R_DER_DECODE_FAILED),		"DER decode failed"},
	{ERR_REASON(CPK_R_UNSUPPORTED_PKCS7_CONTENT_TYPE),"CPK_R_UNSUPPORTED_PKCS7_CONTENT_TYPE"},
	{ERR_REASON(CPK_R_SET_SIGNER),			"CPK_R_SET_SIGNER"},
	{ERR_REASON(CPK_R_SET_RECIP_INFO),		"CPK_R_SET_RECIP_INFO"},
	{ERR_REASON(CPK_R_UNABLE_TO_FIND_MESSAGE_DIGEST),"CPK_R_UNABLE_TO_FIND_MESSAGE_DIGEST"},
	{ERR_REASON(CPK_R_BAD_DATA),			"bad data"},
	{ERR_REASON(CPK_R_MAP_FAILED),			"CPK_R_MAP_FAILED"},
	{ERR_REASON(CPK_R_ADD_SIGNING_TIME),		"CPK_R_ADD_SIGNING_TIME"},
	{ERR_REASON(CPK_R_VERIFY_FAILED),		"CPK_R_VERIFY_FAILED"},
	{ERR_REASON(CPK_R_UNKNOWN_ECDH_TYPE),		"CPK_R_UNKNOWN_ECDH_TYPE"},
	{ERR_REASON(CPK_R_DIGEST_FAILED),		"CPK_R_DIGEST_FAILED"},
	{ERR_REASON(CPK_R_WITHOUT_DECRYPT_KEY),		"CPK_R_WITHOUT_DECRYPT_KEY"},
	{ERR_REASON(CPK_R_UNKNOWN_PKCS7_TYPE),		"CPK_R_UNKNOWN_PKCS7_TYPE"},
	{ERR_REASON(CPK_R_INVALID_ID_LENGTH),		"invalid identity length"},
	{ERR_REASON(CPK_R_INVALID_PKEY_TYPE),		"invalid public key type"},
	{ERR_REASON(CPK_R_INVALID_MAP_ALGOR),		"invalid map algorithm"},
	{ERR_REASON(CPK_R_PKEY_TYPE_NOT_MATCH),         "public key type not match"},
	{0, NULL}
};

#endif

void ERR_load_CPK_strings(void)
{
#ifndef OPENSSL_NO_ERR

	if (ERR_func_error_string(CPK_str_functs[0].error) == NULL) {
		ERR_load_strings(0, CPK_str_functs);
		ERR_load_strings(0, CPK_str_reasons);
	}

#endif
}
