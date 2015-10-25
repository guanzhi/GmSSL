/* crypto/ecies/ecies_asn1.c */
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

#include <string.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/objects.h>
#include <openssl/obj_mac.h>
#include "ecies.h"


/*
 * From SEC 1, Version 1.9 Draft, 2008
 *
secg-scheme OBJECT IDENTIFIER ::= { 
	iso(1) identified-organization(3) certicom(132) schemes(1) }
	
ECIESAlgorithmSet ALGORITHM ::= { 
	{ OID ecies-recommendedParameters} | 
	{ OID ecies-specifiedParameters PARMS ECIESParameters} 
}

ECIESParameters ::= SEQUENCE {
	kdf [0] KeyDerivationFunction OPTIONAL,
	sym [1] SymmetricEncryption OPTIONAL,
	mac [2] MessageAuthenticationCode OPTIONAL
}

KeyDerivationFunction ::= AlgorithmIdentifier {{KDFSet}}
KDFSet ALGORITHM ::= {
	{ OID x9-63-kdf PARMS HashAlgorithm } |
	{ OID nist-concatenation-kdf PARMS HashAlgorithm } | 
	{ OID tls-kdf PARMS HashAlgorithm } |
	{ OID ikev2-kdf PARMS HashAlgorithm }
}

SymmetricEncryption ::= AlgorithmIdentifier {{SYMENCSet}}
SYMENCSet ALGORITHM ::= {
	{ OID xor-in-ecies } |
	{ OID tdes-cbc-in-ecies } |  -- IV should all be set to ZEROs
	{ OID aes128-cbc-in-ecies } |
	{ OID aes192-cbc-in-ecies } |
	{ OID aes256-cbc-in-ecies } |
	{ OID aes128-ctr-in-ecies } |
	{ OID aes192-ctr-in-ecies } |
	{ OID aes256-ctr-in-ecies } ,
}

MessageAuthenticationCode ::= AlgorithmIdentifier {{MACSet}}
MACSet ALGORITHM ::= {
	{ OID hmac-full-ecies PARMS HashAlgorithm} | 
	{ OID hmac-half-ecies PARMS HashAlgorithm} | 
	{ OID cmac-aes128-ecies } |
	{ OID cmac-aes192-ecies } |
	{ OID cmac-aes256-ecies } ,
}

*/

/* 
 * Something about HMAC
 * 1. Key Length: As SHA1 provides 160 bits digest and 80 bits security.
 *    Thus the key length of HMAC-SHA1 should be at least 80 bits. The key
 *    length should be [80, 160] bits. If the key length is larger than 
 *    512 bits, need to hash it.
 * 2. Ouput Length: The HMAC-SHA1 can ouput at most 160 bits. Sometimes the
 *    output is truncated but should be at least 4 bytes. The turncated
 *    output should be the left most bytes (why?) and the length should be 
 *    80 bits to 160 bits. The standard hmac-full means use full output
 *    i.e. hmac-sha1-160 and hmac-half means use the left most 80 bits i.e.
 *    hmac-sha1-80
 *
 * About CMAC
 * In OpenSSL version 1.0.1c CMAC has been supported! For CMAC-AES the 
 * output is always 128 bits. It is obvious that the CMAC key length 
 * should be the same as the block cipher key length.
 */

/*
# Add these to "objects.txt" and run `make'
 
!Alias secg_scheme certicom-arc 1
secg-scheme 7		: ecies-recommendedParameters
secg-scheme 8		: ecies-specifiedParameters
secg-scheme 17 0	: x9-63-kdf
secg-scheme 17 1	: nist-concatenation-kdf
secg-scheme 17 2	: tls-kdf
secg-scheme 17 3	: ikev2-kdf
secg-scheme 18		: xor-in-ecies
secg-scheme 20 0	: aes128-cbc-in-ecies
secg-scheme 20 1	: aes192-cbc-in-ecies
secg-scheme 20 2	: aes256-cbc-in-ecies
secg-scheme 21 0	: aes128-ctr-in-ecies
secg-scheme 21 1	: aes192-ctr-in-ecies
secg-scheme 21 2	: aes256-ctr-in-ecies
secg-scheme 22		: hmac-full-ecies
secg-scheme 23		: hmac-half-ecies
secg-scheme 24 0	: cmac-aes128-ecies
secg-scheme 24 1	: cmac-aes192-ecies

FIXME: we can not get an EVP_algor object from these new NIDs

*/

typedef struct ecies_parameters_st {
	X509_ALGOR *kdf;
	X509_ALGOR *sym;
	X509_ALGOR *mac;
} ECIES_PARAMETERS;

ASN1_SEQUENCE(ECIES_PARAMETERS) = {
	ASN1_EXP_OPT(ECIES_PARAMETERS, kdf, X509_ALGOR, 0),
	ASN1_EXP_OPT(ECIES_PARAMETERS, sym, X509_ALGOR, 1),
	ASN1_EXP_OPT(ECIES_PARAMETERS, mac, X509_ALGOR, 2)
} ASN1_SEQUENCE_END(ECIES_PARAMETERS)
IMPLEMENT_ASN1_FUNCTIONS(ECIES_PARAMETERS)
IMPLEMENT_ASN1_DUP_FUNCTION(ECIES_PARAMETERS)

ASN1_SEQUENCE(ECIES_CIPHERTEXT_VALUE) = {
	ASN1_SIMPLE(ECIES_CIPHERTEXT_VALUE, ephem_point, ASN1_OCTET_STRING),
	ASN1_SIMPLE(ECIES_CIPHERTEXT_VALUE, ciphertext, ASN1_OCTET_STRING),
	ASN1_SIMPLE(ECIES_CIPHERTEXT_VALUE, mactag, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(ECIES_CIPHERTEXT_VALUE)
IMPLEMENT_ASN1_FUNCTIONS(ECIES_CIPHERTEXT_VALUE)
IMPLEMENT_ASN1_DUP_FUNCTION(ECIES_CIPHERTEXT_VALUE)


int i2d_ECIESParameters(const ECIES_PARAMS *param, unsigned char **out)
	{
	int ret = 0;
	ECIES_PARAMETERS *tmp = NULL;
	int sym_nid = NID_xor_in_ecies;

	OPENSSL_assert(param);
	OPENSSL_assert(param->kdf_md);
	OPENSSL_assert(param->mac_md);
	OpenSSL_add_all_digests();

	if (!(tmp = ECIES_PARAMETERS_new()))
		{
		ECIESerr(ECIES_F_I2D_ECIESPARAMETERS, ERR_R_MALLOC_FAILURE);
		goto err;
		}

	if (!(tmp->kdf = X509_ALGOR_new()))
		{
		ECIESerr(ECIES_F_I2D_ECIESPARAMETERS, ERR_R_MALLOC_FAILURE);
		goto err;
		}
	if (!X509_ALGOR_set0(tmp->kdf, OBJ_nid2obj(NID_x9_63_kdf), V_ASN1_OBJECT, OBJ_nid2obj(EVP_MD_nid(param->kdf_md)))) 
		{
		ECIESerr(ECIES_F_I2D_ECIESPARAMETERS, ERR_R_X509_LIB);
		goto err;
		}

	if (!(tmp->sym = X509_ALGOR_new()))
		{
		ECIESerr(ECIES_F_I2D_ECIESPARAMETERS, ERR_R_MALLOC_FAILURE);
		goto err;
		}
	if (param->sym_cipher)
		{
		switch (EVP_CIPHER_nid(param->sym_cipher))
			{
			case NID_aes_128_cbc:
				sym_nid = NID_aes128_cbc_in_ecies;
				break;
			case NID_aes_192_cbc:
				sym_nid = NID_aes192_cbc_in_ecies;
				break;
			case NID_aes_256_cbc:
				sym_nid = NID_aes256_cbc_in_ecies;
				break;
			case NID_aes_128_ctr:
				sym_nid = NID_aes128_ctr_in_ecies;
				break;
			case NID_aes_192_ctr:
				sym_nid = NID_aes192_ctr_in_ecies;
				break;
			case NID_aes_256_ctr:
				sym_nid = NID_aes256_ctr_in_ecies;
				break;
			default:
				ECIESerr(ECIES_F_I2D_ECIESPARAMETERS, ERR_R_MALLOC_FAILURE);
				goto err;
			}
		}	
	if (!X509_ALGOR_set0(tmp->sym, OBJ_nid2obj(sym_nid), V_ASN1_UNDEF, NULL))
		{
		ECIESerr(ECIES_F_I2D_ECIESPARAMETERS, ERR_R_X509_LIB);
		goto err;
		}

	if (!(tmp->mac = X509_ALGOR_new()))
		{
		ECIESerr(ECIES_F_I2D_ECIESPARAMETERS, ERR_R_MALLOC_FAILURE);
		goto err;
		}
	if (!X509_ALGOR_set0(tmp->mac, OBJ_nid2obj(NID_hmac_full_ecies), V_ASN1_OBJECT, OBJ_nid2obj(EVP_MD_nid(param->mac_md))))
		{
		ECIESerr(ECIES_F_I2D_ECIESPARAMETERS, ERR_R_X509_LIB);
		goto err;
		}
	
	if ((ret = i2d_ECIES_PARAMETERS(tmp, out)) <= 0)
		{
		ECIESerr(ECIES_F_I2D_ECIESPARAMETERS, ERR_R_ASN1_LIB);
		goto err;
		}
err:
	if (tmp)
		ECIES_PARAMETERS_free(tmp);
	return ret;
	}

ECIES_PARAMS *d2i_ECIESParameters(ECIES_PARAMS **param, const unsigned char **in, long len)
	{
	int e = 1;
	ECIES_PARAMS     *ret = NULL;
	ECIES_PARAMETERS *tmp = NULL;
	
	if (!(ret = OPENSSL_malloc(sizeof(ECIES_PARAMS))))
		{
		ECIESerr(ECIES_F_D2I_ECIESPARAMETERS, ERR_R_ASN1_LIB);
		goto err;
		}

	if (!(tmp = d2i_ECIES_PARAMETERS(NULL, in, len)))
		{
		ECIESerr(ECIES_F_D2I_ECIESPARAMETERS, ERR_R_ASN1_LIB);
		goto err;
		}

	/* get kdf, parameter is hash oid */
	if (OBJ_obj2nid(tmp->kdf->algorithm) != NID_x9_63_kdf) 
		{
		ECIESerr(ECIES_F_D2I_ECIESPARAMETERS, ERR_R_ECIES_LIB);
		goto err;
		}
	if (tmp->kdf->parameter->type != V_ASN1_OBJECT)
		{
		ECIESerr(ECIES_F_D2I_ECIESPARAMETERS, ERR_R_ECIES_LIB);
		goto err;
		}

	OpenSSL_add_all_digests();
	if (!(ret->kdf_md = EVP_get_digestbynid(OBJ_obj2nid(tmp->kdf->parameter->value.object))))
		{
		ECIESerr(ECIES_F_D2I_ECIESPARAMETERS, ERR_R_ECIES_LIB);
		goto err;
		}

	/* get sym, no parameter for iv is zero */
	switch (OBJ_obj2nid(tmp->sym->algorithm)) {
	case NID_xor_in_ecies:
		ret->sym_cipher = NULL;
		break;
	case NID_aes128_cbc_in_ecies:
		ret->sym_cipher = EVP_aes_128_cbc();
		break;
	case NID_aes192_cbc_in_ecies:
		ret->sym_cipher = EVP_aes_192_cbc();
		break;
	case NID_aes256_cbc_in_ecies:
		ret->sym_cipher = EVP_aes_256_cbc();
		break;
	case NID_aes128_ctr_in_ecies:
		ret->sym_cipher = EVP_aes_128_ctr();
		break;
	case NID_aes192_ctr_in_ecies:
		ret->sym_cipher = EVP_aes_192_ctr();
		break;
	case NID_aes256_ctr_in_ecies:
		ret->sym_cipher = EVP_aes_256_ctr();
		break;
	default:
		goto err;
	}
	
	/* get mac, parameter is hash oid */
	switch (OBJ_obj2nid(tmp->mac->algorithm)) {
	case NID_hmac_full_ecies:
		break;
	case NID_hmac_half_ecies:
	case NID_cmac_aes128_ecies:
	case NID_cmac_aes192_ecies:
		goto err;
		break;
	default:
		goto err;
		break;
	}
	if (tmp->mac->parameter->type != V_ASN1_OBJECT)
		{
		ECIESerr(ECIES_F_D2I_ECIESPARAMETERS, ERR_R_ECIES_LIB);
		goto err;
		}
	if (!(ret->mac_md = EVP_get_digestbynid(OBJ_obj2nid(
		tmp->mac->parameter->value.object)))) 
		{
		ECIESerr(ECIES_F_D2I_ECIESPARAMETERS, ERR_R_ECIES_LIB);
		goto err;
		}

	if (param && *param)
		OPENSSL_free(*param);
	if (param)
		*param = ret;

	e = 0;
err:
	if (e && ret)
		{
		OPENSSL_free(ret);
		ret = NULL;
		}
	if (tmp) ECIES_PARAMETERS_free(tmp);
	return ret;
	}


