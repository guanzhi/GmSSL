/* ====================================================================
 * Copyright (c) 2007 - 2016 The GmSSL Project.  All rights reserved.
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

#include <string.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/objects.h>
#include <openssl/obj_mac.h>
#include <openssl/kdf2.h>
#include <openssl/ecies.h>
#include "ecies_lcl.h"

/*
 * From SEC 1, Version 1.9 Draft, 2008
 *
secg-scheme OBJECT IDENTIFIER ::= {
	iso(1) identified-organization(3) certicom(132) schemes(1) }

ECIESAlgorithmSet ALGORITHM ::= {
	{ OID ecies-recommendedParameters} |
	{ OID ecies-specifiedParameters PARMS ECIESParameters}
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
ECIESParameters ::= SEQUENCE {
	kdf [0] KeyDerivationFunction OPTIONAL,
	sym [1] SymmetricEncryption OPTIONAL,
	mac [2] MessageAuthenticationCode OPTIONAL
}
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
	ECIES_PARAMETERS *asn1 = NULL;

	if (!(asn1 = ECIES_PARAMETERS_new())) {
		ECerr(EC_F_I2D_ECIESPARAMETERS, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	OPENSSL_assert(asn1->kdf && asn1->sym && asn1->mac);

	if (!X509_ALGOR_set0(asn1->kdf, OBJ_nid2obj(param->kdf_nid),
		V_ASN1_OBJECT, OBJ_nid2obj(EVP_MD_nid(param->kdf_md)))) {
		ECerr(EC_F_I2D_ECIESPARAMETERS, ERR_R_X509_LIB);
		goto end;
	}
	if (!X509_ALGOR_set0(asn1->sym, OBJ_nid2obj(param->enc_nid),
		V_ASN1_UNDEF, NULL)) {
		ECerr(EC_F_I2D_ECIESPARAMETERS, ERR_R_X509_LIB);
		goto end;
	}
	if (param->mac_nid == NID_hmac_full_ecies ||
		param->mac_nid == NID_hmac_half_ecies) {
		if (!X509_ALGOR_set0(asn1->mac, OBJ_nid2obj(param->mac_nid),
			V_ASN1_OBJECT, OBJ_nid2obj(EVP_MD_nid(param->hmac_md)))) {
			ECerr(EC_F_I2D_ECIESPARAMETERS, ERR_R_MALLOC_FAILURE);
			goto end;
		}
	} else {
		if (!X509_ALGOR_set0(asn1->mac, OBJ_nid2obj(param->mac_nid),
			V_ASN1_UNDEF, NULL)) {
			ECerr(EC_F_I2D_ECIESPARAMETERS, ERR_R_MALLOC_FAILURE);
			goto end;
		}
	}

	if ((ret = i2d_ECIES_PARAMETERS(asn1, out)) <= 0) {
		ECerr(EC_F_I2D_ECIESPARAMETERS, ERR_R_ASN1_LIB);
		goto end;
	}

end:
	ECIES_PARAMETERS_free(asn1);
	return ret;
}

ECIES_PARAMS *d2i_ECIESParameters(ECIES_PARAMS **param,
	const unsigned char **in, long len)
{
	int e = 1;
	ECIES_PARAMS *ret = NULL;
	ECIES_PARAMETERS *asn1 = NULL;

	if (!(ret = OPENSSL_zalloc(sizeof(ECIES_PARAMS)))) {
		ECerr(EC_F_D2I_ECIESPARAMETERS, ERR_R_ASN1_LIB);
		goto end;
	}
	if (!(asn1 = d2i_ECIES_PARAMETERS(NULL, in, len))) {
		ECerr(EC_F_D2I_ECIESPARAMETERS, ERR_R_ASN1_LIB);
		goto end;
	}

	/* kdf */
	ret->kdf_nid = OBJ_obj2nid(asn1->kdf->algorithm);
	if (ret->kdf_nid != NID_x9_63_kdf) {
		ECerr(EC_F_D2I_ECIESPARAMETERS, EC_R_INVALID_ECIES_PARAMETERS);
		goto end;
	}
	if (asn1->kdf->parameter->type != V_ASN1_OBJECT) {
		ECerr(EC_F_D2I_ECIESPARAMETERS, EC_R_INVALID_ECIES_PARAMETERS);
		goto end;
	}
	if (!(ret->kdf_md = EVP_get_digestbynid(
		OBJ_obj2nid(asn1->kdf->parameter->value.object)))) {
		ECerr(EC_F_D2I_ECIESPARAMETERS, EC_R_INVALID_ECIES_PARAMETERS);
		goto end;
	}

	/* sym */
	ret->enc_nid = OBJ_obj2nid(asn1->sym->algorithm);
	switch (ret->enc_nid) {
	case NID_xor_in_ecies:
	case NID_tdes_cbc_in_ecies:
	case NID_aes128_cbc_in_ecies:
	case NID_aes192_cbc_in_ecies:
	case NID_aes256_cbc_in_ecies:
	case NID_aes128_ctr_in_ecies:
	case NID_aes192_ctr_in_ecies:
	case NID_aes256_ctr_in_ecies:
		break;
	default:
		ECerr(EC_F_D2I_ECIESPARAMETERS, EC_R_INVALID_ECIES_PARAMETERS);
		goto end;
	}

	/* mac */
	ret->mac_nid = OBJ_obj2nid(asn1->mac->algorithm);
	switch (ret->enc_nid) {
	case NID_hmac_full_ecies:
	case NID_hmac_half_ecies:
		if (asn1->mac->parameter->type != V_ASN1_OBJECT) {
			ECerr(EC_F_D2I_ECIESPARAMETERS, EC_R_INVALID_ECIES_PARAMETERS);
			goto end;
		}
		if (!(ret->hmac_md = EVP_get_digestbynid(
			OBJ_obj2nid(asn1->mac->parameter->value.object)))) {
			ECerr(EC_F_D2I_ECIESPARAMETERS, EC_R_INVALID_ECIES_PARAMETERS);
			goto end;
		}
		break;
	case NID_cmac_aes128_ecies:
	case NID_cmac_aes192_ecies:
	case NID_cmac_aes256_ecies:
		break;
	default:
		ECerr(EC_F_D2I_ECIESPARAMETERS, EC_R_INVALID_ECIES_PARAMETERS);
		goto end;
	}

	if (param && *param)
		OPENSSL_free(*param);
	if (param)
		*param = ret;

	e = 0;
end:
	if (e && ret) {
		OPENSSL_free(ret);
		ret = NULL;
	}
	ECIES_PARAMETERS_free(asn1);
	return ret;
}

