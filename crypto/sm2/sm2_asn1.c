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
#include <openssl/sm2.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/objects.h>
#include <openssl/obj_mac.h>


typedef struct SM2CiphertextValue_st {
	ASN1_INTEGER *xCoordinate;
	ASN1_INTEGER *yCoordinate;
	ASN1_OCTET_STRING *hash;
	ASN1_OCTET_STRING *ciphertext;
} SM2CiphertextValue;

ASN1_SEQUENCE(SM2CiphertextValue) = {
	ASN1_SIMPLE(SM2CiphertextValue, xCoordinate, ASN1_INTEGER),
	ASN1_SIMPLE(SM2CiphertextValue, yCoordinate, ASN1_INTEGER),
	ASN1_SIMPLE(SM2CiphertextValue, hash, ASN1_OCTET_STRING),
	ASN1_SIMPLE(SM2CiphertextValue, ciphertext, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(SM2CiphertextValue)
IMPLEMENT_ASN1_FUNCTIONS(SM2CiphertextValue)
IMPLEMENT_ASN1_DUP_FUNCTION(SM2CiphertextValue)


int i2d_SM2_CIPHERTEXT_VALUE(const EC_GROUP *group, const SM2_CIPHERTEXT_VALUE *c,
	unsigned char **out)
{
	int ret = 0;
	SM2CiphertextValue *asn1 = NULL;
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;
	BN_CTX *bn_ctx = NULL;

	asn1 = SM2CiphertextValue_new();
	x = BN_new();
	y = BN_new();
	bn_ctx = BN_CTX_new();
	if (!asn1 || !x || !y || !bn_ctx) {
		ECerr(EC_F_I2D_SM2_CIPHERTEXT_VALUE, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field) {
		if (!EC_POINT_get_affine_coordinates_GFp(group, c->ephem_point, x, y, bn_ctx)) {
			ECerr(EC_F_I2D_SM2_CIPHERTEXT_VALUE, ERR_R_EC_LIB);
			goto end;
		}
	} else {
		if (!EC_POINT_get_affine_coordinates_GF2m(group, c->ephem_point, x, y, bn_ctx)) {
			ECerr(EC_F_I2D_SM2_CIPHERTEXT_VALUE, ERR_R_EC_LIB);
			goto end;
		}
	}

	if (!BN_to_ASN1_INTEGER(x, asn1->xCoordinate)) {
		ECerr(EC_F_I2D_SM2_CIPHERTEXT_VALUE, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_to_ASN1_INTEGER(y, asn1->yCoordinate)) {
		ECerr(EC_F_I2D_SM2_CIPHERTEXT_VALUE, ERR_R_BN_LIB);
		goto end;
	}
	if (!ASN1_OCTET_STRING_set(asn1->hash, c->mactag, c->mactag_size)) {
		ECerr(EC_F_I2D_SM2_CIPHERTEXT_VALUE, ERR_R_ASN1_LIB);
		goto end;
	}
	if (!ASN1_OCTET_STRING_set(asn1->ciphertext, c->ciphertext, c->ciphertext_size)) {
		ECerr(EC_F_I2D_SM2_CIPHERTEXT_VALUE, ERR_R_ASN1_LIB);
		goto end;
	}

	ret = 1;
end:
	SM2CiphertextValue_free(asn1);
	BN_free(x);
	BN_free(y);
	BN_CTX_free(bn_ctx);
	return ret;
}

SM2_CIPHERTEXT_VALUE *d2i_SM2_CIPHERTEXT_VALUE(const EC_GROUP *group,
	SM2_CIPHERTEXT_VALUE **c, const unsigned char **in, long len)
{
	int e = 1;
	SM2_CIPHERTEXT_VALUE *ret = NULL;
	SM2CiphertextValue *asn1 = NULL;
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;
	BN_CTX *bn_ctx = NULL;

	if (!(asn1 = d2i_SM2CiphertextValue(NULL, in, len))) {
		ECerr(EC_F_D2I_SM2_CIPHERTEXT_VALUE, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!(x = ASN1_INTEGER_to_BN(asn1->xCoordinate, NULL))) {
		ECerr(EC_F_D2I_SM2_CIPHERTEXT_VALUE, ERR_R_BN_LIB);
		goto end;
	}
	if (!(y = ASN1_INTEGER_to_BN(asn1->yCoordinate, NULL))) {
		ECerr(EC_F_D2I_SM2_CIPHERTEXT_VALUE, ERR_R_BN_LIB);
		goto end;
	}

	ret = SM2_CIPHERTEXT_VALUE_new(group);
	bn_ctx = BN_CTX_new();
	if (!ret || !bn_ctx) {
		ECerr(EC_F_D2I_SM2_CIPHERTEXT_VALUE, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* (x, y) */
	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field) {
		if (!EC_POINT_set_affine_coordinates_GFp(group, ret->ephem_point, x, y, bn_ctx)) {
			ECerr(EC_F_D2I_SM2_CIPHERTEXT_VALUE, ERR_R_EC_LIB);
			goto end;
		}
	} else {
		if (!EC_POINT_set_affine_coordinates_GF2m(group, ret->ephem_point, x, y, bn_ctx)) {
			ECerr(EC_F_D2I_SM2_CIPHERTEXT_VALUE, ERR_R_EC_LIB);
			goto end;
		}
	}

	/* hash */
	ret->mactag_size = asn1->hash->length;
	memcpy(ret->mactag, asn1->hash->data, asn1->hash->length);

	/* ciphertext */
	ret->ciphertext_size = asn1->ciphertext->length;
	if (!(ret->ciphertext = OPENSSL_malloc(ret->ciphertext_size))) {
		ECerr(EC_F_D2I_SM2_CIPHERTEXT_VALUE, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	memcpy(ret->ciphertext, asn1->ciphertext->data, asn1->ciphertext->length);

	e = 0;

end:
	SM2CiphertextValue_free(asn1);
	BN_free(x);
	BN_free(y);
	BN_CTX_free(bn_ctx);
	if (e && ret) {
		SM2_CIPHERTEXT_VALUE_free(ret);
		ret = NULL;
	}
	return ret;
}

