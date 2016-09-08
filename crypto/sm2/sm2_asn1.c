/* crypto/sm2/sm2_asn1.c */
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
 * 7. This file includes code written by <Jiayuan Chen> (mrpre@163.com) 
 *     for the GmSSL project.
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
#include <openssl/sm2.h>

/*
 * from GM/T 0009-2012
 * "SM2 Cryptography Algorithm Application Specification"
 *

SM2PrivateKey ::= INTEGER

SM2PublicKey ::= BIT STRING

SM2CiphertextValue ::= SEQUENCE {
	XCoordinate	INTEGER,
	YCoordinate	INTEGER,
	Hash		OCTET STRING SIZE(32),
	Ciphertext	OCTET STRING
}

SM2Signature ::= SEQUENCE {
	R		INTEGER,
	S		INTEGER,
}

SM2EnvelopedKey ::= SEQUENCE {
	symAlgID	AlgorithmIdentifier,
	symEncryptedKey	SM2CiphertextValue,
	sm2PublicKey	SM2PublicKey,
	sm2EncryptedPrivateKey	BIT STRING
}

ZID = SM3(nbits(ID)||ID||a||b||xG||yG||xA||yA)

Default ID = "1234567812345678"

*/

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
#if 0

typedef struct SM2EnvelopedKey_st {
	ASN1_ALGOR *symAlgID;
	SM2CiphertextValue *symEncryptedKey;
	ASN1_OCTET_STRING *sm2PublicKey;
	ASN1_BIT_STRING *sm2EncryptedPrivateKey;
} SM2EnvelopedKey;

/* GmSSL specific */
ASN1_SEQUENCE(SM2_CIPHERTEXT_VALUE_ASN1) = {
	ASN1_SIMPLE(SM2_CIPHERTEXT_VALUE_ASN1, ephem_point, ASN1_OCTET_STRING),
	ASN1_SIMPLE(SM2_CIPHERTEXT_VALUE_ASN1, ciphertext, ASN1_OCTET_STRING),
	ASN1_SIMPLE(SM2_CIPHERTEXT_VALUE_ASN1, mactag, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(SM2_CIPHERTEXT_VALUE)
IMPLEMENT_ASN1_FUNCTIONS(SM2_CIPHERTEXT_VALUE_ASN1)
IMPLEMENT_ASN1_DUP_FUNCTION(SM2_CIPHERTEXT_VALUE_ASN1)
#endif

/*On success it returns the length of 'out'*/
int i2d_SM2_CIPHERTEXT_VALUE(const SM2_CIPHERTEXT_VALUE *c, const EC_GROUP *group, unsigned char **out)
{
	int ret = 0;
	SM2CiphertextValue *asn1 = NULL;
	BIGNUM *x = NULL,*y = NULL;
    BN_CTX *ctx = NULL;

	if (!(asn1 = SM2CiphertextValue_new()))
		goto end;

    if (!(ctx = BN_CTX_new()))
		goto end;

    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);

    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) ==
        NID_X9_62_prime_field) {
        if(!EC_POINT_get_affine_coordinates_GFp(
            group, c->ephem_point, x, y, ctx))
            goto end;
    }
# ifndef OPENSSL_NO_EC2M
    else {
        if(!EC_POINT_get_affine_coordinates_GF2m(
            group, c->ephem_point, x, y, ctx))
            goto end;
    }
# endif
    
	if (!BN_to_ASN1_INTEGER(x, asn1->xCoordinate)) 
        goto end;

	if (!BN_to_ASN1_INTEGER(y, asn1->yCoordinate)) 
        goto end;
    
	if (!M_ASN1_OCTET_STRING_set(asn1->ciphertext, c->ciphertext, c->ciphertext_size)) 
        goto end;
    
	if (!M_ASN1_OCTET_STRING_set(asn1->hash, c->mactag, c->mactag_size)) 
        goto end;

    ret = i2d_SM2CiphertextValue(asn1, out);
    
end:
    if (asn1)
        SM2CiphertextValue_free(asn1);

    if (ctx)
        BN_CTX_free(ctx);
	return ret;
}

SM2_CIPHERTEXT_VALUE *d2i_SM2_CIPHERTEXT_VALUE(SM2_CIPHERTEXT_VALUE **c, const EC_GROUP * group,
	const unsigned char **in, long len)
{
    BIGNUM *x = NULL, *y = NULL;
    SM2CiphertextValue *asn1 = NULL;
    SM2_CIPHERTEXT_VALUE *ret = *c, *newcv = NULL;
    BN_CTX *ctx;
    
    if (!ret) 
        newcv = ret = SM2_CIPHERTEXT_VALUE_new(group);

    if (!ret) 
        return NULL;

    asn1 = d2i_SM2CiphertextValue(NULL, in, len);
    if (!asn1) 
        goto err;

    ret->ephem_point = EC_POINT_new(group);
    if (!ret->ephem_point)
        goto err;

    x = ASN1_INTEGER_to_BN(asn1->xCoordinate, NULL);
    y = ASN1_INTEGER_to_BN(asn1->yCoordinate, NULL);

    if(!x || !y) 
        goto err;

    ctx = BN_CTX_new();
    if (!ctx) 
        goto err;
    
    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) ==
            NID_X9_62_prime_field) {
        if (!EC_POINT_set_affine_coordinates_GFp(group, ret->ephem_point , x, y, ctx))
            goto err;
    }
# ifndef OPENSSL_NO_EC2M
    else {
        if (!EC_POINT_set_affine_coordinates_GF2m(group, ret->ephem_point , x, y, ctx))
            goto err;
    }
# endif
    x = y = NULL;
    
    ret->ciphertext_size = asn1->ciphertext->length;
    if(ret->ciphertext_size) {
        ret->ciphertext = OPENSSL_malloc(asn1->ciphertext->length);
        if(!ret->ciphertext) 
            goto err;
        
        memcpy(ret->ciphertext, asn1->ciphertext->data, ret->ciphertext_size);
    }
    
    ret->mactag_size = asn1->hash->length;
    memcpy(ret->mactag, asn1->hash->data, ret->mactag_size);

    SM2CiphertextValue_free(asn1);

	return (*c = ret);

err:
    if (newcv)
        SM2_CIPHERTEXT_VALUE_free(newcv);  /*Free it if we malloc in this function*/

    if (asn1)
        SM2CiphertextValue_free(asn1);

    if (x)
        BN_free(x);
    
    if (y)
        BN_free(y);
    
    return NULL;
}
