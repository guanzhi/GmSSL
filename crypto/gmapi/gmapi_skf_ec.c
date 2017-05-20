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

#include <stdio.h>
#include <openssl/sm2.h>
#include <openssl/ec.h>
#include <openssl/gmapi.h>
#include <openssl/skf.h>
#include "../ec/ec_lcl.h"
#include "../sm2/sm2_lcl.h"

EC_KEY *EC_KEY_new_from_ECCPUBLICKEYBLOB(const ECCPUBLICKEYBLOB *blob)
{
	EC_KEY *ret;

	if (!(ret = EC_KEY_new_by_curve_name(NID_sm2p256v1))) {
		GMAPIerr(GMAPI_F_EC_KEY_NEW_FROM_ECCPUBLICKEYBLOB, ERR_R_EC_LIB);
		return NULL;
	}

	if (!EC_KEY_set_ECCPUBLICKEYBLOB(ret, blob)) {
		GMAPIerr(GMAPI_F_EC_KEY_NEW_FROM_ECCPUBLICKEYBLOB,
			GMAPI_R_DECODE_EC_PUBLIC_KEY_FAILED);
		EC_KEY_free(ret);
		return NULL;
	}

	return ret;
}

int EC_KEY_set_ECCPUBLICKEYBLOB(EC_KEY *ec_key, const ECCPUBLICKEYBLOB *blob)
{
	int ret = 0;
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;

	if (blob->BitLen != EC_GROUP_get_degree(EC_KEY_get0_group(ec_key))) {
		GMAPIerr(GMAPI_F_EC_KEY_SET_ECCPUBLICKEYBLOB, GMAPI_R_INVALID_KEY_LENGTH);
		return 0;
	}

	if (!(x = BN_bin2bn(blob->XCoordinate, ECC_MAX_XCOORDINATE_BITS_LEN/8, NULL))) {
		GMAPIerr(GMAPI_F_EC_KEY_SET_ECCPUBLICKEYBLOB, ERR_R_BN_LIB);
		goto end;
	}
	if (!(y = BN_bin2bn(blob->YCoordinate, ECC_MAX_YCOORDINATE_BITS_LEN/8, NULL))) {
		GMAPIerr(GMAPI_F_EC_KEY_SET_ECCPUBLICKEYBLOB, ERR_R_BN_LIB);
		goto end;
	}
	if (!EC_KEY_set_public_key_affine_coordinates(ec_key, x, y)) {
		GMAPIerr(GMAPI_F_EC_KEY_SET_ECCPUBLICKEYBLOB, GMAPI_R_INVALID_PUBLIC_KEY);
		goto end;
	}

	ret = 1;
end:
	BN_free(x);
	BN_free(y);
	return ret;
}

int EC_KEY_get_ECCPUBLICKEYBLOB(EC_KEY *ec_key, ECCPUBLICKEYBLOB *blob)
{
	int ret = 0;
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;
	BN_CTX *bn_ctx = NULL;
	const EC_GROUP *group = EC_KEY_get0_group(ec_key);
	const EC_POINT *point = EC_KEY_get0_public_key(ec_key);

	if (EC_GROUP_get_degree(group) > ECC_MAX_MODULUS_BITS_LEN) {
		GMAPIerr(GMAPI_F_EC_KEY_GET_ECCPUBLICKEYBLOB, GMAPI_R_INVALID_KEY_LENGTH);
		goto end;
	}

	x = BN_new();
	y = BN_new();
	bn_ctx = BN_CTX_new();
	if (!x || !y || !bn_ctx) {
		GMAPIerr(GMAPI_F_EC_KEY_GET_ECCPUBLICKEYBLOB, ERR_R_BN_LIB);
		goto end;
	}

	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field) {
		if (!EC_POINT_get_affine_coordinates_GFp(group, point, x, y, bn_ctx)) {
			GMAPIerr(GMAPI_F_EC_KEY_GET_ECCPUBLICKEYBLOB, ERR_R_EC_LIB);
			goto end;
		}
	} else  {
		if (!EC_POINT_get_affine_coordinates_GF2m(group, point, x, y, bn_ctx)) {
			GMAPIerr(GMAPI_F_EC_KEY_GET_ECCPUBLICKEYBLOB, ERR_R_EC_LIB);
			goto end;
		}
	}

	memset(blob, 0, sizeof(*blob));
	blob->BitLen = EC_GROUP_get_degree(group);
	if (!BN_bn2bin(x, blob->XCoordinate + (ECC_MAX_XCOORDINATE_BITS_LEN+7)/8 - BN_num_bytes(x))) {
		GMAPIerr(GMAPI_F_EC_KEY_GET_ECCPUBLICKEYBLOB, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_bn2bin(y, blob->YCoordinate + (ECC_MAX_YCOORDINATE_BITS_LEN+7)/8 - BN_num_bytes(y))) {
		GMAPIerr(GMAPI_F_EC_KEY_GET_ECCPUBLICKEYBLOB, ERR_R_BN_LIB);
		goto end;
	}

	ret = 1;
end:
	BN_free(x);
	BN_free(y);
	BN_CTX_free(bn_ctx);
	return ret;
}

EC_KEY *EC_KEY_new_from_ECCPRIVATEKEYBLOB(const ECCPRIVATEKEYBLOB *blob)
{
	EC_KEY *ret;

	if (!(ret = EC_KEY_new_by_curve_name(NID_sm2p256v1))) {
		GMAPIerr(GMAPI_F_EC_KEY_NEW_FROM_ECCPRIVATEKEYBLOB, ERR_R_EC_LIB);
		return NULL;
	}

	if (!EC_KEY_set_ECCPRIVATEKEYBLOB(ret, blob)) {
		GMAPIerr(GMAPI_F_EC_KEY_NEW_FROM_ECCPRIVATEKEYBLOB,
			GMAPI_R_DECODE_EC_PRIVATE_KEY_FAILED);
		EC_KEY_free(ret);
		return NULL;
	}

	return ret;
}

int EC_KEY_set_ECCPRIVATEKEYBLOB(EC_KEY *ec_key, const ECCPRIVATEKEYBLOB *blob)
{
	int ret = 0;
	BIGNUM *d = NULL;

	if (blob->BitLen != EC_GROUP_get_degree(EC_KEY_get0_group(ec_key))) {
		GMAPIerr(GMAPI_F_EC_KEY_SET_ECCPRIVATEKEYBLOB, GMAPI_R_INVALID_KEY_LENGTH);
		goto end;
	}

	if (!(d = BN_bin2bn(blob->PrivateKey, (ECC_MAX_MODULUS_BITS_LEN+7)/8, NULL))) {
		GMAPIerr(GMAPI_F_EC_KEY_SET_ECCPRIVATEKEYBLOB, ERR_R_BN_LIB);
		goto end;
	}

	if (!EC_KEY_set_private_key(ec_key, d)) {
		GMAPIerr(GMAPI_F_EC_KEY_SET_ECCPRIVATEKEYBLOB, GMAPI_R_INVALID_PRIVATE_KEY);
		goto end;
	}

	ret = 1;
end:
	BN_clear_free(d);
	return ret;
}

int EC_KEY_get_ECCPRIVATEKEYBLOB(EC_KEY *ec_key, ECCPRIVATEKEYBLOB *blob)
{
	const BIGNUM *d;

	if (EC_GROUP_get_degree(EC_KEY_get0_group(ec_key)) > ECC_MAX_MODULUS_BITS_LEN) {
		GMAPIerr(GMAPI_F_EC_KEY_GET_ECCPRIVATEKEYBLOB, GMAPI_R_INVALID_KEY_LENGTH);
		return 0;
	}

	if (!(d = EC_KEY_get0_private_key(ec_key))) {
		GMAPIerr(GMAPI_F_EC_KEY_GET_ECCPRIVATEKEYBLOB, GMAPI_R_INVALID_EC_KEY);
		return 0;
	}

	memset(blob, 0, sizeof(*blob));

	blob->BitLen = EC_GROUP_get_degree(EC_KEY_get0_group(ec_key));

	if (!BN_bn2bin(d, blob->PrivateKey + (ECC_MAX_MODULUS_BITS_LEN+7)/8 - BN_num_bytes(d))) {
		GMAPIerr(GMAPI_F_EC_KEY_GET_ECCPRIVATEKEYBLOB, ERR_R_BN_LIB);
		return 0;
	}

	return 1;
}

SM2CiphertextValue *SM2CiphertextValue_new_from_ECCCIPHERBLOB(
	const ECCCIPHERBLOB *blob)
{
	SM2CiphertextValue *ret = NULL;

	if (!(ret = SM2CiphertextValue_new())) {
		GMAPIerr(GMAPI_F_SM2CIPHERTEXTVALUE_NEW_FROM_ECCCIPHERBLOB,
			GMAPI_R_MALLOC_FAILED);
		return NULL;
	}

	if (!SM2CiphertextValue_set_ECCCIPHERBLOB(ret, blob)) {
		GMAPIerr(GMAPI_F_SM2CIPHERTEXTVALUE_NEW_FROM_ECCCIPHERBLOB,
			GMAPI_R_INVALID_EC_PUBLIC_KEY);
		SM2CiphertextValue_free(ret);
		return NULL;
	}

	return ret;
}

int SM2CiphertextValue_set_ECCCIPHERBLOB(SM2CiphertextValue *cv,
	const ECCCIPHERBLOB *blob)
{
	int ret = 0;

	if (!cv || !blob) {
		return 0;
	}

	if (!BN_bin2bn(blob->XCoordinate, ECC_MAX_XCOORDINATE_BITS_LEN/8,
		cv->xCoordinate)) {
		GMAPIerr(GMAPI_F_SM2CIPHERTEXTVALUE_SET_ECCCIPHERBLOB, ERR_R_BN_LIB);
		goto end;
	}

	if (!BN_bin2bn(blob->YCoordinate, ECC_MAX_YCOORDINATE_BITS_LEN/8,
		cv->yCoordinate)) {
		GMAPIerr(GMAPI_F_SM2CIPHERTEXTVALUE_SET_ECCCIPHERBLOB, ERR_R_BN_LIB);
		goto end;
	}

	if (!ASN1_OCTET_STRING_set(cv->hash, blob->HASH, 32)) {
		GMAPIerr(GMAPI_F_SM2CIPHERTEXTVALUE_SET_ECCCIPHERBLOB, ERR_R_ASN1_LIB);
		goto end;
	}

	if (!ASN1_OCTET_STRING_set(cv->ciphertext, blob->Cipher,
		blob->CipherLen)) {
		GMAPIerr(GMAPI_F_SM2CIPHERTEXTVALUE_SET_ECCCIPHERBLOB,
			GMAPI_R_INVALID_CIPHERTEXT_LENGTH);
		goto end;
	}

	ret = 0;
end:
	return ret;
}

int SM2CiphertextValue_get_ECCCIPHERBLOB(const SM2CiphertextValue *cv,
	ECCCIPHERBLOB *blob)
{
	int ret = 0;

	if (BN_num_bits(cv->xCoordinate) > ECC_MAX_XCOORDINATE_BITS_LEN ||
		BN_num_bits(cv->yCoordinate) > ECC_MAX_YCOORDINATE_BITS_LEN) {
		GMAPIerr(GMAPI_F_SM2CIPHERTEXTVALUE_GET_ECCCIPHERBLOB,
			GMAPI_R_INVALID_CIPHERTEXT_POINT);
		return 0;
	}

	if (ASN1_STRING_length(cv->hash) != 32) {
		GMAPIerr(GMAPI_F_SM2CIPHERTEXTVALUE_GET_ECCCIPHERBLOB,
			GMAPI_R_INVALID_CIPHERTEXT_LENGTH);
		return 0;
	}

	if (blob->CipherLen < ASN1_STRING_length(cv->ciphertext)) {
		GMAPIerr(GMAPI_F_SM2CIPHERTEXTVALUE_GET_ECCCIPHERBLOB,
			GMAPI_R_BUFFER_TOO_SMALL);
		return 0;
		return 0;
	}

	if (!BN_bn2bin(cv->xCoordinate, blob->XCoordinate +
		ECC_MAX_XCOORDINATE_BITS_LEN/8 - BN_num_bytes(cv->xCoordinate))) {
		GMAPIerr(GMAPI_F_SM2CIPHERTEXTVALUE_GET_ECCCIPHERBLOB, ERR_R_BN_LIB);
		return 0;
	}
	if (!BN_bn2bin(cv->yCoordinate, blob->YCoordinate +
		ECC_MAX_YCOORDINATE_BITS_LEN/8 - BN_num_bytes(cv->yCoordinate))) {
		GMAPIerr(GMAPI_F_SM2CIPHERTEXTVALUE_GET_ECCCIPHERBLOB, ERR_R_BN_LIB);
		return 0;
	}

	memcpy(blob->HASH, ASN1_STRING_get0_data(cv->hash),
		ASN1_STRING_length(cv->hash));

	blob->CipherLen = ASN1_STRING_length(cv->ciphertext);
	memcpy(blob->Cipher, ASN1_STRING_get0_data(cv->ciphertext),
		ASN1_STRING_length(cv->ciphertext));

	return 1;
}

ECDSA_SIG *ECDSA_SIG_new_from_ECCSIGNATUREBLOB(const ECCSIGNATUREBLOB *blob)
{
	ECDSA_SIG *ret = NULL;

	if (!(ret = ECDSA_SIG_new())) {
		GMAPIerr(GMAPI_F_ECDSA_SIG_NEW_FROM_ECCSIGNATUREBLOB,
			GMAPI_R_MALLOC_FAILED);
		return NULL;
	}

	if (!ECDSA_SIG_set_ECCSIGNATUREBLOB(ret, blob)) {
		GMAPIerr(GMAPI_F_ECDSA_SIG_NEW_FROM_ECCSIGNATUREBLOB,
			GMAPI_R_INVALID_SIGNATURE);
		ECDSA_SIG_free(ret);
		return NULL;
	}

	return ret;
}

int ECDSA_SIG_set_ECCSIGNATUREBLOB(ECDSA_SIG *sig, const ECCSIGNATUREBLOB *blob)
{
	if (!(sig->r = BN_bin2bn(blob->r, 64, sig->r))) {
		GMAPIerr(GMAPI_F_ECDSA_SIG_SET_ECCSIGNATUREBLOB, ERR_R_BN_LIB);
		return 0;
	}

	if (!(sig->s = BN_bin2bn(blob->s, 64, sig->s))) {
		GMAPIerr(GMAPI_F_ECDSA_SIG_SET_ECCSIGNATUREBLOB, ERR_R_BN_LIB);
		return 0;
	}

	return 1;
}

int ECDSA_SIG_get_ECCSIGNATUREBLOB(const ECDSA_SIG *sig, ECCSIGNATUREBLOB *blob)
{
	if ((BN_num_bytes(sig->r) > 256/8) || (BN_num_bytes(sig->s) > 256/8)) {
		GMAPIerr(GMAPI_F_ECDSA_SIG_GET_ECCSIGNATUREBLOB, GMAPI_R_INVALID_BIGNUM_LENGTH);
		return 0;
	}

	if (!BN_bn2bin(sig->r, blob->r + 256/8 - BN_num_bytes(sig->r))) {
		GMAPIerr(GMAPI_F_ECDSA_SIG_GET_ECCSIGNATUREBLOB, ERR_R_BN_LIB);
		return 0;
	}

	if (!BN_bn2bin(sig->s, blob->s + 256/8 - BN_num_bytes(sig->s))) {
		GMAPIerr(GMAPI_F_ECDSA_SIG_GET_ECCSIGNATUREBLOB, ERR_R_BN_LIB);
		return 0;
	}

	return 1;
}
