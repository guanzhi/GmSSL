/* crypto/skf/skf_ec.c */
/* ====================================================================
 * Copyright (c) 2015-2016 The GmSSL Project.  All rights reserved.
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

#include <stdio.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/skf.h>
#include <openssl/skf_ex.h>
#include "skf_lcl.h"

ULONG DEVAPI SKF_GenExtECCKeyPair(DEVHANDLE hDev,
	ECCPRIVATEKEYBLOB *priKey,
	ECCPUBLICKEYBLOB *pubKey)
{
	ULONG ret = SAR_FAIL;
	EC_KEY *ec_key;

	if(!(ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1))) {
		SKFerr(SKF_F_SKF_GENEXTECCKEYPAIR, ERR_R_EC_LIB);
		return SAR_FAIL;
	}
	if (!EC_KEY_get_ECCPRIVATEKEYBLOB(ec_key, priKey)) {
		SKFerr(SKF_F_SKF_GENEXTECCKEYPAIR, SKF_R_GET_PRIVATE_KEY_FAILED);
		goto end;
	}
	if (!EC_KEY_get_ECCPUBLICKEYBLOB(ec_key, pubKey)) {
		SKFerr(SKF_F_SKF_GENEXTECCKEYPAIR, SKF_R_GET_PUBLIC_KEY_FAILED);
		goto end;
	}
	ret = SAR_OK;
end:
	EC_KEY_free(ec_key);
	return ret;
}

ULONG DEVAPI SKF_ExtECCSign(DEVHANDLE hDev,
	ECCPRIVATEKEYBLOB *pECCPriKeyBlob,
	BYTE *pbData,
	ULONG ulDataLen,
	ECCSIGNATUREBLOB *pSignature)
{
	ULONG ret = SAR_FAIL;
	EC_KEY *ec_key = NULL;
	ECDSA_SIG *sig = NULL;

	if (!pECCPriKeyBlob || !pbData || !pSignature) {
		SKFerr(SKF_F_SKF_EXTECCSIGN, SKF_R_NULL_ARGUMENT);
		return SAR_INVALIDPARAMERR;
	}

	if (ulDataLen != SM3_DIGEST_LENGTH) {
		SKFerr(SKF_F_SKF_EXTECCSIGN, SKF_R_INVALID_DIGEST_LENGTH);
		return SAR_INVALIDPARAMERR;
	}

	if (!(ec_key = EC_KEY_new_from_ECCPRIVATEKEYBLOB(pECCPriKeyBlob))) {
		SKFerr(SKF_F_SKF_EXTECCSIGN, SKF_R_INVALID_ECC_PRIVATE_KEY);
		goto end;
	}

	if (!(sig = SM2_do_sign(pbData, (int)ulDataLen, ec_key))) {
		SKFerr(SKF_F_SKF_EXTECCSIGN, SKF_R_SIGN_FAILED);
		goto end;
	}

	if (!ECDSA_SIG_get_ECCSIGNATUREBLOB(sig, pSignature)) {
		SKFerr(SKF_F_SKF_EXTECCSIGN, SKF_R_ENCODE_SIGNATURE_FAILED);
		goto end;
	}

	ret = SAR_OK;
end:
	EC_KEY_free(ec_key);
	ECDSA_SIG_free(sig);
	return ret;
}

ULONG DEVAPI SKF_ExtECCVerify(DEVHANDLE hDev,
	ECCPUBLICKEYBLOB *pECCPubKeyBlob,
	BYTE *pbData,
	ULONG ulDataLen,
	ECCSIGNATUREBLOB *pSignature)
{
	ULONG ret = SAR_FAIL;
	EC_KEY *ec_key = NULL;
	ECDSA_SIG *sig = NULL;

	if (!pECCPubKeyBlob || !pbData || pSignature) {
		SKFerr(SKF_F_SKF_EXTECCVERIFY, SKF_R_NULL_ARGUMENT);
		return SAR_INVALIDPARAMERR;
	}

	if (ulDataLen != SM3_DIGEST_LENGTH) {
		SKFerr(SKF_F_SKF_EXTECCVERIFY, SKF_R_INVALID_DIGEST_LENGTH);
		return SAR_INVALIDPARAMERR;
	}

	if (!(ec_key = EC_KEY_new_from_ECCPUBLICKEYBLOB(pECCPubKeyBlob))) {
		SKFerr(SKF_F_SKF_EXTECCVERIFY, SKF_R_INVALID_ECC_PUBLIC_KEY);
		goto end;
	}

	if (!(sig = ECDSA_SIG_new_from_ECCSIGNATUREBLOB(pSignature))) {
		SKFerr(SKF_F_SKF_EXTECCVERIFY, SKF_R_INVALID_SIGNATURE);
		goto end;
	}

	if (1 != SM2_do_verify(pbData, (int)ulDataLen, sig, ec_key)) {
		SKFerr(SKF_F_SKF_EXTECCVERIFY, SKF_R_VERIFY_NOT_PASS);
		goto end;
	}

	ret = SAR_OK;

end:
	EC_KEY_free(ec_key);
	ECDSA_SIG_free(sig);
	return ret;
}

ULONG DEVAPI SKF_ECCVerify(DEVHANDLE hDev,
	ECCPUBLICKEYBLOB *pECCPubKeyBlob,
	BYTE *pbData,
	ULONG ulDataLen,
	ECCSIGNATUREBLOB *pSignature)
{
	return SKF_ExtECCVerify(hDev, pECCPubKeyBlob, pbData, ulDataLen, pSignature);
}

ULONG DEVAPI SKF_ExtECCEncrypt(DEVHANDLE hDev,
	ECCPUBLICKEYBLOB *pECCPubKeyBlob,
	BYTE *pbPlainText,
	ULONG ulPlainTextLen,
	ECCCIPHERBLOB *pCipherText)
{
	ULONG ret = SAR_FAIL;
	EC_KEY *ec_key = NULL;
	SM2_CIPHERTEXT_VALUE *cv = NULL;
	SM2_ENC_PARAMS params;

	if (!pECCPubKeyBlob || !pbPlainText || !pCipherText) {
		SKFerr(SKF_F_SKF_EXTECCENCRYPT, SKF_R_NULL_ARGUMENT);
		return SAR_INVALIDPARAMERR;
	}

	if (ulPlainTextLen <= 0) {
		SKFerr(SKF_F_SKF_EXTECCENCRYPT, SKF_R_INVALID_PLAINTEXT_LENGTH);
		return SAR_INVALIDPARAMERR;
	}

	if (!(ec_key = EC_KEY_new_from_ECCPUBLICKEYBLOB(pECCPubKeyBlob))) {
		SKFerr(SKF_F_SKF_EXTECCENCRYPT, SKF_R_INVALID_EC_PUBLIC_KEY);
		goto end;
	}

	SM2_ENC_PARAMS_init_with_recommended(&params);
	if (!(cv = SM2_do_encrypt(&params, pbPlainText, ulPlainTextLen, ec_key))) {
		SKFerr(SKF_F_SKF_EXTECCENCRYPT, SKF_R_ENCRYPT_FAILED);
		goto end;
	}

	if (!SM2_CIPHERTEXT_VALUE_get_ECCCIPHERBLOB(cv, pCipherText)) {
		SKFerr(SKF_F_SKF_EXTECCENCRYPT, SKF_R_ENCODE_CIPHERTEXT_FAILED);
		goto end;
	}

	ret = SAR_OK;

end:
	EC_KEY_free(ec_key);
	SM2_CIPHERTEXT_VALUE_free(cv);
	return ret;
}

ULONG DEVAPI SKF_ExtECCDecrypt(DEVHANDLE hDev,
	ECCPRIVATEKEYBLOB *pECCPriKeyBlob,
	ECCCIPHERBLOB *pCipherText,
	BYTE *pbPlainText,
	ULONG *pulPlainTextLen)
{
	ULONG ret = SAR_FAIL;
	EC_KEY *ec_key = NULL;
	SM2_CIPHERTEXT_VALUE *cv = NULL;
	SM2_ENC_PARAMS params;
	size_t len;

	if (!pECCPriKeyBlob || !pCipherText || !pulPlainTextLen) {
		SKFerr(SKF_F_SKF_EXTECCDECRYPT, SKF_R_NULL_ARGUMENT);
		return SAR_INVALIDPARAMERR;
	}

	if (pCipherText->CipherLen <= 0) {
		SKFerr(SKF_F_SKF_EXTECCDECRYPT, SKF_R_INVALID_CIPHERTEXT_LENGTH);
		return SAR_INVALIDPARAMERR;
	}

	if (!pbPlainText) {
		*pulPlainTextLen = pCipherText->CipherLen;
		return SAR_OK;
	}

	if (!(ec_key = EC_KEY_new_from_ECCPRIVATEKEYBLOB(pECCPriKeyBlob))) {
		SKFerr(SKF_F_SKF_EXTECCDECRYPT, SKF_R_INVALID_EC_PRIVATE_KEY);
		goto end;
	}

	if (!(cv = SM2_CIPHERTEXT_VALUE_new_from_ECCCIPHERBLOB(pCipherText))) {
		SKFerr(SKF_F_SKF_EXTECCDECRYPT, SKF_R_INVALID_CIPHERTEXT);
		goto end;
	}

	SM2_ENC_PARAMS_init_with_recommended(&params);
	len = *pulPlainTextLen; //FIXME: check length?
	if (!SM2_do_decrypt(&params, cv, pbPlainText, &len, ec_key)) {
		SKFerr(SKF_F_SKF_EXTECCDECRYPT, SKF_R_DECRYPT_FAILED);
		goto end;
	}
	*pulPlainTextLen = (ULONG)len;

	ret = SAR_OK;

end:
	EC_KEY_free(ec_key);
	SM2_CIPHERTEXT_VALUE_free(cv);
	return ret;
}

/* Wrapper Functions */

EC_KEY *EC_KEY_new_from_ECCPUBLICKEYBLOB(const ECCPUBLICKEYBLOB *blob)
{
	EC_KEY *ret;

	if (!(ret = EC_KEY_new_by_curve_name(NID_sm2p256v1))) {
		SKFerr(SKF_F_EC_KEY_NEW_FROM_ECCPUBLICKEYBLOB, ERR_R_EC_LIB);
		return NULL;
	}

	if (!EC_KEY_set_ECCPUBLICKEYBLOB(ret, blob)) {
		SKFerr(SKF_F_EC_KEY_NEW_FROM_ECCPUBLICKEYBLOB,
			SKF_R_DECODE_EC_PUBLIC_KEY_FAILED);
		EC_KEY_free(ret);
		return NULL;
	}

	return ret;
}

EC_KEY *EC_KEY_new_from_ECCPRIVATEKEYBLOB(const ECCPRIVATEKEYBLOB *blob)
{
	EC_KEY *ret;

	if (!(ret = EC_KEY_new_by_curve_name(NID_sm2p256v1))) {
		SKFerr(SKF_F_EC_KEY_NEW_FROM_ECCPRIVATEKEYBLOB, ERR_R_EC_LIB);
		return NULL;
	}

	if (!EC_KEY_set_ECCPRIVATEKEYBLOB(ret, blob)) {
		SKFerr(SKF_F_EC_KEY_NEW_FROM_ECCPRIVATEKEYBLOB,
			SKF_R_DECODE_EC_PRIVATE_KEY_FAILED);
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
	int nbytes;

	if (blob->BitLen != EC_GROUP_get_degree(EC_KEY_get0_group(ec_key))) {
		SKFerr(SKF_F_EC_KEY_SET_ECCPUBLICKEYBLOB, SKF_R_INVALID_KEY_LENGTH);
		return 0;
	}

	nbytes = (blob->BitLen + 7)/8;

	if (!(x = BN_bin2bn(blob->XCoordinate, nbytes, NULL))) {
		SKFerr(SKF_F_EC_KEY_SET_ECCPUBLICKEYBLOB, ERR_R_BN_LIB);
		goto end;
	}
	if (!(y = BN_bin2bn(blob->YCoordinate, nbytes, NULL))) {
		SKFerr(SKF_F_EC_KEY_SET_ECCPUBLICKEYBLOB, ERR_R_BN_LIB);
		goto end;
	}
	if (!EC_KEY_set_public_key_affine_coordinates(ec_key, x, y)) {
		SKFerr(SKF_F_EC_KEY_SET_ECCPUBLICKEYBLOB, SKF_R_INVALID_PUBLIC_KEY);
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
	int nbytes;
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;
	BN_CTX *bn_ctx = NULL;
	const EC_GROUP *group = EC_KEY_get0_group(ec_key);
	const EC_POINT *point = EC_KEY_get0_public_key(ec_key);

	nbytes = (EC_GROUP_get_degree(group) + 7)/8;
	if (nbytes > ECC_MAX_MODULUS_BITS_LEN/8) {
		SKFerr(SKF_F_EC_KEY_GET_ECCPUBLICKEYBLOB, SKF_R_INVALID_KEY_LENGTH);
		goto end;
	}

	x = BN_new();
	y = BN_new();
	bn_ctx = BN_CTX_new();
	if (!x || !y || !bn_ctx) {
		SKFerr(SKF_F_EC_KEY_GET_ECCPUBLICKEYBLOB, ERR_R_BN_LIB);
		goto end;
	}

	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field) {
		if (!EC_POINT_get_affine_coordinates_GFp(group, point, x, y, bn_ctx)) {
			SKFerr(SKF_F_EC_KEY_GET_ECCPUBLICKEYBLOB, ERR_R_EC_LIB);
			goto end;
		}
	} else  {
		if (!EC_POINT_get_affine_coordinates_GF2m(group, point, x, y, bn_ctx)) {
			SKFerr(SKF_F_EC_KEY_GET_ECCPUBLICKEYBLOB, ERR_R_EC_LIB);
			goto end;
		}
	}

	memset(blob, 0, sizeof(*blob));
	blob->BitLen = EC_GROUP_get_degree(group);
	if (!BN_bn2bin(x, blob->XCoordinate + nbytes - BN_num_bytes(x))) {
		SKFerr(SKF_F_EC_KEY_GET_ECCPUBLICKEYBLOB, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_bn2bin(y, blob->YCoordinate + nbytes - BN_num_bytes(y))) {
		SKFerr(SKF_F_EC_KEY_GET_ECCPUBLICKEYBLOB, ERR_R_BN_LIB);
		goto end;
	}

	ret = 1;
end:
	BN_free(x);
	BN_free(y);
	BN_CTX_free(bn_ctx);
	return ret;
}

int EC_KEY_set_ECCPRIVATEKEYBLOB(EC_KEY *ec_key, const ECCPRIVATEKEYBLOB *blob)
{
	int ret = 0;
	BIGNUM *d = NULL;
	int nbytes;

	//FIXME: is this right?
	if (blob->BitLen != EC_GROUP_get_degree(EC_KEY_get0_group(ec_key))) {
		SKFerr(SKF_F_EC_KEY_SET_ECCPRIVATEKEYBLOB, SKF_R_INVALID_KEY_LENGTH);
		goto end;
	}

	nbytes = (blob->BitLen + 7)/8;

	if (!(d = BN_bin2bn(blob->PrivateKey, nbytes, NULL))) {
		SKFerr(SKF_F_EC_KEY_SET_ECCPRIVATEKEYBLOB, ERR_R_BN_LIB);
		goto end;
	}
	if (!EC_KEY_set_private_key(ec_key, d)) {
		SKFerr(SKF_F_EC_KEY_SET_ECCPRIVATEKEYBLOB, SKF_R_INVALID_PRIVATE_KEY);
		goto end;
	}

	ret = 1;
end:
	BN_clear_free(d);
	return ret;
}

int EC_KEY_get_ECCPRIVATEKEYBLOB(EC_KEY *ec_key, ECCPRIVATEKEYBLOB *blob)
{
	int ret = 0;
	BIGNUM *order = NULL;
	const BIGNUM *d;
	int nbytes;

	if (!(order = BN_new())) {
		SKFerr(SKF_F_EC_KEY_GET_ECCPRIVATEKEYBLOB, SKF_R_MALLOC_FAILED);
		goto end;
	}

	if (!EC_GROUP_get_order(EC_KEY_get0_group(ec_key), order, NULL)) {
		SKFerr(SKF_F_EC_KEY_GET_ECCPRIVATEKEYBLOB, ERR_R_EC_LIB);
		goto end;
	}

	nbytes = BN_num_bytes(order);
	if (nbytes > ECC_MAX_MODULUS_BITS_LEN/8) {
		SKFerr(SKF_F_EC_KEY_GET_ECCPRIVATEKEYBLOB, SKF_R_INVALID_KEY_LENGTH);
		goto end;
	}

	if (!(d = EC_KEY_get0_private_key(ec_key))) {
		SKFerr(SKF_F_EC_KEY_GET_ECCPRIVATEKEYBLOB, SKF_R_INVALID_EC_KEY);
		goto end;
	}

	if (!BN_bn2bin(d, blob->PrivateKey + nbytes - BN_num_bytes(d))) {
		SKFerr(SKF_F_EC_KEY_GET_ECCPRIVATEKEYBLOB, ERR_R_BN_LIB);
		goto end;
	}

	ret = 1;

end:
	BN_free(order);
	return ret;
}

SM2_CIPHERTEXT_VALUE *SM2_CIPHERTEXT_VALUE_new_from_ECCCIPHERBLOB(
	const ECCCIPHERBLOB *blob)
{
	int ok = 0;
	SM2_CIPHERTEXT_VALUE *ret = NULL;
	EC_GROUP *group = NULL;

	if (!(group = EC_GROUP_new_by_curve_name(NID_sm2p256v1))) {
		SKFerr(SKF_F_SM2_CIPHERTEXT_VALUE_NEW_FROM_ECCCIPHERBLOB,
			ERR_R_EC_LIB);
		goto end;
	}

	if (!(ret = SM2_CIPHERTEXT_VALUE_new(group))) {
		SKFerr(SKF_F_SM2_CIPHERTEXT_VALUE_NEW_FROM_ECCCIPHERBLOB,
			SKF_R_MALLOC_FAILED);
		goto end;
	}

	if (!SM2_CIPHERTEXT_VALUE_set_ECCCIPHERBLOB(ret, blob)) {
		SKFerr(SKF_F_SM2_CIPHERTEXT_VALUE_NEW_FROM_ECCCIPHERBLOB,
			SKF_R_INVALID_EC_PUBLIC_KEY);
		goto end;
	}

	ok = 1;

end:
	if (!ok) {
		SM2_CIPHERTEXT_VALUE_free(ret);
		ret = NULL;
	}
	EC_GROUP_free(group);
	return ret;
}

int SM2_CIPHERTEXT_VALUE_set_ECCCIPHERBLOB(SM2_CIPHERTEXT_VALUE *cv,
	const ECCCIPHERBLOB *blob)
{
	int ret = 0;
	EC_GROUP *group = NULL;
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;
	BN_CTX *bn_ctx = NULL;
	int nbytes;

	if (!(group = EC_GROUP_new_by_curve_name(NID_sm2p256v1))) {
		SKFerr(SKF_F_SM2_CIPHERTEXT_VALUE_SET_ECCCIPHERBLOB,
			ERR_R_EC_LIB);
		return 0;
	}

	nbytes = (EC_GROUP_get_degree(group) + 7)/8;
	if (nbytes > ECC_MAX_XCOORDINATE_BITS_LEN/8) {
		SKFerr(SKF_F_SM2_CIPHERTEXT_VALUE_SET_ECCCIPHERBLOB,
			SKF_R_INVALID_KEY_LENGTH);
		goto end;
	}

	if (!(x = BN_bin2bn(blob->XCoordinate, nbytes, NULL))) {
		SKFerr(SKF_F_SM2_CIPHERTEXT_VALUE_SET_ECCCIPHERBLOB, ERR_R_BN_LIB);
		goto end;
	}
	if (!(y = BN_bin2bn(blob->YCoordinate, nbytes, NULL))) {
		SKFerr(SKF_F_SM2_CIPHERTEXT_VALUE_SET_ECCCIPHERBLOB, ERR_R_BN_LIB);
		goto end;
	}
	if (!(bn_ctx = BN_CTX_new())) {
		SKFerr(SKF_F_SM2_CIPHERTEXT_VALUE_SET_ECCCIPHERBLOB, ERR_R_BN_LIB);
		goto end;
	}

	if (!cv->ephem_point) {
		if (!(cv->ephem_point = EC_POINT_new(group))) {
			SKFerr(SKF_F_SM2_CIPHERTEXT_VALUE_SET_ECCCIPHERBLOB, ERR_R_EC_LIB);
			goto end;
		}
	}
	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field) {
		if (!EC_POINT_set_affine_coordinates_GFp(group, cv->ephem_point, x, y, bn_ctx)) {
			SKFerr(SKF_F_SM2_CIPHERTEXT_VALUE_SET_ECCCIPHERBLOB, ERR_R_EC_LIB);
			goto end;
		}
	} else  {
		if (!EC_POINT_get_affine_coordinates_GF2m(group, cv->ephem_point, x, y, bn_ctx)) {
			SKFerr(SKF_F_SM2_CIPHERTEXT_VALUE_SET_ECCCIPHERBLOB, ERR_R_EC_LIB);
			goto end;
		}
	}

	memcpy(cv->mactag, blob->HASH, 32);
	cv->mactag_size = 32;

	if ((cv->ciphertext_size = blob->CipherLen) <= 0) {
		SKFerr(SKF_F_SM2_CIPHERTEXT_VALUE_SET_ECCCIPHERBLOB,
			SKF_R_INVALID_CIPHERTEXT_LENGTH);
		goto end;
	}
	if (!(cv->ciphertext = OPENSSL_realloc(cv->ciphertext, blob->CipherLen))) {
		SKFerr(SKF_F_SM2_CIPHERTEXT_VALUE_SET_ECCCIPHERBLOB,
			SKF_R_MALLOC_FAILED);
		goto end;
	}
	memcpy(cv->ciphertext, blob->Cipher, blob->CipherLen);

	ret = 0;

end:
	EC_GROUP_free(group);
	BN_free(x);
	BN_free(y);
	BN_CTX_free(bn_ctx);
	return ret;
}

int SM2_CIPHERTEXT_VALUE_get_ECCCIPHERBLOB(const SM2_CIPHERTEXT_VALUE *cv,
	ECCCIPHERBLOB *blob)
{
	int ret = 0;
	EC_GROUP *group = NULL;
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;
	BN_CTX *bn_ctx = NULL;

	if (!(group = EC_GROUP_new_by_curve_name(NID_sm2p256v1))) {
		SKFerr(SKF_F_SM2_CIPHERTEXT_VALUE_GET_ECCCIPHERBLOB, ERR_R_EC_LIB);
		return 0;
	}

	x = BN_new();
	y = BN_new();
	bn_ctx = BN_CTX_new();
	if (!x || !y || !bn_ctx) {
		SKFerr(SKF_F_SM2_CIPHERTEXT_VALUE_GET_ECCCIPHERBLOB, ERR_R_BN_LIB);
		goto end;
	}

	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field) {
		if (!EC_POINT_get_affine_coordinates_GFp(group, cv->ephem_point, x, y, bn_ctx)) {
			SKFerr(SKF_F_SM2_CIPHERTEXT_VALUE_GET_ECCCIPHERBLOB, ERR_R_EC_LIB);
			goto end;
		}
	} else  {
		if (!EC_POINT_get_affine_coordinates_GF2m(group, cv->ephem_point, x, y, bn_ctx)) {
			SKFerr(SKF_F_SM2_CIPHERTEXT_VALUE_GET_ECCCIPHERBLOB, ERR_R_EC_LIB);
			goto end;
		}
	}

	if ((BN_num_bytes(x) > 256/8) || (BN_num_bytes(y) > 256/8)) {
		SKFerr(SKF_F_SM2_CIPHERTEXT_VALUE_GET_ECCCIPHERBLOB,
			SKF_R_INVALID_CIPHERTEXT_POINT);
		goto end;
	}
	if (!BN_bn2bin(x, blob->XCoordinate + 256/8 - BN_num_bytes(x))) {
		SKFerr(SKF_F_SM2_CIPHERTEXT_VALUE_GET_ECCCIPHERBLOB, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_bn2bin(y, blob->YCoordinate + 256/8 - BN_num_bytes(y))) {
		SKFerr(SKF_F_SM2_CIPHERTEXT_VALUE_GET_ECCCIPHERBLOB, ERR_R_BN_LIB);
		goto end;
	}

	if (cv->mactag_size != 32) {
		SKFerr(SKF_F_SM2_CIPHERTEXT_VALUE_GET_ECCCIPHERBLOB,
			SKF_R_INVALID_CIPHERTEXT_MAC);
		goto end;
	}
	memcpy(blob->HASH, cv->mactag, cv->mactag_size);

	if (cv->ciphertext_size <= 0) {
		SKFerr(SKF_F_SM2_CIPHERTEXT_VALUE_GET_ECCCIPHERBLOB,
			SKF_R_INVALID_CIPHERTEXT_LENGTH);
		goto end;
	}
	memcpy(blob->Cipher, cv->ciphertext, cv->ciphertext_size);

	ret = 1;
end:
	EC_GROUP_free(group);
	BN_free(x);
	BN_free(y);
	BN_CTX_free(bn_ctx);
	return ret;
}

ECDSA_SIG *ECDSA_SIG_new_from_ECCSIGNATUREBLOB(const ECCSIGNATUREBLOB *blob)
{
	ECDSA_SIG *ret = NULL;

	if (!(ret = ECDSA_SIG_new())) {
		SKFerr(SKF_F_ECDSA_SIG_NEW_FROM_ECCSIGNATUREBLOB,
			SKF_R_MALLOC_FAILED);
		return NULL;
	}

	if (!ECDSA_SIG_set_ECCSIGNATUREBLOB(ret, blob)) {
		SKFerr(SKF_F_ECDSA_SIG_NEW_FROM_ECCSIGNATUREBLOB,
			SKF_R_INVALID_SIGNATURE);
		ECDSA_SIG_free(ret);
		return NULL;
	}

	return ret;
}

int ECDSA_SIG_get_ECCSIGNATUREBLOB(const ECDSA_SIG *sig, ECCSIGNATUREBLOB *blob)
{
	if ((BN_num_bytes(sig->r) > 256/8) || (BN_num_bytes(sig->s) > 256/8)) {
		SKFerr(SKF_F_ECDSA_SIG_GET_ECCSIGNATUREBLOB, SKF_R_INVALID_BIGNUM_LENGTH);
		return SAR_FAIL;
	}

	if (!BN_bn2bin(sig->r, blob->r + 256/8 - BN_num_bytes(sig->r))) {
		SKFerr(SKF_F_ECDSA_SIG_GET_ECCSIGNATUREBLOB, ERR_R_BN_LIB);
		return SAR_FAIL;
	}

	if (!BN_bn2bin(sig->s, blob->s + 256/8 - BN_num_bytes(sig->s))) {
		SKFerr(SKF_F_ECDSA_SIG_GET_ECCSIGNATUREBLOB, ERR_R_BN_LIB);
		return SAR_FAIL;
	}

	return SAR_OK;
}

int ECDSA_SIG_set_ECCSIGNATUREBLOB(ECDSA_SIG *sig, const ECCSIGNATUREBLOB *blob)
{
	if (!(sig->r = BN_bin2bn(blob->r, 256/8, sig->r))) {
		SKFerr(SKF_F_ECDSA_SIG_SET_ECCSIGNATUREBLOB, ERR_R_BN_LIB);
		return SAR_FAIL;
	}

	if (!(sig->s = BN_bin2bn(blob->s, 256/8, sig->s))) {
		SKFerr(SKF_F_ECDSA_SIG_SET_ECCSIGNATUREBLOB, ERR_R_BN_LIB);
		return SAR_FAIL;
	}

	return SAR_OK;
}

