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
#include <openssl/ec.h>
#include <openssl/sm2.h>
#include <openssl/gmskf.h>
#include "skf_lcl.h"

ULONG DEVAPI SKF_GenExtECCKeyPair(DEVHANDLE hDev,
	ECCPRIVATEKEYBLOB *priKey,
	ECCPUBLICKEYBLOB *pubKey)
{
	ULONG ret = SAR_FAIL;
	EC_KEY *ec_key = NULL;

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

