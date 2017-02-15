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
#include <openssl/rsa.h>
#include <openssl/gmskf.h>
#include <openssl/gmapi.h>
#include "../rsa/rsa_locl.h"


ULONG DEVAPI SKF_GenExtRSAKey(DEVHANDLE hDev,
	ULONG ulBitsLen,
	RSAPRIVATEKEYBLOB *pBlob)
{
	ULONG ret = SAR_FAIL;
	RSA *rsa = NULL;

	if ((ulBitsLen > MAX_RSA_MODULUS_LEN * 8) || (ulBitsLen < 1024) ||
		(ulBitsLen % 8 != 0)) {
		SKFerr(SKF_F_SKF_GENEXTRSAKEY, SKF_R_INVALID_KEY_LENGTH);
		return SAR_INVALIDPARAMERR;
	}

	if (!pBlob) {
		SKFerr(SKF_F_SKF_GENEXTRSAKEY, SKF_R_NULL_ARGUMENT);
		return SAR_INVALIDPARAMERR;
	}

	if (!(rsa = RSA_new())) {
		SKFerr(SKF_F_SKF_GENEXTRSAKEY, SKF_R_MALLOC_FAILED);
		return SAR_FAIL;
	}

	if (!RSA_generate_key_ex(rsa, ulBitsLen, NULL, NULL)) {
		SKFerr(SKF_F_SKF_GENEXTRSAKEY, SKF_R_GEN_RSA_FAILED);
		goto end;
	}

	if (!RSA_get_RSAPRIVATEKEYBLOB(rsa, pBlob)) {
		SKFerr(SKF_F_SKF_GENEXTRSAKEY, SKF_R_ENCODE_FAILED);
		goto end;
	}

	ret = SAR_OK;
end:
	RSA_free(rsa);
	return ret;
}

ULONG DEVAPI SKF_ExtRSAPubKeyOperation(DEVHANDLE hDev,
	RSAPUBLICKEYBLOB *pRSAPubKeyBlob,
	BYTE *pbInput,
	ULONG ulInputLen,
	BYTE *pbOutput,
	ULONG *pulOutputLen)
{
	ULONG ret = SAR_FAIL;
	RSA *rsa = NULL;
	int inlen, outlen;

	if (!pRSAPubKeyBlob || !pbInput || !pulOutputLen) {
		SKFerr(SKF_F_SKF_EXTRSAPUBKEYOPERATION, SKF_R_NULL_ARGUMENT);
		return SAR_INVALIDPARAMERR;
	}

	if (pRSAPubKeyBlob->AlgID != SGD_RSA) {
		SKFerr(SKF_F_SKF_EXTRSAPUBKEYOPERATION, SKF_R_INVALID_ALGOR);
		return SAR_INVALIDPARAMERR;
	}
	if (pRSAPubKeyBlob->BitLen % 8) {
		SKFerr(SKF_F_SKF_EXTRSAPUBKEYOPERATION, SKF_R_INVALID_KEY_LENGTH);
		return SAR_INVALIDPARAMERR;
	}

	if (ulInputLen * 8 != pRSAPubKeyBlob->BitLen) {
		SKFerr(SKF_F_SKF_EXTRSAPUBKEYOPERATION, SKF_R_INVALID_INPUT_LENGTH);
		return SAR_INVALIDPARAMERR;
	}

	if (!pbOutput) {
		*pulOutputLen = pRSAPubKeyBlob->BitLen / 8;
		return SAR_OK;
	}

	if (*pulOutputLen < pRSAPubKeyBlob->BitLen / 8) {
		SKFerr(SKF_F_SKF_EXTRSAPUBKEYOPERATION, SKF_R_BUFFER_TOO_SMALL);
		return SAR_BUFFER_TOO_SMALL;
	}

	if (!(rsa = RSA_new_from_RSAPUBLICKEYBLOB(pRSAPubKeyBlob))) {
		SKFerr(SKF_F_SKF_EXTRSAPUBKEYOPERATION, SKF_R_INVALID_RSA_PUBLIC_KEY);
		goto end;
	}

	inlen = (int)ulInputLen;
	if ((outlen = RSA_public_encrypt(inlen, pbInput, pbOutput, rsa, RSA_NO_PADDING)) < 0) {
		SKFerr(SKF_F_SKF_EXTRSAPUBKEYOPERATION, ERR_R_RSA_LIB);
		goto end;
	}

	*pulOutputLen = outlen;
	ret = SAR_OK;
end:
	RSA_free(rsa);
	return ret;
}

ULONG DEVAPI SKF_ExtRSAPriKeyOperation(DEVHANDLE hDev,
	RSAPRIVATEKEYBLOB *pRSAPriKeyBlob,
	BYTE *pbInput,
	ULONG ulInputLen,
	BYTE *pbOutput,
	ULONG *pulOutputLen)
{
	ULONG ret = SAR_FAIL;
	RSA *rsa = NULL;
	int inlen, outlen;

	if (!pRSAPriKeyBlob || !pbInput || !pulOutputLen) {
		SKFerr(SKF_F_SKF_EXTRSAPRIKEYOPERATION, SKF_R_NULL_ARGUMENT);
		return SAR_INVALIDPARAMERR;
	}

	if (pRSAPriKeyBlob->AlgID != SGD_RSA) {
		SKFerr(SKF_F_SKF_EXTRSAPRIKEYOPERATION, SKF_R_INVALID_ALGOR);
		return SAR_INVALIDPARAMERR;
	}
	if (pRSAPriKeyBlob->BitLen % 8) {
		SKFerr(SKF_F_SKF_EXTRSAPRIKEYOPERATION, SKF_R_INVALID_KEY_LENGTH);
		return SAR_INVALIDPARAMERR;
	}

	if (ulInputLen * 8 != pRSAPriKeyBlob->BitLen) {
		SKFerr(SKF_F_SKF_EXTRSAPRIKEYOPERATION, SKF_R_INVALID_INPUT_LENGTH);
		return SAR_INVALIDPARAMERR;
	}

	if (!pbOutput) {
		*pulOutputLen = pRSAPriKeyBlob->BitLen / 8;
		return SAR_OK;
	}

	if (*pulOutputLen < pRSAPriKeyBlob->BitLen / 8) {
		SKFerr(SKF_F_SKF_EXTRSAPRIKEYOPERATION, SKF_R_BUFFER_TOO_SMALL);
		return SAR_BUFFER_TOO_SMALL;
	}

	if (!(rsa = RSA_new_from_RSAPRIVATEKEYBLOB(pRSAPriKeyBlob))) {
		SKFerr(SKF_F_SKF_EXTRSAPRIKEYOPERATION, SKF_R_INVALID_RSA_PUBLIC_KEY);
		goto end;
	}

	inlen = (int)ulInputLen;
	if ((outlen = RSA_private_decrypt(inlen, pbInput, pbOutput, rsa, RSA_NO_PADDING)) < 0) {
		SKFerr(SKF_F_SKF_EXTRSAPRIKEYOPERATION, ERR_R_RSA_LIB);
		goto end;
	}

	*pulOutputLen = outlen;
	ret = SAR_OK;
end:
	RSA_free(rsa);
	return ret;
}

ULONG DEVAPI SKF_RSAVerify(DEVHANDLE hDev,
	RSAPUBLICKEYBLOB *pRSAPubKeyBlob,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbSignature,
	ULONG ulSignLen)
{
	return SAR_FAIL;
}

