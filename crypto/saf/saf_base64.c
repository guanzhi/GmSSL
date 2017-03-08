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
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES
 * LOSS OF USE, DATA, OR PROFITS OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/gmsaf.h>
#include <openssl/gmapi.h>
#include "saf_lcl.h"

/* 7.3.4 */
int SAF_Base64_CreateBase64Obj(
	void **phBase64Obj)
{
	int ret = SAR_UnknownErr;
	SAF_BASE64OBJ *obj = NULL;

	if (!(obj = OPENSSL_malloc(sizeof(*obj)))) {
		SAFerr(SAF_F_SAF_BASE64_CREATEBASE64OBJ, ERR_R_MALLOC_FAILURE);
		return SAR_MemoryErr;
	}

	if (!(obj->ctx = EVP_ENCODE_CTX_new())) {
		SAFerr(SAF_F_SAF_BASE64_CREATEBASE64OBJ, ERR_R_MALLOC_FAILURE);
		ret = SAR_MemoryErr;
		goto end;
	}
	obj->inited = 0;

	*phBase64Obj = obj;
	ret = SAR_OK;

end:
	if (ret != SAR_OK) {
		EVP_ENCODE_CTX_free(obj->ctx);
		OPENSSL_free(obj);
	}
	return ret;
}

/* 7.3.5 */
/* always return success for software implementation */
int SAF_Base64_DestroyBase64Obj(
	void *hBase64Obj)
{
	SAF_BASE64OBJ *obj = (SAF_BASE64OBJ *)hBase64Obj;
	if (obj) {
		EVP_ENCODE_CTX_free(obj->ctx);
	}
	OPENSSL_free(obj);
	return SAR_OK;
}

/* 7.3.6 */
int SAF_Base64_EncodeUpdate(
	void *hBase64Obj,
	unsigned char *pucInData,
	unsigned int puiInDataLen,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen)
{
	SAF_BASE64OBJ *obj = (SAF_BASE64OBJ *)hBase64Obj;
	int inlen, outlen;

	if (!hBase64Obj || !pucInData || !pucOutData || !puiOutDataLen) {
		SAFerr(SAF_F_SAF_BASE64_ENCODEUPDATE, ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}
	/* GMAPI dont check function specific length, leave to EVP */
	if (puiInDataLen > INT_MAX) {
		SAFerr(SAF_F_SAF_BASE64_ENCODEUPDATE, SAF_R_INT_OVERFLOW);
		return SAR_IndataLenErr;
	}
	/* GMAPI dont check function specific length, leave to EVP */
	if (*puiOutDataLen > INT_MAX) {
		SAFerr(SAF_F_SAF_BASE64_ENCODEUPDATE, SAF_R_INT_OVERFLOW);
		return SAR_IndataLenErr;
	}

	/* check handle */
	if (!obj->ctx) {
		SAFerr(SAF_F_SAF_BASE64_ENCODEUPDATE, SAF_R_INVALID_HANDLE);
		return SAR_ObjErr;
	}

	if (!obj->inited) {
		EVP_EncodeInit(obj->ctx);
		obj->inited = 1;
	}

	inlen = (int)puiInDataLen;
	outlen = (int)(*puiOutDataLen);
	//TODO: check outlen, or EVP will fail without error messages
	if (!EVP_EncodeUpdate(obj->ctx, pucOutData, &outlen, pucInData, inlen)) {
		SAFerr(SAF_F_SAF_BASE64_ENCODEUPDATE, ERR_R_EVP_LIB);
		return SAR_UnknownErr;
	}

	*puiOutDataLen = (unsigned int)outlen;
	return SAR_OK;
}

/* 7.3.7 */
int SAF_Base64_EncodeFinal(
	void *hBase64Obj,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen)
{
	SAF_BASE64OBJ *obj = (SAF_BASE64OBJ *)hBase64Obj;
	int len;

	if (!hBase64Obj || !pucOutData || !puiOutDataLen) {
		SAFerr(SAF_F_SAF_BASE64_ENCODEFINAL, ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}
	if (*puiOutDataLen > INT_MAX) {
		SAFerr(SAF_F_SAF_BASE64_ENCODEFINAL, SAF_R_INT_OVERFLOW);
		return SAR_IndataLenErr;
	}
	if (*puiOutDataLen < 66) {
		SAFerr(SAF_F_SAF_BASE64_ENCODEFINAL, SAF_R_BUFFER_TOO_SMALL);
		return SAR_IndataLenErr;
	}

	if (!obj->ctx || !obj->inited) {
		SAFerr(SAF_F_SAF_BASE64_ENCODEFINAL, SAF_R_INVALID_HANDLE);
		return SAR_ObjErr;
	}

	/* the max output length of EVP_EncodeFinal() is 66
	 * this function return void, so we need to check `*outlen`
	 */
	len = (int)(*puiOutDataLen);
	//TODO: check outlen, or EVP will fail without error messages
	EVP_EncodeFinal(obj->ctx, pucOutData, &len);


	*puiOutDataLen = (unsigned int)len;
	return SAR_OK;
}

/* 7.3.8 */
int SAF_Base64_DecodeUpdate(
	void *hBase64Obj,
	unsigned char *pucInData,
	unsigned int puiInDataLen,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen)
{
	SAF_BASE64OBJ *obj = (SAF_BASE64OBJ *)hBase64Obj;
	int inlen, outlen;

	if (!hBase64Obj || !pucInData || !pucOutData || !puiOutDataLen) {
		SAFerr(SAF_F_SAF_BASE64_DECODEUPDATE, ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}
	/* GMAPI dont check function specific length, leave to EVP */
	if (puiInDataLen > INT_MAX) {
		SAFerr(SAF_F_SAF_BASE64_DECODEUPDATE, SAF_R_INT_OVERFLOW);
		return SAR_IndataLenErr;
	}
	/* GMAPI dont check function specific length, leave to EVP */
	if (*puiOutDataLen > INT_MAX) {
		SAFerr(SAF_F_SAF_BASE64_DECODEUPDATE, SAF_R_INT_OVERFLOW);
		return SAR_IndataLenErr;
	}

	if (!obj->ctx) {
		SAFerr(SAF_F_SAF_BASE64_DECODEUPDATE, SAF_R_INVALID_HANDLE);
		return SAR_ObjErr;
	}

	if (!obj->inited) {
		EVP_DecodeInit(obj->ctx);
		obj->inited = 1;
	}

	inlen = (int)puiInDataLen;
	outlen = (int)(*puiOutDataLen);
	//TODO: check outlen, or EVP will fail without error messages

	/*
	 * EVP_DecodeUpdate() return -1 for error, 0 or 1 for success
	 * 0 means the last char of the input is `=`
	 */
	if (EVP_DecodeUpdate(obj->ctx, pucOutData, &outlen, pucInData, inlen) < 0) {
		SAFerr(SAF_F_SAF_BASE64_DECODEUPDATE, ERR_R_EVP_LIB);
		return SAR_UnknownErr;
	}

	*puiOutDataLen = (unsigned int)outlen;
	return SAR_OK;
}

/* 7.3.9 */
int SAF_Base64_DecodeFinal(
	void *hBase64Obj,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen)
{
	SAF_BASE64OBJ *obj = (SAF_BASE64OBJ *)hBase64Obj;
	int len;

	if (!hBase64Obj || !pucOutData || !puiOutDataLen) {
		SAFerr(SAF_F_SAF_BASE64_DECODEFINAL, ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}
	if (*puiOutDataLen > INT_MAX) {
		SAFerr(SAF_F_SAF_BASE64_DECODEFINAL, SAF_R_INT_OVERFLOW);
		return SAR_IndataLenErr;
	}

	if (!obj->ctx || !obj->inited) {
		SAFerr(SAF_F_SAF_BASE64_DECODEFINAL, SAF_R_INVALID_HANDLE);
		return SAR_ObjErr;
	}

	len = (int)(*puiOutDataLen);
	//TODO: check outlen, or EVP will fail without error messages
	if (!EVP_DecodeFinal(obj->ctx, pucOutData, &len)) {
		SAFerr(SAF_F_SAF_BASE64_DECODEFINAL, ERR_R_EVP_LIB);
		return SAR_UnknownErr;
	}

	*puiOutDataLen = (unsigned int)len;
	return SAR_OK;
}

/* 7.3.2 */
int SAF_Base64_Encode(
	unsigned char *pucInData,
	unsigned int puiInDataLen,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen)
{
	int ret = SAR_UnknownErr;
	void *handle = NULL;
	unsigned char *p;
	unsigned int len;

	if (!pucInData || !pucOutData || !puiOutDataLen) {
		SAFerr(SAF_F_SAF_BASE64_ENCODE, ERR_R_PASSED_NULL_PARAMETER);
		return SAR_IndataErr;
	}

	if ((ret = SAF_Base64_CreateBase64Obj(&handle)) != SAR_OK) {
		SAFerr(SAF_F_SAF_BASE64_ENCODE, ERR_R_GMAPI_LIB);
		goto end;
	}

	p = pucOutData;
	len = *puiOutDataLen;

	if ((ret = SAF_Base64_EncodeUpdate(handle, pucInData, puiInDataLen,
		p, &len)) != SAR_OK) {
		SAFerr(SAF_F_SAF_BASE64_ENCODE, ERR_R_GMAPI_LIB);
		goto end;
	}
	p += len;

	len = *puiOutDataLen - len;
	if ((ret = SAF_Base64_EncodeFinal(handle, p, &len)) != SAR_OK) {
		SAFerr(SAF_F_SAF_BASE64_ENCODE, ERR_R_GMAPI_LIB);
		goto end;
	}
	p += len;

	*puiOutDataLen = p - pucOutData;
	ret = SAR_OK;

end:
	SAF_Base64_DestroyBase64Obj(handle);
	return ret;
}

/* 7.3.3 */
int SAF_Base64_Decode(
	unsigned char *pucInData,
	unsigned int puiInDataLen,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen)
{
	int ret = SAR_UnknownErr;
	void *handle = NULL;
	unsigned char *p;
	unsigned int len;

	if ((ret = SAF_Base64_CreateBase64Obj(&handle)) != SAR_OK) {
		SAFerr(SAF_F_SAF_BASE64_DECODE, ERR_R_GMAPI_LIB);
		goto end;
	}

	p = pucOutData;
	len = *puiOutDataLen;

	if ((ret = SAF_Base64_DecodeUpdate(handle, pucInData, puiInDataLen,
		p, &len)) != SAR_OK) {
		SAFerr(SAF_F_SAF_BASE64_DECODE, ERR_R_GMAPI_LIB);
		goto end;
	}
	p += len;

	len = *puiOutDataLen - len;
	if ((ret = SAF_Base64_DecodeFinal(handle, p, &len)) != SAR_OK) {
		SAFerr(SAF_F_SAF_BASE64_DECODE, ERR_R_GMAPI_LIB);
		goto end;
	}
	p += len;

	*puiOutDataLen = p - pucOutData;
	ret = SAR_OK;

end:
	SAF_Base64_DestroyBase64Obj(handle);
	return ret;
}
