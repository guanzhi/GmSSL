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
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/gmsdf.h>
#include <openssl/engine.h>
#include "sdf_lcl.h"

char *deviceHandle = "SDF Device Handle";

int SDF_OpenDevice(
	void **phDeviceHandle)
{
	if (!phDeviceHandle) {
		SDFerr(SDF_F_SDF_OPENDEVICE, ERR_R_PASSED_NULL_PARAMETER);
		return SDR_OUTARGERR;
	}

#ifndef OPENSSL_NO_ENGINE
	ENGINE_load_builtin_engines();
#endif

	*phDeviceHandle = deviceHandle;
	return SDR_OK;
}

int SDF_CloseDevice(
	void *hDeviceHandle)
{
	if (hDeviceHandle != deviceHandle) {
		SDFerr(SDF_F_SDF_CLOSEDEVICE, SDF_R_INVALID_DEVICE_HANDLE);
		return SDR_INARGERR;
	}
#ifndef OPENSSL_NO_ENGINE
	ENGINE_cleanup();
#endif
	return SDR_OK;
}

int SDF_GetDeviceInfo(
	void *hSessionHandle,
	DEVICEINFO *pstDeviceInfo)
{
	SDF_SESSION *session = (SDF_SESSION *)hSessionHandle;

	if (!hSessionHandle || !pstDeviceInfo) {
		SDFerr(SDF_F_SDF_GETDEVICEINFO, ERR_R_PASSED_NULL_PARAMETER);
		return SDR_INARGERR;
	}
	if (session->magic != SDF_SESSION_MAGIC) {
		SDFerr(SDF_F_SDF_GETDEVICEINFO, SDF_R_INVALID_SESSION_HANDLE);
		return SDR_INARGERR;
	}

	memset(pstDeviceInfo, 0, sizeof(*pstDeviceInfo));
	strncpy((char *)pstDeviceInfo->IssuerName, "GmSSL Project (http://gmssl.org)", 40);
	strncpy((char *)pstDeviceInfo->DeviceName, "GmSSL Soft SDF", 16);
	strncpy((char *)pstDeviceInfo->DeviceSerial, "201608020010123", 16);
	pstDeviceInfo->DeviceVersion = 2;
	pstDeviceInfo->StandardVersion = 1;
	pstDeviceInfo->AsymAlgAbility[0] = SGD_RSA|SGD_SM2_1;
	pstDeviceInfo->AsymAlgAbility[1] = SGD_RSA|SGD_SM2_3;
	pstDeviceInfo->SymAlgAbility = SGD_SM1|SGD_SSF33|SGD_SM4|SGD_ZUC;
	pstDeviceInfo->HashAlgAbility = SGD_SM3|SGD_SHA1|SGD_SHA256;
	pstDeviceInfo->BufferSize = 0;

	return SDR_OK;
}

