/* crypto/skf/skf_dev.c */
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
#include <string.h>
#include <openssl/skf.h>
#include <openssl/skf_ex.h>
#include "skf_lcl.h"

#define DEV_NAME		"pseudo_dev"
#define DEV_NAME_LIST		DEV_NAME"\0"


ULONG DEVAPI SKF_EnumDev(BOOL bPresent,
	LPSTR szNameList,
	ULONG *pulSize)
{
	if (!szNameList) {
		*pulSize = sizeof(DEV_NAME_LIST);
		return SAR_OK;
	}

	if (*pulSize < sizeof(DEV_NAME_LIST)) {
		return SAR_FAIL;
	}

	memcpy(szNameList, DEV_NAME_LIST, sizeof(DEV_NAME_LIST));
	return SAR_OK;
}

ULONG DEVAPI SKF_ConnectDev(LPSTR szName,
	DEVHANDLE *phDev)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_DisConnectDev(DEVHANDLE hDev)
{
	return SAR_OK;
}

ULONG DEVAPI SKF_GetDevState(LPSTR szDevName,
	ULONG *pulDevState)
{
	if (!pulDevState) {
		SKFerr(SKF_F_SKF_GETDEVSTATE, SKF_R_NULL_ARGUMENT);
		return SAR_INVALIDPARAMERR;
	}

	*pulDevState = DEV_PRESENT_STATE;
	return SAR_OK;
}

ULONG DEVAPI SKF_GetDevInfo(DEVHANDLE hDev,
	DEVINFO *pDevInfo)
{
	DEVINFO devInfo;

	if (!pDevInfo) {
		SKFerr(SKF_F_SKF_GETDEVINFO, SKF_R_NULL_ARGUMENT);
		return SAR_INVALIDPARAMERR;
	}

	bzero(&devInfo, sizeof(DEVINFO));
	devInfo.Version.major = 1;
	devInfo.Version.minor = 0;
	strcpy((char *)&devInfo.Manufacturer, "GmSSL Project (http://gmssl.org)");
	strcpy((char *)&devInfo.Issuer, "GmSSL Project (http://gmssl.org)");
	strcpy((char *)&devInfo.Label, "SKF Softotken");
	strcpy((char *)&devInfo.SerialNumber, "1");
	devInfo.HWVersion.major = 1;
	devInfo.HWVersion.minor = 0;
	devInfo.FirmwareVersion.major = 1;
	devInfo.FirmwareVersion.minor = 0;
	devInfo.AlgSymCap = 0x0000041F;
	devInfo.AlgAsymCap = 0x00030700;
	devInfo.AlgHashCap = 0x00000007;
	devInfo.DevAuthAlgId = SGD_SM4_CBC;
	devInfo.TotalSpace = 0;
	devInfo.FreeSpace = 0;
	devInfo.MaxECCBufferSize = 0; /* FIXME: max inlen of ECC encrypt */
	devInfo.MaxBufferSize = 0; /* FIXME: max inlen of SM4 encrypt */

	memcpy(pDevInfo, &devInfo, sizeof(DEVINFO));
	return SAR_OK;
}

