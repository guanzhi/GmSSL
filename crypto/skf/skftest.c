/* engines/skf/skftest.c */
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
#include <stdlib.h>
#include <assert.h>
#include "skf.h"

#define AUTH_RAND_LEN		16
#define AUTH_DATA_LEN		16
#define AUTH_KEY_LEN		16

int main(int argc, char **argv)
{
	ULONG rv;
	BYTE buf[2048];
	ULONG len;

	BOOL bPresent = TRUE;
	CHAR devNameList[256];
	LPSTR devName;
	DEVHANDLE hDev = NULL;
	ULONG devState;
	char *devStateStr;
	DEVINFO devInfo;

	BYTE authRand[AUTH_RAND_LEN];
	BYTE authData[AUTH_DATA_LEN];
	BYTE authKey[AUTH_KEY_LEN];
	BLOCKCIPHERPARAM authParam;
	HANDLE hAuthKey = NULL;

	CHAR appNameList[256];
	LPSTR appName;
	HAPPLICATION hApp = NULL;

	CHAR containerNameList[256];
	LPSTR containerName; 
	HCONTAINER hContainer = NULL;
	ULONG containerType;
	char *containerTypeStr;

	BYTE dgst[32];
	ULONG dgstLen = sizeof(dgst);
	ECCSIGNATUREBLOB sigblob;


	len = sizeof(devNameList);
	if ((rv = SKF_EnumDev(bPresent, devNameList, &len)) != SAR_OK) {
		goto end;
	}

	devName = devNameList;
	printf("Device Name : %s\n", devName);

	if ((rv = SKF_GetDevState(devName, &devState)) != SAR_OK) {
		goto end;
	}

	switch (devState) {
	case DEV_ABSENT_STATE:
		devStateStr = "DEV_ABSENT_STATE";
		break;
	case DEV_PRESENT_STATE:
		devStateStr = "DEV_PRESENT_STATE";
		break;
	case DEV_UNKNOW_STATE:
		devStateStr = "DEV_UNKNOW_STATE";
		break;
	default:
		devStateStr = "(undefined)";	
	}
	printf("Device State: %s\n", devStateStr);

	if ((rv = SKF_ConnectDev(devName, &hDev)) != SAR_OK) {
		goto end;
	}

	if ((rv = SKF_GetDevInfo(hDev, &devInfo)) != SAR_OK) {
		goto end;
	}

	printf("Device Info:\n");
	printf(" Device Version   : %d.%d\n", devInfo.Version.major, devInfo.Version.minor);
	printf(" Manufacturer     : %s\n", devInfo.Manufacturer);
	printf(" Issuer           : %s\n", devInfo.Issuer);
	printf(" Label            : %s\n", devInfo.Label);
	printf(" Serial Number    : %s\n", devInfo.SerialNumber);
	printf(" Hardware Version : %d.%d\n", devInfo.HWVersion.major, devInfo.HWVersion.minor);
	printf(" Firmware Version : %d.%d\n", devInfo.FirmwareVersion.major, devInfo.FirmwareVersion.minor);
	printf(" AlgSymCap        : 0x%08x\n", devInfo.AlgSymCap);
	printf(" AlgAsymCap       : 0x%08x\n", devInfo.AlgAsymCap);
	printf(" AlgHashCap       : 0x%08x\n", devInfo.AlgHashCap);
	printf(" AlgHashCap       : 0x%08x\n", devInfo.DevAuthAlgId);
	printf(" Total Space      : %u\n", devInfo.TotalSpace);
	printf(" Free Space       : %u\n", devInfo.FreeSpace);
	printf(" MaxECCBuffer     : %u\n", devInfo.MaxECCBufferSize);
	printf(" MaxBuffer        : %u\n", devInfo.MaxBufferSize);


	/* Device Authentication */
	if ((rv = SKF_GenRandom(hDev, authRand, sizeof(authRand))) != SAR_OK) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if ((rv = SKF_SetSymmKey(hDev, authKey, devInfo.DevAuthAlgId, &hAuthKey)) != SAR_OK) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	bzero(&authParam, sizeof(authParam));
	if ((rv = SKF_EncryptInit(hAuthKey, authParam)) != SAR_OK) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if ((rv = SKF_Encrypt(hAuthKey, authRand, sizeof(authRand), authData, &len)) != SAR_OK) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}

	if ((rv = SKF_DevAuth(hDev, authData, len)) != SAR_OK) {
		fprintf(stderr, "error: %s %d\n", __FILE__, __LINE__);
		goto end;
	}
	
	printf("Device Authentication Passed.\n");

	/* Open Application */

	len = sizeof(appNameList);		

	if ((rv = SKF_EnumApplication(hDev, appNameList, &len)) != SAR_OK) {
		goto end;
	}

	appName = appNameList;
	printf("Application Name : %s\n", appName);

	if ((rv = SKF_OpenApplication(hDev, appName, &hApp)) != SAR_OK) {
		goto end;
	}

	/* Open Containter */	

	len = sizeof(containerNameList);

	if ((rv = SKF_EnumContainer(hApp, containerNameList, &len)) != SAR_OK) {
		goto end;
	}

	containerName = containerNameList;
	printf("Container Name: %s\n", containerName);

	if ((rv = SKF_OpenContainer(hApp, containerName, &hContainer)) != SAR_OK) {
		goto end;
	}

	if ((rv = SKF_GetContainerType(hContainer, &containerType)) != SAR_OK) {
		goto end;
	}

	switch (containerType) {
	case CONTAINER_TYPE_UNDEF:
		containerTypeStr = "Undef";
		break;
	case CONTAINER_TYPE_RSA:
		containerTypeStr = "RSA";
		break;
	case CONTAINER_TYPE_ECC:
		containerTypeStr = "ECC";
		break;
	default:
		containerTypeStr = "(error)";
	}		
	printf("Container Type: %s\n", containerTypeStr);


	/* Sign */
	if ((rv = SKF_ECCSignData(hContainer, dgst, dgstLen, &sigblob)) != SAR_OK) {
		goto end;
	}

	/* Export Signing Public Key */
	if ((rv = SKF_ExportPublicKey(hContainer, TRUE, buf, &len)) != SAR_OK) {
		goto end;
	}

	printf("Success\n");
end:
	//SKF_CloseContainer(hContainer);
	//SKF_CloseApplication(hApp);
	return 0;
}

int open_container(const char *dev, const char *app, const char *container,
	const unsigned char *authkey, size_t authkeylen)
{
	DEVHANDLE hDev = NULL;
	DEVINFO devInfo;
	HAPPLICATION hApp = NULL;
	HCONTAINER hContainer = NULL;

	

	return 0;
}


