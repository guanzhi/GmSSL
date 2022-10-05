/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#ifndef SDFUTIL_SDF_EXT_H
#define SDFUTIL_SDF_EXT_H


#include <stdio.h>
#include <stdint.h>
#include "../sgd.h"
#include "sdf.h"


#ifdef __cplusplus
extern "C" {
#endif


#define SDF_MIN_KEY_INDEX	  1 /* defined by GM/T 0018 */
#define SDF_MAX_KEY_INDEX	 32 /* defined by GmSSL */
#define SDF_MIN_PASSWORD_LENGTH	  8 /* defined by GM/T 0018 */
#define SDF_MAX_PASSWORD_LENGTH	255 /* defined by GmSSL */
#define SDF_MAX_FILE_SIZE	(256 * 1024)



int SDF_LoadLibrary(char *so_path, char *vendor);
int SDF_UnloadLibrary(void);
int SDF_ImportKey(void *hSessionHandle, unsigned char *pucKey,
	unsigned int uiKeyLength, void **phKeyHandle);

int SDF_PrintDeviceInfo(FILE *fp, const DEVICEINFO *devInfo);
int SDF_PrintRSAPublicKey(FILE *fp, const RSArefPublicKey *ref);
int SDF_PrintRSAPrivateKey(FILE *fp, const RSArefPrivateKey *ref);
int SDF_PrintECCPublicKey(FILE *fp, const ECCrefPublicKey *ref);
int SDF_PrintECCPrivateKey(FILE *fp, const ECCrefPrivateKey *ref);
int SDF_NewECCCipher(ECCCipher **cipher, size_t ulDataLen); // FIMXE: 和GmSSL的内存使用方式不同		
int SDF_FreeECCCipher(ECCCipher *cipher);
int SDF_PrintECCCipher(FILE *out, ECCCipher *cipher);
int SDF_PrintECCSignature(FILE *out, ECCSignature *sig);
const char *SDF_GetErrorReason(int err);


#ifdef __cplusplus
}
#endif
#endif
