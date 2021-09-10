/* 
 *   Copyright 2014-2021 The GmSSL Project Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#ifndef GMSSL_SDF_EXT_H
#define GMSSL_SDF_EXT_H


#include <stdio.h>
#include <stdint.h>
#include "sgd.h"
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

int SDF_PrintDeviceInfo(FILE *out, DEVICEINFO *devInfo);
int SDF_PrintRSAPublicKey(FILE *out, RSArefPublicKey *ref);
int SDF_PrintRSAPrivateKey(FILE *out, RSArefPrivateKey *ref);
int SDF_PrintECCPublicKey(FILE *out, ECCrefPublicKey *ref);
int SDF_PrintECCPrivateKey(FILE *out, ECCrefPrivateKey *ref);
int SDF_NewECCCipher(ECCCipher **cipher, size_t ulDataLen);
int SDF_FreeECCCipher(ECCCipher *cipher);
int SDF_PrintECCCipher(FILE *out, ECCCipher *cipher);
int SDF_PrintECCSignature(FILE *out, ECCSignature *sig);
int SDF_GetErrorString(int err, char **str);


#ifdef __cplusplus
}
#endif
#endif
