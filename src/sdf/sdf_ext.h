/*
 * Copyright (c) 2014 - 2021 The GmSSL Project.  All rights reserved.
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
