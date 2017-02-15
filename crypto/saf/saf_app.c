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
/*
 * the software implementation of SAF application and related storage
 * is determined by a standard OpenSSL configuration file `openssl.cnf`.
 * If no config file is given, the default openssl config file will be
 * used. This means that the SAF API is only a wrapper of the EVP API.
 *
 * The OpenSSL use file-level access control, i.e. private keys are
 * encrypted by passwords, there is no default container-level access
 * control mechnsims such as the Java Keytool for the application-level
 * access control of SAF API.
 *
 * We use the AppHandle to preserve the CONF object.
 *
 * So we dont provide such access control. The Login() will always
 * success. And the ChangePin() has no effects.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/gmsaf.h>

/* 7.1.2 */
int SAF_Initialize(
	void **phAppHandle,
	char *pubCfgFilePath)
{

	return SAR_Ok;
}

/* 7.1.3 */
int SAF_Finalize(
	void *hAppHandle)
{
	return SAR_Ok;
}

/* 7.1.4 */
int SAF_GetVersion(
	unsigned int *puiVersion)
{
	*puiVersion = 0x01000000;
	return SAR_Ok;
}

/* 7.1.5 */
int SAF_Login(
	void *hAppHandle,
	unsigned int uiUsrType,
	unsigned char *pucContainerName,
	unsigned int uiContainerNameLen,
	unsigned char *pucPin,
	unsigned int uiPinLen,
	unsigned int *puiRemainCount)
{
	*puiRemainCount = 100;
	return SAR_Ok;
}

/* 7.1.6 */
int SAF_ChangePin(
	void *hAppHandle,
	unsigned int uiUsrType,
	unsigned char *pucContainerName,
	unsigned int uiContainerNameLen,
	unsigned char *pucOldPin,
	unsigned int uiOldPinLen,
	unsigned char *pucNewPin,
	unsigned int uiNewPinLen,
	unsigned int *puiRemainCount)
{
	*puiRemainCount = 100;
	return SAR_Ok;
}

/* 7.1.7 */
int SAF_Logout(
	void *hAppHandle,
	unsigned int uiUsrType)
{
	return SAR_Ok;
}

