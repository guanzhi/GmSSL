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
#include <openssl/gmsdf.h>
#include <openssl/gmapi.h>
#include "sdf_lcl.h"

int SDF_PrintDeviceInfo(FILE *fp, DEVICEINFO *devInfo)
{
	char issuerName[41];
	char deviceName[17];
	char deviceSerial[17];

	/* IssuerName */
	memcpy(issuerName, devInfo->IssuerName, 40);
	issuerName[40] = 0;
	fprintf(fp, "IssuerName = %s\n", issuerName);

	/* DeviceName */
	memcpy(deviceName, devInfo->DeviceName, 16);
	deviceName[16] = 0;
	fprintf(fp, "DeviceName = %s\n", deviceName);

	/* DeviceSerial */
	memcpy(deviceSerial, devInfo->DeviceSerial, 16);
	deviceSerial[16] = 0;
	fprintf(fp, "DeviceSerial = %s\n", deviceSerial);

	/* DeviceVersion */
	fprintf(fp, "DeviceVersion = 0x%08X\n", devInfo->DeviceVersion);

	/* StandardVersion */
	fprintf(fp, "StandardVersion = 0x%08X\n", devInfo->StandardVersion);

	/* AsymAlgAbility */
	fputs("AsymAlgAbility[0] =", fp);
	if (devInfo->AsymAlgAbility[0] & SGD_RSA) {
		fputs(" RSA", fp);
	}
	if (devInfo->AsymAlgAbility[0] & SGD_SM2) {
		fputs(" SM2", fp);
	}
	fputs("\n", fp);
	fprintf(fp, "AsymAlgAbility[1] = 0x%08X\n", devInfo->AsymAlgAbility[1]);

	/* SymAlgAbility */
	fputs("SymAlgAbility =", fp);
	if (devInfo->SymAlgAbility & SGD_SM1)
		fputs(" SM1", fp);
	if (devInfo->SymAlgAbility & SGD_SSF33)
		fputs(" SSF33", fp);
	if (devInfo->SymAlgAbility & SGD_SM4)
		fputs(" SM4", fp);
	if (devInfo->SymAlgAbility & SGD_ZUC)
		fputs(" ZUC", fp);
	fputs("\n", fp);

	/* HashAlgAbility */
	fputs("HashAlgAbility =", fp);
	if (devInfo->HashAlgAbility & SGD_SM3)
		fputs(" SM3", fp);
	if (devInfo->HashAlgAbility & SGD_SHA1)
		fputs(" SHA1", fp);
	if (devInfo->HashAlgAbility & SGD_SHA256)
		fputs(" SHA256", fp);
	fputs("\n", fp);

	/* BufferSize */
	fprintf(fp, "BufferSize = %u\n", devInfo->BufferSize);

	return SDR_OK;
}

int SDF_PrintRSAPublicKey(FILE *fp, RSArefPublicKey *pk)
{
	int i;

	/* bits */
	(void)fprintf(fp, "bits = %u\n", pk->bits);

	/* m */
	(void)fputs("m = ", fp);
	for (i = 0; i < RSAref_MAX_LEN; i++) {
		(void)fprintf(fp, "%02X", pk->m[i]);
	}
	(void)fputs("\n", fp);

	/* e */
	(void)fputs("e = ", fp);
	for (i = 0; i < RSAref_MAX_LEN; i++) {
		(void)fprintf(fp, "%02X", pk->e[i]);
	}
	(void)fputs("\n", fp);

	return 1;
}

int SDF_PrintRSAPrivateKey(FILE *fp, RSArefPrivateKey *sk)
{
	return 0;
}

int SDF_PrintECCPublicKey(FILE *fp, ECCrefPublicKey *pk)
{
	int i;

	/* bits */
	(void)fprintf(fp, "bits = %u\n", pk->bits);

	/* x */
	(void)fputs("x = ", fp);
	for (i = 0; i < ECCref_MAX_LEN; i++) {
		(void)fprintf(fp, "%02X", pk->x[i]);
	}
	(void)fputs("\n", fp);

	/* y */
	(void)fputs("y = ", fp);
	for (i = 0; i < ECCref_MAX_LEN; i++) {
		(void)fprintf(fp, "%02X", pk->y[i]);
	}
	(void)fputs("\n", fp);

	return 1;
}

int SDF_PrintECCPrivateKey(FILE *fp, ECCrefPrivateKey *pk)
{
	return 0;
}

int SDF_PrintECCCipher(FILE *fp, ECCCipher *cipher)
{
	int i;

	/* x */
	(void)fputs("x = ", fp);
	for (i = 0; i < ECCref_MAX_LEN; i++) {
		(void)fprintf(fp, "%02X", cipher->x[i]);
	}
	(void)fputs("\n", fp);

	/* y */
	(void)fputs("y = ", fp);
	for (i = 0; i < ECCref_MAX_LEN; i++) {
		(void)fprintf(fp, "%02X", cipher->y[i]);
	}
	(void)fputs("\n", fp);

	/* M */
	(void)fputs("M = ", fp);
	for (i = 0; i < 32; i++) {
		(void)fprintf(fp, "%02X", cipher->M[i]);
	}
	(void)fputs("\n", fp);

	/* L */
	(void)fprintf(fp, "L = %u\n", cipher->L);

	/* C */
	for (i = 0; i < cipher->L; i++) {
		(void)fprintf(fp, "%02X", cipher->C[i]);
	}
	(void)fputs("\n", fp);

	return 1;
}

int SDF_PrintECCSignature(FILE *fp, ECCSignature *sig)
{
	int i;

	/* r */
	(void)fputs("r = ", fp);
	for (i = 0; i < ECCref_MAX_LEN; i++) {
		(void)fprintf(fp, "%02X", sig->r[i]);
	}
	(void)fputs("\n", fp);

	/* s */
	(void)fputs("s = ", fp);
	for (i = 0; i < ECCref_MAX_LEN; i++) {
		(void)fprintf(fp, "%02X", sig->s[i]);
	}
	(void)fputs("\n", fp);

	return 1;
}

