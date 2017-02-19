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
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../e_os.h"

#ifdef OPENSSL_NO_GMAPI
int main(int argc, char **argv)
{
	printf("NO GMAPI support\n");
	return 0;
}
#else

/*
 * We assume there are two key containers in the device. The first container
 * with index 1 is the RSA key container, two key pairs inside. The second
 * container with index 2 is the ECC key container.
 *
 * In this test we have 6 key pairs:
 *	1. Generate RSA key pair
 *	2. Generate ECC key pair
 *	3. RSA signing key pair with index 1
 *	4. RSA encryption key pair with index 1
 *	5. ECC signing key pair with index 2
 *	6. ECC encryption key pair with index 2
 *
 * We have 2 passwords to access public key container with index 1 and 2
 *
 * We also have a token symmetric key with index 1. In SDF API the indexes of
 * key pairs and symmetric keys are seperated.
 *
 * We have the following session keys, the key handles will also created.
 *	1. Generate and encrypted with internal RSA public key 4
 *	2. Generate and encrypted with external RSA public key 1
 *	3. Generate and encrypted with internal ECC public key 6
 *	4. Generate and encrypted with external ECC public key 2
 *
 * We will import (1) and (3) back to the device, we will have 2 extra handles.
 *
 */


# include <openssl/gmsdf.h>

/* RSA Key Container */
#ifndef RSA_KEY_INDEX
#define RSA_KEY_INDEX 1
#endif
static unsigned int uiRSAKeyIndex = RSA_KEY_INDEX;
static unsigned char pucRSAPassword[] = "12345678";
static unsigned int uiRSAPwdLength = sizeof(pucRSAPassword) - 1;

/* ECC Key Container */
#ifndef ECC_KEY_INDEX
#define ECC_KEY_INDEX 2
#endif
static unsigned int uiECCKeyIndex = ECC_KEY_INDEX;
static unsigned char pucECCPassword[] = "12345678";
static unsigned int uiECCPwdLength = sizeof(pucECCPassword) - 1;

#ifndef KEK_INDEX
#define KEK_INDEX 1
#endif
static unsigned int uiKEKIndex = KEK_INDEX;

#define PRINT_ERRSTR(rv) \
	fprintf(stderr, "Error (%s %d): %s\n", __FILE__, __LINE__, \
		SDF_GetErrorString(rv))

static int test_sdf_gen_symkey_rsa(void *hSessionHandle, unsigned int uiRSAKeyIndex);
static int test_sdf_ecdh(void *hSessionHandle, unsigned int uiECCKeyIndex);
static int test_sdf_gen_symkey_ecc(void *hSessionHandle, unsigned int uiECCKeyIndex);
static int test_sdf_gen_symkey_ecc(void *hSessionHandle, unsigned int uiECCKeyIndex);
static int test_sdf_kek(void *hSessionHandle, unsigned int uiKEKIndex);
static int test_sdf_gen_keypair(void *hSessionHandle);
static int test_sdf_rsa(void *hSessionHandle, unsigned int uiRSAKeyIndex);
static int test_sdf_ec(void *hSessionHandle, unsigned int uiECCKeyIndex);
static int test_sdf_cipher(void *hSessionHandle, unsigned int uiKEKIndex);
static int test_sdf_hash(void *hSessionHandle, unsigned int uiECCKeyIndex);
static int test_sdf_file(void *hSessionHandle);

int test_sdf(void)
{
	void *hDeviceHandle;
	void *hSessionHandle;

	DEVICEINFO devInfo;
	unsigned char buf[128];
	int rv;

	/*
	 * Open device and session
	 */

	hDeviceHandle = NULL;
	if ((rv = SDF_OpenDevice(
		&hDeviceHandle)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	hSessionHandle = NULL;
	if ((rv = SDF_OpenSession(
		hDeviceHandle,
		&hSessionHandle)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	memset(&devInfo, 0, sizeof(devInfo));
	if ((rv = SDF_GetDeviceInfo(
		hSessionHandle,
		&devInfo)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}
	(void)SDF_PrintDeviceInfo(stdout, &devInfo);

	memset(buf, 0, sizeof(buf));
	if ((rv = SDF_GenerateRandom(
		hSessionHandle,
		sizeof(buf),
		buf)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SDF_GetPrivateKeyAccessRight(
		hSessionHandle,
		uiRSAKeyIndex,
		pucRSAPassword,
		uiRSAPwdLength)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}
	if ((rv = SDF_GetPrivateKeyAccessRight(
		hSessionHandle,
		uiECCKeyIndex,
		pucECCPassword,
		uiECCPwdLength)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if (!test_sdf_gen_symkey_rsa(hSessionHandle, uiRSAKeyIndex)) {
		return 0;
	}
	if (!test_sdf_ecdh(hSessionHandle, uiECCKeyIndex)) {
		return 0;
	}
	if (!test_sdf_gen_symkey_ecc(hSessionHandle, uiECCKeyIndex)) {
		return 0;
	}
	if (!test_sdf_kek(hSessionHandle, uiKEKIndex)) {
		return 0;
	}
	if (!test_sdf_gen_keypair(hSessionHandle)) {
		return 0;
	}
	if (!test_sdf_rsa(hSessionHandle, uiRSAKeyIndex)) {
		return 0;
	}
	if (!test_sdf_ec(hSessionHandle, uiECCKeyIndex)) {
		return 0;
	}
	if (!test_sdf_cipher(hSessionHandle, uiKEKIndex)) {
		return 0;
	}
	if (!test_sdf_hash(hSessionHandle, uiECCKeyIndex)) {
		return 0;
	}
	if (!test_sdf_file(hSessionHandle)) {
		return 0;
	}

	if ((rv = SDF_ReleasePrivateKeyAccessRight(
		hSessionHandle,
		uiRSAKeyIndex)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}
	if ((rv = SDF_ReleasePrivateKeyAccessRight(
		hSessionHandle,
		uiECCKeyIndex)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SDF_CloseSession(
		hSessionHandle)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SDF_CloseDevice(
		hDeviceHandle)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	return 1;
}

static int test_sdf_gen_symkey_rsa(
	void *hSessionHandle,
	unsigned int uiRSAKeyIndex)
{
	RSArefPublicKey rsaEncPublicKey;
	unsigned int uiSM4KeyBits = 128;
	unsigned char pucKey[2048/8];
	unsigned int uiKeyLength;
	unsigned char pucKey2[2048/8];
	unsigned int uiKeyLength2;
	void *hKeyHandle;
	int rv;

	memset(pucKey, 0, sizeof(pucKey));
	uiKeyLength = sizeof(pucKey);
	hKeyHandle = NULL;

	/* 6.3.4 */
	if ((rv = SDF_GenerateKeyWithIPK_RSA(
		hSessionHandle,
		uiRSAKeyIndex,
		uiSM4KeyBits,
		pucKey,
		&uiKeyLength,
		&hKeyHandle)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SDF_DestroyKey(
		hSessionHandle,
		hKeyHandle)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	hKeyHandle = NULL;

	/* 6.3.6 */
	if ((rv = SDF_ImportKeyWithISK_RSA(
		hSessionHandle,
		uiRSAKeyIndex,
		pucKey,
		uiKeyLength,
		&hKeyHandle)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SDF_DestroyKey(
		hSessionHandle,
		hKeyHandle)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	memset(&rsaEncPublicKey, 0, sizeof(rsaEncPublicKey));

	if ((rv = SDF_ExportEncPublicKey_RSA(
		hSessionHandle,
		uiRSAKeyIndex,
		&rsaEncPublicKey)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	memset(pucKey, 0, sizeof(pucKey));
	uiKeyLength = sizeof(pucKey);
	hKeyHandle = NULL;

	/* 6.3.5 */
	if ((rv = SDF_GenerateKeyWithEPK_RSA(
		hSessionHandle,
		uiSM4KeyBits,
		&rsaEncPublicKey,
		pucKey,
		&uiKeyLength,
		&hKeyHandle)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SDF_DestroyKey(
		hSessionHandle,
		hKeyHandle)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SDF_ImportKeyWithISK_RSA(
		hSessionHandle,
		uiRSAKeyIndex,
		pucKey,
		uiKeyLength,
		&hKeyHandle)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SDF_DestroyKey(
		hSessionHandle,
		hKeyHandle)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	memset(pucKey2, 0, sizeof(pucKey2));
	uiKeyLength2 = sizeof(pucKey2);

	/* 6.3.7 */
	if ((rv = SDF_ExchangeDigitEnvelopeBaseOnRSA(
		hSessionHandle,
		uiRSAKeyIndex,
		&rsaEncPublicKey,
		pucKey,
		uiKeyLength,
		pucKey2,
		&uiKeyLength2)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	return 1;
}

static int test_sdf_ecdh(void *hSessionHandle, unsigned int uiECCKeyIndex)
{
	ECCrefPublicKey sponsorPublicKey;
	ECCrefPublicKey sponsorTmpPublicKey;
	ECCrefPublicKey responsePublicKey;
	ECCrefPublicKey responseTmpPublicKey;
	unsigned char pucSponsorID[] = "Alice";
	unsigned int uiSponsorIDLength = sizeof(pucSponsorID) - 1;
	unsigned char pucResponseID[] = "Bob";
	unsigned int uiResponseIDLength = sizeof(pucResponseID) - 1;
	unsigned int uiSM4KeyBits = 128;
	void *hAgreementHandle;
	void *hKeyHandle;
	int rv;

	memset(&sponsorPublicKey, 0, sizeof(sponsorPublicKey));
	memset(&sponsorTmpPublicKey, 0, sizeof(sponsorTmpPublicKey));
	hAgreementHandle = NULL;

	/* 6.3.14 */
	if ((rv = SDF_GenerateAgreementDataWithECC(
		hSessionHandle,
		uiECCKeyIndex,
		uiSM4KeyBits * 4, /* encrypt/mac keys for 2 channels*/
		pucSponsorID,
		uiSponsorIDLength,
		&sponsorPublicKey,
		&sponsorTmpPublicKey,
		&hAgreementHandle)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	memset(&responsePublicKey, 0, sizeof(responsePublicKey));
	memset(&responseTmpPublicKey, 0, sizeof(responseTmpPublicKey));
	hKeyHandle = NULL;

	/* 6.3.16 */
	if ((rv = SDF_GenerateKeyWithECC(
		hSessionHandle,
		pucResponseID,
		uiResponseIDLength,
		&responsePublicKey,
		&responseTmpPublicKey,
		hAgreementHandle,
		&hKeyHandle)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SDF_DestroyKey(
		hSessionHandle,
		hKeyHandle)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	memset(&sponsorPublicKey, 0, sizeof(sponsorPublicKey));
	memset(&sponsorTmpPublicKey, 0, sizeof(sponsorTmpPublicKey));
	hAgreementHandle = NULL;
	memset(&responsePublicKey, 0, sizeof(responsePublicKey));
	memset(&responseTmpPublicKey, 0, sizeof(responseTmpPublicKey));
	hKeyHandle = NULL;

	/* 6.3.16 */
	if ((rv = SDF_GenerateAgreementDataAndKeyWithECC(
		hSessionHandle,
		uiECCKeyIndex,
		uiSM4KeyBits * 4,
		pucResponseID,
		uiResponseIDLength,
		pucSponsorID,
		uiSponsorIDLength,
		&sponsorPublicKey,
		&sponsorTmpPublicKey,
		&responsePublicKey,
		&responseTmpPublicKey,
		&hKeyHandle)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SDF_DestroyKey(
		hSessionHandle,
		hKeyHandle)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	/* 6.3.17 */
	/*
	if ((rv = SDF_ExchangeDigitEnvelopeBaseECC(
		hSession,
		uiECCKeyIndex,
		SGD_SM2_3,
		&eccPublicKey,
		(ECCCipher *)pucKeyIPKECC,
		(ECCCipher *)pucKeyEPKECC)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	*/
	return 1;
}

static int test_sdf_gen_symkey_ecc(void *hSessionHandle,
	unsigned int uiECCKeyIndex)
{
	ECCrefPublicKey eccEncPublicKey;
	unsigned int uiSM4KeyBits = 128;
	unsigned char pucKey[2048];
	void *hKeyHandle;
	int rv;

	/* 6.3.11 */
	memset(pucKey, 0, sizeof(pucKey));
	hKeyHandle = NULL;
	if ((rv = SDF_GenerateKeyWithIPK_ECC(
		hSessionHandle,
		uiECCKeyIndex,
		uiSM4KeyBits,
		(ECCCipher *)pucKey,
		&hKeyHandle)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}
	if ((rv = SDF_DestroyKey(
		hSessionHandle,
		hKeyHandle)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}
	hKeyHandle = NULL;

	/* 6.3.13 */
	if ((rv = SDF_ImportKeyWithISK_ECC(
		hSessionHandle,
		uiECCKeyIndex,
		(ECCCipher *)pucKey,
		&hKeyHandle)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}
	if ((rv = SDF_DestroyKey(
		hSessionHandle,
		hKeyHandle)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}
	hKeyHandle = NULL;

	/* 6.3.8 */
	memset(&eccEncPublicKey, 0, sizeof(eccEncPublicKey));
	if ((rv = SDF_ExportEncPublicKey_ECC(
		hSessionHandle,
		uiECCKeyIndex,
		&eccEncPublicKey)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	/* 6.3.12 */
	memset(pucKey, 0, sizeof(pucKey));
	hKeyHandle = NULL;
	if ((rv = SDF_GenerateKeyWithEPK_ECC(
		hSessionHandle,
		uiSM4KeyBits,
		SGD_SM2_3,
		&eccEncPublicKey,
		(ECCCipher *)pucKey,
		&hKeyHandle)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}
	if ((rv = SDF_DestroyKey(
		hSessionHandle,
		hKeyHandle)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}
	hKeyHandle = NULL;

	/* 6.3.13 */
	if ((rv = SDF_ImportKeyWithISK_ECC(
		hSessionHandle,
		uiECCKeyIndex,
		(ECCCipher *)pucKey,
		&hKeyHandle)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}
	if ((rv = SDF_DestroyKey(
		hSessionHandle,
		hKeyHandle)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}
	hKeyHandle = NULL;

	return 1;
}

static int test_sdf_kek(void *hSessionHandle, unsigned int uiKEKIndex)
{
	unsigned char pucKey[16];
	unsigned int uiKeyLength;
	void *hKeyHandle;
	int rv;

	memset(pucKey, 0, sizeof(pucKey));
	uiKeyLength = sizeof(pucKey);
	hKeyHandle = NULL;

	/* 6.3.18 */
	if ((rv = SDF_GenerateKeyWithKEK(
		hSessionHandle,
		128, /* generated symmetric key bits */
		SGD_SM4, /* is this usefule ? */
		uiKEKIndex,
		pucKey,
		&uiKeyLength,
		&hKeyHandle)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	/* 6.3.20 */
	if ((rv = SDF_DestroyKey(
		hSessionHandle,
		hKeyHandle)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	hKeyHandle = NULL;

	/* 6.3.19 */
	if ((rv = SDF_ImportKeyWithKEK(
		hSessionHandle,
		SGD_SM4,
		uiKEKIndex,
		pucKey,
		uiKeyLength,
		&hKeyHandle)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	/* 6.3.20 */
	if ((rv = SDF_DestroyKey(
		hSessionHandle,
		hKeyHandle)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	return 1;
}

static int test_sdf_gen_keypair(void *hSessionHandle)
{
	RSArefPublicKey rsaPublicKey;
	RSArefPrivateKey rsaPrivateKey;
	ECCrefPublicKey eccPublicKey;
	ECCrefPrivateKey eccPrivateKey;
	int rv;

	/* 6.3.3 */

	/* 1024-bit RSA */
	memset(&rsaPublicKey, 0, sizeof(rsaPublicKey));
	memset(&rsaPrivateKey, 0, sizeof(rsaPrivateKey));

	if ((rv = SDF_GenerateKeyPair_RSA(
		hSessionHandle,
		1024,
		&rsaPublicKey,
		&rsaPrivateKey)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	printf("Generate 1024-bit RSA key pair success\n");
	printf("RSA Public Key:\n");
	(void)SDF_PrintRSAPublicKey(stdout, &rsaPublicKey);
	printf("RSA Private Key:\n");
	(void)SDF_PrintRSAPrivateKey(stdout, &rsaPrivateKey);

	/* 2048-bit RSA */
	memset(&rsaPublicKey, 0, sizeof(rsaPublicKey));
	memset(&rsaPrivateKey, 0, sizeof(rsaPrivateKey));

	if ((rv = SDF_GenerateKeyPair_RSA(
		hSessionHandle,
		2048,
		&rsaPublicKey,
		&rsaPrivateKey)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	printf("Generate 2048-bit RSA key pair success\n");
	printf("RSA Public Key:\n");
	(void)SDF_PrintRSAPublicKey(stdout, &rsaPublicKey);
	printf("RSA Private Key:\n");
	(void)SDF_PrintRSAPrivateKey(stdout, &rsaPrivateKey);

	/* 6.3.10 */
	memset(&eccPublicKey, 0, sizeof(eccPublicKey));
	memset(&eccPrivateKey, 0, sizeof(eccPrivateKey));
	if ((rv = SDF_GenerateKeyPair_ECC(
		hSessionHandle,
		SGD_SM2,
		256,
		&eccPublicKey,
		&eccPrivateKey)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	(void)SDF_PrintECCPublicKey(stdout, &eccPublicKey);
	(void)SDF_PrintECCPrivateKey(stdout, &eccPrivateKey);

	return 1;
}

static int test_sdf_rsa(void *hSessionHandle, unsigned int uiRSAKeyIndex)
{
	RSArefPublicKey rsaSignPublicKey;
	RSArefPublicKey rsaEncPublicKey;
	unsigned char pucData[] = "abc";
	unsigned int uiDataLength = sizeof(pucData) - 1;
	unsigned char pucRSASignature[2048/8];
	unsigned int uiRSASignatureLength;
	unsigned char pucOutputData[2048/8];
	unsigned int uiOutputLength;
	int rv;

	memset(&rsaSignPublicKey, 0, sizeof(rsaSignPublicKey));
	memset(&rsaEncPublicKey, 0, sizeof(rsaEncPublicKey));

	/* 6.3.2 */
	if ((rv = SDF_ExportEncPublicKey_RSA(
		hSessionHandle,
		uiRSAKeyIndex,
		&rsaEncPublicKey)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	(void)SDF_PrintRSAPublicKey(stdout, &rsaEncPublicKey);

	/* 6.2.7 */
	if ((rv = SDF_GetPrivateKeyAccessRight(
		hSessionHandle,
		uiRSAKeyIndex,
		pucRSAPassword,
		uiRSAPwdLength)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	/* 6.4.3 */
	if ((rv = SDF_InternalPrivateKeyOperation_RSA(
		hSessionHandle,
		uiRSAKeyIndex,
		pucData,
		uiDataLength,
		pucRSASignature,
		&uiRSASignatureLength)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	memset(pucOutputData, 0, sizeof(pucOutputData));
	uiOutputLength = sizeof(pucOutputData);

	/* 6.4.1 */
	if ((rv = SDF_ExternalPublicKeyOperation_RSA(
		hSessionHandle,
		&rsaSignPublicKey,
		pucRSASignature,
		uiRSASignatureLength,
		pucOutputData,
		&uiOutputLength)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	// check output == orignal input

	memset(pucOutputData, 0, sizeof(pucOutputData));
	uiOutputLength = sizeof(pucOutputData);

	/* 6.4.2 */
	if ((rv = SDF_InternalPublicKeyOperation_RSA(
		hSessionHandle,
		uiRSAKeyIndex,
		pucRSASignature,
		uiRSASignatureLength,
		pucOutputData,
		&uiOutputLength)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	// check output == orignal input
	return 1;
}

static int test_sdf_ec(void *hSessionHandle, unsigned int uiECCKeyIndex)
{
	unsigned char pucData[] = "abc";
	unsigned int uiDataLength = sizeof(pucData) - 1;
	ECCSignature eccSignature;
	ECCrefPublicKey eccSignPublicKey;
	ECCrefPublicKey eccEncPublicKey;
	unsigned char pucEncData[2048];
	int rv;

	memset(&eccSignature, 0, sizeof(eccSignature));

	/* 6.4.5 */
	if ((rv = SDF_InternalSign_ECC(
		hSessionHandle,
		uiECCKeyIndex,
		pucData,
		uiDataLength,
		&eccSignature)) != SDR_OK) {
	}

	/* 6.4.6 */
	if ((rv = SDF_InternalVerify_ECC(
		hSessionHandle,
		uiECCKeyIndex,
		pucData,
		uiDataLength,
		&eccSignature)) != SDR_OK) {
	}

	memset(&eccSignPublicKey, 0, sizeof(eccSignPublicKey));

	/* 6.3.8 */
	if ((rv = SDF_ExportSignPublicKey_ECC(
		hSessionHandle,
		uiECCKeyIndex,
		&eccSignPublicKey)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	(void)SDF_PrintECCPublicKey(stdout, &eccSignPublicKey);

	/* 6.4.4 */
	if ((rv = SDF_ExternalVerify_ECC(
		hSessionHandle,
		SGD_SM2_1,
		&eccSignPublicKey,
		pucData,
		uiDataLength,
		&eccSignature)) != SDR_OK) {
	}

	memset(&eccEncPublicKey, 0, sizeof(eccEncPublicKey));

	/* 6.3.9 */
	if ((rv = SDF_ExportEncPublicKey_ECC(
		hSessionHandle,
		uiECCKeyIndex,
		&eccEncPublicKey)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	(void)SDF_PrintECCPublicKey(stdout, &eccEncPublicKey);

	memset(pucEncData, 0, sizeof(pucEncData));

	/* 6.4.7 */
	if ((rv = SDF_ExternalEncrypt_ECC(
		hSessionHandle,
		SGD_SM2_3,
		&eccEncPublicKey,
		pucData,
		uiDataLength,
		(ECCCipher *)pucEncData)) != SDR_OK) {
	}

	return 1;
}

static int test_sdf_cipher(void *hSessionHandle, unsigned int uiKEKIndex)
{
	void *hKeyHandle;
	unsigned char pucKey[2048];
	unsigned int uiKeyLength;
	unsigned int uiSM4KeyBits = 128;
	unsigned int uiEncAlgID = SGD_SM4_CBC;
	unsigned int uiMACAlgID = SGD_SM4_MAC;
	unsigned char pucIV[16] = {0};
	unsigned char pucData[] = "12345678901234567890123456789012"; /* 32-byte = 2 blocks */
	unsigned int uiDataLength = sizeof(pucData);
	unsigned char pucEncData[sizeof(pucData)];
	unsigned int uiEncDataLength;
	unsigned char pucDecData[sizeof(pucData)];
	unsigned int uiDecDataLength;
	unsigned char pucMAC[32];
	unsigned int uiMACLength = sizeof(pucMAC);
	int rv;


	memset(pucKey, 0, sizeof(pucKey));
	uiKeyLength = 0;
	hKeyHandle = NULL;
	if ((rv = SDF_GenerateKeyWithKEK(
		hSessionHandle,
		uiSM4KeyBits,
		SGD_SM4,
		uiKEKIndex,
		pucKey,
		&uiKeyLength,
		&hKeyHandle)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	/* 6.5.1 */
	uiEncDataLength = sizeof(pucEncData);
	if ((rv = SDF_Encrypt(
		hSessionHandle,
		hKeyHandle,
		uiEncAlgID,
		pucIV,
		pucData,
		uiDataLength,
		pucEncData,
		&uiEncDataLength)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	/* 6.5.2 */
	uiDecDataLength = sizeof(pucDecData);
	if ((rv = SDF_Decrypt(
		hSessionHandle,
		hKeyHandle,
		uiEncAlgID,
		pucIV,
		pucEncData,
		uiEncDataLength,
		pucDecData,
		&uiDecDataLength)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if (uiDecDataLength != uiDataLength ||
		memcmp(pucDecData, pucData, uiDataLength) != 0) {
		fprintf(stderr, "Error (%s %d): SDF_Encrypt/Decrypt failed\n", __FILE__, __LINE__);
	}

	/* 6.5.3 */
	if ((rv = SDF_CalculateMAC(
		hSessionHandle,
		hKeyHandle,
		uiMACAlgID,
		pucIV,
		pucData,
		uiDataLength,
		pucMAC,
		&uiMACLength)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	return 1;
}

static int test_sdf_hash(void *hSessionHandle, unsigned int uiECCKeyIndex)
{
	ECCrefPublicKey eccSignPublicKey;
	unsigned char pucID[] = "1234567812345678";
	unsigned int uiIDLength = sizeof(pucID) - 1;
	unsigned char pucData[] = "abc";
	unsigned int uiDataLength = sizeof(pucData) - 1;
	unsigned char sm3abc[] = {
		0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9,
		0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
		0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2,
		0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0,
	};
	unsigned char pucHash[64];
	unsigned int uiHashLength;
	int rv;

	/* 6.6.1 */
	if ((rv = SDF_HashInit(
		hSessionHandle,
		SGD_SM3,
		NULL,
		NULL,
		0)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	/* 6.6.2 */
	if ((rv = SDF_HashUpdate(
		hSessionHandle,
		pucData,
		uiDataLength)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	/* 6.6.3 */
	uiHashLength = sizeof(pucHash);
	if ((rv = SDF_HashFinal(
		hSessionHandle,
		pucHash,
		&uiHashLength)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if (uiHashLength != sizeof(sm3abc) ||
		memcmp(pucHash, sm3abc, sizeof(sm3abc)) != 0) {
		fprintf(stderr, "Error: SM3 hash \"abc\" failed\n");
	}

	/* prepare public key */
	memset(&eccSignPublicKey, 0, sizeof(eccSignPublicKey));
	if ((rv = SDF_ExportSignPublicKey_ECC(
		hSessionHandle,
		uiECCKeyIndex,
		&eccSignPublicKey)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	/* 6.6.1 */
	if ((rv = SDF_HashInit(
		hSessionHandle,
		SGD_SM3,
		&eccSignPublicKey,
		pucID,
		uiIDLength)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	/* 6.6.2 */
	if ((rv = SDF_HashUpdate(
		hSessionHandle,
		pucData,
		uiDataLength)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	/* 6.6.3 */
	uiHashLength = (unsigned int)sizeof(pucHash);
	if ((rv = SDF_HashFinal(
		hSessionHandle,
		pucHash,
		&uiHashLength)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}


	return 1;
}

static int test_sdf_file(void *hSessionHandle)
{
	unsigned char pucFileName[128] = "certificate.cer";
	unsigned int uiNameLen = sizeof(pucFileName) - 1;
	unsigned char pucBuffer[4096];
	unsigned int uiFileLength;
	unsigned int uiFileLength2;
	unsigned int uiOffset = 0;
	int rv;

	/* 6.7.1 */
	uiFileLength = (unsigned int)sizeof(pucBuffer);
	if ((rv = SDF_CreateFile(
		hSessionHandle,
		pucFileName,
		uiNameLen,
		uiFileLength)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if (uiFileLength != sizeof(pucBuffer)) {
		printf("Warning: created file length = %u, shorter\n", uiFileLength);
	}

	/* 6.7.3 */
	memset(pucBuffer, 'A', sizeof(pucBuffer));
	if ((rv = SDF_WriteFile(
		hSessionHandle,
		pucFileName,
		uiNameLen,
		uiOffset,
		uiFileLength,
		pucBuffer)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	/* 6.7.2 */
	uiFileLength2 = uiFileLength;
	if ((rv = SDF_ReadFile(
		hSessionHandle,
		pucFileName,
		uiNameLen,
		uiOffset,
		&uiFileLength2,
		pucBuffer)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}
	if (uiFileLength2 != uiFileLength) {
		printf("Warning: read length length %u < %u\n", uiFileLength2, uiFileLength);
	}

	/* 6.7.4 */
	if ((rv = SDF_DeleteFile(
		hSessionHandle,
		pucFileName,
		uiNameLen)) != SDR_OK) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	return 1;
}

int main(int argc, char **argv)
{
	if (!test_sdf()) {
		return -1;
	}
	return 0;
}
#endif
