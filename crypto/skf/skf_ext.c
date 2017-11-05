/* ====================================================================
 * Copyright (c) 2014 - 2017 The GmSSL Project.  All rights reserved.
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
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <openssl/err.h>
#include <openssl/gmskf.h>
#include "internal/skf_int.h"
#include "../../e_os.h"


static void print_str(const char *name, const char *value)
{
	(void)printf("%-17s: %s\n", name, value);
}

static void print_int(const char *name, ULONG value)
{
	(void)printf("%-17s: ", name);
	if (value == UINT_MAX) {
		puts("(unlimited)");
	} else {
		printf("%u\n", value);
	}
}

static void print_buf(const char *name, BYTE *value, size_t len)
{
	size_t i;
	(void)printf("%-17s : ", name);
	for (i = 0; i < len; i++) {
		(void)printf("%02X", value[i]);
	}
	putchar('\n');
}

static char *skf_algor_name(ULONG ulAlgID)
{
	switch (ulAlgID) {
	case SGD_SM1_ECB: return "sm1-ecb";
	case SGD_SM1_CBC: return "sm1-cbc";
	case SGD_SM1_CFB: return "sm1-cfb";
	case SGD_SM1_OFB: return "sm1-ofb128";
	case SGD_SM1_MAC: return "sm1-mac";
	case SGD_SM4_ECB: return "sms4-ecb";
	case SGD_SM4_CBC: return "sms4-cbc";
	case SGD_SM4_CFB: return "sms4-cfb";
	case SGD_SM4_OFB: return "sms4-ofb128";
	case SGD_SM4_MAC: return "sms4-mac";
	case SGD_SSF33_ECB: return "ssf33-ecb";
	case SGD_SSF33_CBC: return "ssf33-cbc";
	case SGD_SSF33_CFB: return "ssf33-cfb";
	case SGD_SSF33_OFB: return "ssf33-ofb128";
	case SGD_SSF33_MAC: return "ssf33-mac";
	case SGD_RSA: return "rsa";
	case SGD_SM2_1: return "sm2sign";
	case SGD_SM2_2: return "sm2encrypt";
	case SGD_SM2_3: return "sm2keyagreement";
	case SGD_SM3: return "sm3";
	case SGD_SHA1: return "sha1";
	case SGD_SHA256: return "sha256";
	}
	return NULL;
}

ULONG SKF_GetDevStateName(ULONG ulDevState, LPSTR *szDevStateName)
{
	if (!szDevStateName) {
		return SAR_INDATALENERR;
	}

	switch (ulDevState) {
	case SKF_DEV_STATE_ABSENT:
		*szDevStateName = (LPSTR)"Absent";
		break;
	case SKF_DEV_STATE_PRESENT:
		*szDevStateName = (LPSTR)"Present";
		break;
	case SKF_DEV_STATE_UNKNOW:
		*szDevStateName = (LPSTR)"Unknown";
		break;
	default:
		*szDevStateName = (LPSTR)"(Error)";
		return SAR_INDATALENERR;
	}

	return SAR_OK;
}

ULONG SKF_GetContainerTypeName(ULONG ulContainerType, LPSTR *szName)
{
	switch (ulContainerType) {
	case SKF_CONTAINER_TYPE_UNDEF:
		*szName = (LPSTR)"(undef)";
		break;
	case SKF_CONTAINER_TYPE_RSA:
		*szName = (LPSTR)"RSA";
		break;
	case SKF_CONTAINER_TYPE_ECC:
		*szName = (LPSTR)"EC";
		break;
	default:
		*szName = (LPSTR)"(unknown)";
	}
	/* always success for help functions */
	return SAR_OK;
}

typedef struct {
	ULONG id;
	char *name;
} table_item_t;

static table_item_t skf_cipher_caps[] = {
	{ SGD_SM1_ECB, "sm1-ecb" },
	{ SGD_SM1_CBC, "sm1-cbc" },
	{ SGD_SM1_CFB, "sm1-cfb" },
	{ SGD_SM1_OFB, "sm1-ofb128" },
	{ SGD_SM1_MAC, "cbcmac-sm1" },
	{ SGD_SSF33_ECB, "ssf33-ecb" },
	{ SGD_SSF33_CBC, "ssf33-cbc" },
	{ SGD_SSF33_CFB, "ssf33-cfb" },
	{ SGD_SSF33_OFB, "ssf33-ofb128" },
	{ SGD_SSF33_MAC, "cbcmac-ssf33" },
	{ SGD_SM4_ECB, "sms4-ecb" },
	{ SGD_SM4_CBC, "sms4-cbc" },
	{ SGD_SM4_CFB, "sms4-cfb" },
	{ SGD_SM4_OFB, "sms4-ofb128" },
	{ SGD_SM4_MAC, "cbcmac-sms4" },
	{ SGD_ZUC_EEA3, "zuc_128eea3" },
	{ SGD_ZUC_EIA3, "zuc_128eia3" }
};

static table_item_t skf_digest_caps[] = {
	{ SGD_SM3,  "sm3" },
	{ SGD_SHA1, "sha1" },
	{ SGD_SHA256, "sha256" },
};

static table_item_t skf_pkey_caps[] = {
	{ SGD_RSA_SIGN, "rsa" },
	{ SGD_RSA_ENC, "rsaEncryption" },
	{ SGD_SM2_1, "sm2sign" },
	{ SGD_SM2_2, "sm2exchange" },
	{ SGD_SM2_3, "sm2encrypt" }
};

ULONG SKF_PrintDevInfo(DEVINFO *devInfo)
{
	int i, n;

	printf("  Version          : %d.%d\n", devInfo->Version.major,
						devInfo->Version.minor);
	printf("  Manufacturer     : %s\n", devInfo->Manufacturer);
	printf("  Issuer           : %s\n", devInfo->Issuer);
	printf("  Label            : %s\n", devInfo->Label);
	print_buf("  Serial Number", devInfo->SerialNumber, strlen((char *)devInfo->SerialNumber));
	printf("  Hardware Version : %d.%d\n", devInfo->HWVersion.major,
						devInfo->HWVersion.minor);
	printf("  Firmware Version : %d.%d\n", devInfo->FirmwareVersion.major,
						devInfo->FirmwareVersion.minor);
	printf("  Ciphers          : ");
	for (i = n = 0; i < OSSL_NELEM(skf_cipher_caps); i++) {
		if ((devInfo->AlgSymCap & skf_cipher_caps[i].id) ==
			skf_cipher_caps[i].id) {
			printf("%s%s", n ? ", " : "", skf_cipher_caps[i].name);
			n++;
		}
	}
	printf("\n");
	printf("  Public Keys      : ");
	for (i = n = 0; i < OSSL_NELEM(skf_pkey_caps); i++) {
		if ((devInfo->AlgAsymCap & skf_pkey_caps[i].id) ==
			skf_pkey_caps[i].id) {
			printf("%s%s", n ? ", " : "", skf_pkey_caps[i].name);
			n++;
		}
	}
	printf("\n");
	printf("  Digests          : ");
	for (i = n = 0; i < OSSL_NELEM(skf_digest_caps); i++) {
		if ((devInfo->AlgHashCap & skf_digest_caps[i].id) ==
			skf_digest_caps[i].id) {
			printf("%s%s", n ? ", " : "", skf_digest_caps[i].name);
			n++;
		}
	}
	printf("\n");
	printf("  Auth Cipher      : ");
	for (i = 0; i < OSSL_NELEM(skf_cipher_caps); i++) {
		if (devInfo->DevAuthAlgId == skf_cipher_caps[i].id) {
			printf("%s\n", skf_cipher_caps[i].name);
			break;
		}
	}
	if (i == OSSL_NELEM(skf_cipher_caps)) {
		printf("(unknown)\n");
	}
	print_int("  Total Sapce  ", devInfo->TotalSpace);
	print_int("  Free Space  ", devInfo->FreeSpace);
	print_int("  MAX ECC Input", devInfo->MaxECCBufferSize);
	print_int("  MAX Cipher Input", devInfo->MaxBufferSize);

	return SAR_OK;
}

ULONG SKF_PrintRSAPublicKey(RSAPUBLICKEYBLOB *blob)
{
	print_str("AlgID", skf_algor_name(blob->AlgID));
	print_int("BitLen", blob->BitLen);
	print_buf("Modulus", blob->Modulus, MAX_RSA_MODULUS_LEN);
	print_buf("PublicExponent", blob->PublicExponent, MAX_RSA_EXPONENT_LEN);
	return SAR_OK;
}

ULONG SKF_PrintRSAPrivateKey(RSAPRIVATEKEYBLOB *blob)
{
	print_str("AlgID", skf_algor_name(blob->AlgID));
	print_int("BitLen", blob->BitLen);
	print_buf("Modulus", blob->Modulus, MAX_RSA_MODULUS_LEN);
	print_buf("PublicExponent", blob->PublicExponent, MAX_RSA_EXPONENT_LEN);
	print_buf("PrivateExponent", blob->PrivateExponent, MAX_RSA_MODULUS_LEN);
	print_buf("Prime1", blob->Prime1, MAX_RSA_MODULUS_LEN/2);
	print_buf("Prime2", blob->Prime2, MAX_RSA_MODULUS_LEN/2);
	print_buf("Prime1Exponent", blob->Prime1Exponent, MAX_RSA_MODULUS_LEN/2);
	print_buf("Prime2Exponent", blob->Prime2Exponent, MAX_RSA_MODULUS_LEN/2);
	print_buf("Coefficient", blob->Coefficient, MAX_RSA_MODULUS_LEN/2);
	return SAR_OK;
}

ULONG SKF_PrintECCPublicKey(ECCPUBLICKEYBLOB *blob)
{
	print_int("BitLen", blob->BitLen);
	print_buf("XCoordinate", blob->XCoordinate, ECC_MAX_XCOORDINATE_BITS_LEN/8);
	print_buf("YCoordinate", blob->YCoordinate, ECC_MAX_XCOORDINATE_BITS_LEN/8);
	return SAR_OK;
}

ULONG SKF_PrintECCPrivateKey(ECCPRIVATEKEYBLOB *blob)
{
	print_int("BitLen", blob->BitLen);
	print_buf("PrivateKey", blob->PrivateKey, ECC_MAX_MODULUS_BITS_LEN/8);
	return SAR_OK;
}

ULONG SKF_PrintECCCipher(ECCCIPHERBLOB *blob)
{
	print_buf("XCoordinate", blob->XCoordinate, ECC_MAX_XCOORDINATE_BITS_LEN/8);
	print_buf("YCoordinate", blob->YCoordinate, ECC_MAX_XCOORDINATE_BITS_LEN/8);
	print_buf("HASH", blob->HASH, 32);
	print_int("CipherLen", blob->CipherLen);
	print_buf("Cipher", blob->Cipher, blob->CipherLen);
	return SAR_OK;
}

ULONG SKF_PrintECCSignature(ECCSIGNATUREBLOB *blob)
{
	print_buf("r", blob->r, ECC_MAX_XCOORDINATE_BITS_LEN/8);
	print_buf("s", blob->s, ECC_MAX_XCOORDINATE_BITS_LEN/8);
	return SAR_OK;
}

ULONG DEVAPI SKF_NewECCCipher(ULONG ulCipherLen, ECCCIPHERBLOB **cipherBlob)
{
	ECCCIPHERBLOB *ret = NULL;

	if (!(ret = OPENSSL_malloc(sizeof(ECCCIPHERBLOB) - 1 + ulCipherLen))) {
		SKFerr(SKF_F_SKF_NEWECCCIPHER, ERR_R_MALLOC_FAILURE);
		return SAR_MEMORYERR;
	}

	ret->CipherLen = ulCipherLen;
	*cipherBlob = ret;
	return SAR_OK;
}

ULONG DEVAPI SKF_NewEnvelopedKey(ULONG ulCipherLen, ENVELOPEDKEYBLOB **envelopedKeyBlob)
{
	ENVELOPEDKEYBLOB *ret = NULL;

	if (!(ret = OPENSSL_zalloc(sizeof(ENVELOPEDKEYBLOB) - 1 + ulCipherLen))) {
		SKFerr(SKF_F_SKF_NEWENVELOPEDKEY, ERR_R_MALLOC_FAILURE);
		return SAR_MEMORYERR;
	}

	ret->ECCCipherBlob.CipherLen = ulCipherLen;
	*envelopedKeyBlob = ret;
	return SAR_OK;
}

ULONG DEVAPI SKF_PrintErrorString(ULONG ulError)
{
	LPSTR str = NULL;
	SKF_GetErrorString(ulError, &str);
	printf("SKF Error: %s\n", (char *)str);
	return SAR_OK;
}

ULONG DEVAPI SKF_GetAlgorName(ULONG ulAlgID, LPSTR *szName)
{
	return SAR_OK;
}
