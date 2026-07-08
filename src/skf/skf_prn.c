/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <gmssl/error.h>
#include "skf.h"
#include "skf_int.h"
#include "skf_ext.h"



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

ULONG DEVAPI SKF_GetDevStateName(ULONG ulDevState, LPSTR *szDevStateName)
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

ULONG DEVAPI SKF_GetContainerTypeName(ULONG ulContainerType, LPSTR *szName)
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

ULONG DEVAPI SKF_PrintDevInfo(FILE *fp, const DEVINFO *devInfo)
{
	size_t i, n;
	int fmt = 0, ind = 4;

	format_print(fp, fmt, ind, "Version: %d.%d\n", devInfo->Version.major, devInfo->Version.minor);
	format_print(fp, fmt, ind, "Manufacturer: %s\n", devInfo->Manufacturer);
	format_print(fp, fmt, ind, "Issuer: %s\n", devInfo->Issuer);
	format_print(fp, fmt, ind, "Label: %s\n", devInfo->Label);
	format_bytes(fp, fmt, ind, "SerialNumber", devInfo->SerialNumber, strlen((char *)devInfo->SerialNumber));
	format_print(fp, fmt, ind, "FirmwareVersion: %d.%d\n", devInfo->HWVersion.major, devInfo->HWVersion.minor);

	format_print(fp, fmt, ind, "Ciphers: ");
	for (i = n = 0; i < sizeof(skf_cipher_caps)/sizeof(skf_cipher_caps[0]); i++) {
		if ((devInfo->AlgSymCap & skf_cipher_caps[i].id) ==
			skf_cipher_caps[i].id) {
			format_print(fp, fmt, 0, "%s%s", n ? "," : "", skf_cipher_caps[i].name);
			n++;
		}
	}
	format_print(fp, fmt, 0, "\n");

	format_print(fp, fmt, ind, "Public Keys: ");
	for (i = n = 0; i < sizeof(skf_pkey_caps)/sizeof(skf_pkey_caps[0]); i++) {
		if ((devInfo->AlgAsymCap & skf_pkey_caps[i].id) ==
			skf_pkey_caps[i].id) {
			format_print(fp, fmt, 0, "%s%s", n ? "," : "", skf_pkey_caps[i].name);
			n++;
		}
	}
	format_print(fp, fmt, 0, "\n");

	format_print(fp, fmt, ind, "Digests: ");
	for (i = n = 0; i < sizeof(skf_digest_caps)/sizeof(skf_digest_caps[0]); i++) {
		if ((devInfo->AlgHashCap & skf_digest_caps[i].id) ==
			skf_digest_caps[i].id) {
			format_print(fp, fmt, 0, "%s%s", n ? "," : "", skf_digest_caps[i].name);
			n++;
		}
	}
	format_print(fp, fmt, 0, "\n");

	format_print(fp, fmt, ind, "AuthCipher");
	for (i = 0; i < sizeof(skf_cipher_caps)/sizeof(skf_cipher_caps[0]); i++) {
		if (devInfo->DevAuthAlgId == skf_cipher_caps[i].id) {
			format_print(fp, fmt, 0, "%s\n", skf_cipher_caps[i].name);
			break;
		}
	}
	if (i == sizeof(skf_cipher_caps)/sizeof(skf_cipher_caps[0])) {
		format_print(fp, fmt, 0, "(unknown)\n");
	}
	format_print(fp, fmt, 0, "\n");



	if (devInfo->TotalSpace == UINT_MAX)
		format_print(fp, fmt, ind, "Total Sapce: %s\n", "(unlimited)");
	else	format_print(fp, fmt, ind, "Total Sapce: %u\n", devInfo->TotalSpace);

	if (devInfo->FreeSpace == UINT_MAX)
		format_print(fp, fmt, ind, "Free Space: %s\n", "(unlimited)");
	else	format_print(fp, fmt, ind, "Free Space: %u\n", devInfo->FreeSpace);

	if (devInfo->MaxECCBufferSize == UINT_MAX)
		format_print(fp, fmt, ind, "MAX ECC Input: %s\n", "(unlimited)");
	else	format_print(fp, fmt, ind, "MAX ECC Input: %u\n",  devInfo->MaxECCBufferSize);

	if (devInfo->MaxBufferSize == UINT_MAX)
		format_print(fp, fmt, ind, "MAX Cipher Input: %s\n", "(unlimited)");
	else	format_print(fp, fmt, ind, "MAX Cipher Input: %u\n", devInfo->MaxBufferSize);

	return SAR_OK;
}

ULONG DEVAPI SKF_PrintRSAPublicKey(FILE *fp, const RSAPUBLICKEYBLOB *blob)
{
	int fmt = 0, ind = 4;
	format_print(fp, fmt, ind, "AlgID: %s\n", skf_algor_name(blob->AlgID));
	format_print(fp, fmt, ind, "BitLen: %u\n", blob->BitLen);
	format_bytes(fp, fmt, ind, "Modulus", blob->Modulus, MAX_RSA_MODULUS_LEN);
	format_bytes(fp, fmt, ind, "PublicExponent", blob->PublicExponent, MAX_RSA_EXPONENT_LEN);
	return SAR_OK;
}

ULONG DEVAPI SKF_PrintRSAPrivateKey(FILE *fp, const RSAPRIVATEKEYBLOB *blob)
{
	int fmt = 0, ind = 4;
	format_print(fp, fmt, ind, "AlgID: %s\n", skf_algor_name(blob->AlgID));
	format_print(fp, fmt, ind, "BitLen: %u\n", blob->BitLen);
	format_bytes(fp, fmt, ind, "Modulus", blob->Modulus, MAX_RSA_MODULUS_LEN);
	format_bytes(fp, fmt, ind, "PublicExponent", blob->PublicExponent, MAX_RSA_EXPONENT_LEN);
	format_bytes(fp, fmt, ind, "PrivateExponent", blob->PrivateExponent, MAX_RSA_MODULUS_LEN);
	format_bytes(fp, fmt, ind, "Prime1", blob->Prime1, MAX_RSA_MODULUS_LEN/2);
	format_bytes(fp, fmt, ind, "Prime2", blob->Prime2, MAX_RSA_MODULUS_LEN/2);
	format_bytes(fp, fmt, ind, "Prime1Exponent", blob->Prime1Exponent, MAX_RSA_MODULUS_LEN/2);
	format_bytes(fp, fmt, ind, "Prime2Exponent", blob->Prime2Exponent, MAX_RSA_MODULUS_LEN/2);
	format_bytes(fp, fmt, ind, "Coefficient", blob->Coefficient, MAX_RSA_MODULUS_LEN/2);
	return SAR_OK;
}

ULONG DEVAPI SKF_PrintECCPublicKey(FILE *fp, const ECCPUBLICKEYBLOB *blob)
{
	int fmt = 0, ind = 4;
	format_print(fp, fmt, ind, "BitLen: %u\n", blob->BitLen);
	format_bytes(fp, fmt, ind, "XCoordinate", blob->XCoordinate, ECC_MAX_XCOORDINATE_BITS_LEN/8);
	format_bytes(fp, fmt, ind, "YCoordinate", blob->YCoordinate, ECC_MAX_XCOORDINATE_BITS_LEN/8);
	return SAR_OK;
}

ULONG DEVAPI SKF_PrintECCPrivateKey(FILE *fp, const ECCPRIVATEKEYBLOB *blob)
{
	int fmt = 0, ind = 4;
	format_print(fp, fmt, ind, "BitLen: %u\n", blob->BitLen);
	format_bytes(fp, fmt, ind, "PrivateKey", blob->PrivateKey, ECC_MAX_MODULUS_BITS_LEN/8);
	return SAR_OK;
}

ULONG DEVAPI SKF_PrintECCCipher(FILE *fp, const ECCCIPHERBLOB *blob)
{
	int fmt = 0, ind = 4;
	format_bytes(fp, fmt, ind, "XCoordinate", blob->XCoordinate, ECC_MAX_XCOORDINATE_BITS_LEN/8);
	format_bytes(fp, fmt, ind, "YCoordinate", blob->YCoordinate, ECC_MAX_XCOORDINATE_BITS_LEN/8);
	format_bytes(fp, fmt, ind, "HASH", blob->HASH, 32);
	format_print(fp, fmt, ind, "CipherLen: %u\n", blob->CipherLen);
	format_bytes(fp, fmt, ind, "Cipher", blob->Cipher, blob->CipherLen);
	return SAR_OK;
}

ULONG DEVAPI SKF_PrintECCSignature(FILE *fp, const ECCSIGNATUREBLOB *blob)
{
	int fmt = 0, ind = 4;
	format_bytes(fp, fmt, ind, "r", blob->r, ECC_MAX_XCOORDINATE_BITS_LEN/8);
	format_bytes(fp, fmt, ind, "s", blob->s, ECC_MAX_XCOORDINATE_BITS_LEN/8);
	return SAR_OK;
}

ULONG DEVAPI SKF_GetAlgorName(ULONG ulAlgID, LPSTR *szName)
{
	char *name;
	if ((name = skf_algor_name(ulAlgID)) != NULL) {
		*szName = (LPSTR)&name;
		return SAR_OK;
	}
	return SAR_FAIL;
}

ULONG DEVAPI SKF_PrintErrorString(FILE *fp, ULONG ulError)
{
	LPSTR str = NULL;
	SKF_GetErrorString(ulError, &str);
	fprintf(fp, "SKF Error: %s\n", (char *)str);
	return SAR_OK;
}
