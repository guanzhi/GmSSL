/* ====================================================================
 * Copyright (c) 2014 - 2019 The GmSSL Project.  All rights reserved.
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

ULONG SKF_PrintDevInfo(BIO *out, DEVINFO *devInfo)
{
	size_t i, n;
	char *serial = OPENSSL_buf2hexstr(devInfo->SerialNumber, strlen((char *)devInfo->SerialNumber));

	BIO_printf(out, "  %-16s : %d.%d\n", "Version", devInfo->Version.major, devInfo->Version.minor);
	BIO_printf(out, "  %-16s : %s\n", "Manufacturer", devInfo->Manufacturer);
	BIO_printf(out, "  %-16s : %s\n", "Issuer", devInfo->Issuer);
	BIO_printf(out, "  %-16s : %s\n", "Label", devInfo->Label);
	BIO_printf(out, "  %-16s : %s\n", "Serial Number", serial);
	BIO_printf(out, "  %-16s : %d.%d\n", "Firmware Version", devInfo->HWVersion.major, devInfo->HWVersion.minor);

	BIO_printf(out, "  %-16s : ", "Ciphers");
	for (i = n = 0; i < OSSL_NELEM(skf_cipher_caps); i++) {
		if ((devInfo->AlgSymCap & skf_cipher_caps[i].id) ==
			skf_cipher_caps[i].id) {
			BIO_printf(out, "%s%s", n ? "," : "", skf_cipher_caps[i].name);
			n++;
		}
	}
	BIO_puts(out, "\n");

	BIO_printf(out, "  %-16s : ", "Public Keys");
	for (i = n = 0; i < OSSL_NELEM(skf_pkey_caps); i++) {
		if ((devInfo->AlgAsymCap & skf_pkey_caps[i].id) ==
			skf_pkey_caps[i].id) {
			BIO_printf(out, "%s%s", n ? "," : "", skf_pkey_caps[i].name);
			n++;
		}
	}
	BIO_puts(out, "\n");

	BIO_printf(out, "  %-16s : ", "Digests");
	for (i = n = 0; i < OSSL_NELEM(skf_digest_caps); i++) {
		if ((devInfo->AlgHashCap & skf_digest_caps[i].id) ==
			skf_digest_caps[i].id) {
			BIO_printf(out, "%s%s", n ? "," : "", skf_digest_caps[i].name);
			n++;
		}
	}
	BIO_puts(out, "\n");

	BIO_printf(out, "  %-16s : ", "Auth Cipher");
	for (i = 0; i < OSSL_NELEM(skf_cipher_caps); i++) {
		if (devInfo->DevAuthAlgId == skf_cipher_caps[i].id) {
			BIO_printf(out, "%s\n", skf_cipher_caps[i].name);
			break;
		}
	}
	if (i == OSSL_NELEM(skf_cipher_caps)) {
		BIO_puts(out, "(unknown)\n");
	}

	if (devInfo->TotalSpace == UINT_MAX)
		BIO_printf(out, "  %-16s : %s\n", "Total Sapce", "(unlimited)");
	else	BIO_printf(out, "  %-16s : %u\n", "Total Sapce", devInfo->TotalSpace);

	if (devInfo->FreeSpace == UINT_MAX)
		BIO_printf(out, "  %-16s : %s\n", "Free Space", "(unlimited)");
	else	BIO_printf(out, "  %-16s : %u\n", "Free Space", devInfo->FreeSpace);

	if (devInfo->MaxECCBufferSize == UINT_MAX)
		BIO_printf(out, "  %-16s : %s\n", "MAX ECC Input", "(unlimited)");
	else	BIO_printf(out, "  %-16s : %u\n", "MAX ECC Input", devInfo->MaxECCBufferSize);

	if (devInfo->MaxBufferSize == UINT_MAX)
		BIO_printf(out, "  %-16s : %s\n", "MAX Cipher Input", "(unlimited)");
	else	BIO_printf(out, "  %-16s : %u\n", "MAX Cipher Input", devInfo->MaxBufferSize);

	OPENSSL_free(serial);
	return SAR_OK;
}

ULONG SKF_PrintRSAPublicKey(BIO *out, RSAPUBLICKEYBLOB *blob)
{
	BIO_printf(out, "AlgID : %s\n", skf_algor_name(blob->AlgID));
	BIO_printf(out, "BitLen : %u\n", blob->BitLen);
	BIO_puts(out, "Modulus:\n");
	BIO_puts(out, "    ");
	BIO_hex_string(out, 4, 16, blob->Modulus, MAX_RSA_MODULUS_LEN);
	BIO_puts(out, "\n");
	BIO_puts(out, "PublicExponent:\n");
	BIO_puts(out, "    ");
	BIO_hex_string(out, 4, 16, blob->PublicExponent, MAX_RSA_EXPONENT_LEN);
	BIO_puts(out, "\n");
	return SAR_OK;
}

ULONG SKF_PrintRSAPrivateKey(BIO *out, RSAPRIVATEKEYBLOB *blob)
{
	BIO_printf(out, "AlgID : %s\n", skf_algor_name(blob->AlgID));
	BIO_printf(out, "BitLen : %u\n", blob->BitLen);
	BIO_puts(out, "Modulus:\n");
	BIO_puts(out, "    ");
	BIO_hex_string(out, 4, 16, blob->Modulus, MAX_RSA_MODULUS_LEN);
	BIO_puts(out, "\n");
	BIO_puts(out, "PublicExponent:\n");
	BIO_puts(out, "    ");
	BIO_hex_string(out, 4, 16, blob->PublicExponent, MAX_RSA_EXPONENT_LEN);
	BIO_puts(out, "\n");
	BIO_puts(out, "PrivateExponent:\n");
	BIO_puts(out, "    ");
	BIO_hex_string(out, 4, 16, blob->PrivateExponent, MAX_RSA_MODULUS_LEN);
	BIO_puts(out, "\n");
	BIO_puts(out, "Prime1:\n");
	BIO_puts(out, "    ");
	BIO_hex_string(out, 4, 16, blob->Prime1, MAX_RSA_MODULUS_LEN/2);
	BIO_puts(out, "\n");
	BIO_puts(out, "Prime2:\n");
	BIO_puts(out, "    ");
	BIO_hex_string(out, 4, 16, blob->Prime2, MAX_RSA_MODULUS_LEN/2);
	BIO_puts(out, "\n");
	BIO_puts(out, "Prime1Exponent:\n");
	BIO_hex_string(out, 4, 16, blob->Prime1Exponent, MAX_RSA_MODULUS_LEN/2);
	BIO_puts(out, "\n");
	BIO_puts(out, "    ");
	BIO_puts(out, "Prime2Exponent:\n");
	BIO_puts(out, "    ");
	BIO_hex_string(out, 4, 16, blob->Prime2Exponent, MAX_RSA_MODULUS_LEN/2);
	BIO_puts(out, "\n");
	BIO_puts(out, "Coefficient:\n");
	BIO_puts(out, "    ");
	BIO_hex_string(out, 4, 16, blob->Coefficient, MAX_RSA_MODULUS_LEN/2);
	BIO_puts(out, "\n");
	return SAR_OK;
}

ULONG SKF_PrintECCPublicKey(BIO *out, ECCPUBLICKEYBLOB *blob)
{
	BIO_printf(out, "BitLen : %u\n", blob->BitLen);
	BIO_puts(out, "XCoordinate:\n");
	BIO_puts(out, "    ");
	BIO_hex_string(out, 4, 16, blob->XCoordinate, ECC_MAX_XCOORDINATE_BITS_LEN/8);
	BIO_puts(out, "\n");
	BIO_puts(out, "YCoordinate:\n");
	BIO_puts(out, "    ");
	BIO_hex_string(out, 4, 16, blob->YCoordinate, ECC_MAX_XCOORDINATE_BITS_LEN/8);
	BIO_puts(out, "\n");
	return SAR_OK;
}

ULONG SKF_PrintECCPrivateKey(BIO *out, ECCPRIVATEKEYBLOB *blob)
{
	BIO_printf(out, "BitLen : %u\n", blob->BitLen);
	BIO_puts(out, "PrivateKey:\n");
	BIO_puts(out, "    ");
	BIO_hex_string(out, 4, 16, blob->PrivateKey, ECC_MAX_MODULUS_BITS_LEN/8);
	BIO_puts(out, "\n");
	return SAR_OK;
}

ULONG SKF_PrintECCCipher(BIO *out, ECCCIPHERBLOB *blob)
{
	BIO_puts(out, "XCoordinate:\n");
	BIO_puts(out, "    ");
	BIO_hex_string(out, 4, 16, blob->XCoordinate, ECC_MAX_XCOORDINATE_BITS_LEN/8);
	BIO_puts(out, "\n");
	BIO_puts(out, "YCoordinate:\n");
	BIO_puts(out, "    ");
	BIO_hex_string(out, 4, 16, blob->YCoordinate, ECC_MAX_XCOORDINATE_BITS_LEN/8);
	BIO_puts(out, "\n");
	BIO_puts(out, "HASH:\n");
	BIO_puts(out, "    ");
	BIO_hex_string(out, 4, 16, blob->HASH, 32);
	BIO_puts(out, "\n");
	BIO_printf(out, "CipherLen: %u\n", blob->CipherLen);
	BIO_puts(out, "Cipher:\n");
	BIO_puts(out, "    ");
	BIO_hex_string(out, 4, 16, blob->Cipher, blob->CipherLen);
	BIO_puts(out, "\n");
	return SAR_OK;
}

ULONG SKF_PrintECCSignature(BIO *out, ECCSIGNATUREBLOB *blob)
{
	BIO_puts(out, "r:\n");
	BIO_puts(out, "    ");
	BIO_hex_string(out, 4, 16, blob->r, ECC_MAX_XCOORDINATE_BITS_LEN/8);
	BIO_puts(out, "\n");
	BIO_puts(out, "s:\n");
	BIO_puts(out, "    ");
	BIO_hex_string(out, 4, 16, blob->s, ECC_MAX_XCOORDINATE_BITS_LEN/8);
	BIO_puts(out, "\n");
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

ULONG DEVAPI SKF_PrintErrorString(BIO *out, ULONG ulError)
{
	LPSTR str = NULL;
	SKF_GetErrorString(ulError, &str);
	BIO_printf(out, "SKF Error: %s\n", (char *)str);
	return SAR_OK;
}
