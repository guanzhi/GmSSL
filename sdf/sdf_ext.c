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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "sdf_int.h"
#include "sdf_sansec.h"



int format_bytes(FILE *out, int indent, int format, const uint8_t *data, size_t datalen)
{
	return 0;
}

#define SDFerr(a,b)


typedef struct {
	ULONG id;
	char *name;
} table_item_t;

static table_item_t sdf_cipher_caps[] = {
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

static table_item_t sdf_digest_caps[] = {
	{ SGD_SM3,  "sm3" },
	{ SGD_SHA1, "sha1" },
	{ SGD_SHA256, "sha256" },
};

static table_item_t sdf_pkey_caps[] = {
	{ SGD_RSA_SIGN, "rsa" },
	{ SGD_RSA_ENC, "rsaEncryption" },
	{ SGD_SM2_1, "sm2sign" },
	{ SGD_SM2_2, "sm2exchange" },
	{ SGD_SM2_3, "sm2encrypt" }
};

int SDF_PrintDeviceInfo(FILE *out, DEVICEINFO *pstDeviceInfo)
{
	size_t i, n;
	DEVICEINFO buf;
	DEVICEINFO *devInfo = &buf;

	memcpy(devInfo, pstDeviceInfo, sizeof(DEVICEINFO));
	devInfo->IssuerName[39] = 0;
	devInfo->DeviceName[15] = 0;
	devInfo->DeviceSerial[15] = 0;

	fprintf(out, "  %-18s : %s\n", "Device Name", devInfo->DeviceName);
	fprintf(out, "  %-18s : %s\n", "Serial Number", devInfo->DeviceSerial);
	fprintf(out, "  %-18s : %s\n", "Issuer", devInfo->IssuerName);
	fprintf(out, "  %-18s : %u\n", "Hardware Version", devInfo->DeviceVersion);
	fprintf(out, "  %-18s : %u\n", "Standard Version", devInfo->StandardVersion);
	fprintf(out, "  %-18s : ", "Public Key Algors");
	for (i = n = 0; i < sizeof(sdf_pkey_caps)/sizeof(sdf_pkey_caps[0]); i++) {
		if ((devInfo->AsymAlgAbility[0] & sdf_pkey_caps[i].id) ==
			sdf_pkey_caps[i].id) {
			fprintf(out, "%s%s", n ? "," : "", sdf_pkey_caps[i].name);
			n++;
		}
	}
	fprintf(out, "\n");

	fprintf(out, "  %-18s : ", "Ciphers");
	for (i = n = 0; i < sizeof(sdf_cipher_caps)/sizeof(sdf_cipher_caps[0]); i++) {
		if ((devInfo->SymAlgAbility & sdf_cipher_caps[i].id) ==
			sdf_cipher_caps[i].id) {
			fprintf(out, "%s%s", n ? "," : "", sdf_cipher_caps[i].name);
			n++;
		}
	}
	fprintf(out, "\n");

	fprintf(out, "  %-18s : ", "Digests");
	for (i = n = 0; i < sizeof(sdf_digest_caps)/sizeof(sdf_digest_caps[0]); i++) {
		if ((devInfo->HashAlgAbility & sdf_digest_caps[i].id) ==
			sdf_digest_caps[i].id) {
			fprintf(out, "%s%s", n ? "," : "", sdf_digest_caps[i].name);
			n++;
		}
	}
	fprintf(out, "\n");
	fprintf(out, "\n");

	return SDR_OK;
}

int SDF_PrintRSAPublicKey(FILE *out, RSArefPublicKey *blob)
{
	(void)fprintf(out, "bits: %d\n", blob->bits);
	(void)fprintf(out, "m:\n    ");
	(void)format_bytes(out, 4, 16, blob->m, sizeof(blob->m));
	(void)fprintf(out, "\n");
	(void)fprintf(out, "e:\n    ");
	(void)format_bytes(out, 4, 16, blob->e, sizeof(blob->e));
	(void)fprintf(out, "\n");
	return SDR_OK;
}

int SDF_PrintRSAPrivateKey(FILE *bio, RSArefPrivateKey *blob)
{
	(void)fprintf(bio, "bits: %d", blob->bits);
	(void)fprintf(bio, "\n%s:\n    ", "m");
	(void)format_bytes(bio, 4, 16, blob->m, sizeof(blob->m));
	(void)fprintf(bio, "\n%s:\n    ", "e");
	(void)format_bytes(bio, 4, 16, blob->e, sizeof(blob->e));
	(void)fprintf(bio, "\n%s:\n    ", "d");
	(void)format_bytes(bio, 4, 16, blob->d, sizeof(blob->d));
	(void)fprintf(bio, "\n%s:\n    ", "prime[0]");
	(void)format_bytes(bio, 4, 16, blob->prime[0], sizeof(blob->prime[0]));
	(void)fprintf(bio, "\n%s:\n    ", "prime[1]");
	(void)format_bytes(bio, 4, 16, blob->prime[1], sizeof(blob->prime[1]));
	(void)fprintf(bio, "\n%s:\n    ", "pexp[0]");
	(void)format_bytes(bio, 4, 16, blob->pexp[0], sizeof(blob->pexp[0]));
	(void)fprintf(bio, "\n%s:\n    ", "pexp[1]");
	(void)format_bytes(bio, 4, 16, blob->pexp[1], sizeof(blob->pexp[1]));
	(void)fprintf(bio, "\n%s:\n    ", "coef");
	(void)format_bytes(bio, 4, 16, blob->coef, sizeof(blob->coef));
	(void)fprintf(bio, "\n");

	return SDR_OK;
}

int SDF_PrintECCPublicKey(FILE *bio, ECCrefPublicKey *blob)
{
	(void)fprintf(bio, "bits: %d", blob->bits);
	(void)fprintf(bio, "\n%s:\n    ", "x");
	(void)format_bytes(bio, 4, 16, blob->x, sizeof(blob->x));
	(void)fprintf(bio, "\n%s:\n    ", "y");
	(void)format_bytes(bio, 4, 16, blob->y, sizeof(blob->y));
	(void)fprintf(bio, "\n");

	return SDR_OK;
}

int SDF_PrintECCPrivateKey(FILE *bio, ECCrefPrivateKey *blob)
{
	(void)fprintf(bio, "bits: %d", blob->bits);
	(void)fprintf(bio, "\n%s:\n    ", "K");
	(void)format_bytes(bio, 4, 16, blob->K, sizeof(blob->K));
	(void)fprintf(bio, "\n");

	return SDR_OK;
}

int SDF_PrintECCCipher(FILE *bio, ECCCipher *blob)
{
	(void)fprintf(bio, "%s:\n    ", "x");
	(void)format_bytes(bio, 4, 16, blob->x, sizeof(blob->x));
	(void)fprintf(bio, "\n%s:\n    ", "y");
	(void)format_bytes(bio, 4, 16, blob->y, sizeof(blob->y));
	(void)fprintf(bio, "\n%s:\n    ", "M");
	(void)format_bytes(bio, 4, 16, blob->M, sizeof(blob->M));
	(void)fprintf(bio, "\nL: %d", blob->L);
	(void)fprintf(bio, "\n%s:\n    ", "C");
	(void)format_bytes(bio, 4, 16, blob->C, sizeof(blob->C));
	(void)fprintf(bio, "\n");

	return SDR_OK;
}

int SDF_PrintECCSignature(FILE *bio, ECCSignature *blob)
{
	(void)fprintf(bio, "%s:\n    ", "r");
	(void)format_bytes(bio, 4, 16, blob->r, sizeof(blob->r));
	(void)fprintf(bio, "\n%s:\n    ", "s");
	(void)format_bytes(bio, 4, 16, blob->s, sizeof(blob->s));
	(void)fprintf(bio, "\n");

	return SDR_OK;
}

int SDF_ImportKey(
	void *hSessionHandle,
	unsigned char *pucKey,
	unsigned int uiKeyLength,
	void **phKeyHandle)
{
	(void)hSessionHandle;
	(void)pucKey;
	(void)uiKeyLength;
	(void)phKeyHandle;
	SDFerr(SDF_F_SDF_IMPORTKEY, SDF_R_NOT_IMPLEMENTED);
	return SDR_NOTSUPPORT;
}

int SDF_NewECCCipher(ECCCipher **cipher, size_t ulDataLen)
{
	ECCCipher *ecc_cipher = NULL;
	size_t len;

	if (!cipher) {
		SDFerr(SDF_F_SDF_NEWECCCIPHER, ERR_R_PASSED_NULL_PARAMETER);
		return SDR_INARGERR;
	}

	if (!ulDataLen || ulDataLen > INT_MAX) {
		SDFerr(SDF_F_SDF_NEWECCCIPHER,
			SDF_R_INVALID_SM2_CIPHERTEXT_LENGTH);
		return SDR_INARGERR;
	}

	len = sizeof(ECCCipher) - 1 + ulDataLen;
	if (len < sizeof(SANSEC_ECCCipher)) {
		len = sizeof(SANSEC_ECCCipher);
	}

	if (!(ecc_cipher = malloc(len))) {
		SDFerr(SDF_F_SDF_NEWECCCIPHER, ERR_R_MALLOC_FAILURE);
		return SDR_NOBUFFER;
	}
	memset(ecc_cipher, 0, sizeof(*ecc_cipher));

	ecc_cipher->L = (unsigned int)ulDataLen;

	*cipher = ecc_cipher;
	return SDR_OK;
}

int SDF_FreeECCCipher(ECCCipher *cipher)
{
	free(cipher);
	return SDR_OK;
}
