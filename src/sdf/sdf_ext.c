/* ====================================================================
 * Copyright (c) 2016 - 2017 The GmSSL Project.  All rights reserved.
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
#include <stdint.h>
#include <limits.h>
#include <gmssl/error.h>
#include "sdf_int.h"
#include "sdf_sansec.h"


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

int SDF_PrintDeviceInfo(FILE *fp, const DEVICEINFO *pstDeviceInfo)
{
	size_t i, n;
	DEVICEINFO buf;
	DEVICEINFO *devInfo = &buf;
	int fmt = 0, ind = 4;

	memcpy(devInfo, pstDeviceInfo, sizeof(DEVICEINFO));
	devInfo->IssuerName[39] = 0;
	devInfo->DeviceName[15] = 0;
	devInfo->DeviceSerial[15] = 0;

	format_print(fp, fmt, ind, "%-18s: %s\n", "Device Name", devInfo->DeviceName);
	format_print(fp, fmt, ind, "%-18s: %s\n", "Serial Number", devInfo->DeviceSerial);
	format_print(fp, fmt, ind, "%-18s: %s\n", "Issuer", devInfo->IssuerName);
	format_print(fp, fmt, ind, "%-18s: %u\n", "Hardware Version", devInfo->DeviceVersion);
	format_print(fp, fmt, ind, "%-18s: %u\n", "Standard Version", devInfo->StandardVersion);
	format_print(fp, fmt, ind, "%-18s: ", "Public Key Algors");
	for (i = n = 0; i < sizeof(sdf_pkey_caps)/sizeof(sdf_pkey_caps[0]); i++) {
		if ((devInfo->AsymAlgAbility[0] & sdf_pkey_caps[i].id) ==
			sdf_pkey_caps[i].id) {
			format_print(fp, fmt, 0, "%s%s", n ? "," : "", sdf_pkey_caps[i].name);
			n++;
		}
	}
	format_print(fp, fmt, 0, "\n");

	format_print(fp, fmt, ind, "%-18s: ", "Ciphers");
	for (i = n = 0; i < sizeof(sdf_cipher_caps)/sizeof(sdf_cipher_caps[0]); i++) {
		if ((devInfo->SymAlgAbility & sdf_cipher_caps[i].id) ==
			sdf_cipher_caps[i].id) {
			format_print(fp, fmt, 0, "%s%s", n ? "," : "", sdf_cipher_caps[i].name);
			n++;
		}
	}
	format_print(fp, fmt, 0, "\n");

	format_print(fp, fmt, ind, "%-18s: ", "Digests");
	for (i = n = 0; i < sizeof(sdf_digest_caps)/sizeof(sdf_digest_caps[0]); i++) {
		if ((devInfo->HashAlgAbility & sdf_digest_caps[i].id) ==
			sdf_digest_caps[i].id) {
			format_print(fp, fmt, 0, "%s%s", n ? "," : "", sdf_digest_caps[i].name);
			n++;
		}
	}
	format_print(fp, fmt, 0, "\n");
	return SDR_OK;
}

int SDF_PrintRSAPublicKey(FILE *fp, const RSArefPublicKey *blob)
{
	int fmt = 0, ind = 4;
	(void)format_print(fp, fmt, ind, "bits: %d\n", blob->bits);
	(void)format_bytes(fp, fmt, ind, "m", blob->m, sizeof(blob->m));
	(void)format_bytes(fp, fmt, ind, "e", blob->e, sizeof(blob->e));
	return SDR_OK;
}

int SDF_PrintRSAPrivateKey(FILE *fp, const RSArefPrivateKey *blob)
{
	int fmt = 0, ind = 4;
	(void)format_print(fp, fmt, ind, "bits: %d", blob->bits);
	(void)format_bytes(fp, fmt, ind, "m", blob->m, sizeof(blob->m));
	(void)format_bytes(fp, fmt, ind, "e", blob->e, sizeof(blob->e));
	(void)format_bytes(fp, fmt, ind, "d", blob->d, sizeof(blob->d));
	(void)format_bytes(fp, fmt, ind, "prime[0]", blob->prime[0], sizeof(blob->prime[0]));
	(void)format_bytes(fp, fmt, ind, "prime[1]", blob->prime[1], sizeof(blob->prime[1]));
	(void)format_bytes(fp, fmt, ind, "pexp[0]", blob->pexp[0], sizeof(blob->pexp[0]));
	(void)format_bytes(fp, fmt, ind, "pexp[1]", blob->pexp[1], sizeof(blob->pexp[1]));
	(void)format_bytes(fp, fmt, ind, "coef", blob->coef, sizeof(blob->coef));
	return SDR_OK;
}

int SDF_PrintECCPublicKey(FILE *fp, const ECCrefPublicKey *blob)
{
	int fmt = 0, ind = 4;
	(void)format_print(fp, fmt, ind, "bits: %d", blob->bits);
	(void)format_bytes(fp, fmt, ind, "x", blob->x, sizeof(blob->x));
	(void)format_bytes(fp, fmt, ind, "y", blob->y, sizeof(blob->y));
	return SDR_OK;
}

int SDF_PrintECCPrivateKey(FILE *fp, const ECCrefPrivateKey *blob)
{
	int fmt = 0, ind = 4;
	(void)format_print(fp, fmt, ind, "bits: %d", blob->bits);
	(void)format_bytes(fp, fmt, ind, "K", blob->K, sizeof(blob->K));
	return SDR_OK;
}

int SDF_PrintECCCipher(FILE *fp, const ECCCipher *blob)
{
	int fmt = 0, ind = 4;
	(void)format_bytes(fp, fmt, ind, "x", blob->x, sizeof(blob->x));
	(void)format_bytes(fp, fmt, ind, "y", blob->y, sizeof(blob->y));
	(void)format_bytes(fp, fmt, ind, "M", blob->M, sizeof(blob->M));
	(void)format_print(fp, fmt, ind, "L: %d", blob->L);
	(void)format_bytes(fp, fmt, ind, "C", blob->C, sizeof(blob->C));
	return SDR_OK;
}

int SDF_PrintECCSignature(FILE *fp, const ECCSignature *blob)
{
	int fmt = 0, ind = 4;
	(void)format_bytes(fp, fmt, ind, "r", blob->r, sizeof(blob->r));
	(void)format_bytes(fp, fmt, ind, "s", blob->s, sizeof(blob->s));
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

const char *SDF_GetErrorReason(int err)
{
	switch (err) {
	case SDR_OK: return "SDR_OK";
	case SDR_BASE: return "SDR_BASE";
	case SDR_UNKNOWERR: return "SDR_UNKNOWERR";
	case SDR_NOTSUPPORT: return "SDR_NOTSUPPORT";
	case SDR_COMMFAIL: return "SDR_COMMFAIL";
	case SDR_HARDFAIL: return "SDR_HARDFAIL";
	case SDR_OPENDEVICE: return "SDR_OPENDEVICE";
	case SDR_OPENSESSION: return "SDR_OPENSESSION";
	case SDR_PARDENY: return "SDR_PARDENY";
	case SDR_KEYNOTEXIST: return "SDR_KEYNOTEXIST";
	case SDR_ALGNOTSUPPORT: return "SDR_ALGNOTSUPPORT";
	case SDR_ALGMODNOTSUPPORT: return "SDR_ALGMODNOTSUPPORT";
	case SDR_PKOPERR: return "SDR_PKOPERR";
	case SDR_SKOPERR: return "SDR_SKOPERR";
	case SDR_SIGNERR: return "SDR_SIGNERR";
	case SDR_VERIFYERR: return "SDR_VERIFYERR";
	case SDR_SYMOPERR: return "SDR_SYMOPERR";
	case SDR_STEPERR: return "SDR_STEPERR";
	case SDR_FILESIZEERR: return "SDR_FILESIZEERR";
	case SDR_FILENOEXIST: return "SDR_FILENOEXIST";
	case SDR_FILEOFSERR: return "SDR_FILEOFSERR";
	case SDR_KEYTYPEERR: return "SDR_KEYTYPEERR";
	case SDR_KEYERR: return "SDR_KEYERR";
	case SDR_ENCDATAERR: return "SDR_ENCDATAERR";
	case SDR_RANDERR: return "SDR_RANDERR";
	case SDR_PRKRERR: return "SDR_PRKRERR";
	case SDR_MACERR: return "SDR_MACERR";
	case SDR_FILEEXSITS: return "SDR_FILEEXSITS";
	case SDR_FILEWERR: return "SDR_FILEWERR";
	case SDR_NOBUFFER: return "SDR_NOBUFFER";
	case SDR_INARGERR: return "SDR_INARGERR";
	case SDR_OUTARGERR: return "SDR_OUTARGERR";
	}
	return "(unknown)";
}
