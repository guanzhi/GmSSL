/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <string.h>
#include "sdf.h"
#include "sdf_int.h"
#include "sdf_sansec.h"


#define SDFerr(a,b)

typedef struct {
	unsigned int std_id;
	unsigned int vendor_id;
} SDF_ALGOR_PAIR;

static SDF_ALGOR_PAIR sansec_ciphers[] = {
	{ SGD_SM1, SANSEC_SM1 },
	{ SGD_SM1_ECB, SANSEC_SM1_ECB },
	{ SGD_SM1_CBC, SANSEC_SM1_CBC },
	{ SGD_SM1_CFB, SANSEC_SM1_CFB },
	{ SGD_SM1_OFB, SANSEC_SM1_OFB },
	{ SGD_SM1_MAC, SANSEC_SM1_MAC },
	{ SGD_SM4, SANSEC_SM4 },
	{ SGD_SM4_ECB, SANSEC_SM4_ECB },
	{ SGD_SM4_CBC, SANSEC_SM4_CBC },
	{ SGD_SM4_CFB, SANSEC_SM4_CFB },
	{ SGD_SM4_OFB, SANSEC_SM4_OFB },
	{ SGD_SM4_MAC, SANSEC_SM4_MAC },
	{ SGD_SSF33, SANSEC_SSF33 },
	{ SGD_SSF33_ECB, SANSEC_SSF33_ECB },
	{ SGD_SSF33_CBC, SANSEC_SSF33_CBC },
	{ SGD_SSF33_CFB, SANSEC_SSF33_CFB },
	{ SGD_SSF33_OFB, SANSEC_SSF33_OFB },
	{ SGD_SSF33_MAC, SANSEC_SSF33_MAC },
	{ 0, SANSEC_AES },
	{ 0, SANSEC_AES_ECB },
	{ 0, SANSEC_AES_CBC },
	{ 0, SANSEC_AES_CFB },
	{ 0, SANSEC_AES_OFB },
	{ 0, SANSEC_AES_MAC },
	{ 0, SANSEC_DES },
	{ 0, SANSEC_DES_ECB },
	{ 0, SANSEC_DES_CBC },
	{ 0, SANSEC_DES_CFB },
	{ 0, SANSEC_DES_OFB },
	{ 0, SANSEC_DES_MAC },
	{ 0, SANSEC_3DES },
	{ 0, SANSEC_3DES_ECB },
	{ 0, SANSEC_3DES_CBC },
	{ 0, SANSEC_3DES_CFB },
	{ 0, SANSEC_3DES_OFB },
	{ 0, SANSEC_3DES_MAC },
};

static unsigned int sansec_cipher_vendor2std(unsigned int vendor_id)
{
	size_t i;
	for (i = 0; i < sizeof(sansec_ciphers)/sizeof(sansec_ciphers[0]); i++) {
		if (vendor_id == sansec_ciphers[i].vendor_id) {
			return sansec_ciphers[i].std_id;
		}
	}
	return 0;
}

static unsigned int sansec_cipher_std2vendor(unsigned int std_id)
{
	size_t i;
	for (i = 0; i < sizeof(sansec_ciphers)/sizeof(sansec_ciphers[0]); i++) {
		if (std_id == sansec_ciphers[i].std_id) {
			return sansec_ciphers[i].vendor_id;
		}
	}
	return 0;
}

static unsigned int sansec_cipher_cap(unsigned int vendor_cap)
{
	unsigned int std_cap = 0;
	size_t i;

	for (i = 0; i < sizeof(sansec_ciphers)/sizeof(sansec_ciphers[0]); i++) {
		if (vendor_cap & sansec_ciphers[i].vendor_id) {
			std_cap |= sansec_ciphers[i].std_id;
		}
	}

	return std_cap;
}

static SDF_ALGOR_PAIR sansec_digests[] = {
	{ SGD_SM3, SANSEC_SM3 },
	{ SGD_SHA1, SANSEC_SHA1 },
	{ SGD_SHA256, SANSEC_SHA256 },
	{ 0, SANSEC_SHA512 },
	{ 0, SANSEC_SHA384 },
	{ 0, SANSEC_SHA224 },
	{ 0, SANSEC_MD5 },
};

static unsigned int sansec_digest_vendor2std(unsigned int vendor_id)
{
	size_t i;
	for (i = 0; i < sizeof(sansec_digests)/sizeof(sansec_digests[0]); i++) {
		if (vendor_id == sansec_digests[i].vendor_id) {
			return sansec_digests[i].std_id;
		}
	}
	return 0;
}

static unsigned int sansec_digest_std2vendor(unsigned int std_id)
{
	size_t i;
	for (i = 0; i < sizeof(sansec_digests)/sizeof(sansec_digests[0]); i++) {
		if (std_id == sansec_digests[i].std_id) {
			return sansec_digests[i].vendor_id;
		}
	}
	return 0;
}

static unsigned int sansec_digest_cap(unsigned int vendor_cap)
{
	unsigned int std_cap = 0;
	size_t i;

	for (i = 0; i < sizeof(sansec_digests)/sizeof(sansec_digests[0]); i++) {
		if (vendor_cap & sansec_digests[i].vendor_id) {
			std_cap |= sansec_digests[i].std_id;
		}
	}

	return std_cap;
}

static SDF_ALGOR_PAIR sansec_pkeys[] = {
	{ SGD_RSA,SANSEC_RSA },
	{ SGD_RSA_SIGN,SANSEC_RSA_SIGN },
	{ SGD_RSA_ENC,SANSEC_RSA_ENC },
	{ SGD_SM2,SANSEC_SM2 },
	{ SGD_SM2_1,SANSEC_SM2_1 },
	{ SGD_SM2_2,SANSEC_SM2_2 },
	{ SGD_SM2_3,SANSEC_SM2_3 },
};

static unsigned int sansec_pkey_vendor2std(unsigned int vendor_id)
{
	size_t i;
	for (i = 0; i < sizeof(sansec_pkeys)/sizeof(sansec_pkeys[0]); i++) {
		if (vendor_id == sansec_pkeys[i].vendor_id) {
			return sansec_pkeys[i].std_id;
		}
	}
	return 0;
}

static unsigned int sansec_pkey_std2vendor(unsigned int std_id)
{
	size_t i;
	for (i = 0; i < sizeof(sansec_pkeys)/sizeof(sansec_pkeys[0]); i++) {
		if (std_id == sansec_pkeys[i].std_id) {
			return sansec_pkeys[i].vendor_id;
		}
	}
	return 0;
}

static unsigned int sansec_pkey_cap(unsigned int vendor_cap)
{
	unsigned int std_cap = 0;
	size_t i;

	for (i = 0; i < sizeof(sansec_pkeys)/sizeof(sansec_pkeys[0]); i++) {
		if (vendor_cap & sansec_pkeys[i].vendor_id) {
			std_cap |= sansec_pkeys[i].std_id;
		}
	}

	return std_cap;
}

static int sansec_encode_ecccipher(const ECCCipher *ec, void *vendor)
{
	int ret;
	SANSEC_ECCCipher *sansec = vendor;
	ret = sizeof(SANSEC_ECCCipher);

	if (ec->L > sizeof(sansec->C)) {
		SDFerr(SDF_F_SANSEC_ENCODE_ECCCIPHER,
			SDF_R_INVALID_SANSEC_ECCCIPHER_LENGTH);
		return 0;
	}

	if (vendor) {
		sansec->clength = ec->L;
		memcpy(sansec->x, ec->x, sizeof(ec->x));
		memcpy(sansec->y, ec->y, sizeof(ec->y));
		memcpy(sansec->M, ec->M, sizeof(ec->M));
		memset(sansec->M + sizeof(ec->M), 0, sizeof(sansec->M) - sizeof(ec->M));
		memcpy(sansec->C, ec->C, ec->L);
		memset(sansec->C + ec->L, 0, sizeof(sansec->C) - ec->L);
	}

	return ret;
}

static int sansec_decode_ecccipher(ECCCipher *ec, const void *vendor)
{
	int ret;
	const SANSEC_ECCCipher *sansec = vendor;
	ret = sizeof(ECCCipher) -1 + sansec->clength;

	if (sansec->clength > sizeof(sansec->C)) {
		SDFerr(SDF_F_SANSEC_DECODE_ECCCIPHER,
			SDF_R_INVALID_SANSEC_ECCCIPHER_LENGTH);
		return 0;
	}

	if (ec) {
		memcpy(ec->x, sansec->x, sizeof(ec->x));
		memcpy(ec->y, sansec->y, sizeof(ec->y));
		memcpy(ec->M, sansec->M, sizeof(ec->M));
		ec->L = sansec->clength;
		memcpy(ec->C, sansec->C, sansec->clength);
	}

	return ret;
}

static unsigned long sansec_get_error_reason(int err)
{
/*
	size_t i = 0;
	for (i = 0; i < OSSL_NELEM(sansec_errors); i++) {
		if (err == sansec_errors[i].err) {
			return sansec_errors[i].reason;
		}
	}
*/
	return 0;
}

SDF_VENDOR sdf_sansec = {
	"sansec",
	sansec_cipher_vendor2std,
	sansec_cipher_std2vendor,
	sansec_cipher_cap,
	sansec_digest_vendor2std,
	sansec_digest_std2vendor,
	sansec_digest_cap,
	sansec_pkey_vendor2std,
	sansec_pkey_std2vendor,
	sansec_pkey_cap,
	sansec_encode_ecccipher,
	sansec_decode_ecccipher,
	sansec_get_error_reason,
};
