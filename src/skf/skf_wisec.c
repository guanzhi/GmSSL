/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "skf_int.h"
#include "skf_wisec.h"


typedef struct {
	ULONG std_id;
	ULONG vendor_id;
} SKF_ALGOR_PAIR;

static SKF_ALGOR_PAIR wisec_ciphers[] = {
	{ SGD_SM1, WISEC_SM1 },
	{ SGD_SM1_ECB, WISEC_SM1_ECB },
	{ SGD_SM1_CBC, WISEC_SM1_CBC },
	{ SGD_SM1_CFB, WISEC_SM1_CFB },
	{ SGD_SM1_OFB, WISEC_SM1_OFB },
	{ SGD_SM1_MAC, WISEC_SM1_MAC },
	{ SGD_SM4, WISEC_SM4 },
	{ SGD_SM4_ECB, WISEC_SM4_ECB },
	{ SGD_SM4_CBC, WISEC_SM4_CBC },
	{ SGD_SM4_CFB, WISEC_SM4_CFB },
	{ SGD_SM4_OFB, WISEC_SM4_OFB },
	{ SGD_SM4_MAC, WISEC_SM4_MAC },
	{ SGD_SSF33, WISEC_SSF33 },
	{ SGD_SSF33_ECB, WISEC_SSF33_ECB },
	{ SGD_SSF33_CBC, WISEC_SSF33_CBC },
	{ SGD_SSF33_CFB, WISEC_SSF33_CFB },
	{ SGD_SSF33_OFB, WISEC_SSF33_OFB },
	{ SGD_SSF33_MAC, WISEC_SSF33_MAC },
};

static ULONG wisec_get_cipher_algor(ULONG vendor_id)
{
	size_t i;
	for (i = 0; i < sizeof(wisec_ciphers)/sizeof(wisec_ciphers[0]); i++) {
		if (vendor_id == wisec_ciphers[i].vendor_id) {
			return wisec_ciphers[i].std_id;
		}
	}
	return 0;
}

static ULONG wisec_get_cipher_cap(ULONG vendor_cap)
{
	ULONG std_cap = 0;
	size_t i;
	for (i = 0; i < sizeof(wisec_ciphers)/sizeof(wisec_ciphers[0]); i++) {
		if (vendor_cap & wisec_ciphers[i].vendor_id) {
			std_cap |= wisec_ciphers[i].std_id;
		}
	}
	return std_cap;
}

static SKF_ALGOR_PAIR wisec_digests[] = {
	{ SGD_SM3, WISEC_SM3 },
	{ SGD_SHA1, WISEC_SHA1 },
	{ SGD_SHA256, WISEC_SHA256 },
};

static ULONG wisec_get_digest_algor(ULONG vendor_id)
{
	size_t i;
	for (i = 0; i < sizeof(wisec_digests)/sizeof(wisec_digests[0]); i++) {
		if (vendor_id == wisec_digests[i].vendor_id) {
			return wisec_digests[i].std_id;
		}
	}
	return 0;
}

static ULONG wisec_get_digest_cap(ULONG vendor_cap)
{
	ULONG std_cap = 0;
	size_t i;
	for (i = 0; i < sizeof(wisec_digests)/sizeof(wisec_digests[0]); i++) {
		if (vendor_cap & wisec_digests[i].vendor_id) {
			std_cap |= wisec_digests[i].std_id;
		}
	}
	return std_cap;
}

static SKF_ALGOR_PAIR wisec_pkeys[] = {
	{ SGD_RSA, WISEC_RSA },
	{ SGD_RSA_SIGN, WISEC_RSA_SIGN },
	{ SGD_RSA_ENC, WISEC_RSA_ENC },
	{ SGD_SM2, WISEC_SM2 },
	{ SGD_SM2_1, WISEC_SM2_1 },
	{ SGD_SM2_2, WISEC_SM2_2 },
	{ SGD_SM2_3, WISEC_SM2_3 },
};

static ULONG wisec_get_pkey_algor(ULONG vendor_id)
{
	size_t i;
	for (i = 0; i < sizeof(wisec_pkeys)/sizeof(wisec_pkeys[0]); i++) {
		if (vendor_id == wisec_pkeys[i].vendor_id) {
			return wisec_pkeys[i].std_id;
		}
	}
	return 0;
}

static ULONG wisec_get_pkey_cap(ULONG vendor_cap)
{
	ULONG std_cap = 0;
	size_t i;
	for (i = 0; i < sizeof(wisec_pkeys)/sizeof(wisec_pkeys[0]); i++) {
		if (vendor_cap & wisec_pkeys[i].vendor_id) {
			std_cap |= wisec_pkeys[i].std_id;
		}
	}
	return std_cap;
}

static unsigned long wisec_get_error_reason(ULONG err)
{
	return 0;
}

SKF_VENDOR skf_wisec = {
	"wisec",
	16,
	wisec_get_cipher_algor,
	wisec_get_cipher_cap,
	wisec_get_digest_algor,
	wisec_get_digest_cap,
	wisec_get_pkey_algor,
	wisec_get_pkey_cap,
	wisec_get_error_reason,
};
