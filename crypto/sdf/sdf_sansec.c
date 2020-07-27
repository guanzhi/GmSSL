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

#include <string.h>
#include <openssl/err.h>
#include <openssl/gmsdf.h>
#include "internal/sdf_int.h"
#include "../../e_os.h"
#include "sdf_sansec.h"

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
	for (i = 0; i < OSSL_NELEM(sansec_ciphers); i++) {
		if (vendor_id == sansec_ciphers[i].vendor_id) {
			return sansec_ciphers[i].std_id;
		}
	}
	return 0;
}

static unsigned int sansec_cipher_std2vendor(unsigned int std_id)
{
	size_t i;
	for (i = 0; i < OSSL_NELEM(sansec_ciphers); i++) {
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

	for (i = 0; i < OSSL_NELEM(sansec_ciphers); i++) {
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
	for (i = 0; i < OSSL_NELEM(sansec_digests); i++) {
		if (vendor_id == sansec_digests[i].vendor_id) {
			return sansec_digests[i].std_id;
		}
	}
	return 0;
}

static unsigned int sansec_digest_std2vendor(unsigned int std_id)
{
	size_t i;
	for (i = 0; i < OSSL_NELEM(sansec_digests); i++) {
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

	for (i = 0; i < OSSL_NELEM(sansec_digests); i++) {
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
	for (i = 0; i < OSSL_NELEM(sansec_pkeys); i++) {
		if (vendor_id == sansec_pkeys[i].vendor_id) {
			return sansec_pkeys[i].std_id;
		}
	}
	return 0;
}

static unsigned int sansec_pkey_std2vendor(unsigned int std_id)
{
	size_t i;
	for (i = 0; i < OSSL_NELEM(sansec_pkeys); i++) {
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

	for (i = 0; i < OSSL_NELEM(sansec_pkeys); i++) {
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

static SDF_ERR_REASON sansec_errors[] = {
	{ SANSEC_BASE, SDF_R_SANSEC_BASE },
	{ SANSEC_INVALID_USER, SDF_R_SANSEC_INVALID_USER },
	{ SANSEC_INVALID_AUTHENCODE, SDF_R_SANSEC_INVALID_AUTHENCODE },
	{ SANSEC_PROTOCOL_VERSION_ERROR, SDF_R_SANSEC_PROTOCOL_VERSION_ERROR },
	{ SANSEC_INVALID_COMMAND, SDF_R_SANSEC_INVALID_COMMAND },
	{ SANSEC_INVALID_PARAMETERS, SDF_R_SANSEC_INVALID_PARAMETERS },
	{ SANSEC_FILE_ALREADY_EXIST, SDF_R_SANSEC_FILE_ALREADY_EXIST },
	{ SANSEC_SYNC_ERROR, SDF_R_SANSEC_SYNC_ERROR },
	{ SANSEC_SYNC_LOGIN_ERROR, SDF_R_SANSEC_SYNC_LOGIN_ERROR },
	{ SANSEC_SOCKET_TIMEOUT, SDF_R_SANSEC_SOCKET_TIMEOUT },
	{ SANSEC_CONNECT_ERROR, SDF_R_SANSEC_CONNECT_ERROR },
	{ SANSEC_SET_SOCKET_OPTION_ERROR, SDF_R_SANSEC_SET_SOCKET_OPTION_ERROR },
	{ SANSEC_SOCKET_SEND_ERROR, SDF_R_SANSEC_SOCKET_SEND_ERROR },
	{ SANSEC_SOCKET_RECV_ERROR, SDF_R_SANSEC_SOCKET_RECV_ERROR },
	{ SANSEC_SOCKET_RECV_0, SDF_R_SANSEC_SOCKET_RECV_0 },
	{ SANSEC_SEM_TIMEOUT, SDF_R_SANSEC_SEM_TIMEOUT },
	{ SANSEC_NO_AVAILABLE_HSM, SDF_R_SANSEC_NO_AVAILABLE_HSM },
	{ SANSEC_NO_AVAILABLE_CSM, SDF_R_SANSEC_NO_AVAILABLE_CSM },
	{ SANSEC_CONFIG_ERROR, SDF_R_SANSEC_CONFIG_ERROR },
	{ SANSEC_CARD_BASE, SDF_R_SANSEC_CARD_BASE },
	{ SANSEC_CARD_UNKNOW_ERROR, SDF_R_SANSEC_CARD_UNKNOW_ERROR },
	{ SANSEC_CARD_NOT_SUPPORTED, SDF_R_SANSEC_CARD_NOT_SUPPORTED },
	{ SANSEC_CARD_COMMMUCATION_FAILED, SDF_R_SANSEC_CARD_COMMMUCATION_FAILED },
	{ SANSEC_CARD_HARDWARE_FAILURE, SDF_R_SANSEC_CARD_HARDWARE_FAILURE },
	{ SANSEC_CARD_OPEN_DEVICE_FAILED, SDF_R_SANSEC_CARD_OPEN_DEVICE_FAILED },
	{ SANSEC_CARD_OPEN_SESSION_FAILED, SDF_R_SANSEC_CARD_OPEN_SESSION_FAILED },
	{ SANSEC_CARD_PRIVATE_KEY_ACCESS_DENYED, SDF_R_SANSEC_CARD_PRIVATE_KEY_ACCESS_DENYED },
	{ SANSEC_CARD_KEY_NOT_EXIST, SDF_R_SANSEC_CARD_KEY_NOT_EXIST },
	{ SANSEC_CARD_ALGOR_NOT_SUPPORTED, SDF_R_SANSEC_CARD_ALGOR_NOT_SUPPORTED },
	{ SANSEC_CARD_ALG_MODE_NOT_SUPPORTED, SDF_R_SANSEC_CARD_ALG_MODE_NOT_SUPPORTED },
	{ SANSEC_CARD_PUBLIC_KEY_OPERATION_ERROR, SDF_R_SANSEC_CARD_PUBLIC_KEY_OPERATION_ERROR },
	{ SANSEC_CARD_PRIVATE_KEY_OPERATION_ERROR, SDF_R_SANSEC_CARD_PRIVATE_KEY_OPERATION_ERROR },
	{ SANSEC_CARD_SIGN_ERROR, SDF_R_SANSEC_CARD_SIGN_ERROR },
	{ SANSEC_CARD_VERIFY_ERROR, SDF_R_SANSEC_CARD_VERIFY_ERROR },
	{ SANSEC_CARD_SYMMETRIC_ALGOR_ERROR, SDF_R_SANSEC_CARD_SYMMETRIC_ALGOR_ERROR },
	{ SANSEC_CARD_STEP_ERROR, SDF_R_SANSEC_CARD_STEP_ERROR },
	{ SANSEC_CARD_FILE_SIZE_ERROR, SDF_R_SANSEC_CARD_FILE_SIZE_ERROR },
	{ SANSEC_CARD_FILE_NOT_EXIST, SDF_R_SANSEC_CARD_FILE_NOT_EXIST },
	{ SANSEC_CARD_FILE_OFFSET_ERROR, SDF_R_SANSEC_CARD_FILE_OFFSET_ERROR },
	{ SANSEC_CARD_KEY_TYPE_ERROR, SDF_R_SANSEC_CARD_KEY_TYPE_ERROR },
	{ SANSEC_CARD_KEY_ERROR, SDF_R_SANSEC_CARD_KEY_ERROR },
	{ SANSEC_CARD_BUFFER_TOO_SMALL, SDF_R_SANSEC_CARD_BUFFER_TOO_SMALL },
	{ SANSEC_CARD_DATA_PADDING_ERROR, SDF_R_SANSEC_CARD_DATA_PADDING_ERROR },
	{ SANSEC_CARD_DATA_SIZE, SDF_R_SANSEC_CARD_DATA_SIZE },
	{ SANSEC_CARD_CRYPTO_NOT_INITED, SDF_R_SANSEC_CARD_CRYPTO_NOT_INITED },
	{ SANSEC_CARD_MANAGEMENT_DENYED, SDF_R_SANSEC_CARD_MANAGEMENT_DENYED },
	{ SANSEC_CARD_OPERATION_DENYED, SDF_R_SANSEC_CARD_OPERATION_DENYED },
	{ SANSEC_CARD_DEVICE_STATUS_ERROR, SDF_R_SANSEC_CARD_DEVICE_STATUS_ERROR },
	{ SANSEC_CARD_LOGIN_ERROR, SDF_R_SANSEC_CARD_LOGIN_ERROR },
	{ SANSEC_CARD_USERID_ERROR, SDF_R_SANSEC_CARD_USERID_ERROR },
	{ SANSEC_CARD_PARAMENT_ERROR, SDF_R_SANSEC_CARD_PARAMENT_ERROR },
	{ SANSEC_CARD_MANAGEMENT_DENYED_05, SDF_R_SANSEC_CARD_MANAGEMENT_DENYED_05 },
	{ SANSEC_CARD_OPERATION_DENYED_05, SDF_R_SANSEC_CARD_OPERATION_DENYED_05 },
	{ SANSEC_CARD_DEVICE_STATUS_ERROR_05, SDF_R_SANSEC_CARD_DEVICE_STATUS_ERROR_05 },
	{ SANSEC_CARD_LOGIN_ERROR_05, SDF_R_SANSEC_CARD_LOGIN_ERROR_05 },
	{ SANSEC_CARD_USERID_ERROR_05, SDF_R_SANSEC_CARD_USERID_ERROR_05 },
	{ SANSEC_CARD_PARAMENT_ERROR_05, SDF_R_SANSEC_CARD_PARAMENT_ERROR_05 },
	{ SANSEC_CARD_READER_BASE, SDF_R_SANSEC_CARD_READER_BASE },
	{ SANSEC_CARD_READER_PIN_ERROR, SDF_R_SANSEC_CARD_READER_PIN_ERROR },
	{ SANSEC_CARD_READER_NO_CARD, SDF_R_SANSEC_CARD_READER_NO_CARD },
	{ SANSEC_CARD_READER_CARD_INSERT, SDF_R_SANSEC_CARD_READER_CARD_INSERT },
	{ SANSEC_CARD_READER_CARD_INSERT_TYPE, SDF_R_SANSEC_CARD_READER_CARD_INSERT_TYPE },
};

static unsigned long sansec_get_error_reason(int err)
{
	size_t i = 0;
	for (i = 0; i < OSSL_NELEM(sansec_errors); i++) {
		if (err == sansec_errors[i].err) {
			return sansec_errors[i].reason;
		}
	}
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
