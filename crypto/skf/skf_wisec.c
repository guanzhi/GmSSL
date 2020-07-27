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

#include <openssl/err.h>
#include <openssl/gmskf.h>
#include "internal/skf_int.h"
#include "../../e_os.h"
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
	for (i = 0; i < OSSL_NELEM(wisec_ciphers); i++) {
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
	for (i = 0; i < OSSL_NELEM(wisec_ciphers); i++) {
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
	for (i = 0; i < OSSL_NELEM(wisec_digests); i++) {
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
	for (i = 0; i < OSSL_NELEM(wisec_digests); i++) {
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
	for (i = 0; i < OSSL_NELEM(wisec_pkeys); i++) {
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
	for (i = 0; i < OSSL_NELEM(wisec_pkeys); i++) {
		if (vendor_cap & wisec_pkeys[i].vendor_id) {
			std_cap |= wisec_pkeys[i].std_id;
		}
	}
	return std_cap;
}

static SKF_ERR_REASON wisec_errors[] = {
	{ WISEC_AUTH_BLOCKED, SKF_R_WISEC_AUTH_BLOCKED },
	{ WISEC_CERTNOUSAGEERR, SKF_R_WISEC_CERTNOUSAGEERR },
	{ WISEC_INVALIDCONTAINERERR, SKF_R_WISEC_INVALIDCONTAINERERR },
	{ WISEC_CONTAINER_NOT_EXISTS, SKF_R_WISEC_CONTAINER_NOT_EXISTS },
	{ WISEC_CONTAINER_EXISTS, SKF_R_WISEC_CONTAINER_EXISTS },
	{ WISEC_CERTUSAGEERR, SKF_R_WISEC_CERTUSAGEERR },
	{ WISEC_KEYNOUSAGEERR, SKF_R_WISEC_KEYNOUSAGEERR },
	{ WISEC_FILEATTRIBUTEERR, SKF_R_WISEC_FILEATTRIBUTEERR },
	{ WISEC_DEVNOAUTH, SKF_R_WISEC_DEVNOAUTH },
};

static unsigned long wisec_get_error_reason(ULONG err)
{
	size_t i = 0;
	for (i = 0; i < OSSL_NELEM(wisec_errors); i++) {
		if (err == wisec_errors[i].err) {
			return wisec_errors[i].reason;
		}
	}
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
