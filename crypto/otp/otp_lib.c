/* ====================================================================
 * Copyright (c) 2015 - 2016 The GmSSL Project.  All rights reserved.
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

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/cmac.h>
#include <openssl/kdf2.h>
#include <openssl/e_os2.h>
#include <openssl/otp.h>
#include "../modes/modes_lcl.h"

static int pow_table[] = {
	1,
	10,
	100,
	1000,
	10000,
	100000,
	1000000,
	10000000,
	100000000,
};

static int check_params(const OTP_PARAMS *params)
{
	if ((params->te < 1 || params->te > 60) ||
		(params->type != NID_sm3 && params->type != NID_sms4_ecb) || /* about to change */
		(params->otp_digits >= sizeof(pow_table) || params->otp_digits < 4)) {
		return 0;
	}
	return 1;
}

int OTP_generate(const OTP_PARAMS *params, const void *event, size_t eventlen,
	unsigned int *otp, const unsigned char *key, size_t keylen)
{
	int ret = 0;
	time_t t = 0;
	unsigned char *id = NULL;
	size_t idlen;
	const EVP_MD *md;
	const EVP_CIPHER *cipher;
	EVP_MD_CTX *mdctx = NULL;
	CMAC_CTX *cmctx = NULL;
	unsigned char s[EVP_MAX_MD_SIZE];
	size_t slen;
	uint32_t od;
	int i, n;

	OPENSSL_assert(sizeof(time_t) == 8);

	if (!check_params(params)) {
		OTPerr(OTP_F_OTP_GENERATE, OTP_R_INVALID_PARAMS);
		return 0;
	}

	idlen = sizeof(uint64_t) + eventlen + params->option_size;
	if (idlen < 16) {
		idlen = 16;
	}
	if (!(id = OPENSSL_malloc(idlen))) {
		OTPerr(OTP_F_OTP_GENERATE, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	memset(id, 0, idlen);

	t = time(NULL) + params->offset;
	t /= params->te;

	memcpy(id, &t, sizeof(t));
	memcpy(id + sizeof(t), event, eventlen);
	memcpy(id + sizeof(t) + eventlen, params->option, params->option_size);


	/* FIXME: try to get md and cipher, and check if cipher is ECB */
	if (params->type == NID_sm3) {
		md = EVP_get_digestbynid(params->type);
		if (!(mdctx = EVP_MD_CTX_new())) {
			OTPerr(OTP_F_OTP_GENERATE, ERR_R_MALLOC_FAILURE);
			goto end;
		}
		if (!EVP_DigestInit_ex(mdctx, md, NULL)) {
			OTPerr(OTP_F_OTP_GENERATE, ERR_R_EVP_LIB);
			goto end;
		}
		if (!EVP_DigestUpdate(mdctx, key, keylen)) {
			OTPerr(OTP_F_OTP_GENERATE, ERR_R_EVP_LIB);
			goto end;
		}
		if (!EVP_DigestUpdate(mdctx, id, idlen)) {
			OTPerr(OTP_F_OTP_GENERATE, ERR_R_EVP_LIB);
			goto end;
		}
		if (!EVP_DigestFinal_ex(mdctx, s, (unsigned int *)&slen)) {
			OTPerr(OTP_F_OTP_GENERATE, ERR_R_EVP_LIB);
			goto end;
		}
	} else if (params->type == NID_sms4_ecb) {
		cipher = EVP_get_cipherbynid(params->type);
		if (!(cmctx = CMAC_CTX_new())) {
			OTPerr(OTP_F_OTP_GENERATE, ERR_R_MALLOC_FAILURE);
			goto end;
		}
		if (!CMAC_Init(cmctx, key, keylen, cipher, NULL)) {
			OTPerr(OTP_F_OTP_GENERATE, OTP_R_CMAC_FAILURE);
			goto end;
		}
		if (!CMAC_Update(cmctx, id, idlen)) {
			OTPerr(OTP_F_OTP_GENERATE, OTP_R_CMAC_FAILURE);
			goto end;
		}
		if (!CMAC_Final(cmctx, s, &slen)) {
			OTPerr(OTP_F_OTP_GENERATE, OTP_R_CMAC_FAILURE);
			goto end;
		}
	} else {
		goto end;
	}
	OPENSSL_assert(slen % 4 == 0);

	od = 0;

	n = (int)slen;
	for (i = 0; i < n/4; i++) {
		od += GETU32(&s[i * 4]);
	}

	*otp = od % pow_table[params->otp_digits];
	ret = 1;
end:
	OPENSSL_free(id);
	EVP_MD_CTX_free(mdctx);
	CMAC_CTX_free(cmctx);
	return ret;
}

