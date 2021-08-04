/*
 * Copyright (c) 2021 - 2021 The GmSSL Project.  All rights reserved.
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
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmssl/sm3.h>
#include <gmssl/hmac.h>
#include <gmssl/error.h>

/*

HKDF-Extract(salt, IKM) -> PRK

	salt optional, len(salt) == hash_len is recommended
	IKM input key material
	PRK output pseudorandom key, len(PRK) = hashLen

	PRK = HMAC_hash(salt, IKM)
	salt as key?


HKDF-Expand(PRK, info, L) -> OKM
	info optional
	L output length, L <= 255 * hashLen
	OKM output key


	N = (L + hashLen - 1)//hashLen
	T = T(1) || T(2) || ... | T(N)
	OKM = T[0..L-1]

	T(0) = empty string (len = 0)
	T(1) = HMAC_hash(PRK, T(0) | info | 0x01)
	T(2) = HMAC_hash(PRK, T(1) | info | 0x02)
	T(3) = HMAC_hash(PRK, T(2) | info | 0x03)
	...


*/

int hkdf_extract(const DIGEST *digest, const uint8_t *salt, size_t saltlen,
	const uint8_t *ikm, size_t ikmlen,
	uint8_t *prk, size_t *prklen)
{
	HMAC_CTX hmac_ctx;

	if (!salt || saltlen == 0) {
		uint8_t zeros[DIGEST_MAX_SIZE] = {0};
		if (hmac_init(&hmac_ctx, digest, zeros, digest_size(digest)) != 1) {
			error_print();
			return -1;
		}
	} else {
		if (hmac_init(&hmac_ctx, digest, salt, saltlen) != 1) {
			error_print();
			return -1;
		}
	}

	if (hmac_update(&hmac_ctx, ikm, ikmlen) != 1
		|| hmac_finish(&hmac_ctx, prk, prklen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int hkdf_expand(const DIGEST *digest, const uint8_t *prk, size_t prklen,
	const uint8_t *info, size_t infolen,
	size_t L, uint8_t *okm)
{
	HMAC_CTX hmac_ctx;
	uint8_t T[HMAC_MAX_SIZE];
	uint8_t counter = 0x01;
	size_t len;

	if (L > 0) {
		if (hmac_init(&hmac_ctx, digest, prk, prklen) != 1
			|| hmac_update(&hmac_ctx, info, infolen) != 1
			|| hmac_update(&hmac_ctx, &counter, 1) != 1
			|| hmac_finish(&hmac_ctx, T, &len) != 1) {
			error_print();
			return -1;
		}
		counter++;
		if (len > L) {
			len = L;
		}
		memcpy(okm, T, len);
		okm += len;
		L -= len;
	}
	while (L > 0) {
		if (counter == 0) {
			error_print();
			return -1;
		}
		if (hmac_init(&hmac_ctx, digest, prk, prklen) != 1
			|| hmac_update(&hmac_ctx, T, len) != 1
			|| hmac_update(&hmac_ctx, info, infolen) != 1
			|| hmac_update(&hmac_ctx, &counter, 1) != 1
			|| hmac_finish(&hmac_ctx, T, &len) != 1) {
			error_print();
			return -1;
		}
		counter++;
		if (len > L) {
			len = L;
		}
		memcpy(okm, T, len);
		okm += len;
		L -= len;
	}
	return 1;
}
