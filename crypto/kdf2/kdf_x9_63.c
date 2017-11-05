/* ====================================================================
 * Copyright (c) 2007 - 2017 The GmSSL Project.  All rights reserved.
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
#include <string.h>
#include <openssl/e_os2.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf2.h>
#include "internal/byteorder.h"


static void *x963_kdf(const EVP_MD *md, const void *in, size_t inlen,
	void *out, size_t *outlen)
{
	void *ret = NULL;
	EVP_MD_CTX *ctx = NULL;
	uint32_t counter = 1;
	uint32_t counter_be;
	unsigned char dgst[EVP_MAX_MD_SIZE];
	unsigned int dgstlen;
	unsigned char *pout = out;
	size_t rlen = *outlen;
	size_t len;

	if (!(ctx = EVP_MD_CTX_new())) {
		KDF2err(KDF2_F_X963_KDF, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	while (rlen > 0) {
		counter_be = cpu_to_be32(counter);
		counter++;

		if (!EVP_DigestInit(ctx, md)) {
			KDF2err(KDF2_F_X963_KDF, KDF2_R_DIGEST_FAILURE);
			goto end;
		}
		if (!EVP_DigestUpdate(ctx, in, inlen)) {
			KDF2err(KDF2_F_X963_KDF, KDF2_R_DIGEST_FAILURE);
			goto end;
		}
		if (!EVP_DigestUpdate(ctx, &counter_be, sizeof(counter_be))) {
			KDF2err(KDF2_F_X963_KDF, KDF2_R_DIGEST_FAILURE);
			goto end;
		}
		if (!EVP_DigestFinal(ctx, dgst, &dgstlen)) {
			KDF2err(KDF2_F_X963_KDF, KDF2_R_DIGEST_FAILURE);
			goto end;
		}

		len = dgstlen <= rlen ? dgstlen : rlen;
		memcpy(pout, dgst, len);
		rlen -= len;
		pout += len;
	}

	ret = out;
end:
	EVP_MD_CTX_free(ctx);
	return ret;
}

#define IMPLEMENT_X963_KDF(md) \
static void *x963_##md##kdf(const void *in, size_t inlen, void *out, size_t *outlen) { \
	return x963_kdf(EVP_##md(), in, inlen, out, outlen); \
}

IMPLEMENT_X963_KDF(sm3)
#ifndef OPENSSL_NO_MD5
IMPLEMENT_X963_KDF(md5)
#endif
#ifndef OPENSSL_NO_BLAKE2
IMPLEMENT_X963_KDF(blake2b512)
IMPLEMENT_X963_KDF(blake2s256)
#endif
#ifndef OPENSSL_NO_SHA
IMPLEMENT_X963_KDF(sha1)
# ifndef OPENSSL_NO_SHA256
IMPLEMENT_X963_KDF(sha224)
IMPLEMENT_X963_KDF(sha256)
# endif
# ifndef OPENSSL_NO_SHA512
IMPLEMENT_X963_KDF(sha384)
IMPLEMENT_X963_KDF(sha512)
# endif
#endif
#ifndef OPENSSL_NO_MDC2
IMPLEMENT_X963_KDF(mdc2)
#endif
#ifndef OPENSSL_NO_RMD160
IMPLEMENT_X963_KDF(ripemd160)
#endif
#ifndef OPENSSL_NO_WHIRLPOOL
IMPLEMENT_X963_KDF(whirlpool)
#endif

KDF_FUNC KDF_get_x9_63(const EVP_MD *md)
{
	switch (EVP_MD_type(md)) {
	case NID_sm3:
		return x963_sm3kdf;
#ifndef OPENSSL_NO_MD5
	case NID_md5:
		return x963_md5kdf;
#endif
#ifndef OPENSSL_NO_BLAKE2
	case NID_blake2b512:
		return x963_blake2b512kdf;
	case NID_blake2s256:
		return x963_blake2s256kdf;
#endif
#ifndef OPENSSL_NO_SHA
	case NID_sha1:
		return x963_sha1kdf;
# ifndef OPENSSL_NO_SHA256
	case NID_sha224:
		return x963_sha224kdf;
	case NID_sha256:
		return x963_sha256kdf;
# endif
# ifndef OPENSSL_NO_SHA512
	case NID_sha384:
		return x963_sha384kdf;
	case NID_sha512:
		return x963_sha512kdf;
# endif
#endif
#ifndef OPENSSL_NO_MDC2
	case NID_mdc2:
		return x963_mdc2kdf;
#endif
#ifndef OPENSSL_NO_RMD160
	case NID_ripemd160:
		return x963_ripemd160kdf;
#endif
#ifndef OPENSSL_NO_WHIRLPOOL
	case NID_whirlpool:
		return x963_whirlpoolkdf;
#endif
	}

	return NULL;
}
