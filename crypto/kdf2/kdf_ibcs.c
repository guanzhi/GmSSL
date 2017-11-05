/* ====================================================================
 * Copyright (c) 2015 - 2017 The GmSSL Project.  All rights reserved.
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
#include <stdlib.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf2.h>

static void *ibcs_kdf(const EVP_MD *md, const void *in, size_t inlen,
	void *out, size_t *outlen)
{
	unsigned char state[EVP_MAX_MD_SIZE * 2];
	unsigned char dgst[EVP_MAX_MD_SIZE];
	unsigned int dgstlen;
	size_t rlen;
	unsigned char *pout;
	int i;

	dgstlen = EVP_MD_size(md);
	memset(state, 0, dgstlen);
	if (!EVP_Digest(in, inlen, state + dgstlen, &dgstlen, md, NULL)) {
		KDF2err(KDF2_F_IBCS_KDF, KDF2_R_DIGEST_FAILURE);
		return NULL;
	}

	rlen = *outlen;
	pout = out;
	for (i = 0; i < (*outlen + dgstlen - 1)/dgstlen; i++) {
		size_t len;

		if (!EVP_Digest(state, dgstlen, state, &dgstlen, md, NULL)) {
			KDF2err(KDF2_F_IBCS_KDF, KDF2_R_DIGEST_FAILURE);
			return NULL;
		}
		if (!EVP_Digest(state, dgstlen*2, dgst, &dgstlen, md, NULL)) {
			KDF2err(KDF2_F_IBCS_KDF, KDF2_R_DIGEST_FAILURE);
			return NULL;
		}

		len = (dgstlen <= rlen) ? dgstlen : rlen;
		memcpy(pout, dgst, len);
		pout += len;
		rlen -= len;
	}

	return out;
}

#define IMPLEMENT_IBCS_KDF(md) \
static void *ibcs_##md##kdf(const void *in, size_t inlen, void *out, size_t *outlen) { \
	return ibcs_kdf(EVP_##md(), in, inlen, out, outlen); \
}

#ifndef OPENSSL_NO_SM3
IMPLEMENT_IBCS_KDF(sm3)
#endif
#ifndef OPENSSL_NO_MD5
IMPLEMENT_IBCS_KDF(md5)
#endif
#ifndef OPENSSL_NO_BLAKE2
IMPLEMENT_IBCS_KDF(blake2b512)
IMPLEMENT_IBCS_KDF(blake2s256)
#endif
#ifndef OPENSSL_NO_SHA
IMPLEMENT_IBCS_KDF(sha1)
# ifndef OPENSSL_NO_SHA256
IMPLEMENT_IBCS_KDF(sha224)
IMPLEMENT_IBCS_KDF(sha256)
# endif
# ifndef OPENSSL_NO_SHA512
IMPLEMENT_IBCS_KDF(sha384)
IMPLEMENT_IBCS_KDF(sha512)
# endif
#endif
#ifndef OPENSSL_NO_MDC2
IMPLEMENT_IBCS_KDF(mdc2)
#endif
#ifndef OPENSSL_NO_RMD160
IMPLEMENT_IBCS_KDF(ripemd160)
#endif
#ifndef OPENSSL_NO_WHIRLPOOL
IMPLEMENT_IBCS_KDF(whirlpool)
#endif

KDF_FUNC KDF_get_ibcs(const EVP_MD *md)
{
	switch (EVP_MD_type(md)) {
#ifndef OPENSSL_NO_SM3
	case NID_sm3:
		return ibcs_sm3kdf;
#endif
#ifndef OPENSSL_NO_MD5
	case NID_md5:
		return ibcs_md5kdf;
#endif
#ifndef OPENSSL_NO_BLAKE2
	case NID_blake2b512:
		return ibcs_blake2b512kdf;
	case NID_blake2s256:
		return ibcs_blake2s256kdf;
#endif
#ifndef OPENSSL_NO_SHA
	case NID_sha1:
		return ibcs_sha1kdf;
# ifndef OPENSSL_NO_SHA256
	case NID_sha224:
		return ibcs_sha224kdf;
	case NID_sha256:
		return ibcs_sha256kdf;
# endif
# ifndef OPENSSL_NO_SHA512
	case NID_sha384:
		return ibcs_sha384kdf;
	case NID_sha512:
		return ibcs_sha512kdf;
# endif
#endif
#ifndef OPENSSL_NO_MDC2
	case NID_mdc2:
		return ibcs_mdc2kdf;
#endif
#ifndef OPENSSL_NO_RMD160
	case NID_ripemd160:
		return ibcs_ripemd160kdf;
#endif
#ifndef OPENSSL_NO_WHIRLPOOL
	case NID_whirlpool:
		return ibcs_whirlpoolkdf;
#endif
	}

	return NULL;
}
