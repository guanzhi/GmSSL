/* crypto/kdf/kdf_x9_63.c */
/* ====================================================================
 * Copyright (c) 2007 - 2015 The GmSSL Project.  All rights reserved.
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
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <openssl/kdf.h>

#ifdef CPU_BIGENDIAN
#define cpu_to_be16(v) (v)
#define cpu_to_be32(v) (v)
#else
#define cpu_to_be16(v) ((v << 8) | (v >> 8))
#define cpu_to_be32(v) ((cpu_to_be16(v) << 16) | cpu_to_be16(v >> 16))
#endif

static void *x963_kdf(const EVP_MD *md, const void *in, size_t inlen,
	void *out, size_t *outlen)
{
	EVP_MD_CTX ctx;
	uint32_t counter = 1;
	uint32_t counter_be;
	unsigned char dgst[EVP_MAX_MD_SIZE];
	unsigned int dgstlen;
	unsigned char *pout = out;
	size_t rlen = *outlen;
	size_t len;

	EVP_MD_CTX_init(&ctx);

	while (rlen > 0) {
		counter_be = cpu_to_be32(counter);
		counter++;

		EVP_DigestInit(&ctx, md);
		EVP_DigestUpdate(&ctx, in, inlen);
		EVP_DigestUpdate(&ctx, &counter_be, sizeof(counter_be));
		EVP_DigestFinal(&ctx, dgst, &dgstlen);

		len = dgstlen <= rlen ? dgstlen : rlen;
		memcpy(pout, dgst, len);
		rlen -= len;
		pout += len;
	}

	EVP_MD_CTX_cleanup(&ctx);
	return out;
}

static void *x963_md5kdf(const void *in, size_t inlen,
	void *out, size_t *outlen)
{
	return x963_kdf(EVP_md5(), in, inlen, out, outlen);
}

static void *x963_rmd160kdf(const void *in, size_t inlen,
	void *out, size_t *outlen)
{
	return x963_kdf(EVP_ripemd160(), in, inlen, out, outlen);
}

static void *x963_sha1kdf(const void *in, size_t inlen,
	void *out, size_t *outlen)
{
	return x963_kdf(EVP_sha1(), in, inlen, out, outlen);
}

static void *x963_sha224kdf(const void *in, size_t inlen,
	void *out, size_t *outlen)
{
	return x963_kdf(EVP_sha224(), in, inlen, out, outlen);
}

static void *x963_sha256kdf(const void *in, size_t inlen,
	void *out, size_t *outlen)
{
	return x963_kdf(EVP_sha256(), in, inlen, out, outlen);
}

static void *x963_sha384kdf(const void *in, size_t inlen,
	void *out, size_t *outlen)
{
	return x963_kdf(EVP_sha384(), in, inlen, out, outlen);
}

static void *x963_sha512kdf(const void *in, size_t inlen,
	void *out, size_t *outlen)
{
	return x963_kdf(EVP_sha512(), in, inlen, out, outlen);
}

static void *x963_whirlpoolkdf(const void *in, size_t inlen,
	void *out, size_t *outlen)
{
	return x963_kdf(EVP_whirlpool(), in, inlen, out, outlen);
}

static void *x963_sm3kdf(const void *in, size_t inlen,
	void *out, size_t *outlen)
{
	return x963_kdf(EVP_sm3(), in, inlen, out, outlen);
}

KDF_FUNC KDF_get_x9_63(const EVP_MD *md)
{
	if (md == EVP_md5()) {
		return x963_md5kdf;

	} else if (md == EVP_ripemd160()) {
		return x963_rmd160kdf;

	} else if (md == EVP_sha1()) {
		return x963_sha1kdf;

	} else if (md == EVP_sha224()) {
		return x963_sha224kdf;

	} else if (md == EVP_sha256()) {
		return x963_sha256kdf;

	} else if (md == EVP_sha384()) {
		return x963_sha384kdf;

	} else if (md == EVP_sha512()) {
		return x963_sha512kdf;

	} else if (md == EVP_whirlpool()) {
		return x963_whirlpoolkdf;

	} else if (md == EVP_sm3()) {
		return x963_sm3kdf;
	}

	return NULL;
}

