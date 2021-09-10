/*
 * Copyright (c) 2014 - 2021 The GmSSL Project.  All rights reserved.
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

/* NIST SP800-90A Rev.1 "Recommendation for Random Number Generation
 * Using Deterministic Random Bit Generators", 10.1.1 Hash_DRBG */

#ifndef GMSSL_HASH_DRBG_H
#define GMSSL_HASH_DRBG_H


#include <stdint.h>
#include <stdlib.h>
#include <gmssl/digest.h>


/* seedlen for hash_drgb, table 2 of nist sp 800-90a rev.1 */
#define HASH_DRBG_SM3_SEED_BITS		440 /* 55 bytes */
#define HASH_DRBG_SHA1_SEED_BITS	440
#define HASH_DRBG_SHA224_SEED_BITS	440
#define HASH_DRBG_SHA512_224_SEED_BITS	440
#define HASH_DRBG_SHA256_SEED_BITS	440
#define HASH_DRBG_SHA512_256_SEED_BITS	440
#define HASH_DRBG_SHA384_SEED_BITS	888 /* 110 bytes */
#define HASH_DRBG_SHA512_SEED_BITS	888
#define HASH_DRBG_MAX_SEED_BITS		888

#define HASH_DRBG_SM3_SEED_SIZE		(HASH_DRBG_SM3_SEED_BITS/8)
#define HASH_DRBG_SHA1_SEED_SIZE	(HASH_DRBG_SHA1_SEED_BITS/8)
#define HASH_DRBG_SHA224_SEED_SIZE	(HASH_DRBG_SHA224_SEED_BITS/8)
#define HASH_DRBG_SHA512_224_SEED_SIZE	(HASH_DRBG_SHA512_224_SEED_BITS/8)
#define HASH_DRBG_SHA256_SEED_SIZE	(HASH_DRBG_SHA256_SEED_BITS/8)
#define HASH_DRBG_SHA512_256_SEED_SIZE	(HASH_DRBG_SHA512_256_SEED_BITS/8)
#define HASH_DRBG_SHA384_SEED_SIZE	(HASH_DRBG_SHA384_SEED_BITS/8)
#define HASH_DRBG_SHA512_SEED_SIZE	(HASH_DRBG_SHA512_SEED_BITS/8)
#define HASH_DRBG_MAX_SEED_SIZE		(HASH_DRBG_MAX_SEED_BITS/8)

#define HASH_DRBG_RESEED_INTERVAL	((uint64_t)1 << 48)

#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
	const DIGEST *digest;
	uint8_t V[HASH_DRBG_MAX_SEED_SIZE];
	uint8_t C[HASH_DRBG_MAX_SEED_SIZE];
	size_t seedlen;
	uint64_t reseed_counter;
} HASH_DRBG;


int hash_drbg_init(HASH_DRBG *drbg,
	const DIGEST *digest,
	const uint8_t *entropy, size_t entropy_len,
	const uint8_t *nonce, size_t nonce_len,
	const uint8_t *personalstr, size_t personalstr_len);

int hash_drbg_reseed(HASH_DRBG *drbg,
	const uint8_t *entropy, size_t entropy_len,
	const uint8_t *additional, size_t additional_len);

int hash_drbg_generate(HASH_DRBG *drbg,
	const uint8_t *additional, size_t additional_len,
	size_t outlen, uint8_t *out);


#ifdef __cplusplus
}
#endif
#endif
