/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
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
