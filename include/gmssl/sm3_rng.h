/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GMSSL_SM3_RNG_H
#define GMSSL_SM3_RNG_H

#include <time.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


#define SM3_RNG_MAX_RESEED_COUNTER (1<<20)
#define SM3_RNG_MAX_RESEED_SECONDS 600


typedef struct {
	uint8_t V[55];
	uint8_t C[55];
	uint32_t reseed_counter;
	time_t last_reseed_time;
} SM3_RNG;

int sm3_rng_init(SM3_RNG *rng, const uint8_t *nonce, size_t nonce_len,
	const uint8_t *label, size_t label_len);
int sm3_rng_reseed(SM3_RNG *rng, const uint8_t *addin, size_t addin_len);
int sm3_rng_generate(SM3_RNG *rng, const uint8_t *addin, size_t addin_len,
	uint8_t *out, size_t outlen);


#ifdef __cplusplus
}
#endif
#endif
