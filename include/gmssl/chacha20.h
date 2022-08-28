/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


/* RFC 8439 "ChaCha20 and Poly1305 for IETF Protocols" */

#ifndef GMSSL_CHACHA20_H
#define GMSSL_CHACHA20_H

#define CHACHA20_IS_BIG_ENDIAN	0

#include <stdint.h>
#include <stdlib.h>

#include <string.h>

#define CHACHA20_KEY_BITS	256
#define CHACHA20_NONCE_BITS	96
#define CHACHA20_COUNTER_BITS	32

#define CHACHA20_KEY_SIZE	(CHACHA20_KEY_BITS/8)
#define CHACHA20_NONCE_SIZE	(CHACHA20_NONCE_BITS/8)
#define CHACHA20_COUNTER_SIZE	(CHACHA20_COUNTER_BITS/8)

#define CHACHA20_KEY_WORDS	(CHACHA20_KEY_SIZE/sizeof(uint32_t))
#define CHACHA20_NONCE_WORDS	(CHACHA20_NONCE_SIZE/sizeof(uint32_t))
#define CHACHA20_COUNTER_WORDS	(CHACHA20_COUNTER_SIZE/sizeof(uint32_t))


#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
	uint32_t d[16];
} CHACHA20_STATE;


void chacha20_init(CHACHA20_STATE *state,
	const uint8_t key[CHACHA20_KEY_SIZE],
	const uint8_t nonce[CHACHA20_NONCE_SIZE], uint32_t counter);

void chacha20_generate_keystream(CHACHA20_STATE *state,
	size_t counts, uint8_t *out);


#ifdef __cplusplus
}
#endif
#endif
