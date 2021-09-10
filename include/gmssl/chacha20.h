/* 
 *   Copyright 2014-2021 The GmSSL Project Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
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


void chacha20_set_key(CHACHA20_STATE *state,
	const uint8_t key[CHACHA20_KEY_SIZE],
	const uint8_t nonce[CHACHA20_NONCE_SIZE],
	uint32_t counter);

void chacha20_generate_keystream(CHACHA20_STATE *state,
	unsigned int counts,
	uint8_t *out);


#ifdef __cplusplus
}
#endif
#endif
