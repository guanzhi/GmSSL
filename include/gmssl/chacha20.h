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
