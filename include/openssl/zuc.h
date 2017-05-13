/* ====================================================================
 * Copyright (c) 2015 - 2016 The GmSSL Project.  All rights reserved.
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

#ifndef HEADER_ZUC_H
#define HEADER_ZUC_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
	uint32_t state[22];
} zuc_key_t;

/*
void zuc_set_key(zuc_key_t *key, const unsigned char *user_key, const unsigned char *iv);
void zuc_generate_keystream(zuc_key_t *key, size_t nwords, uint32_t *words);
*/

typedef struct {
	zuc_key_t key;
	unsigned char buf[4];
	size_t buflen;
} zuc_ctx_t;

/*
void zuc_ctx_init(zuc_ctx_t *ctx, const unsigned char *user_key, const unsigned char *iv);
void zuc_encrypt(zuc_ctx_t *ctx, size_t len, const unsigned char *in, unsigned char *out);
#define zuc_decrypt(ctx,len,in,out)  zuc_encrypt(ctx,len,in,out)
*/

#define EEA3_MIN_BITS	1
#define EEA3_MAX_BITS	65504
#define EEA3_MIN_BYTES	((EEA3_MIN_BITS + 7)/8)
#define EEA3_MAX_BYTES	((EEA3_MAX_BITS + 7)/8)

typedef struct {
	zuc_ctx_t zuc;
	size_t length;
	/* maybe buffer */
} eea3_ctx_t;

/*
void eea3_init(eea3_ctx_t *ctx, const unsigned char *user_key, uint32_t count, uint32_t bearer, int direction);
void eea3_encrypt(eea3_ctx_t *ctx, size_t len, const unsigned char *in, unsigned char *out);
#define eea3_decrypt(ctx,len,in,out) eea3_encrypt(ctx,len,in,out)
void eea3(const unsigned char *key, uint32_t count, uint32_t bearer, int direction,
	size_t len, const unsigned char *in, unsigned char *out);
*/

#define EIA3_MIN_BYTES	EEA3_MIN_BYTES
#define EIA3_MAX_BYTES	EEA3_MAX_BYTES
#define EIA3_MAC_SIZE	4

typedef struct {
	zuc_ctx_t zuc;
	size_t length;
	/* maybe buffer */
} eia3_ctx_t;

/*
void eia3_init(eia3_ctx_t *ctx, const unsigned char *user_key, uint32_t count, uint32_t bearer, int direction);
void eia3_update(eia3_ctx_t *ctx, const unsigned char *data, size_t datalen);
void eia3_final(eia3_ctx_t *ctx, uint32_t *mac);
void eia3(const unsigned char *key, uint32_t count, uint32_t bearer, int direction,
	const unsigned char *data, size_t len, uint32_t *mac);
*/

#ifdef __cplusplus
}
#endif
#endif
