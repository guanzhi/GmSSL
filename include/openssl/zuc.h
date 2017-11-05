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

#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_ZUC

#include <stdlib.h>
#include <openssl/e_os2.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
	uint32_t state[22];
} zuc_key_t;

void zuc_set_key(zuc_key_t *key, const unsigned char *user_key, const unsigned char *iv);
void zuc_generate_keystream(zuc_key_t *key, size_t nwords, uint32_t *words);

typedef struct {
	zuc_key_t key;
	unsigned char buf[4];
	size_t buflen;
} zuc_ctx_t;

void zuc_ctx_init(zuc_ctx_t *ctx, const unsigned char *user_key, const unsigned char *iv);
void zuc_encrypt(zuc_ctx_t *ctx, size_t len, const unsigned char *in, unsigned char *out);
#define zuc_decrypt(ctx,len,in,out)  zuc_encrypt(ctx,len,in,out)

#define ZUC_128EEA3_MIN_BITS	1
#define ZUC_128EEA3_MAX_BITS	65504
#define ZUC_128EEA3_MIN_BYTES	((ZUC_128EEA3_MIN_BITS + 7)/8)
#define ZUC_128EEA3_MAX_BYTES	((ZUC_128EEA3_MAX_BITS + 7)/8)

typedef struct {
	zuc_ctx_t zuc;
	size_t length;
	/* maybe buffer */
} eea3_ctx_t;

void zuc_128eea3_init(zuc_128eea3_t *eea3, const unsigned char *user_key,
	uint32_t count, uint32_t bearer, int direction);
void zuc_128eea3_encrypt(zuc_128eea3_t *ctx, size_t len,
	const unsigned char *in, unsigned char *out);
#define eea3_decrypt(ctx,len,in,out) eea3_encrypt(ctx,len,in,out)
void eea3(const unsigned char *key, uint32_t count, uint32_t bearer,
	int direction, size_t len, const unsigned char *in, unsigned char *out);

#define ZUC_128EIA3_MIN_BYTES	EEA3_MIN_BYTES
#define ZUC_128EIA3_MAX_BYTES	EEA3_MAX_BYTES
#define ZUC_128EIA3_MAC_SIZE	4

typedef struct {
	zuc_ctx_t zuc;
	size_t length;
	/* maybe buffer */
} eia3_ctx_t;

void zuc_128eia3_init(zuc_128eia3_t *eia3, const unsigned char *user_key,
	uint32_t count, uint32_t bearer, int direction);
void zuc_128eia3_update(zuc_128eia3_t *eia3, const unsigned char *data,
	size_t datalen);
void zuc_128eia3_final(zuc_128eia3_t *eia3, uint32_t *mac);
void zuc_128eia3(const unsigned char *key, uint32_t count, uint32_t bearer,
	int direction, const unsigned char *data, size_t len, uint32_t *mac);


#ifdef __cplusplus
}
#endif
#endif
#endif
