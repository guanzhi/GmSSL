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

#ifndef GMSSL_ZUC_H
#define GMSSL_ZUC_H


#include <stdlib.h>
#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif


# define ZUC_KEY_SIZE	16
# define ZUC_IV_SIZE	16
# define ZUC_MAC_SIZE	4

typedef uint32_t ZUC_BIT;
typedef uint32_t ZUC_UINT5;
typedef uint8_t  ZUC_UINT6;
typedef uint32_t ZUC_UINT15;
typedef uint32_t ZUC_UINT31;
typedef uint32_t ZUC_UINT32;

typedef struct {
	ZUC_UINT31 LFSR[16];
	ZUC_UINT32 R1;
	ZUC_UINT32 R2;
} ZUC_STATE;

void zuc_init(ZUC_STATE *state, const uint8_t key[ZUC_KEY_SIZE], const uint8_t iv[ZUC_IV_SIZE]);
void zuc_generate_keystream(ZUC_STATE *state, size_t nwords, ZUC_UINT32 *words);
ZUC_UINT32 zuc_generate_keyword(ZUC_STATE *state);
void zuc_encrypt(ZUC_STATE *state, const uint8_t *in, size_t inlen, uint8_t *out);

typedef struct ZUC_MAC_CTX_st {
	ZUC_UINT31 LFSR[16];
	ZUC_UINT32 R1;
	ZUC_UINT32 R2;
	ZUC_UINT32 T;
	ZUC_UINT32 K0;
	uint8_t buf[4];
	size_t buflen;
} ZUC_MAC_CTX;

void zuc_mac_init(ZUC_MAC_CTX *ctx, const uint8_t key[ZUC_KEY_SIZE], const uint8_t iv[ZUC_IV_SIZE]);
void zuc_mac_update(ZUC_MAC_CTX *ctx, const uint8_t *data, size_t len);
void zuc_mac_finish(ZUC_MAC_CTX *ctx, const uint8_t *data, size_t nbits, uint8_t mac[ZUC_MAC_SIZE]);

void zuc_eea_encrypt(const ZUC_UINT32 *in, ZUC_UINT32 *out, size_t nbits,
	const uint8_t key[ZUC_KEY_SIZE], ZUC_UINT32 count, ZUC_UINT5 bearer,
	ZUC_BIT direction);
ZUC_UINT32 zuc_eia_generate_mac(const ZUC_UINT32 *data, size_t nbits,
	const uint8_t key[ZUC_KEY_SIZE], ZUC_UINT32 count, ZUC_UINT5 bearer,
	ZUC_BIT direction);


# define ZUC256_KEY_SIZE	32
# define ZUC256_IV_SIZE		23
# define ZUC256_MAC32_SIZE	4
# define ZUC256_MAC64_SIZE	8
# define ZUC256_MAC128_SIZE	16
# define ZUC256_MIN_MAC_SIZE	ZUC256_MAC32_SIZE
# define ZUC256_MAX_MAC_SIZE	ZUC256_MAC128_SIZE

typedef ZUC_STATE ZUC256_STATE;

void zuc256_init(ZUC256_STATE *state, const uint8_t key[ZUC256_KEY_SIZE], const uint8_t iv[ZUC256_IV_SIZE]);
#define zuc256_generate_keystream(state,nwords,words) zuc_generate_keystream(state,nwords,words)
#define zuc256_generate_keyword(state) zuc_generate_keyword(state)


typedef struct ZUC256_MAC_CTX_st {
	ZUC_UINT31 LFSR[16];
	ZUC_UINT32 R1;
	ZUC_UINT32 R2;
	ZUC_UINT32 T[4];
	ZUC_UINT32 K0[4];
	uint8_t buf[4];
	int buflen;
	int macbits;
} ZUC256_MAC_CTX;

void zuc256_mac_init(ZUC256_MAC_CTX *ctx, const uint8_t key[ZUC256_KEY_SIZE],
	const uint8_t iv[ZUC256_IV_SIZE], int macbits);
void zuc256_mac_update(ZUC256_MAC_CTX *ctx, const uint8_t *data, size_t len);
void zuc256_mac_finish(ZUC256_MAC_CTX *ctx, const uint8_t *data, size_t nbits, uint8_t *mac);


// Public API

typedef struct {
	ZUC_STATE zuc_state;
	uint8_t block[4];
	size_t block_nbytes;
} ZUC_CTX;

int zuc_encrypt_init(ZUC_CTX *ctx, const uint8_t key[ZUC_KEY_SIZE], const uint8_t iv[ZUC_IV_SIZE]);
int zuc_encrypt_update(ZUC_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int zuc_encrypt_finish(ZUC_CTX *ctx, uint8_t *out, size_t *outlen);

#define zuc_decrypt_init(ctx,key,iv) zuc_encrypt_init(ctx,key,iv)
#define zuc_decrypt_update(ctx,in,inlen,out,outlen) zuc_encrypt_update(ctx,in,inlen,out,outlen)
#define zuc_decrypt_finish(ctx,out,outlen) zuc_encrypt_finish(ctx,out,outlen)


#ifdef __cplusplus
}
#endif
#endif
