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

#ifndef GMSSL_SM4_H
#define GMSSL_SM4_H

#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif


/*
SM4 Public API

	SM4_KEY_SIZE
	SM4_BLOCK_SIZE

	SM4_CBC_CTX
	sm4_cbc_encrypt_init
	sm4_cbc_encrypt_update
	sm4_cbc_encrypt_finish
	sm4_cbc_decrypt_init
	sm4_cbc_decrypt_update
	sm4_cbc_decrypt_finish

	SM4_CTR_CTX
	sm4_ctr_encrypt_init
	sm4_ctr_encrypt_update
	sm4_ctr_encrypt_finish
	sm4_ctr_decrypt_init
	sm4_ctr_decrypt_update
	sm4_ctr_decrypt_finish
*/

#define SM4_KEY_SIZE		(16)
#define SM4_BLOCK_SIZE		(16)
#define SM4_NUM_ROUNDS		(32)


typedef struct {
	uint32_t rk[SM4_NUM_ROUNDS];
} SM4_KEY;

void sm4_set_encrypt_key(SM4_KEY *key, const uint8_t raw_key[SM4_KEY_SIZE]);
void sm4_set_decrypt_key(SM4_KEY *key, const uint8_t raw_key[SM4_KEY_SIZE]);
void sm4_encrypt(const SM4_KEY *key, const uint8_t in[SM4_BLOCK_SIZE], uint8_t out[SM4_BLOCK_SIZE]);
#define sm4_decrypt(key,in,out) sm4_encrypt(key,in,out)


void sm4_cbc_encrypt(const SM4_KEY *key, const uint8_t iv[SM4_BLOCK_SIZE],
	const uint8_t *in, size_t nblocks, uint8_t *out);
void sm4_cbc_decrypt(const SM4_KEY *key, const uint8_t iv[SM4_BLOCK_SIZE],
	const uint8_t *in, size_t nblocks, uint8_t *out);
int sm4_cbc_padding_encrypt(const SM4_KEY *key, const uint8_t iv[SM4_BLOCK_SIZE],
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sm4_cbc_padding_decrypt(const SM4_KEY *key, const uint8_t iv[SM4_BLOCK_SIZE],
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);


void sm4_ctr_encrypt(const SM4_KEY *key, uint8_t ctr[SM4_BLOCK_SIZE],
	const uint8_t *in, size_t inlen, uint8_t *out);
#define sm4_ctr_decrypt(key,ctr,in,inlen,out) sm4_ctr_encrypt(key,ctr,in,inlen,out)


#define SM4_GCM_IV_MIN_SIZE		1
#define SM4_GCM_IV_MAX_SIZE		((uint64_t)(1 << (64-3)))
#define SM4_GCM_IV_DEFAULT_BITS		96
#define SM4_GCM_IV_DEFAULT_SIZE		12

#define SM4_GCM_MIN_AAD_SIZE		0
#define SM4_GCM_MAX_AAD_SIZE		((uint64_t)(1 << (64-3)))

#define SM4_GCM_MIN_PLAINTEXT_SIZE	0
#define SM4_GCM_MAX_PLAINTEXT_SIZE	((((uint64_t)1 << 39) - 256) >> 3)

int sm4_gcm_encrypt(const SM4_KEY *key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	uint8_t *out, size_t taglen, uint8_t *tag);
int sm4_gcm_decrypt(const SM4_KEY *key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	const uint8_t *tag, size_t taglen, uint8_t *out);


typedef struct {
	SM4_KEY sm4_key;
	uint8_t iv[SM4_BLOCK_SIZE];
	uint8_t block[SM4_BLOCK_SIZE];
	size_t block_nbytes;
} SM4_CBC_CTX;

int sm4_cbc_encrypt_init(SM4_CBC_CTX *ctx, const uint8_t key[SM4_KEY_SIZE], const uint8_t iv[SM4_BLOCK_SIZE]);
int sm4_cbc_encrypt_update(SM4_CBC_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sm4_cbc_encrypt_finish(SM4_CBC_CTX *ctx, uint8_t *out, size_t *outlen);

int sm4_cbc_decrypt_init(SM4_CBC_CTX *ctx, const uint8_t key[SM4_KEY_SIZE], const uint8_t iv[SM4_BLOCK_SIZE]);
int sm4_cbc_decrypt_update(SM4_CBC_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sm4_cbc_decrypt_finish(SM4_CBC_CTX *ctx, uint8_t *out, size_t *outlen);


typedef struct {
	SM4_KEY sm4_key;
	uint8_t ctr[SM4_BLOCK_SIZE];
	uint8_t block[SM4_BLOCK_SIZE];
	size_t block_nbytes;
} SM4_CTR_CTX;

int sm4_ctr_encrypt_init(SM4_CTR_CTX *ctx, const uint8_t key[SM4_KEY_SIZE], const uint8_t ctr[SM4_BLOCK_SIZE]);
int sm4_ctr_encrypt_update(SM4_CTR_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sm4_ctr_encrypt_finish(SM4_CTR_CTX *ctx, uint8_t *out, size_t *outlen);

#define sm4_ctr_decrypt_init(ctx,key,ctr) sm4_ctr_encrypt_init(ctx,key,ctr)
#define sm4_ctr_decrypt_update(ctx,in,inlen,out,outlen) sm4_ctr_encrypt_update(ctx,in,inlen,out,outlen)
#define sm4_ctr_decrypt_finish(ctx,out,outlen) sm4_ctr_encrypt_finish(ctx,out,outlen)


#ifdef __cplusplus
}
#endif
#endif
