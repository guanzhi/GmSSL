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


#ifndef GMSSL_AES_H
#define GMSSL_AES_H

#include <stdint.h>
#include <stdlib.h>

#ifdef  __cplusplus
extern "C" {
#endif


#define AES128_KEY_BITS		128
#define AES192_KEY_BITS		192
#define AES256_KEY_BITS		256

#define AES128_KEY_SIZE		(AES128_KEY_BITS/8)
#define AES192_KEY_SIZE		(AES192_KEY_BITS/8)
#define AES256_KEY_SIZE		(AES256_KEY_BITS/8)

#define AES_BLOCK_SIZE		16

#define AES128_ROUNDS		10
#define AES192_ROUNDS		12
#define AES256_ROUNDS		14
#define AES_MAX_ROUNDS		AES256_ROUNDS


typedef struct {
	uint32_t rk[4 * (AES_MAX_ROUNDS + 1)];
	size_t rounds;
} AES_KEY;

int aes_set_encrypt_key(AES_KEY *key, const uint8_t *raw_key, size_t raw_key_len);
int aes_set_decrypt_key(AES_KEY *key, const uint8_t *raw_key, size_t raw_key_len);
void aes_encrypt(const AES_KEY *key, const uint8_t in[AES_BLOCK_SIZE], uint8_t out[AES_BLOCK_SIZE]);
void aes_decrypt(const AES_KEY *key, const uint8_t in[AES_BLOCK_SIZE], uint8_t out[AES_BLOCK_SIZE]);


void aes_cbc_encrypt(const AES_KEY *key, const uint8_t iv[AES_BLOCK_SIZE],
	const uint8_t *in, size_t nblocks, uint8_t *out);
void aes_cbc_decrypt(const AES_KEY *key, const uint8_t iv[AES_BLOCK_SIZE],
	const uint8_t *in, size_t nblocks, uint8_t *out);
int aes_cbc_padding_encrypt(const AES_KEY *key, const uint8_t iv[AES_BLOCK_SIZE],
	const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen);
int aes_cbc_padding_decrypt(const AES_KEY *key, const uint8_t iv[AES_BLOCK_SIZE],
	const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen);

void aes_ctr_encrypt(const AES_KEY *key, uint8_t ctr[AES_BLOCK_SIZE],
	const uint8_t *in, size_t inlen, uint8_t *out);
#define aes_ctr_decrypt(key,ctr,in,inlen,out) aes_ctr_encrypt(key,ctr,in,inlen,out)


#define AES_GCM_IV_MIN_SIZE		1
#define AES_GCM_IV_MAX_SIZE		((uint64_t)(1 << (64-3)))
#define AES_GCM_IV_DEFAULT_BITS		96
#define AES_GCM_IV_DEFAULT_SIZE		12

#define AES_GCM_MIN_AAD_SIZE		0
#define AES_GCM_MAX_AAD_SIZE		((uint64_t)(1 << (64-3)))

#define AES_GCM_MIN_PLAINTEXT_SIZE	0
#define AES_GCM_MAX_PLAINTEXT_SIZE	((((uint64_t)1 << 39) - 256) >> 3)

int aes_gcm_encrypt(const AES_KEY *key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	uint8_t *out, size_t taglen, uint8_t *tag);
int aes_gcm_decrypt(const AES_KEY *key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	const uint8_t *tag, size_t taglen, uint8_t *out);


#ifdef  __cplusplus
}
#endif
#endif
