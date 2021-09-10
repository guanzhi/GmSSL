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


#include <sys/types.h>
#include <stdint.h>
#include <string.h>


#ifdef __cplusplus
extern "C" {
#endif


#define SM4_KEY_SIZE		(16)
#define SM4_BLOCK_SIZE		(16)
#define SM4_NUM_ROUNDS		(32)

// TODO: 增加一个flag标注用于加密还是解密，使用时用assert检查这个flag
typedef struct {
	uint32_t rk[SM4_NUM_ROUNDS];
} SM4_KEY;


void sm4_set_encrypt_key(SM4_KEY *sm4_key, const uint8_t key[16]);
void sm4_set_decrypt_key(SM4_KEY *sm4_key, const uint8_t key[16]);
void sm4_encrypt(const SM4_KEY *sm4_key, const uint8_t in[16], uint8_t out[16]);


void sm4_cbc_encrypt(const SM4_KEY *key, const uint8_t iv[16],
	const uint8_t *in, size_t nblocks, uint8_t *out);

void sm4_cbc_decrypt(const SM4_KEY *key, const uint8_t iv[16],
	const uint8_t *in, size_t nblocks, uint8_t *out);

int sm4_cbc_padding_encrypt(const SM4_KEY *key, const uint8_t iv[16],
	const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen);

int sm4_cbc_padding_decrypt(const SM4_KEY *key, const uint8_t iv[16],
	const uint8_t *in, size_t inlen,
	uint8_t *out, size_t *outlen);

void sm4_ctr_encrypt(const SM4_KEY *key, uint8_t ctr[16],
	const uint8_t *in, size_t inlen, uint8_t *out);

int sm4_gcm_encrypt(const SM4_KEY *key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	uint8_t *out, const size_t taglen, uint8_t *tag);

int sm4_gcm_decrypt(const SM4_KEY *key, const uint8_t *iv, size_t ivlen,
	const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
	const uint8_t *tag, size_t taglen, uint8_t *out);


#ifdef __cplusplus
}
#endif
#endif
