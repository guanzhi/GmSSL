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



#ifndef GMSSL_CIPHER_H
#define GMSSL_CIPHER_H

#ifdef __cplusplus
extern "C" {
#endif






struct cipher_st {
	int nid;
	size_t block_size;
	size_t key_size;
	size_t iv_size;
	unsigned long flags;
	int (*init)(CIPHER_CTX *ctx, const uint8_t *key);
	int (*encrypt)(CIPHER_CTX *ctx);
};

struct cipher_ctx_st {
	CIPHER *cipher;
	int is_encrypt;
	uint8_t iv[16];
	uint8_t block[16];
};

int cipher_encyrpt_init(CIPHER_CTX *ctx, const CIPHER *cipher, const uint8_t *key, const uint8_t *iv);
int cipher_encrypt_update(CIPHER_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int cipher_encrypt_finish(CIPHER_CTX *ctx, uint8_t *out, size_t *outlen);

int cipher_decrypt_init(CIPHER_CTX *ctx, const CIPHER *cipher, const uint8_t *key, const uint8_t *iv);
int cipher_decrypt_update(CIPHER_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int cipher_decrypt_finish(CIPHER_CTX *ctx, uint8_t *out, size_t *outlen);

int cipher_init(CIPHER_CTX *ctx, const CIPHER *cipher, const uint8_t *key, const uint8_t *iv, int enc);
int cipher_update(CIPHER_CTX *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int cipher_finish(CIPHER_CTX *ctx, uint8_t *out, size_t *outlen);


const CIPHER *CIPHER_sm4_ecb(void);
const CIPHER *CIPHER_sm4_cbc(void);
const CIPHER *CIPHER_sm4_ofb(void);
const CIPHER *CIPHER_sm4_cfb1(void);
const CIPHER *CIPHER_sm4_cfb8(void);
const CIPHER *CIPHER_sm4_cfb128(void);
const CIPHER *CIPHER_sm4_ctr(void);
const CIPHER *CIPHER_sm4_gcm(void);
const CIPHER *CIPHER_zuc(void);
const CIPHER *CIPHER_zuc256(void);



#ifdef __cplusplus
}
#endif
#endif
