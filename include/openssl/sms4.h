/* ====================================================================
 * Copyright (c) 2014 - 2017 The GmSSL Project.  All rights reserved.
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

#ifndef HEADER_SMS4_H
#define HEADER_SMS4_H

#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_SMS4

#define SMS4_KEY_LENGTH		16
#define SMS4_BLOCK_SIZE		16
#define SMS4_IV_LENGTH		(SMS4_BLOCK_SIZE)
#define SMS4_NUM_ROUNDS		32

#include <sys/types.h>
#include <openssl/e_os2.h>
#include <string.h>


#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	uint32_t rk[SMS4_NUM_ROUNDS];
} sms4_key_t;

void sms4_set_encrypt_key(sms4_key_t *key, const unsigned char *user_key);
void sms4_set_decrypt_key(sms4_key_t *key, const unsigned char *user_key);
void sms4_encrypt(const unsigned char *in, unsigned char *out, const sms4_key_t *key);
#define sms4_decrypt(in,out,key)  sms4_encrypt(in,out,key)

void sms4_encrypt_init(sms4_key_t *key);
void sms4_encrypt_8blocks(const unsigned char *in, unsigned char *out, const sms4_key_t *key);
void sms4_encrypt_16blocks(const unsigned char *in, unsigned char *out, const sms4_key_t *key);

void sms4_ecb_encrypt(const unsigned char *in, unsigned char *out,
	const sms4_key_t *key, int enc);
void sms4_cbc_encrypt(const unsigned char *in, unsigned char *out,
	size_t len, const sms4_key_t *key, unsigned char *iv, int enc);
void sms4_cfb128_encrypt(const unsigned char *in, unsigned char *out,
	size_t len, const sms4_key_t *key, unsigned char *iv, int *num, int enc);
void sms4_ofb128_encrypt(const unsigned char *in, unsigned char *out,
	size_t len, const sms4_key_t *key, unsigned char *iv, int *num);
void sms4_ctr128_encrypt(const unsigned char *in, unsigned char *out,
	size_t len, const sms4_key_t *key, unsigned char *iv,
	unsigned char ecount_buf[SMS4_BLOCK_SIZE], unsigned int *num);

int sms4_wrap_key(sms4_key_t *key, const unsigned char *iv,
	unsigned char *out, const unsigned char *in, unsigned int inlen);
int sms4_unwrap_key(sms4_key_t *key, const unsigned char *iv,
	unsigned char *out, const unsigned char *in, unsigned int inlen);

/*
void sms4_avx2_encrypt_init(sms4_key_t *key);
void sms4_avx2_encrypt_8blocks(const unsigned char *in, unsigned char *out, const sms4_key_t *key);
void sms4_avx2_encrypt_16blocks(const unsigned char *in, unsigned char *out, const sms4_key_t *key);

void sms4_knc_encrypt_init(sms4_key_t *key);
void sms4_knc_encrypt_8blocks(const unsigned char *in, unsigned char *out, const sms4_key_t *key);
void sms4_knc_encrypt_16blocks(const unsigned char *in, unsigned char *out, const sms4_key_t *key);

#define SMS4_EDE_KEY_LENGTH	32

typedef struct {
	sms4_key_t k1;
	sms4_key_t k2;
} sms4_ede_key_t;

void sms4_ede_set_encrypt_key(sms4_ede_key_t *key, const unsigned char *user_key);
void sms4_ede_set_decrypt_key(sms4_ede_key_t *key, const unsigned char *user_key);
void sms4_ede_encrypt(sms4_ede_key_t *key, const unsigned char *in, unsigned char *out);
void sms4_ede_encrypt_8blocks(sms4_ede_key_t *key, const unsigned char *in, unsigned char *out);
void sms4_ede_encrypt_16blocks(sms4_ede_key_t *key, const unsigned char *in, unsigned char *out);
void sms4_ede_decrypt(sms4_ede_key_t *key, const unsigned char *in, unsigned char *out);
void sms4_ede_decrypt_8blocks(sms4_ede_key_t *key, const unsigned char *in, unsigned char *out);
void sms4_ede_decrypt_16blocks(sms4_ede_key_t *key, const unsigned char *in, unsigned char *out);
*/

#ifdef __cplusplus
}
#endif
#endif
#endif
