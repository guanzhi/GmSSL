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
#ifndef HEADER_SPECK_H
#define HEADER_SPECK_H

#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_SPECK

#define SPECK_ROUNDS16	22
#define SPECK_KEY_LEN16	4

#define SPECK_ROUNDS32	27
#define SPECK_KEY_LEN32	4

#define SPECK_ROUNDS64	34
#define SPECK_KEY_LEN64	4

#include <string.h>
#include <sys/types.h>
#include <openssl/e_os2.h>

#ifdef __cplusplus
extern "C" {
#endif

void speck_set_encrypt_key16(const uint16_t user[SPECK_KEY_LEN16], uint16_t key[SPECK_ROUNDS16]);
void speck_set_decrypt_key16(uint16_t const user[SPECK_KEY_LEN16], uint16_t key[SPECK_ROUNDS16]);
void speck_encrypt16(const uint16_t pt[2], uint16_t ct[2], const uint16_t K[SPECK_ROUNDS16]);
void speck_decrypt16(const uint16_t ct[2], uint16_t pt[2], const uint16_t K[SPECK_ROUNDS16]);

void speck_set_encrypt_key32(const uint32_t user[SPECK_KEY_LEN32], uint32_t key[SPECK_ROUNDS32]);
void speck_set_decrypt_key32(const uint32_t user[SPECK_KEY_LEN32], uint32_t key[SPECK_ROUNDS32]);
void speck_encrypt32(const uint32_t pt[2], uint32_t ct[2], const uint32_t K[SPECK_ROUNDS32]);
void speck_decrypt32(const uint32_t ct[2], uint32_t pt[2], const uint32_t K[SPECK_ROUNDS32]);

void speck_set_encrypt_key64(const uint64_t user[SPECK_KEY_LEN64], uint64_t key[SPECK_ROUNDS64]);
void speck_set_decrypt_key64(const uint64_t user[SPECK_KEY_LEN64], uint64_t key[SPECK_ROUNDS64]);
void speck_encrypt64(const uint64_t pt[2], uint64_t ct[2], const uint64_t K[SPECK_ROUNDS64]);
void speck_decrypt64(const uint64_t ct[2], uint64_t pt[2], const uint64_t K[SPECK_ROUNDS64]);

#ifdef __cplusplus
}
#endif
#endif
#endif
