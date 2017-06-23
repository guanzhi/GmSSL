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
#ifndef SPECK_H
#define SPECK_H

#define SPECK_TYPE16 uint16_t
#define SPECK_ROUNDS16 22
#define SPECK_KEY_LEN16 4


#define SPECK_TYPE32 uint32_t
#define SPECK_ROUNDS32 27
#define SPECK_KEY_LEN32 4

#define SPECK_TYPE64 uint64_t
#define SPECK_ROUNDS64 34
#define SPECK_KEY_LEN64 4

#define ROR16(x, r) ((x >> r) | (x << ((sizeof(SPECK_TYPE16) * 8) - r)))//循环右移
#define ROL16(x, r) ((x << r) | (x >> ((sizeof(SPECK_TYPE16) * 8) - r)))//循环左移

#define ROR32(x, r) ((x >> r) | (x << ((sizeof(SPECK_TYPE32) * 8) - r)))//循环右移
#define ROL32(x, r) ((x << r) | (x >> ((sizeof(SPECK_TYPE32) * 8) - r)))//循环左移

#define ROR64(x, r) ((x >> r) | (x << ((sizeof(SPECK_TYPE64) * 8) - r)))//循环右移
#define ROL64(x, r) ((x << r) | (x >> ((sizeof(SPECK_TYPE64) * 8) - r)))//循环左移


#define R16(x, y, k) (x = ROR16(x, 7), x += y, x ^= k, y = ROL16(y, 2), y ^= x)
#define RR16(x, y, k) (y ^= x, y = ROR16(y, 2), x ^= k, x -= y, x = ROL16(x, 7))

#define R32(x, y, k) (x = ROR32(x, 8), x += y, x ^= k, y = ROL32(y, 3), y ^= x)
#define RR32(x, y, k) (y ^= x, y = ROR32(y, 3), x ^= k, x -= y, x = ROL32(x, 8))

#define R64(x, y, k) (x = ROR64(x, 8), x += y, x ^= k, y = ROL64(y, 3), y ^= x)
#define RR64(x, y, k) (y ^= x, y = ROR64(y, 3), x ^= k, x -= y, x = ROL64(x, 8))

#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#ifdef __cplusplus
extern "C" {
#endif

	void speck_set_encrypt_key16(SPECK_TYPE16 const user[SPECK_KEY_LEN16], SPECK_TYPE16 key[SPECK_ROUNDS16]);
	void speck_set_decrypt_key16(SPECK_TYPE16 const user[SPECK_KEY_LEN16], SPECK_TYPE16 key[SPECK_ROUNDS16]);
	void speck_expand16(SPECK_TYPE16 const K[SPECK_KEY_LEN16], SPECK_TYPE16 S[SPECK_ROUNDS16]);
	void speck_encrypt16(SPECK_TYPE16 const pt[2], SPECK_TYPE16 ct[2], SPECK_TYPE16 const K[SPECK_ROUNDS16]);
	void speck_decrypt16(SPECK_TYPE16 const ct[2], SPECK_TYPE16 pt[2], SPECK_TYPE16 const K[SPECK_ROUNDS16]);

	void speck_set_encrypt_key32(SPECK_TYPE32 const user[SPECK_KEY_LEN32], SPECK_TYPE32 key[SPECK_ROUNDS32]);
	void speck_set_decrypt_key32(SPECK_TYPE32 const user[SPECK_KEY_LEN32], SPECK_TYPE32 key[SPECK_ROUNDS32]);
	void speck_expand32(SPECK_TYPE32 const K[SPECK_KEY_LEN32], SPECK_TYPE32 S[SPECK_ROUNDS32]);
	void speck_encrypt32(SPECK_TYPE32 const pt[2], SPECK_TYPE32 ct[2], SPECK_TYPE32 const K[SPECK_ROUNDS32]);
	void speck_decrypt32(SPECK_TYPE32 const ct[2], SPECK_TYPE32 pt[2], SPECK_TYPE32 const K[SPECK_ROUNDS32]);

	void speck_set_encrypt_key64(SPECK_TYPE64 const user[SPECK_KEY_LEN64], SPECK_TYPE64 key[SPECK_ROUNDS64]);
	void speck_set_decrypt_key64(SPECK_TYPE64 const user[SPECK_KEY_LEN64], SPECK_TYPE64 key[SPECK_ROUNDS64]);
	void speck_expand64(SPECK_TYPE64 const K[SPECK_KEY_LEN64], SPECK_TYPE64 S[SPECK_ROUNDS64]);
	void speck_encrypt64(SPECK_TYPE64 const pt[2], SPECK_TYPE64 ct[2], SPECK_TYPE64 const K[SPECK_ROUNDS64]);
	void speck_decrypt64(SPECK_TYPE64 const ct[2], SPECK_TYPE64 pt[2], SPECK_TYPE64 const K[SPECK_ROUNDS64]);

#ifdef __cplusplus
}
#endif
#endif
