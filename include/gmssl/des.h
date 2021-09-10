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

/* FIPS PUB 46-3 "Data Encryption Standard (DES)" */

#ifndef GMSSL_DES_H
#define GMSSL_DES_H


#include <stdint.h>
#include <stdlib.h>


#ifdef __cplusplus
extern "C" {
#endif


#define DES_KEY_BITS	56
#define DES_BLOCK_BITS	64
#define DES_KEY_SIZE	(DES_KEY_BITS/8)
#define DES_BLOCK_SIZE	(DES_BLOCK_BITS/8)

#define DES_RK_BITS	48
#define DES_RK_SIZE	(DES_RK_BITS/8)
#define DES_ROUNDS	16


typedef struct {
	uint64_t rk[DES_ROUNDS];
} DES_KEY;

void des_set_encrypt_key(DES_KEY *key, const unsigned char user_key[8]);
void des_set_decrypt_key(DES_KEY *key, const unsigned char user_key[8]);
void des_encrypt(DES_KEY *key, const unsigned char in[8], unsigned char out[8]);


typedef struct {
	DES_KEY K[3];
} DES_EDE_KEY;

void des_ede_set_encrypt_key(DES_EDE_KEY *key, const unsigned char user_key[24]);
void des_ede_set_decrypt_key(DES_EDE_KEY *key, const unsigned char user_key[24]);
void des_ede_encrypt(DES_EDE_KEY *key, const unsigned char in[8], unsigned char out[8]);


#ifdef __cplusplus
}
#endif
#endif
