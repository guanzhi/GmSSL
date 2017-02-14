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

#include <openssl/sms4.h>
#include "sms4_lcl.h"

static uint32_t FK[4] = {
	0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc,
};

static uint32_t CK[32] = {
	0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
	0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
	0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
	0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
	0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
	0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
	0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
	0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
};

#define L32_(x)					\
	((x) ^ 					\
	ROT32((x), 13) ^			\
	ROT32((x), 23))

#define ENC_ROUND(x0, x1, x2, x3, x4, i)	\
	x4 = x1 ^ x2 ^ x3 ^ *(CK + i);		\
	x4 = S32(x4);				\
	x4 = x0 ^ L32_(x4);			\
	*(rk + i) = x4

#define DEC_ROUND(x0, x1, x2, x3, x4, i)	\
	x4 = x1 ^ x2 ^ x3 ^ *(CK + i);		\
	x4 = S32(x4);				\
	x4 = x0 ^ L32_(x4);			\
	*(rk + 31 - i) = x4

void sms4_set_encrypt_key(sms4_key_t *key, const unsigned char *user_key)
{
	uint32_t *rk = key->rk;
	uint32_t x0, x1, x2, x3, x4;

	x0 = GET32(user_key     ) ^ FK[0];
	x1 = GET32(user_key  + 4) ^ FK[1];
	x2 = GET32(user_key  + 8) ^ FK[2];
	x3 = GET32(user_key + 12) ^ FK[3];

#define ROUND ENC_ROUND
	ROUNDS(x0, x1, x2, x3, x4);

	x0 = x1 = x2 = x3 = x4 = 0;
}

void sms4_set_decrypt_key(sms4_key_t *key, const unsigned char *user_key)
{
	uint32_t *rk = key->rk;
	uint32_t x0, x1, x2, x3, x4;

	x0 = GET32(user_key     ) ^ FK[0];
	x1 = GET32(user_key  + 4) ^ FK[1];
	x2 = GET32(user_key  + 8) ^ FK[2];
	x3 = GET32(user_key + 12) ^ FK[3];

#undef ROUND
#define ROUND DEC_ROUND
	ROUNDS(x0, x1, x2, x3, x4);

	x0 = x1 = x2 = x3 = x4 = 0;
}
