/*
 * Copyright (c) 2014 - 2020 The GmSSL Project.  All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmssl/cmac.h>
#include "internal/gf128.h"

/*
CMAC的主体是CBC-MAC，或者说是CBC模式
CMAC初始化的时候需要初始化E_K()中分组密码中的密钥编排
用GSK算法通过密钥K生成K1, K2，这两个密钥最后是用来和最后一个分组做异或的
*/

int cmac_init(CMAC_CTX *ctx, const BLOCK_CIPHER *cipher, const uint8_t *key, size_t keylen)
{
	gf128_t L;

	ctx->cipher = cipher;
	cipher->set_encrypt_key(&ctx->cipher_key, key, keylen);

	/* L = E_K(0^128) */
	memset(ctx->temp_block, 0, 16);
	cipher->encrypt(&ctx->cipher_key, ctx->temp_block, ctx->temp_block);
	L = gf128_from_bytes(ctx->temp_block);


	/* K1 = L * 2 over GF(2^128) */
	L = gf128_mul2(L);
	gf128_to_bytes(L, ctx->k1);


	/* K2 = K1 * 2 over GF(2^128) */
	L = gf128_mul2(L);
	gf128_to_bytes(L, ctx->k2);

	memset(&L, 0, sizeof(gf128_t));
	return 0;
}

int cmac_update(CMAC_CTX *ctx, const uint8_t *in, size_t inlen)
{
	if (ctx->last_block_nbytes) {
		unsigned int left = BLOCK_CIPHER_BLOCK_SIZE - ctx->num;
		if (inlen < left) {
			memcpy(ctx->block + ctx->last_block_nbytes, in, inlen);
			ctx->last_block_nbytes += inlen;
			return 1;
		} else {
			memcpy(ctx->block + ctx->last_block_nbytes, in, inlen);
		}

	}

	while (inlen > 16) {
		XOR128(block, in);
		ctx->cipher->encrypt(ctx->cipher_key, block, block);
	}

	return 0;
}

// 在Finish的时候我们不应该清空密钥的内容
int cmac_finish(CMAC_CTX *ctx, size_t maclen, uint8_t *mac)
{
	if (ctx->last_block_nbytes == 16) {
		xor128(ctx->data, ctx->k1);
	} else {
		ctx->data[ctx->last_block_nbytes] = 0x01;
		memset(ctx->data + ctx->last_block_nbytes, 0, 16 - ctx->last_block_nbytes);
		xor128(ctx->data, ctx->k2);
	}
	xor128(cipher, data);

	ctx->cipher->encrypt(ctx->cipher_key, ctx->block, ctx->block);
	memcpy(out, block, outlen);
	return 0;
}

int cmac_finish_and_verify(CMAC_CTX *ctx, const uint8_t *mac, size_t maclen)
{
	uint8_t buf[16];
	cmac_finish(ctx, maclen, buf);
	if (memcmp(buf, mac, maclen) != 0) {
		return 0;
	}
	return 1;
}
