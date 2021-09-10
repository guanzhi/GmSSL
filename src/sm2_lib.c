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
#include <string.h>
#include <stdlib.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/error.h>
#include "endian.h"


#define SM2_SIGNATURE_MAX_DER_SIZE 77

int sm2_sign(const SM2_KEY *key, const uint8_t dgst[32], uint8_t *der, size_t *derlen)
{
	SM2_SIGNATURE sig;
	uint8_t *p = der;
	size_t len = 0;

	if (!der && derlen) {
		*derlen = SM2_SIGNATURE_MAX_DER_SIZE;
		return 1;
	}
	if (!key || !der || !derlen) {
		return -1;
	}

	sm2_do_sign(key, dgst, &sig);
	sm2_signature_to_der(&sig, &p, &len);
	*derlen = len;

	return 1;
}

int sm2_verify(const SM2_KEY *key, const uint8_t dgst[32], const uint8_t *der, size_t derlen)
{
	int ret;
	SM2_SIGNATURE sig;
	const uint8_t *p = der;
	size_t len = derlen;

	if (!key || !der || !derlen) {
		error_print();
		return -1;
	}
	if (sm2_signature_from_der(&sig, &p, &len) < 0
		|| len > 0) {
		error_print();
		return -2;
	}
	if ((ret = sm2_do_verify(key, dgst, &sig)) != 1) {
		error_print(); // 此处应该判断ret是否为0，如果返回的是0，那么不应该输出错误日志，会产生不必要的终端输出
	}
	return ret;
}

//FIXME: 由于每次加密的时候密文编码长度不同，因此这个函数应该避免在out == NULL时输出一个长度！
int sm2_encrypt(const SM2_KEY *key, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	size_t clen = SM2_CIPHERTEXT_SIZE(inlen);
	size_t cbuf[clen];
	SM2_CIPHERTEXT *c = (SM2_CIPHERTEXT *)cbuf;

	sm2_do_encrypt(key, in, inlen, c);

	*outlen = 0;
	sm2_ciphertext_to_der(c, &out, outlen);
	return 1;
}

int sm2_decrypt(const SM2_KEY *key, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	size_t cbuf[inlen];
	SM2_CIPHERTEXT *c = (SM2_CIPHERTEXT *)cbuf;

	sm2_ciphertext_from_der(c, &in, &inlen); // FIXME: 检查是否有剩余长度		
	sm2_do_decrypt(key, c, out, outlen);
	return 1;
}

extern void sm3_compress_blocks(uint32_t digest[8], const uint8_t *data, size_t blocks);

int sm2_compute_z(uint8_t z[32], const SM2_POINT *pub, const char *id)
{
	uint8_t zin[] = {
		0x00, 0x80,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
		0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
		0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34,
		0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7,
		0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92,
		0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93,
       		0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19,
		0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
		0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1,
		0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7,
		0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C,
		0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
		0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40,
        	0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x06, 0x90,
	};

	if (!z || !pub || !id) {
		error_print();
		return -1;
	}

	if (strcmp(id, "1234567812345678") == 0) {
		uint32_t digest[8] = {
			0xadadedb5U, 0x0446043fU, 0x08a87aceU, 0xe86d2243U,
			0x8e232383U, 0xbfc81fe2U, 0xcf9117c8U, 0x4707011dU,
		};
		memcpy(&zin[128], pub->x, 32);
		memcpy(&zin[160], pub->y, 32);
		sm3_compress_blocks(digest, zin, 2);
		PUTU32(z     , digest[0]);
		PUTU32(z +  4, digest[1]);
		PUTU32(z +  8, digest[2]);
		PUTU32(z + 12, digest[3]);
		PUTU32(z + 16, digest[4]);
		PUTU32(z + 20, digest[5]);
		PUTU32(z + 24, digest[6]);
		PUTU32(z + 28, digest[7]);

	} else {
		SM3_CTX ctx;
		uint8_t idbits[2];
		size_t len;

		len = strlen(id);
		idbits[0] = (uint8_t)(len >> 5);
		idbits[1] = (uint8_t)(len << 3);

		sm3_init(&ctx);
		sm3_update(&ctx, idbits, 2);
		sm3_update(&ctx, (uint8_t *)id, len);
		sm3_update(&ctx, zin + 18, 128);
		sm3_update(&ctx, pub->x, 32);
		sm3_update(&ctx, pub->y, 32);
		sm3_finish(&ctx, z);
	}

	return 1;
}

int sm2_sign_init(SM2_SIGN_CTX *ctx, const SM2_KEY *key, const char *id)
{
	uint8_t z[32];
	if (!ctx || !key || !id || strlen(id) > SM2_MAX_ID_SIZE) {
		return -1;
	}
	sm2_compute_z(z, &key->public_key, id);

	sm3_init(&ctx->sm3_ctx);
	sm3_update(&ctx->sm3_ctx, z, 32);
	memcpy(&ctx->key, key, sizeof(SM2_KEY));
	return 1;
}

int sm2_sign_update(SM2_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	sm3_update(&ctx->sm3_ctx, data, datalen);
	return 1;
}

int sm2_sign_finish(SM2_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen)
{
	uint8_t dgst[32];
	sm3_finish(&ctx->sm3_ctx, dgst);
	sm2_sign(&ctx->key, dgst, sig, siglen);
	return 1;
}

int sm2_sign_resume(SM2_SIGN_CTX *ctx)
{
	return 0;
}

int sm2_verify_init(SM2_SIGN_CTX *ctx, const SM2_KEY *key, const char *id)
{
	uint8_t z[32];
	if (!ctx || !key || !id || strlen(id) > SM2_MAX_ID_SIZE) {
		return -1;
	}
	sm2_compute_z(z, &key->public_key, id);
	sm3_init(&ctx->sm3_ctx);
	sm3_update(&ctx->sm3_ctx, z, 32);
	memcpy(&ctx->key, key, sizeof(SM2_KEY));
	return 1;
}

int sm2_verify_update(SM2_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	sm3_update(&ctx->sm3_ctx, data, datalen);
	return 1;
}

int sm2_verify_finish(SM2_SIGN_CTX *ctx, const uint8_t *sig, size_t siglen)
{
	int ret;
	uint8_t dgst[32];
	sm3_finish(&ctx->sm3_ctx, dgst);
	ret = sm2_verify(&ctx->key, dgst, sig, siglen);
	return ret;
}

int sm2_set_private_key(SM2_KEY *key, const uint8_t private_key[32])
{
	memcpy(&key->private_key, private_key, 32);
	return 1;
}

// FIXME: 检查公钥是否正确
int sm2_set_public_key(SM2_KEY *key, const uint8_t public_key[64])
{
	memcpy(&key->public_key, public_key, 64);
	return 1;
}
