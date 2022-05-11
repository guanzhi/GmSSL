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
#include <stdint.h>
#include <gmssl/sm3.h>
#include <gmssl/sm9.h>
#include <gmssl/error.h>


void sm9_fn_rand(sm9_fn_t r)
{
	// FIXME: add impl
}

int sm9_fn_equ(const sm9_fn_t a, const sm9_fn_t b)
{
	// FIXME: add impl
	return 1;
}

void sm9_fp12_to_bytes(const sm9_fp12_t a, uint8_t buf[32 * 12])
{
	// FIXME: add impl
}

int sm9_sign_init(SM9_SIGN_CTX *ctx)
{
	const uint8_t prefix[1] = {0x02};
	sm3_init(&ctx->sm3_ctx);
	sm3_update(&ctx->sm3_ctx, prefix, sizeof(prefix));
	return 1;
}

int sm9_sign_update(SM9_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	sm3_update(&ctx->sm3_ctx, data, datalen);
	return 1;
}

int sm9_sign_finish(SM9_SIGN_CTX *ctx, SM9_SIGN_KEY *key, SM9_SIGNATURE *sig)
{
	sm9_fn_t r;
	sm9_fn_t h;
	sm9_fp12_t g;
	sm9_fp12_t w;
	uint8_t wbuf[32 * 12];
	uint8_t dgst[32];

	sm9_pairing(g, &key->Ppubs, SM9_P1);
	do {
		sm9_fn_rand(r);
		sm9_fp12_pow(w, g, r);
		sm9_fp12_to_bytes(w, wbuf);
		sm3_update(&ctx->sm3_ctx, wbuf, sizeof(wbuf));
		sm3_finish(&ctx->sm3_ctx, dgst);
		// do H2() staff, generate output sig->h
		sm9_fn_sub(r, r, h);
	} while (sm9_fn_is_zero(r));
	sm9_point_mul(&sig->S, r, &key->ds);
	return 1;
}

int sm9_verify_init(SM9_SIGN_CTX *ctx)
{
	const uint8_t prefix[1] = {0x02};
	sm3_init(&ctx->sm3_ctx);
	sm3_update(&ctx->sm3_ctx, prefix, sizeof(prefix));
	return 1;
}

int sm9_verify_update(SM9_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	sm3_update(&ctx->sm3_ctx, data, datalen);
	return 1;
}

// 签名的时候
int sm9_verify_finish(SM9_SIGN_CTX *ctx, const SM9_SIGNATURE *sig,
	const SM9_SIGN_MASTER_KEY *master_public, const char *id, size_t idlen)
{
	sm9_fn_t h1;
	sm9_fn_t h2;
	sm9_fp12_t g;
	sm9_fp12_t t;
	sm9_fp12_t u;
	sm9_fp12_t w;
	sm9_twist_point_t P;
	uint8_t wbuf[32 * 12];

	sm9_pairing(g, &master_public->Ppubs, SM9_P1);
	sm9_fp12_pow(t, g, sig->h);
	sm9_hash1(h1, id, idlen, SM9_HID_SIGN);
	sm9_twist_point_mul_G(&P, h1);
	sm9_twist_point_add(&P, &P, &master_public->Ppubs);
	sm9_pairing(u, &P, &sig->S);
	sm9_fp12_mul(w, u, t);
	sm9_fp12_to_bytes(w, wbuf);

	sm3_update(&ctx->sm3_ctx, wbuf, sizeof(wbuf));
	// convert h2

	if (sm9_fn_equ(h2, sig->h) != 1) {
		return 0;
	}
	return 1;
}


