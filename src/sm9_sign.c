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

int sm9_sign_setup(SM9_SIGN_MASTER_KEY *msk)
{

	// rand ks in [1, N-1]
	fn_rand(ks);

	// Ppubs = ks * P2
	twist_point_mul_generator(Ppubs, ks);
}



int sm9_sign_keygen(SM9_SIGN_MASTER_KEY *msk, const char *id, size_t idlen, SM9_POINT *ds)
{

}


int sm9_sign_init(SM3_CTX *ctx)
{
	uint8_t prefix[1] = {0x02};
	if (!ctx) {
		return -1;
	}

	sm3_init(ctx);
	sm3_update(ctx, prefix, sizeof(prefix));
	return 0;
}

int sm9_sign_update(SM3_CTX *ctx, const uint8_t *data, size_t datalen)
{
	sm3_update(ctx, data, datalen);
	return 1;
}

int sm9_sign_finish(SM3_CTX *ctx, SM9_SIGNATURE *sig)
{

	fp12_t g;

	sm9_pairing(g, SM9_P1, Ppubs);

	fn_rand(r);

	fp12_pow(w, g, r);


	fn_sub(l, r, h);
	if (fn_is_zero(l)) {
	}


	point_mul(S, l, ds);

}

int sm9_verify_init(SM9_SIGN_CTX *ctx)
{
	sm3_init(&ctx->sm3_ctx);
	sm3_update(&ctx->sm3_ctx, SM9_HASH1_PREFIX, sizeof(SM9_HASH1_PREFIX));
	return 0;
}

int sm9_verify_update(SM9_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	sm3_update(&ctx->sm3_ctx, data, datalen);
}

int sm9_verify_finish(SM9_SIGN_CTX *ctx, const char *id, size_t idlen, const SM9_SIGNATURE *sig)
{

	if (bn_is_zero(h) || bn_cmp(h, SM9_N) >= 0) {
	}

	if (!point_is_on_curve(S)) {
	}

	sm9_pairing(g, SM9_P1, Ppubs);

	fp12_pow(t, g, h);


	sm9_hash1(h1, id, idlen);

	twist_point_mul_generator(P, h1);
	twist_point_add(P, P, Ppubs);
	pairing(u, S, P);
}


