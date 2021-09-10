/* 
 *   Copyright 2014-2021 The GmSSL Project Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
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


