/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <gmssl/sm2.h>
#include <gmssl/mem.h>
#include <gmssl/asn1.h>
#include <gmssl/error.h>
#include <gmssl/sm2_blind.h>


int sm2_blind_sign_commit(SM2_Fn k, uint8_t *commit, size_t *commitlen)
{
	SM2_POINT K;
	uint8_t k_bytes[32];

	sm2_fn_rand(k); // FIXME: check return
	sm2_bn_to_bytes(k, k_bytes);

	// commitment = k * G
	sm2_point_mul_generator(&K, k_bytes);
	sm2_point_to_compressed_octets(&K, commit);
	*commitlen = 33;
	gmssl_secure_clear(k_bytes, sizeof(k_bytes));

	return 1;
}

int sm2_blind_sign_init(SM2_BLIND_SIGN_CTX *ctx, const SM2_KEY *public_key, const char *id, size_t idlen)
{
	ctx->public_key = *public_key;
	sm3_init(&ctx->sm3_ctx);
	if (id) {
		uint8_t z[SM3_DIGEST_SIZE];
		if (idlen <= 0 || idlen > SM2_MAX_ID_LENGTH) {
			error_print();
			return -1;
		}
		sm2_compute_z(z, &public_key->public_key, id, idlen);
		sm3_update(&ctx->sm3_ctx, z, sizeof(z));
	}
	return 1;
}

int sm2_blind_sign_update(SM2_BLIND_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	if (data && datalen > 0) {
		sm3_update(&ctx->sm3_ctx, data, datalen);
	}
	return 1;
}

int sm2_blind_sign_finish(SM2_BLIND_SIGN_CTX *ctx,
	const uint8_t *commit, size_t commitlen,
	uint8_t blinded_sig_r[32])
{
	int ret = -1;
	SM2_Fn a;
	SM2_Fn b;
	SM2_POINT K;
	SM2_Fn e;
	SM2_Fn r;
	uint8_t dgst[32];

	sm3_finish(&ctx->sm3_ctx, dgst);
	sm2_bn_from_bytes(e, dgst);
	if (sm2_bn_cmp(e, SM2_N) >= 0) {
		sm2_bn_sub(e, e, SM2_N);
	}

	//FIXME: return value of sm2_fn_rand()
	sm2_fn_rand(a);
	sm2_bn_to_bytes(a, ctx->blind_factor_a);
	sm2_fn_rand(b);
	sm2_bn_to_bytes(b, ctx->blind_factor_b);

	if (sm2_point_from_octets(&K, commit, commitlen) != 1) {
		error_print();
		goto end;
	}
	// K'(x1, y1) = a * K + b * G
	if (sm2_point_mul_sum(&K, ctx->blind_factor_a, &K, ctx->blind_factor_b) != 1) {
		error_print();
		goto end;
	}
	sm2_bn_from_bytes(r, K.x);
	if (sm2_bn_cmp(r, SM2_N) >= 0) {
		sm2_bn_sub(r, r, SM2_N);
	}

	// r = x1 + e (mod n)
	sm2_fn_add(r, r, e);
	sm2_bn_to_bytes(r, ctx->sig_r);

	// r' = a^-1 * (r + b)
	sm2_fn_add(r, r, b);
	sm2_fn_inv(a, a);
	sm2_fn_mul(r, r, a);

	sm2_bn_to_bytes(r, blinded_sig_r);
	ret = 1;

end:
	gmssl_secure_clear(a, sizeof(a));
	gmssl_secure_clear(b, sizeof(b));
	return ret;
}

int sm2_blind_sign(const SM2_KEY *key, const SM2_Fn k, const uint8_t blinded_r[32], uint8_t blinded_s[32])
{
	SM2_Fn x;
	SM2_Fn r;
	SM2_Fn s;

	sm2_bn_from_bytes(x, key->private_key);
	sm2_bn_from_bytes(r, blinded_r);

	// s = (1 + x)^-1 * (k - r * x) (mod n)
	sm2_fn_mul(r, r, x);
	sm2_fn_sub(s, k, r);
	sm2_fn_add(x, x, SM2_ONE);
	sm2_fn_inv(x, x);
	sm2_fn_mul(s, s, x);
	sm2_bn_to_bytes(s, blinded_s);

	gmssl_secure_clear(x, sizeof(x));
	gmssl_secure_clear(r, sizeof(r));
	gmssl_secure_clear(s, sizeof(s));
	return 1;
}

int sm2_blind_sign_unblind(SM2_BLIND_SIGN_CTX *ctx, const uint8_t blinded_sig_s[32], uint8_t *sig, size_t *siglen)
{
	SM2_Fn a;
	SM2_Fn b;
	SM2_Fn s;
	SM2_SIGNATURE signature;

	sm2_bn_from_bytes(a, ctx->blind_factor_a);
	sm2_bn_from_bytes(b, ctx->blind_factor_b);
	sm2_bn_from_bytes(s, blinded_sig_s);

	// s = a * s' + b
	sm2_fn_mul(s, s, a);
	sm2_fn_add(s, s, b);

	memcpy(signature.r, ctx->sig_r, 32);
	sm2_bn_to_bytes(s, signature.s);


	*siglen = 0;
	sm2_signature_to_der(&signature, &sig, siglen);

	gmssl_secure_clear(a, sizeof(a));
	gmssl_secure_clear(b, sizeof(b));
	gmssl_secure_clear(ctx, sizeof(*ctx));
	return 1;
}

int test_sm2_blind_sign(void)
{
	int r = -1;

	// signer
	SM2_KEY key;
	SM2_Fn k;
	uint8_t commit[65];
	size_t commitlen;

	// caller
	SM2_KEY public_key;
	SM2_BLIND_SIGN_CTX sign_ctx;
	uint8_t msg[128] = {0};
	uint8_t blinded_sig_s[32];
	uint8_t blinded_sig_r[32];
	uint8_t sig[128];
	size_t siglen;

	// verifier
	SM2_SIGN_CTX verify_ctx;


	// signer
	if (sm2_key_generate(&key) != 1
		|| sm2_key_set_public_key(&public_key, &key.public_key) != 1) {
		error_print();
		goto end;
	}
	if (sm2_blind_sign_commit(k, commit, &commitlen) != 1) {
		error_print();
		return -1;
	}
	format_bytes(stderr, 0, 0, "signer: commitment", commit, commitlen);

	// caller
	if (sm2_blind_sign_init(&sign_ctx, &public_key,
		SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID)) != 1
		|| sm2_blind_sign_update(&sign_ctx, msg, 32) != 1
		|| sm2_blind_sign_update(&sign_ctx, msg + 32, 32) != 1
		|| sm2_blind_sign_update(&sign_ctx, msg + 64, 64) != 1
		|| sm2_blind_sign_finish(&sign_ctx, commit, commitlen, blinded_sig_r) != 1) {
		error_print();
		goto end;
	}
	format_bytes(stderr, 0, 0, "caller: blinded_sig_r", blinded_sig_r, sizeof(blinded_sig_r));

	// signer
	if (sm2_blind_sign(&key, k, blinded_sig_r, blinded_sig_s) != 1) {
		error_print();
		goto end;
	}
	format_bytes(stderr, 0, 0, "signer: blinded_sig_s", blinded_sig_s, sizeof(blinded_sig_s));

	// caller
	if (sm2_blind_sign_unblind(&sign_ctx, blinded_sig_s, sig, &siglen) != 1) {
		error_print();
		goto end;
	}
	format_bytes(stderr, 0, 0, "caller: unblinded_sig", sig, siglen);

	// verifier
	if (sm2_verify_init(&verify_ctx, &public_key,
		SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID)) != 1
		|| sm2_verify_update(&verify_ctx, msg, sizeof(msg)) != 1
		|| (r = sm2_verify_finish(&verify_ctx, sig, siglen)) < 0) {
		error_print();
		goto end;
	}
	format_print(stderr, 0, 0, "verifier: %s\n", r == 1 ? "success" : "failure");

end:
	gmssl_secure_clear(&key, sizeof(key));
	gmssl_secure_clear(&sign_ctx, sizeof(sign_ctx));
	return r;
}
