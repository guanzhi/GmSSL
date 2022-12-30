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
#include <gmssl/sm2_ring.h>
#include <gmssl/asn1.h>
#include <gmssl/error.h>


extern SM2_BN SM2_N;
extern SM2_BN SM2_ONE;


static int compare_point(const void *P, const void *Q)
{
	const uint8_t *p = (uint8_t *)P;
	const uint8_t *q = (uint8_t *)Q;
	int i, r;
	for (i = 0; i < sizeof(SM2_POINT); i++) {
		r = p[i] - q[i];
		if (r) {
			return r;
		}
	}
	return 0;
}

static int sm2_ring_sort_public_keys(SM2_POINT *points, size_t points_cnt)
{
	qsort(points, points_cnt, sizeof(SM2_POINT), compare_point);
	return 1;
}

int sm2_ring_signature_to_der(const sm2_bn_t r, const sm2_bn_t *s, size_t s_cnt, uint8_t **out, size_t *outlen)
{
	size_t i, len = 0;
	uint8_t *p = *out;

	if (asn1_integer_to_der(r, 32, NULL, &len) != 1) {
		error_print();
		return -1;
	}
	for (i = 0; i < s_cnt; i++) {
		if (asn1_integer_to_der(s[i], 32, NULL, &len) != 1) {
			error_print();
			return -1;
		}
	}
	if (asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_integer_to_der(r, 32, out, outlen) != 1) {
		error_print();
		return -1;
	}
	for (i = 0; i < s_cnt; i++) {
		if (asn1_integer_to_der(s[i], 32, out, outlen) != 1) {
			error_print();
			return -1;
		}
	}
	return 1;
}

// FIXME: support when s_vec == NULL
int sm2_ring_signature_from_der(sm2_bn_t r0, sm2_bn_t *s_vec, size_t *s_cnt, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;
	const uint8_t *p;
	size_t len;
	uint8_t *s = (uint8_t *)&s_vec[0];

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_integer_from_der(&p, &len, &d, &dlen) != 1
		|| asn1_length_le(len, 32) != 1) {
		error_print();
		return -1;
	}
	memset(r0, 0, 32);
	memcpy(r0 + 32 - len, p, len);

	*s_cnt = 0;
	while (dlen) {
		if (asn1_integer_from_der(&p, &len, &d, &dlen) != 1
			|| asn1_length_le(len, 32) != 1) {
			error_print();
			return -1;
		}
		memset(s, 0, 32 - len);
		memcpy(s + 32 - len, p, len);
		s += 32;

		(*s_cnt)++;
	}
	return 1;
}

int sm2_ring_do_sign(const SM2_KEY *sign_key,
	const SM2_POINT *public_keys, size_t public_keys_cnt,
	const uint8_t dgst[32], uint8_t r0[32], sm2_bn_t *s_vec)
{
	size_t i;
	size_t sign_index = public_keys_cnt; // assign an invalid value

	SM2_JACOBIAN_POINT R;
	SM2_JACOBIAN_POINT P;
	SM2_Fn e;
	SM2_Fn k;
	SM2_Fp x;
	SM2_Fn r;
	SM2_Fn s;
	SM2_Fn t;
	SM2_Fn d;

	// e = H(M) (mod n)
	sm2_bn_from_bytes(e, dgst);
	if (sm2_bn_cmp(e, SM2_N) >= 0) {
		sm2_bn_sub(e, e, SM2_N);
	}

	// find signer's index
	for (i = 0; i < public_keys_cnt; i++) {
		if (memcmp(&public_keys[i], &(sign_key->public_key), sizeof(SM2_POINT)) == 0) {
			sign_index = i;
			break;
		}
	}
	if (sign_index >= public_keys_cnt) {
		error_print();
		return -1;
	}

	// k[i] = rand(1, n-1), r[i], s[i] will be computed at the last step
	sm2_fn_rand(k);

	// R[i+1] = k[i] * G
	sm2_jacobian_point_mul_generator(&R, k);
	sm2_jacobian_point_get_xy(&R, x, NULL);

	// i = i + 1 (mod N)
	for (i = (i + 1) % public_keys_cnt; i != sign_index; i = (i + 1) % public_keys_cnt) {

		// r[i] = x[i] + e (mod n)
		sm2_fn_add(r, x, e);

		// output r[0]
		if (i == 0) {
			sm2_bn_to_bytes(r, r0);
		}

		// s[i] = rand(1, n-1)
		sm2_fn_rand(s);
		sm2_bn_to_bytes(s, s_vec[i]);

		// R[i+1] = k[i] * G = (s[i] + r[i]) * P[i] + s[i] * G
		sm2_fn_add(t, s, r);
		sm2_jacobian_point_from_bytes(&P, (const uint8_t *)&public_keys[i]);
		sm2_jacobian_point_mul_sum(&R, t, &P, s);
		sm2_jacobian_point_get_xy(&R, x, NULL);
	}

	// r[i] = x[i] + e (mod n)
	sm2_fn_add(r, x, e);
	if (i == 0) {
		sm2_bn_to_bytes(r, r0);
	}

	// s[i] = (k[i] - r[i] * d)/(1 + d)
	sm2_bn_from_bytes(d, sign_key->private_key);
	sm2_fn_mul(r, r, d);
	sm2_fn_sub(s, k, r);
	sm2_fn_add(d, d, SM2_ONE);
	sm2_fn_inv(d, d);
	sm2_fn_mul(s, s, d);
	sm2_bn_to_bytes(s, s_vec[i]);

	// cleanup
	memset(d, 0, sizeof(d));
	memset(k, 0, sizeof(k));
	memset(r, 0, sizeof(r));
	return 1;
}

int sm2_ring_do_verify(const SM2_POINT *public_keys, size_t public_keys_cnt,
	const uint8_t dgst[32], const uint8_t r0[32], const sm2_bn_t *s_vec)
{
	SM2_JACOBIAN_POINT P;
	SM2_JACOBIAN_POINT R;
	SM2_Fn r;
	SM2_Fn r_;
	SM2_Fn s;
	SM2_Fn e;
	SM2_Fn t;
	SM2_Fn x;
	size_t i;

	sm2_bn_from_bytes(e, dgst);
	if (sm2_bn_cmp(e, SM2_N) >= 0) {
		sm2_bn_sub(e, e, SM2_N);
	}

	sm2_bn_from_bytes(r, r0);

	for (i = 0; i < public_keys_cnt; i++) {
		sm2_bn_from_bytes(s, s_vec[i]);

		// R(x, y) = k * G = s * G + (s + r) * P
		sm2_fn_add(t, s, r);
		sm2_jacobian_point_from_bytes(&P, (const uint8_t *)&public_keys[i]);
		sm2_jacobian_point_mul_sum(&R, t, &P, s);
		sm2_jacobian_point_get_xy(&R, x, NULL);

		// r = e + x (mod n)
		sm2_fn_add(r, x, e);
	}

	sm2_bn_from_bytes(r_, r0);
	if (sm2_bn_cmp(r_, r) != 0) {
		return 0;
	}
	return 1;
}

int sm2_ring_sign(const SM2_KEY *sign_key,
	const SM2_POINT *public_keys, size_t public_keys_cnt,
	const uint8_t dgst[32], uint8_t *sig, size_t *siglen)
{
	sm2_bn_t r;
	sm2_bn_t s[SM2_RING_SIGN_MAX_SIGNERS];

	if (!public_keys_cnt || public_keys_cnt > sizeof(s)/sizeof(s[0])) {
		error_print();
		return -1;
	}
	if (sm2_ring_do_sign(sign_key, public_keys, public_keys_cnt, dgst, r, s) != 1) {
		error_print();
		return -1;
	}

	*siglen = 0;
	if (sm2_ring_signature_to_der(r, s, public_keys_cnt, &sig, siglen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_ring_verify(const SM2_POINT *public_keys, size_t public_keys_cnt,
	const uint8_t dgst[32], const uint8_t *sig, size_t siglen)
{
	int ret;
	sm2_bn_t r;
	sm2_bn_t s[SM2_RING_SIGN_MAX_SIGNERS];
	size_t s_cnt;

	if (!public_keys_cnt || public_keys_cnt > sizeof(s)/sizeof(s[0])) {
		error_print();
		return -1;
	}
	if (sm2_ring_signature_from_der(r, s, &s_cnt, &sig, &siglen) != 1
		|| asn1_length_is_zero(siglen) != 1) {
		error_print();
		return -1;
	}
	if (s_cnt != public_keys_cnt) {
		error_print();
		return -1;
	}

	if ((ret = sm2_ring_do_verify(public_keys, public_keys_cnt, dgst, r, s)) < 0) {
		error_print();
		return -1;
	}
	return ret;
}

int sm2_ring_sign_init(SM2_RING_SIGN_CTX *ctx, const SM2_KEY *sign_key, const char *id, size_t idlen)
{
	sm3_init(&ctx->sm3_ctx);
	ctx->sign_key = *sign_key;
	ctx->public_keys[0] = sign_key->public_key;
	ctx->public_keys_count = 1;
	if (!(ctx->id = malloc(idlen + 1))) {
		error_print();
		return -1;
	}
	memcpy(ctx->id, id, idlen);
	ctx->id[idlen] = 0;
	ctx->idlen = idlen;
	ctx->state = 0;
	return 1;
}

int sm2_ring_sign_add_signer(SM2_RING_SIGN_CTX *ctx, const SM2_KEY *public_key)
{
	if (ctx->state) {
		error_print();
		return -1;
	}
	if (ctx->public_keys_count >= SM2_RING_SIGN_MAX_SIGNERS) {
		error_print();
		return -1;
	}
	ctx->public_keys[ctx->public_keys_count++] = public_key->public_key;
	return 1;
}

int sm2_ring_sign_update(SM2_RING_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	if (!ctx->state) {
		SM2_POINT point = ctx->public_keys[0];
		uint8_t z[32];
		size_t i;

		for (i = 1; i < ctx->public_keys_count; i++) {
			sm2_point_add(&point, &point, &ctx->public_keys[i]);
		}
		sm2_compute_z(z, &point, ctx->id, ctx->idlen);
		sm3_update(&ctx->sm3_ctx, z, sizeof(z));
		ctx->state = 1;
	}
	if (data && datalen) {
		sm3_update(&ctx->sm3_ctx, data, datalen);
	}
	return 1;
}

int sm2_ring_sign_finish(SM2_RING_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen)
{
	uint8_t dgst[32];

	sm3_finish(&ctx->sm3_ctx, dgst);

	if (sm2_ring_sort_public_keys(ctx->public_keys, ctx->public_keys_count) != 1) {
		error_print();
		return -1;
	}
	if (sm2_ring_sign(&ctx->sign_key, ctx->public_keys, ctx->public_keys_count, dgst, sig, siglen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_ring_verify_init(SM2_RING_SIGN_CTX *ctx, const char *id, size_t idlen)
{
	sm3_init(&ctx->sm3_ctx);
	ctx->public_keys_count = 0;
	if (!(ctx->id = malloc(idlen + 1))) {
		error_print();
		return -1;
	}
	memcpy(ctx->id, id, idlen);
	ctx->id[idlen] = 0;
	ctx->idlen = idlen;
	ctx->state = 0;
	return 1;
}

int sm2_ring_verify_add_signer(SM2_RING_SIGN_CTX *ctx, const SM2_KEY *public_key)
{
	if (ctx->state) {
		error_print();
		return -1;
	}
	if (ctx->public_keys_count >= SM2_RING_SIGN_MAX_SIGNERS) {
		error_print();
		return -1;
	}
	ctx->public_keys[ctx->public_keys_count++] = public_key->public_key;
	return 1;
}

int sm2_ring_verify_update(SM2_RING_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	if (!ctx->state) {
		SM2_POINT point = ctx->public_keys[0];
		uint8_t z[32];
		size_t i;

		for (i = 1; i < ctx->public_keys_count; i++) {
			sm2_point_add(&point, &point, &ctx->public_keys[i]);
		}
		sm2_compute_z(z, &point, ctx->id, ctx->idlen);
		sm3_update(&ctx->sm3_ctx, z, sizeof(z));
		ctx->state = 1;
	}
	if (data && datalen) {
		sm3_update(&ctx->sm3_ctx, data, datalen);
	}
	return 1;
}

int sm2_ring_verify_finish(SM2_RING_SIGN_CTX *ctx, uint8_t *sig, size_t siglen)
{
	uint8_t dgst[32];
	int ret;

	sm3_finish(&ctx->sm3_ctx, dgst);

	if (sm2_ring_sort_public_keys(ctx->public_keys, ctx->public_keys_count) != 1) {
		error_print();
		return -1;
	}
	if ((ret = sm2_ring_verify(ctx->public_keys, ctx->public_keys_count, dgst, sig, siglen)) != 1) {
		error_print();
		return -1;
	}
	return ret;
}

static int test_sm2_ring_do_sign(void)
{
	SM2_KEY sign_key;
	SM2_POINT public_keys[5];
	size_t public_keys_count = sizeof(public_keys)/sizeof(public_keys[0]);
	size_t sign_index, i;
	uint8_t dgst[32];
	uint8_t r[32];
	uint8_t s[sizeof(public_keys)/sizeof(public_keys[0])][32];

	for (sign_index = 0; sign_index < 5; sign_index++) {

		for (i = 0; i < public_keys_count; i++) {
			SM2_KEY key;
			sm2_key_generate(&key);
			memcpy(&public_keys[i], &(key.public_key), sizeof(SM2_POINT));

			if (i == sign_index) {
				memcpy(&sign_key, &key, sizeof(SM2_KEY));
			}
		}
		if (sm2_ring_do_sign(&sign_key, public_keys, public_keys_count, dgst, r, s) != 1) {
			error_print();
			return -1;
		}
		if (sm2_ring_do_verify(public_keys, public_keys_count, dgst, r, s) != 1) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int test_sm2_ring_sign(void)
{
	SM2_KEY sign_key;
	SM2_POINT public_keys[5];
	size_t public_keys_count = sizeof(public_keys)/sizeof(public_keys[0]);
	size_t sign_index = 2, i;
	uint8_t dgst[32];
	uint8_t sig[9 + (2 + 33) * (1 + sizeof(public_keys)/sizeof(public_keys[0]))];
	size_t siglen = 0;

	for (i = 0; i < public_keys_count; i++) {
		SM2_KEY key;
		sm2_key_generate(&key);
		memcpy(&public_keys[i], &(key.public_key), sizeof(SM2_POINT));

		if (i == sign_index) {
			memcpy(&sign_key, &key, sizeof(SM2_KEY));
		}
	}
	if (sm2_ring_sign(&sign_key, public_keys, public_keys_count, dgst, sig, &siglen) != 1) {
		error_print();
		return -1;
	}
	if (sm2_ring_verify(public_keys, 5, dgst, sig, siglen) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int test_sm2_ring_sign_crosscheck(void)
{
	SM2_KEY sign_key;
	SM2_POINT public_key;
	uint8_t dgst[32];
	uint8_t sig[SM2_MAX_SIGNATURE_SIZE];
	size_t siglen = 0;

	sm2_key_generate(&sign_key);
	public_key = sign_key.public_key;

	if (sm2_ring_sign(&sign_key, &public_key, 1, dgst, sig, &siglen) != 1) {
		error_print();
		return -1;
	}
	if (sm2_ring_verify(&public_key, 1, dgst, sig, siglen) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int test_sm2_ring_sign_update(void)
{
	SM2_KEY keys[5];
	SM2_RING_SIGN_CTX sign_ctx;
	SM2_RING_SIGN_CTX verify_ctx;
	size_t public_keys_count = sizeof(keys)/sizeof(keys[0]);
	char *id = "Alice";
	uint8_t msg[128] = {0};
	uint8_t sig[9 + (2 + 33) * (1 + sizeof(keys)/sizeof(keys[0]))];
	size_t siglen = 0;
	size_t i;

	for (i = 0; i < public_keys_count; i++) {
		sm2_key_generate(&keys[i]);
	}

	if (sm2_ring_sign_init(&sign_ctx, &keys[0], id, strlen(id)) != 1) {
		error_print();
		return -1;
	}
	for (i = 1; i < public_keys_count; i++) {
		if (sm2_ring_sign_add_signer(&sign_ctx, &keys[i]) != 1) {
			error_print();
			return -1;
		}
	}
	if (sm2_ring_sign_update(&sign_ctx, msg, 32) != 1
		|| sm2_ring_sign_update(&sign_ctx, msg + 32, 32) != 1
		|| sm2_ring_sign_update(&sign_ctx, msg + 64, 64) != 1
		|| sm2_ring_sign_finish(&sign_ctx, sig, &siglen) != 1) {
		error_print();
		return -1;
	}

	if (sm2_ring_verify_init(&verify_ctx, id, strlen(id)) != 1) {
		error_print();
		return -1;
	}
	for (i = 0; i < public_keys_count; i++) {
		if (sm2_ring_verify_add_signer(&verify_ctx, &keys[i]) != 1) {
			error_print();
			return -1;
		}
	}
	if (sm2_ring_verify_update(&verify_ctx, msg, sizeof(msg)) != 1) {
		error_print();
		return -1;
	}
	if (sm2_ring_verify_finish(&verify_ctx, sig, siglen) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int test_sm2_ring()
{
	if (test_sm2_ring_do_sign() != 1) { error_print(); return -1; }
	if (test_sm2_ring_sign() != 1) { error_print(); return -1; }
	if (test_sm2_ring_sign_crosscheck() != 1) { error_print(); return -1; }
	if (test_sm2_ring_sign_update() != 1) { error_print(); return -1; }
	return 1;
}

