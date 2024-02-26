/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/mem.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/asn1.h>
#include <gmssl/error.h>
#include <gmssl/endian.h>


int sm2_do_sign(const SM2_KEY *key, const uint8_t dgst[32], SM2_SIGNATURE *sig)
{
	SM2_JACOBIAN_POINT _P, *P = &_P;
	SM2_BN d;
	SM2_BN d_inv;
	SM2_BN e;
	SM2_BN k;
	SM2_BN x;
	SM2_BN t;
	SM2_BN r;
	SM2_BN s;

	const uint64_t *one = sm2_bn_one();
	const uint64_t *order = sm2_bn_order();

	//fprintf(stderr, "sm2_do_sign\n");
	sm2_bn_from_bytes(d, key->private_key);

	// compute (d + 1)^-1 (mod n)
	sm2_fn_add(d_inv, d, one);	//sm2_bn_print(stderr, 0, 4, "(1+d)", d_inv);
	if (sm2_bn_is_zero(d_inv)) {
		error_print();
		return -1;
	}
	sm2_fn_inv(d_inv, d_inv);	//sm2_bn_print(stderr, 0, 4, "(1+d)^-1", d_inv);

	// e = H(M)
	sm2_bn_from_bytes(e, dgst);	//sm2_bn_print(stderr, 0, 4, "e", e);

retry:
	// rand k in [1, n - 1]
	do {
		if (sm2_fn_rand(k) != 1) {
			error_print();
			return -1;
		}
	} while (sm2_bn_is_zero(k));	//sm2_bn_print(stderr, 0, 4, "k", k);

	// (x, y) = kG
	sm2_jacobian_point_mul_generator(P, k);
	sm2_jacobian_point_get_xy(P, x, NULL);
					//sm2_bn_print(stderr, 0, 4, "x", x);

	// r = e + x (mod n)
	if (sm2_bn_cmp(e, order) >= 0) {
		sm2_bn_sub(e, e, order);
	}
	if (sm2_bn_cmp(x, order) >= 0) {
		sm2_bn_sub(x, x, order);
	}
	sm2_fn_add(r, e, x);		//sm2_bn_print(stderr, 0, 4, "r = e + x (mod n)", r);

	// if r == 0 or r + k == n re-generate k
	sm2_bn_add(t, r, k);
	if (sm2_bn_is_zero(r) || sm2_bn_cmp(t, order) == 0) {
					//sm2_bn_print(stderr, 0, 4, "r + k", t);
		goto retry;
	}

	// s = ((1 + d)^-1 * (k - r * d)) mod n
	sm2_fn_mul(t, r, d);		//sm2_bn_print(stderr, 0, 4, "r*d", t);
	sm2_fn_sub(k, k, t);		//sm2_bn_print(stderr, 0, 4, "k-r*d", k);
	sm2_fn_mul(s, d_inv, k);	//sm2_bn_print(stderr, 0, 4, "s = ((1 + d)^-1 * (k - r * d)) mod n", s);

	// check s != 0
	if (sm2_bn_is_zero(s)) {
		goto retry;
	}

	sm2_bn_to_bytes(r, sig->r);	//sm2_bn_print_bn(stderr, 0, 4, "r", r);
	sm2_bn_to_bytes(s, sig->s);	//sm2_bn_print_bn(stderr, 0, 4, "s", s);

	gmssl_secure_clear(d, sizeof(d));
	gmssl_secure_clear(d_inv, sizeof(d_inv ));
	gmssl_secure_clear(k, sizeof(k));
	gmssl_secure_clear(t, sizeof(t));
	return 1;
}

// (x1, y1) = k * G
// r = e + x1
// s = (k - r * d)/(1 + d) = (k +r - r * d - r)/(1 + d) = (k + r - r(1 +d))/(1 + d) = (k + r)/(1 + d) - r
//	= -r + (k + r)*(1 + d)^-1
//	= -r + (k + r) * d'

int sm2_do_sign_fast(const SM2_Fn d, const uint8_t dgst[32], SM2_SIGNATURE *sig)
{
	SM2_JACOBIAN_POINT R;
	SM2_BN e;
	SM2_BN k;
	SM2_BN x1;
	SM2_BN r;
	SM2_BN s;

	const uint64_t *order = sm2_bn_order();

	// e = H(M)
	sm2_bn_from_bytes(e, dgst);
	if (sm2_bn_cmp(e, order) >= 0) {
		sm2_bn_sub(e, e, order);
	}

	// rand k in [1, n - 1]
	do {
		if (sm2_fn_rand(k) != 1) {
			error_print();
			return -1;
		}
	} while (sm2_bn_is_zero(k));

	// (x1, y1) = kG
	sm2_jacobian_point_mul_generator(&R, k);
	sm2_jacobian_point_get_xy(&R, x1, NULL);

	// r = e + x1 (mod n)
	sm2_fn_add(r, e, x1);

	// s = (k + r) * d' - r
	sm2_bn_add(s, k, r);
	sm2_fn_mul(s, s, d);
	sm2_fn_sub(s, s, r);

	sm2_bn_to_bytes(r, sig->r);
	sm2_bn_to_bytes(s, sig->s);
	return 1;
}

int sm2_do_verify(const SM2_KEY *key, const uint8_t dgst[32], const SM2_SIGNATURE *sig)
{
	SM2_JACOBIAN_POINT _P, *P = &_P;
	SM2_JACOBIAN_POINT _R, *R = &_R;
	SM2_BN r;
	SM2_BN s;
	SM2_BN e;
	SM2_BN x;
	SM2_BN t;

	const uint64_t *order = sm2_bn_order();

	// parse public key
	sm2_jacobian_point_from_bytes(P, (const uint8_t *)&key->public_key);
					//sm2_jacobian_point_print(stderr, 0, 4, "P", P);

	// parse signature values
	sm2_bn_from_bytes(r, sig->r);	//sm2_bn_print(stderr, 0, 4, "r", r);
	sm2_bn_from_bytes(s, sig->s);	//sm2_bn_print(stderr, 0, 4, "s", s);

	// check r, s in [1, n-1]
	if (sm2_bn_is_zero(r) == 1
		|| sm2_bn_cmp(r, order) >= 0
		|| sm2_bn_is_zero(s) == 1
		|| sm2_bn_cmp(s, order) >= 0) {
		error_print();
		return -1;
	}

	// e = H(M)
	sm2_bn_from_bytes(e, dgst);	//sm2_bn_print(stderr, 0, 4, "e = H(M)", e);

	// t = r + s (mod n), check t != 0
	sm2_fn_add(t, r, s);		//sm2_bn_print(stderr, 0, 4, "t = r + s (mod n)", t);
	if (sm2_bn_is_zero(t)) {
		error_print();
		return -1;
	}

	// Q = s * G + t * P
	sm2_jacobian_point_mul_sum(R, t, P, s);
	sm2_jacobian_point_get_xy(R, x, NULL);
					//sm2_bn_print(stderr, 0, 4, "x", x);

	// r' = e + x (mod n)
	if (sm2_bn_cmp(e, order) >= 0) {
		sm2_bn_sub(e, e, order);
	}
	if (sm2_bn_cmp(x, order) >= 0) {
		sm2_bn_sub(x, x, order);
	}
	sm2_fn_add(e, e, x);		//sm2_bn_print(stderr, 0, 4, "e + x (mod n)", e);

	// check if r == r'
	if (sm2_bn_cmp(e, r) != 0) {
		error_print();
		return -1;
	}
	return 1;
}

static int all_zero(const uint8_t *buf, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++) {
		if (buf[i]) {
			return 0;
		}
	}
	return 1;
}

int sm2_do_encrypt(const SM2_KEY *key, const uint8_t *in, size_t inlen, SM2_CIPHERTEXT *out)
{
	SM2_BN k;
	SM2_JACOBIAN_POINT _P, *P = &_P;
	SM2_JACOBIAN_POINT _C1, *C1 = &_C1;
	SM2_JACOBIAN_POINT _kP, *kP = &_kP;
	uint8_t x2y2[64];
	SM3_CTX sm3_ctx;

	if (!(SM2_MIN_PLAINTEXT_SIZE <= inlen && inlen <= SM2_MAX_PLAINTEXT_SIZE)) {
		error_print();
		return -1;
	}

	sm2_jacobian_point_from_bytes(P, (uint8_t *)&key->public_key);

	// S = h * P, check S != O
	// for sm2 curve, h == 1 and S == P
	// SM2_POINT can not present point at infinity, do do nothing here

retry:
	// rand k in [1, n - 1]
	do {
		if (sm2_fn_rand(k) != 1) {
			error_print();
			return -1;
		}
	} while (sm2_bn_is_zero(k));	//sm2_bn_print(stderr, 0, 4, "k", k);

	// output C1 = k * G = (x1, y1)
	sm2_jacobian_point_mul_generator(C1, k);
	sm2_jacobian_point_to_bytes(C1, (uint8_t *)&out->point);

	// k * P = (x2, y2)
	sm2_jacobian_point_mul(kP, k, P);
	sm2_jacobian_point_to_bytes(kP, x2y2);

	// t = KDF(x2 || y2, inlen)
	sm2_kdf(x2y2, 64, inlen, out->ciphertext);

	// if t is all zero, retry
	if (all_zero(out->ciphertext, inlen)) {
		goto retry;
	}

	// output C2 = M xor t
	gmssl_memxor(out->ciphertext, out->ciphertext, in, inlen);
	out->ciphertext_size = (uint32_t)inlen;

	// output C3 = Hash(x2 || m || y2)
	sm3_init(&sm3_ctx);
	sm3_update(&sm3_ctx, x2y2, 32);
	sm3_update(&sm3_ctx, in, inlen);
	sm3_update(&sm3_ctx, x2y2 + 32, 32);
	sm3_finish(&sm3_ctx, out->hash);

	gmssl_secure_clear(k, sizeof(k));
	gmssl_secure_clear(kP, sizeof(SM2_JACOBIAN_POINT));
	gmssl_secure_clear(x2y2, sizeof(x2y2));
	return 1;
}

int sm2_do_encrypt_fixlen(const SM2_KEY *key, const uint8_t *in, size_t inlen, int point_size, SM2_CIPHERTEXT *out)
{
	unsigned int trys = 200;
	SM2_BN k;
	SM2_JACOBIAN_POINT _P, *P = &_P;
	SM2_JACOBIAN_POINT _C1, *C1 = &_C1;
	SM2_JACOBIAN_POINT _kP, *kP = &_kP;
	uint8_t x2y2[64];
	SM3_CTX sm3_ctx;

	if (!(SM2_MIN_PLAINTEXT_SIZE <= inlen && inlen <= SM2_MAX_PLAINTEXT_SIZE)) {
		error_print();
		return -1;
	}

	switch (point_size) {
	case SM2_ciphertext_compact_point_size:
	case SM2_ciphertext_typical_point_size:
	case SM2_ciphertext_max_point_size:
		break;
	default:
		error_print();
		return -1;
	}

	sm2_jacobian_point_from_bytes(P, (uint8_t *)&key->public_key);

	// S = h * P, check S != O
	// for sm2 curve, h == 1 and S == P
	// SM2_POINT can not present point at infinity, do do nothing here

retry:
	// rand k in [1, n - 1]
	do {
		if (sm2_fn_rand(k) != 1) {
			error_print();
			return -1;
		}
	} while (sm2_bn_is_zero(k));	//sm2_bn_print(stderr, 0, 4, "k", k);

	// output C1 = k * G = (x1, y1)
	sm2_jacobian_point_mul_generator(C1, k);
	sm2_jacobian_point_to_bytes(C1, (uint8_t *)&out->point);

	// check fixlen
	if (trys) {
		size_t len = 0;
		asn1_integer_to_der(out->point.x, 32, NULL, &len);
		asn1_integer_to_der(out->point.y, 32, NULL, &len);
		if (len != point_size) {
			trys--;
			goto retry;
		}
	} else {
		gmssl_secure_clear(k, sizeof(k));
		error_print();
		return -1;
	}

	// k * P = (x2, y2)
	sm2_jacobian_point_mul(kP, k, P);
	sm2_jacobian_point_to_bytes(kP, x2y2);

	// t = KDF(x2 || y2, inlen)
	sm2_kdf(x2y2, 64, inlen, out->ciphertext);

	// if t is all zero, retry
	if (all_zero(out->ciphertext, inlen)) {
		goto retry;
	}

	// output C2 = M xor t
	gmssl_memxor(out->ciphertext, out->ciphertext, in, inlen);
	out->ciphertext_size = (uint32_t)inlen;

	// output C3 = Hash(x2 || m || y2)
	sm3_init(&sm3_ctx);
	sm3_update(&sm3_ctx, x2y2, 32);
	sm3_update(&sm3_ctx, in, inlen);
	sm3_update(&sm3_ctx, x2y2 + 32, 32);
	sm3_finish(&sm3_ctx, out->hash);

	gmssl_secure_clear(k, sizeof(k));
	gmssl_secure_clear(kP, sizeof(SM2_JACOBIAN_POINT));
	gmssl_secure_clear(x2y2, sizeof(x2y2));
	return 1;
}

int sm2_do_decrypt(const SM2_KEY *key, const SM2_CIPHERTEXT *in, uint8_t *out, size_t *outlen)
{
	int ret = -1;
	SM2_BN d;
	SM2_JACOBIAN_POINT _C1, *C1 = &_C1;
	uint8_t x2y2[64];
	SM3_CTX sm3_ctx;
	uint8_t hash[32];

	// check C1 is on sm2 curve
	sm2_jacobian_point_from_bytes(C1, (uint8_t *)&in->point);
	if (!sm2_jacobian_point_is_on_curve(C1)) {
		error_print();
		return -1;
	}

	// check if S = h * C1 is point at infinity
	// this will not happen, as SM2_POINT can not present point at infinity

	// d * C1 = (x2, y2)
	sm2_bn_from_bytes(d, key->private_key);
	sm2_jacobian_point_mul(C1, d, C1);

	// t = KDF(x2 || y2, klen) and check t is not all zeros
	sm2_jacobian_point_to_bytes(C1, x2y2);
	sm2_kdf(x2y2, 64, in->ciphertext_size, out);
	if (all_zero(out, in->ciphertext_size)) {
		error_print();
		goto end;
	}

	// M = C2 xor t
	gmssl_memxor(out, out, in->ciphertext, in->ciphertext_size);
	*outlen = in->ciphertext_size;

	// u = Hash(x2 || M || y2)
	sm3_init(&sm3_ctx);
	sm3_update(&sm3_ctx, x2y2, 32);
	sm3_update(&sm3_ctx, out, in->ciphertext_size);
	sm3_update(&sm3_ctx, x2y2 + 32, 32);
	sm3_finish(&sm3_ctx, hash);

	// check if u == C3
	if (memcmp(in->hash, hash, sizeof(hash)) != 0) {
		error_print();
		goto end;
	}
	ret = 1;

end:
	gmssl_secure_clear(d, sizeof(d));
	gmssl_secure_clear(C1, sizeof(SM2_JACOBIAN_POINT));
	gmssl_secure_clear(x2y2, sizeof(x2y2));
	return ret;
}
