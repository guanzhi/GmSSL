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
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/mem.h>
#include <gmssl/asn1.h>
#include <gmssl/error.h>
#include <gmssl/endian.h>


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

int sm2_kdf(const uint8_t *in, size_t inlen, size_t outlen, uint8_t *out)
{
	SM3_CTX ctx;
	uint8_t counter_be[4];
	uint8_t dgst[SM3_DIGEST_SIZE];
	uint32_t counter = 1;
	size_t len;

	while (outlen) {
		PUTU32(counter_be, counter);
		counter++;

		sm3_init(&ctx);
		sm3_update(&ctx, in, inlen);
		sm3_update(&ctx, counter_be, sizeof(counter_be));
		sm3_finish(&ctx, dgst);

		len = outlen < SM3_DIGEST_SIZE ? outlen : SM3_DIGEST_SIZE;
		memcpy(out, dgst, len);
		out += len;
		outlen -= len;
	}

	memset(&ctx, 0, sizeof(SM3_CTX));
	memset(dgst, 0, sizeof(dgst));
	return 1;
}

// use Montgomery's Trick to inverse Z coordinates on multiple (x1, y1) = [k]G
int sm2_encrypt_pre_compute(SM2_ENC_PRE_COMP pre_comp[SM2_ENC_PRE_COMP_NUM])
{
	SM2_Z256_POINT P[SM2_ENC_PRE_COMP_NUM];
	sm2_z256_t f[SM2_ENC_PRE_COMP_NUM];
	sm2_z256_t g[SM2_ENC_PRE_COMP_NUM];
	int i;

	for (i = 0; i < SM2_ENC_PRE_COMP_NUM; i++) {

		// rand k in [1, n - 1]
		do {
			if (sm2_z256_rand_range(pre_comp[i].k, sm2_z256_order()) != 1) {
				error_print();
				return -1;
			}
		} while (sm2_z256_is_zero(pre_comp[i].k));

		// (x1, y1) = kG
		sm2_z256_point_mul_generator(&P[i], pre_comp[i].k);
	}

	// f[0] = Z[0]
	// f[1] = Z[0] * Z[1]
	// ...
	// f[31] = Z[0] * Z[1] * ... * Z[31]
	sm2_z256_copy(f[0], P[0].Z);
	for (i = 1; i < SM2_ENC_PRE_COMP_NUM; i++) {
		sm2_z256_modp_mont_mul(f[i], f[i - 1], P[i].Z);
	}

	// f[31]^-1 = (Z[0] * ... * Z[31])^-1
	sm2_z256_modp_mont_inv(f[SM2_ENC_PRE_COMP_NUM - 1], f[SM2_ENC_PRE_COMP_NUM - 1]);

	// g[31] = Z[31]
	// g[30] = Z[30] * Z[31]
	// ...
	// g[1] = Z[1] * Z[2] * ... * Z[31]
	//
	sm2_z256_copy(g[SM2_ENC_PRE_COMP_NUM - 1], P[SM2_ENC_PRE_COMP_NUM - 1].Z);
	for (i = SM2_ENC_PRE_COMP_NUM - 2; i >= 1; i--) {
		sm2_z256_modp_mont_mul(g[i], g[i + 1], P[i].Z);
	}

	// Z[0]^-1 = g[1] * f[31]^-1
	// Z[1]^-1 = g[2] * f[0] * f[31]^-1
	// Z[2]^-1 = g[3] * f[1] * f[31]^-1
	// ...
	// Z[30]^-1 = g[31] * f[29] * f[31]^-1
	// Z[31]^-1 = f[30] * f[31]^-1
	sm2_z256_modp_mont_mul(P[0].Z, g[1], f[SM2_ENC_PRE_COMP_NUM - 1]);
	for (i = 1; i < SM2_ENC_PRE_COMP_NUM - 1; i++) {
		sm2_z256_modp_mont_mul(P[i].Z, g[i + 1], f[i - 1]);
		sm2_z256_modp_mont_mul(P[i].Z, P[i].Z, f[SM2_ENC_PRE_COMP_NUM - 1]);
	}
	sm2_z256_modp_mont_mul(P[SM2_ENC_PRE_COMP_NUM - 1].Z,
		f[SM2_ENC_PRE_COMP_NUM - 2], f[SM2_ENC_PRE_COMP_NUM - 1]);

	// y[i] = Y[i] * Z[i]^-3 (mod n)
	// x[i] = X[i] * Z[i]^-2 (mod n)
	for (i = 0; i < SM2_ENC_PRE_COMP_NUM; i++) {

		sm2_z256_modp_mont_mul(P[i].Y, P[i].Y, P[i].Z);
		sm2_z256_modp_mont_sqr(P[i].Z, P[i].Z);
		sm2_z256_modp_mont_mul(P[i].Y, P[i].Y, P[i].Z);
		sm2_z256_modp_mont_mul(P[i].X, P[i].X, P[i].Z);

		sm2_z256_modp_from_mont(P[i].X, P[i].X);
		sm2_z256_modp_from_mont(P[i].Y, P[i].Y);

		sm2_z256_to_bytes(P[i].X, pre_comp[i].C1.x);
		sm2_z256_to_bytes(P[i].Y, pre_comp[i].C1.y);
	}

	return 1;
}

int sm2_do_encrypt_ex(const SM2_KEY *key, const SM2_ENC_PRE_COMP *pre_comp,
	const uint8_t *in, size_t inlen, SM2_CIPHERTEXT *out)
{
	SM2_Z256_POINT kP;
	uint8_t x2y2[64];
	SM3_CTX sm3_ctx;

	if (inlen < 1 || inlen > SM2_MAX_PLAINTEXT_SIZE) {
		error_print();
		return -1;
	}

	// output C1
	out->point = pre_comp->C1;

	// k * P = (x2, y2)
	sm2_z256_point_mul(&kP, pre_comp->k, &key->public_key);
	sm2_z256_point_to_bytes(&kP, x2y2);

	// t = KDF(x2 || y2, inlen)
	sm2_kdf(x2y2, 64, inlen, out->ciphertext);

	// if t is all zero, return 0, caller should change pre_comp and retry
	if (all_zero(out->ciphertext, inlen)) {
		return 0;
	}

	// output C2 = M xor t
	gmssl_memxor(out->ciphertext, out->ciphertext, in, inlen);
	out->ciphertext_size = (uint8_t)inlen;

	// output C3 = Hash(x2 || m || y2)
	sm3_init(&sm3_ctx);
	sm3_update(&sm3_ctx, x2y2, 32);
	sm3_update(&sm3_ctx, in, inlen);
	sm3_update(&sm3_ctx, x2y2 + 32, 32);
	sm3_finish(&sm3_ctx, out->hash);

	gmssl_secure_clear(&kP, sizeof(SM2_Z256_POINT));
	gmssl_secure_clear(x2y2, sizeof(x2y2));
	return 1;
}

// key->public_key will not be point_at_infinity when decoded from_bytes/octets/der
int sm2_do_encrypt(const SM2_KEY *key, const uint8_t *in, size_t inlen, SM2_CIPHERTEXT *out)
{
	sm2_z256_t k;
	SM2_Z256_POINT C1;
	SM2_Z256_POINT kP;
	uint8_t x2y2[64];
	SM3_CTX sm3_ctx;

	if (inlen < 1 || inlen > SM2_MAX_PLAINTEXT_SIZE) {
		error_print();
		return -1;
	}

retry:
	// rand k in [1, n - 1]
	do {
		if (sm2_z256_rand_range(k, sm2_z256_order()) != 1) {
			error_print();
			return -1;
		}
	} while (sm2_z256_is_zero(k));

	// output C1 = k * G = (x1, y1)
	sm2_z256_point_mul_generator(&C1, k);
	sm2_z256_point_to_bytes(&C1, (uint8_t *)&out->point);

	// k * P = (x2, y2)
	sm2_z256_point_mul(&kP, k, &key->public_key);
	sm2_z256_point_to_bytes(&kP, x2y2);

	// t = KDF(x2 || y2, inlen)
	sm2_kdf(x2y2, 64, inlen, out->ciphertext);

	// if t is all zero, retry
	if (all_zero(out->ciphertext, inlen)) {
		goto retry;
	}

	// output C2 = M xor t
	gmssl_memxor(out->ciphertext, out->ciphertext, in, inlen);
	out->ciphertext_size = (uint8_t)inlen;

	// output C3 = Hash(x2 || m || y2)
	sm3_init(&sm3_ctx);
	sm3_update(&sm3_ctx, x2y2, 32);
	sm3_update(&sm3_ctx, in, inlen);
	sm3_update(&sm3_ctx, x2y2 + 32, 32);
	sm3_finish(&sm3_ctx, out->hash);

	gmssl_secure_clear(k, sizeof(k));
	gmssl_secure_clear(&kP, sizeof(SM2_Z256_POINT));
	gmssl_secure_clear(x2y2, sizeof(x2y2));
	return 1;
}

int sm2_do_encrypt_fixlen(const SM2_KEY *key, const uint8_t *in, size_t inlen, int point_size, SM2_CIPHERTEXT *out)
{
	unsigned int trys = 200;
	sm2_z256_t k;
	SM2_Z256_POINT C1;
	SM2_Z256_POINT kP;
	uint8_t x2y2[64];
	SM3_CTX sm3_ctx;

	if (inlen < 1 || inlen > SM2_MAX_PLAINTEXT_SIZE) {
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

retry:
	// rand k in [1, n - 1]
	do {
		if (sm2_z256_rand_range(k, sm2_z256_order()) != 1) {
			error_print();
			return -1;
		}
	} while (sm2_z256_is_zero(k));

	// output C1 = k * G = (x1, y1)
	sm2_z256_point_mul_generator(&C1, k);
	sm2_z256_point_to_bytes(&C1, (uint8_t *)&out->point);

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
	sm2_z256_point_mul(&kP, k, &key->public_key);
	sm2_z256_point_to_bytes(&kP, x2y2);

	// t = KDF(x2 || y2, inlen)
	sm2_kdf(x2y2, 64, inlen, out->ciphertext);

	// if t is all zero, retry
	if (all_zero(out->ciphertext, inlen)) {
		goto retry;
	}

	// output C2 = M xor t
	gmssl_memxor(out->ciphertext, out->ciphertext, in, inlen);
	out->ciphertext_size = (uint8_t)inlen;

	// output C3 = Hash(x2 || m || y2)
	sm3_init(&sm3_ctx);
	sm3_update(&sm3_ctx, x2y2, 32);
	sm3_update(&sm3_ctx, in, inlen);
	sm3_update(&sm3_ctx, x2y2 + 32, 32);
	sm3_finish(&sm3_ctx, out->hash);

	gmssl_secure_clear(k, sizeof(k));
	gmssl_secure_clear(&kP, sizeof(SM2_Z256_POINT));
	gmssl_secure_clear(x2y2, sizeof(x2y2));
	return 1;
}

int sm2_do_decrypt(const SM2_KEY *key, const SM2_CIPHERTEXT *in, uint8_t *out, size_t *outlen)
{
	int ret = -1;
	SM2_Z256_POINT C1;
	uint8_t x2y2[64];
	SM3_CTX sm3_ctx;
	uint8_t hash[32];

	// check C1 is on sm2 curve
	if (sm2_z256_point_from_bytes(&C1, (uint8_t *)&in->point) != 1) {
		error_print();
		return -1;
	}

	// d * C1 = (x2, y2)
	sm2_z256_point_mul(&C1, key->private_key, &C1);

	// t = KDF(x2 || y2, klen) and check t is not all zeros
	sm2_z256_point_to_bytes(&C1, x2y2);
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
	gmssl_secure_clear(&C1, sizeof(SM2_Z256_POINT));
	gmssl_secure_clear(x2y2, sizeof(x2y2));
	return ret;
}


int sm2_ciphertext_to_der(const SM2_CIPHERTEXT *C, uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (!C) {
		return 0;
	}
	if (asn1_integer_to_der(C->point.x, 32, NULL, &len) != 1
		|| asn1_integer_to_der(C->point.y, 32, NULL, &len) != 1
		|| asn1_octet_string_to_der(C->hash, 32, NULL, &len) != 1
		|| asn1_octet_string_to_der(C->ciphertext, C->ciphertext_size, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_integer_to_der(C->point.x, 32, out, outlen) != 1
		|| asn1_integer_to_der(C->point.y, 32, out, outlen) != 1
		|| asn1_octet_string_to_der(C->hash, 32, out, outlen) != 1
		|| asn1_octet_string_to_der(C->ciphertext, C->ciphertext_size, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_ciphertext_from_der(SM2_CIPHERTEXT *C, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;
	const uint8_t *x;
	const uint8_t *y;
	const uint8_t *hash;
	const uint8_t *c;
	size_t xlen, ylen, hashlen, clen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_integer_from_der(&x, &xlen, &d, &dlen) != 1
		|| asn1_length_le(xlen, 32) != 1) {
		error_print();
		return -1;
	}
	if (asn1_integer_from_der(&y, &ylen, &d, &dlen) != 1
		|| asn1_length_le(ylen, 32) != 1) {
		error_print();
		return -1;
	}
	if (asn1_octet_string_from_der(&hash, &hashlen, &d, &dlen) != 1
		|| asn1_check(hashlen == 32) != 1) {
		error_print();
		return -1;
	}
	if (asn1_octet_string_from_der(&c, &clen, &d, &dlen) != 1
	//	|| asn1_length_is_zero(clen) == 1				
		|| asn1_length_le(clen, SM2_MAX_PLAINTEXT_SIZE) != 1) {
		error_print();
		return -1;
	}
	if (asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	memset(C, 0, sizeof(SM2_CIPHERTEXT));
	memcpy(C->point.x + 32 - xlen, x, xlen);
	memcpy(C->point.y + 32 - ylen, y, ylen);
	memcpy(C->hash, hash, hashlen);
	memcpy(C->ciphertext, c, clen);
	C->ciphertext_size = (uint8_t)clen;
	return 1;
}

int sm2_ciphertext_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *a, size_t alen)
{
	uint8_t buf[512] = {0};
	SM2_CIPHERTEXT *c = (SM2_CIPHERTEXT *)buf;

	if (sm2_ciphertext_from_der(c, &a, &alen) != 1
		|| asn1_length_is_zero(alen) != 1) {
		error_print();
		return -1;
	}
	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	format_bytes(fp, fmt, ind, "XCoordinate", c->point.x, 32);
	format_bytes(fp, fmt, ind, "YCoordinate", c->point.y, 32);
	format_bytes(fp, fmt, ind, "HASH", c->hash, 32);
	format_bytes(fp, fmt, ind, "CipherText", c->ciphertext, c->ciphertext_size);
	return 1;
}

int sm2_encrypt(const SM2_KEY *key, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	SM2_CIPHERTEXT C;

	if (!key || !in || !out || !outlen) {
		error_print();
		return -1;
	}
	if (!inlen) {
		error_print();
		return -1;
	}

	if (sm2_do_encrypt(key, in, inlen, &C) != 1) {
		error_print();
		return -1;
	}
	*outlen = 0;
	if (sm2_ciphertext_to_der(&C, &out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_encrypt_fixlen(const SM2_KEY *key, const uint8_t *in, size_t inlen, int point_size, uint8_t *out, size_t *outlen)
{
	SM2_CIPHERTEXT C;

	if (!key || !in || !out || !outlen) {
		error_print();
		return -1;
	}
	if (!inlen) {
		error_print();
		return -1;
	}

	if (sm2_do_encrypt_fixlen(key, in, inlen, point_size, &C) != 1) {
		error_print();
		return -1;
	}
	*outlen = 0;
	if (sm2_ciphertext_to_der(&C, &out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_decrypt(const SM2_KEY *key, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	SM2_CIPHERTEXT C;

	if (!key || !in || !out || !outlen) {
		error_print();
		return -1;
	}
	if (sm2_ciphertext_from_der(&C, &in, &inlen) != 1
		|| asn1_length_is_zero(inlen) != 1) {
		error_print();
		return -1;
	}
	if (sm2_do_decrypt(key, &C, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}
int sm2_encrypt_init(SM2_ENC_CTX *ctx)
{
	if (!ctx) {
		error_print();
		return -1;
	}

#if ENABLE_SM2_ENC_PRE_COMPUTE
	if (sm2_encrypt_pre_compute(ctx->pre_comp) != 1) {
		error_print();
		return -1;
	}
	ctx->pre_comp_num = SM2_ENC_PRE_COMP_NUM;
#endif

	ctx->buf_size = 0;

	return 1;
}

int sm2_encrypt_update(SM2_ENC_CTX *ctx, const uint8_t *in, size_t inlen)
{
	if (!ctx) {
		error_print();
		return -1;
	}

	if (ctx->buf_size > SM2_MAX_PLAINTEXT_SIZE) {
		error_print();
		return -1;
	}

	if (in) {
		if (inlen > SM2_MAX_PLAINTEXT_SIZE - ctx->buf_size) {
			error_print();
			return -1;
		}

		memcpy(ctx->buf + ctx->buf_size, in, inlen);
		ctx->buf_size += inlen;
	}

	return 1;
}

int sm2_encrypt_finish(SM2_ENC_CTX *ctx, const SM2_KEY *public_key, uint8_t *out, size_t *outlen)
{
	SM2_CIPHERTEXT ciphertext;

	if (!ctx || !public_key || !outlen) {
		error_print();
		return -1;
	}

	if (ctx->buf_size > SM2_MAX_PLAINTEXT_SIZE) {
		error_print();
		return -1;
	}
	if (ctx->buf_size == 0) {
		error_print();
		return -1;
	}

	if (!out) {
		*outlen = SM2_MAX_CIPHERTEXT_SIZE;
		return 1;
	}

#if ENABLE_SM2_ENC_PRE_COMPUTE
	if (ctx->pre_comp_num == 0) {
		if (sm2_encrypt_pre_compute(ctx->pre_comp) != 1) {
			error_print();
			return -1;
		}
		ctx->pre_comp_num = SM2_ENC_PRE_COMP_NUM;
	}

	ctx->pre_comp_num--;
	if (sm2_do_encrypt_ex(public_key, &ctx->pre_comp[ctx->pre_comp_num], ctx->buf, ctx->buf_size, &ciphertext) != 1) {
		error_print();
		return -1;
	}

	*outlen = 0;
	if (sm2_ciphertext_to_der(&ciphertext, &out, outlen) != 1) {
		error_print();
		return -1;
	}
#else
	if (sm2_encrypt(public_key, ctx->buf, ctx->buf_size, out, outlen) != 1) {
		error_print();
		return -1;
	}
#endif

	return 1;
}

int sm2_encrypt_reset(SM2_ENC_CTX *ctx)
{
	if (!ctx) {
		error_print();
		return -1;
	}

	ctx->buf_size = 0;
	return 1;
}

int sm2_decrypt_init(SM2_DEC_CTX *ctx)
{
	if (!ctx) {
		error_print();
		return -1;
	}

	ctx->buf_size = 0;

	return 1;
}

int sm2_decrypt_update(SM2_DEC_CTX *ctx, const uint8_t *in, size_t inlen)
{
	if (!ctx) {
		error_print();
		return -1;
	}

	if (ctx->buf_size > SM2_MAX_CIPHERTEXT_SIZE) {
		error_print();
		return -1;
	}

	if (in) {
		if (inlen > SM2_MAX_CIPHERTEXT_SIZE - ctx->buf_size) {
			error_print();
			return -1;
		}

		memcpy(ctx->buf + ctx->buf_size, in, inlen);
		ctx->buf_size += inlen;
	}

	return 1;
}

int sm2_decrypt_finish(SM2_DEC_CTX *ctx, const SM2_KEY *key, uint8_t *out, size_t *outlen)
{
	if (!ctx || !key || !outlen) {
		error_print();
		return -1;
	}

	if (ctx->buf_size > SM2_MAX_CIPHERTEXT_SIZE) {
		error_print();
		return -1;
	}
	if (ctx->buf_size < SM2_MIN_CIPHERTEXT_SIZE) {
		error_print();
		return -1;
	}

	if (!out) {
		*outlen = SM2_MAX_PLAINTEXT_SIZE;
		return 1;
	}

	if (sm2_decrypt(key, ctx->buf, ctx->buf_size, out, outlen) != 1) {
		error_print();
		return -1;
	}

	return 1;
}

int sm2_decrypt_reset(SM2_DEC_CTX *ctx)
{
	if (!ctx) {
		error_print();
		return -1;
	}

	ctx->buf_size = 0;
	return 1;
}
