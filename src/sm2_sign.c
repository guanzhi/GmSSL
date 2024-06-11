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
	SM2_Z256_POINT P;
	sm2_z256_t d_inv;
	sm2_z256_t e;
	sm2_z256_t k;
	sm2_z256_t x;
	sm2_z256_t t;
	sm2_z256_t r;
	sm2_z256_t s;

	// compute (d + 1)^-1 (mod n)
	sm2_z256_modn_add(d_inv, key->private_key, sm2_z256_one());
	if (sm2_z256_is_zero(d_inv)) {
		error_print();
		return -1;
	}
	sm2_z256_modn_to_mont(d_inv, d_inv);
	sm2_z256_modn_mont_inv(d_inv, d_inv);

	// e = H(M)
	sm2_z256_from_bytes(e, dgst);

retry:

	// rand k in [1, n - 1]
	do {
		if (sm2_z256_rand_range(k, sm2_z256_order()) != 1) {
			error_print();
			return -1;
		}
	} while (sm2_z256_is_zero(k));

	// (x, y) = kG
	sm2_z256_point_mul_generator(&P, k);
	sm2_z256_point_get_xy(&P, x, NULL);

	// r = e + x (mod n)
	if (sm2_z256_cmp(e, sm2_z256_order()) >= 0) {
		sm2_z256_sub(e, e, sm2_z256_order());
	}
	if (sm2_z256_cmp(x, sm2_z256_order()) >= 0) {
		sm2_z256_sub(x, x, sm2_z256_order());
	}
	sm2_z256_modn_add(r, e, x);

	// if r == 0 or r + k == n re-generate k
	sm2_z256_add(t, r, k);
	if (sm2_z256_is_zero(r) || sm2_z256_cmp(t, sm2_z256_order()) == 0) {
		goto retry;
	}

	// s = ((1 + d)^-1 * (k - r * d)) mod n
	sm2_z256_modn_to_mont(r, t);
	sm2_z256_modn_mont_mul(t, t, key->private_key);
	sm2_z256_modn_sub(k, k, t);
	sm2_z256_modn_mont_mul(s, d_inv, k);

	// check s != 0
	if (sm2_z256_is_zero(s)) {
		goto retry;
	}

	sm2_z256_to_bytes(r, sig->r);
	sm2_z256_to_bytes(s, sig->s);

	gmssl_secure_clear(d_inv, sizeof(d_inv));
	gmssl_secure_clear(k, sizeof(k));
	gmssl_secure_clear(t, sizeof(t));
	return 1;
}

// d' = (d + 1)^-1 (mod n)
int sm2_fast_sign_compute_key(const SM2_KEY *key, sm2_z256_t fast_private)
{
	if (sm2_z256_cmp(key->private_key, sm2_z256_order_minus_one()) >= 0) {
		error_print();
		return -1;
	}
	sm2_z256_modn_add(fast_private, key->private_key, sm2_z256_one());
	sm2_z256_modn_inv(fast_private, fast_private);
	return 1;
}

// use Montgomery's Trick to inverse Z coordinates on multiple (x1, y1) = [k]G
int sm2_fast_sign_pre_compute(SM2_SIGN_PRE_COMP pre_comp[32])
{
	SM2_Z256_POINT P[32];
	sm2_z256_t f[32];
	sm2_z256_t g[32];
	int i;

	for (i = 0; i < 32; i++) {

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
	for (i = 1; i < 32; i++) {
		sm2_z256_modp_mont_mul(f[i], f[i - 1], P[i].Z);
	}

	// f[31]^-1 = (Z[0] * ... * Z[31])^-1
	sm2_z256_modp_mont_inv(f[31], f[31]);

	// g[31] = Z[31]
	// g[30] = Z[30] * Z[31]
	// ...
	// g[1] = Z[1] * Z[2] * ... * Z[31]
	//
	sm2_z256_copy(g[31], P[31].Z);
	for (i = 30; i >= 1; i--) {
		sm2_z256_modp_mont_mul(g[i], g[i + 1], P[i].Z);
	}

	// Z[0]^-1 = g[1] * f[31]^-1
	// Z[1]^-1 = g[2] * f[0] * f[31]^-1
	// Z[2]^-1 = g[3] * f[1] * f[31]^-1
	// ...
	// Z[30]^-1 = g[31] * f[29] * f[31]^-1
	// Z[31]^-1 = f[30] * f[31]^-1
	sm2_z256_modp_mont_mul(P[0].Z, g[1], f[31]);
	for (i = 1; i <= 30; i++) {
		sm2_z256_modp_mont_mul(P[i].Z, g[i + 1], f[i - 1]);
		sm2_z256_modp_mont_mul(P[i].Z, P[i].Z, f[31]);
	}
	sm2_z256_modp_mont_mul(P[31].Z, f[30], f[31]);

	// x[i] = X[i] * Z[i]^-2 (mod n)
	for (i = 0; i < 32; i++) {
		sm2_z256_modp_mont_sqr(P[i].Z, P[i].Z);
		sm2_z256_modp_mont_mul(pre_comp[i].x1_modn, P[i].X, P[i].Z);
		sm2_z256_modp_from_mont(pre_comp[i].x1_modn, pre_comp[i].x1_modn);
		if (sm2_z256_cmp(pre_comp[i].x1_modn, sm2_z256_order()) >= 0) {
			sm2_z256_sub(pre_comp[i].x1_modn, pre_comp[i].x1_modn, sm2_z256_order());
		}
	}

	return 1;
}


// s = (k - r * d)/(1 + d)
//	= -r + (k + r)*(1 + d)^-1
//	= -r + (k + r) * d'
int sm2_fast_sign(const sm2_z256_t fast_private, SM2_SIGN_PRE_COMP *pre_comp,
	const uint8_t dgst[32], SM2_SIGNATURE *sig)
{
	sm2_z256_t e;
	sm2_z256_t r;
	sm2_z256_t s;

	// e = H(M)
	sm2_z256_from_bytes(e, dgst);
	if (sm2_z256_cmp(e, sm2_z256_order()) >= 0) {
		sm2_z256_sub(e, e, sm2_z256_order());
	}

	// r = e + x1 (mod n)
	sm2_z256_modn_add(r, e, pre_comp->x1_modn);

	// s = (k + r) * d' - r
	sm2_z256_modn_add(s, pre_comp->k, r);
	sm2_z256_modn_to_mont(s, s);
	sm2_z256_modn_mont_mul(s, s, fast_private); // mont(s) * d = s * R^-1 * d * R = s * d
	sm2_z256_modn_sub(s, s, r);

	sm2_z256_to_bytes(r, sig->r);
	sm2_z256_to_bytes(s, sig->s);

	return 1;
}

int sm2_fast_verify(const SM2_Z256_POINT point_table[16], const uint8_t dgst[32], const SM2_SIGNATURE *sig)
{
	SM2_Z256_POINT R;
	SM2_Z256_POINT T;
	sm2_z256_t r;
	sm2_z256_t s;
	sm2_z256_t e;
	sm2_z256_t x;
	sm2_z256_t t;

	// check r, s in [1, n-1]
	sm2_z256_from_bytes(r, sig->r);
	if (sm2_z256_is_zero(r) == 1) {
		error_print();
		return -1;
	}
	if (sm2_z256_cmp(r, sm2_z256_order()) >= 0) {
		error_print();
		return -1;
	}
	sm2_z256_from_bytes(s, sig->s);
	if (sm2_z256_is_zero(s) == 1) {
		error_print();
		return -1;
	}
	if (sm2_z256_cmp(s, sm2_z256_order()) >= 0) {
		error_print();
		return -1;
	}

	// t = r + s (mod n), check t != 0
	sm2_z256_modn_add(t, r, s);
	if (sm2_z256_is_zero(t)) {
		error_print();
		return -1;
	}

	// Q(x,y) = s * G + t * P
	sm2_z256_point_mul_generator(&R, s);
	sm2_z256_point_mul_ex(&T, t, point_table);
	sm2_z256_point_add(&R, &R, &T);
	sm2_z256_point_get_xy(&R, x, NULL);

	// e = H(M)
	sm2_z256_from_bytes(e, dgst);
	if (sm2_z256_cmp(e, sm2_z256_order()) >= 0) {
		sm2_z256_sub(e, e, sm2_z256_order());
	}

	// r' = e + x (mod n)
	if (sm2_z256_cmp(x, sm2_z256_order()) >= 0) {
		sm2_z256_sub(x, x, sm2_z256_order());
	}
	sm2_z256_modn_add(e, e, x);

	// check if r == r'
	if (sm2_z256_cmp(e, r) != 0) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_do_verify(const SM2_KEY *key, const uint8_t dgst[32], const SM2_SIGNATURE *sig)
{
	SM2_Z256_POINT R;
	SM2_Z256_POINT T;
	sm2_z256_t r;
	sm2_z256_t s;
	sm2_z256_t e;
	sm2_z256_t x;
	sm2_z256_t t;

	// check r, s in [1, n-1]
	sm2_z256_from_bytes(r, sig->r);
	if (sm2_z256_is_zero(r) == 1) {
		error_print();
		return -1;
	}
	if (sm2_z256_cmp(r, sm2_z256_order()) >= 0) {
		error_print();
		return -1;
	}
	sm2_z256_from_bytes(s, sig->s);
	if (sm2_z256_is_zero(s) == 1) {
		error_print();
		return -1;
	}
	if (sm2_z256_cmp(s, sm2_z256_order()) >= 0) {
		error_print();
		return -1;
	}

	// t = r + s (mod n), check t != 0
	sm2_z256_modn_add(t, r, s);
	if (sm2_z256_is_zero(t)) {
		error_print();
		return -1;
	}

	// Q(x,y) = s * G + t * P
	sm2_z256_point_mul_generator(&R, s);
	sm2_z256_point_mul(&T, t, &key->public_key);
	sm2_z256_point_add(&R, &R, &T);
	sm2_z256_point_get_xy(&R, x, NULL);

	// e = H(M)
	sm2_z256_from_bytes(e, dgst);
	if (sm2_z256_cmp(e, sm2_z256_order()) >= 0) {
		sm2_z256_sub(e, e, sm2_z256_order());
	}

	// r' = e + x (mod n)
	if (sm2_z256_cmp(x, sm2_z256_order()) >= 0) {
		sm2_z256_sub(x, x, sm2_z256_order());
	}
	sm2_z256_modn_add(e, e, x);

	// check if r == r'
	if (sm2_z256_cmp(e, r) != 0) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_signature_to_der(const SM2_SIGNATURE *sig, uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	if (!sig) {
		return 0;
	}
	if (asn1_integer_to_der(sig->r, 32, NULL, &len) != 1
		|| asn1_integer_to_der(sig->s, 32, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_integer_to_der(sig->r, 32, out, outlen) != 1
		|| asn1_integer_to_der(sig->s, 32, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_signature_from_der(SM2_SIGNATURE *sig, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;
	const uint8_t *r;
	size_t rlen;
	const uint8_t *s;
	size_t slen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_integer_from_der(&r, &rlen, &d, &dlen) != 1
		|| asn1_integer_from_der(&s, &slen, &d, &dlen) != 1
		|| asn1_length_le(rlen, 32) != 1
		|| asn1_length_le(slen, 32) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	memset(sig, 0, sizeof(*sig));
	memcpy(sig->r + 32 - rlen, r, rlen);
	memcpy(sig->s + 32 - slen, s, slen);
	return 1;
}

int sm2_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *a, size_t alen)
{
	SM2_SIGNATURE sig;
	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	if (sm2_signature_from_der(&sig, &a, &alen) != 1
		|| asn1_length_is_zero(alen) != 1) {
		error_print();
		return -1;
	}
	format_bytes(fp, fmt, ind, "r", sig.r, 32);
	format_bytes(fp, fmt, ind, "s", sig.s, 32);
	return 1;
}

int sm2_sign(const SM2_KEY *key, const uint8_t dgst[32], uint8_t *sigbuf, size_t *siglen)
{
	SM2_SIGNATURE sig;

	if (!key || !dgst || !sigbuf || !siglen) {
		error_print();
		return -1;
	}

	if (sm2_do_sign(key, dgst, &sig) != 1) {
		error_print();
		return -1;
	}

	*siglen = 0;
	if (sm2_signature_to_der(&sig, &sigbuf, siglen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_sign_fixlen(const SM2_KEY *key, const uint8_t dgst[32], size_t siglen, uint8_t *sig)
{
	unsigned int trys = 200; // 200 trys is engouh
	uint8_t buf[SM2_MAX_SIGNATURE_SIZE];
	size_t len;

	switch (siglen) {
	case SM2_signature_compact_size:
	case SM2_signature_typical_size:
	case SM2_signature_max_size:
		break;
	default:
		error_print();
		return -1;
	}

	while (trys--) {
		if (sm2_sign(key, dgst, buf, &len) != 1) {
			error_print();
			return -1;
		}
		if (len == siglen) {
			memcpy(sig, buf, len);
			return 1;
		}
	}

	// might caused by bad randomness
	error_print();
	return -1;
}

int sm2_verify(const SM2_KEY *key, const uint8_t dgst[32], const uint8_t *sigbuf, size_t siglen)
{
	SM2_SIGNATURE sig;

	if (!key || !dgst || !sigbuf || !siglen) {
		error_print();
		return -1;
	}

	if (sm2_signature_from_der(&sig, &sigbuf, &siglen) != 1
		|| asn1_length_is_zero(siglen) != 1) {
		error_print();
		return -1;
	}
	if (sm2_do_verify(key, dgst, &sig) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_compute_z(uint8_t z[32], const SM2_Z256_POINT *pub, const char *id, size_t idlen)
{
	SM3_CTX ctx;
	uint8_t zin[18 + 32 * 6] = {
		0x00, 0x80,
		0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,
		0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFC,
		0x28,0xE9,0xFA,0x9E,0x9D,0x9F,0x5E,0x34,0x4D,0x5A,0x9E,0x4B,0xCF,0x65,0x09,0xA7,
		0xF3,0x97,0x89,0xF5,0x15,0xAB,0x8F,0x92,0xDD,0xBC,0xBD,0x41,0x4D,0x94,0x0E,0x93,
       		0x32,0xC4,0xAE,0x2C,0x1F,0x19,0x81,0x19,0x5F,0x99,0x04,0x46,0x6A,0x39,0xC9,0x94,
		0x8F,0xE3,0x0B,0xBF,0xF2,0x66,0x0B,0xE1,0x71,0x5A,0x45,0x89,0x33,0x4C,0x74,0xC7,
		0xBC,0x37,0x36,0xA2,0xF4,0xF6,0x77,0x9C,0x59,0xBD,0xCE,0xE3,0x6B,0x69,0x21,0x53,
		0xD0,0xA9,0x87,0x7C,0xC6,0x2A,0x47,0x40,0x02,0xDF,0x32,0xE5,0x21,0x39,0xF0,0xA0,
	};

	if (!z || !pub || !id) {
		error_print();
		return -1;
	}

	sm2_z256_point_to_bytes(pub, &zin[18 + 32 * 4]);

	sm3_init(&ctx);
	if (strcmp(id, SM2_DEFAULT_ID) == 0) {
		sm3_update(&ctx, zin, sizeof(zin));
	} else {
		uint8_t idbits[2];
		idbits[0] = (uint8_t)(idlen >> 5);
		idbits[1] = (uint8_t)(idlen << 3);
		sm3_update(&ctx, idbits, 2);
		sm3_update(&ctx, (uint8_t *)id, idlen);
		sm3_update(&ctx, zin + 18, 32 * 6);
	}
	sm3_finish(&ctx, z);
	return 1;
}

int sm2_sign_init(SM2_SIGN_CTX *ctx, const SM2_KEY *key, const char *id, size_t idlen)
{
	if (!ctx || !key) {
		error_print();
		return -1;
	}

	sm3_init(&ctx->sm3_ctx);
	if (id) {
		uint8_t z[SM3_DIGEST_SIZE];

		if (idlen <= 0 || idlen > SM2_MAX_ID_LENGTH) {
			error_print();
			return -1;
		}
		sm2_compute_z(z, &key->public_key, id, idlen);
		sm3_update(&ctx->sm3_ctx, z, sizeof(z));
	}
	ctx->saved_sm3_ctx = ctx->sm3_ctx;

	if (sm2_fast_sign_pre_compute(ctx->pre_comp) != 1) {
		error_print();
		return -1;
	}
	ctx->num_pre_comp = SM2_SIGN_PRE_COMP_COUNT;

	// copy private key at last
	ctx->key = *key;
	sm2_fast_sign_compute_key(key, ctx->fast_sign_private);

	return 1;
}

int sm2_sign_reset(SM2_SIGN_CTX *ctx)
{
	ctx->sm3_ctx = ctx->saved_sm3_ctx;
	return 1;
}

int sm2_sign_update(SM2_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
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

int sm2_sign_finish(SM2_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen)
{
	uint8_t dgst[SM3_DIGEST_SIZE];
	SM2_SIGNATURE signature;

	if (!ctx || !sig || !siglen) {
		error_print();
		return -1;
	}

	sm3_finish(&ctx->sm3_ctx, dgst);

	if (ctx->num_pre_comp == 0) {
		if (sm2_fast_sign_pre_compute(ctx->pre_comp) != 1) {
			error_print();
			return -1;
		}
		ctx->num_pre_comp = SM2_SIGN_PRE_COMP_COUNT;
	}

	ctx->num_pre_comp--;
	if (sm2_fast_sign(ctx->fast_sign_private, &ctx->pre_comp[ctx->num_pre_comp],
		dgst, &signature) != 1) {
		error_print();
		return -1;
	}

	*siglen = 0;
	if (sm2_signature_to_der(&signature, &sig, siglen) != 1) {
		error_print();
		return -1;
	}

	return 1;
}

int sm2_sign_finish_fixlen(SM2_SIGN_CTX *ctx, size_t siglen, uint8_t *sig)
{
	uint8_t dgst[SM3_DIGEST_SIZE];

	if (!ctx || !sig || !siglen) {
		error_print();
		return -1;
	}
	sm3_finish(&ctx->sm3_ctx, dgst);
	if (sm2_sign_fixlen(&ctx->key, dgst, siglen, sig) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_verify_init(SM2_VERIFY_CTX *ctx, const SM2_KEY *key, const char *id, size_t idlen)
{
	if (!ctx || !key) {
		error_print();
		return -1;
	}

	sm3_init(&ctx->sm3_ctx);
	if (id) {
		uint8_t z[SM3_DIGEST_SIZE];

		if (idlen <= 0 || idlen > SM2_MAX_ID_LENGTH) {
			error_print();
			return -1;
		}
		sm2_compute_z(z, &key->public_key, id, idlen);
		sm3_update(&ctx->sm3_ctx, z, sizeof(z));
	}
	ctx->saved_sm3_ctx = ctx->sm3_ctx;

	if (sm2_key_set_public_key(&ctx->key, &key->public_key) != 1) {
		error_print();
		return -1;
	}

	sm2_z256_point_mul_pre_compute(&key->public_key, ctx->public_point_table);

	return 1;
}

int sm2_verify_update(SM2_VERIFY_CTX *ctx, const uint8_t *data, size_t datalen)
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

int sm2_verify_finish(SM2_VERIFY_CTX *ctx, const uint8_t *sigbuf, size_t siglen)
{
	uint8_t dgst[SM3_DIGEST_SIZE];
	SM2_SIGNATURE sig;

	if (!ctx || !sigbuf) {
		error_print();
		return -1;
	}

	if (sm2_signature_from_der(&sig, &sigbuf, &siglen) != 1
		|| asn1_length_is_zero(siglen) != 1) {
		error_print();
		return -1;
	}

	sm3_finish(&ctx->sm3_ctx, dgst);

	if (sm2_fast_verify(ctx->public_point_table, dgst, &sig) != 1) {
		error_print();
		return -1;
	}

	return 1;
}

int sm2_verify_reset(SM2_VERIFY_CTX *ctx)
{
	ctx->sm3_ctx = ctx->saved_sm3_ctx;
	return 1;
}
