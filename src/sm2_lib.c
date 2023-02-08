/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
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


extern const SM2_BN SM2_N;
extern const SM2_BN SM2_ONE;

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

	//fprintf(stderr, "sm2_do_sign\n");
	sm2_bn_from_bytes(d, key->private_key);

	// compute (d + 1)^-1 (mod n)
	sm2_fn_add(d_inv, d, SM2_ONE);	//sm2_bn_print(stderr, 0, 4, "(1+d)", d_inv);
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
	if (sm2_bn_cmp(e, SM2_N) >= 0) {
		sm2_bn_sub(e, e, SM2_N);
	}
	if (sm2_bn_cmp(x, SM2_N) >= 0) {
		sm2_bn_sub(x, x, SM2_N);
	}
	sm2_fn_add(r, e, x);		//sm2_bn_print(stderr, 0, 4, "r = e + x (mod n)", r);

	// if r == 0 or r + k == n re-generate k
	sm2_bn_add(t, r, k);
	if (sm2_bn_is_zero(r) || sm2_bn_cmp(t, SM2_N) == 0) {
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

int sm2_do_verify(const SM2_KEY *key, const uint8_t dgst[32], const SM2_SIGNATURE *sig)
{
	SM2_JACOBIAN_POINT _P, *P = &_P;
	SM2_JACOBIAN_POINT _R, *R = &_R;
	SM2_BN r;
	SM2_BN s;
	SM2_BN e;
	SM2_BN x;
	SM2_BN t;

	// parse public key
	sm2_jacobian_point_from_bytes(P, (const uint8_t *)&key->public_key);
					//sm2_jacobian_point_print(stderr, 0, 4, "P", P);

	// parse signature values
	sm2_bn_from_bytes(r, sig->r);	//sm2_bn_print(stderr, 0, 4, "r", r);
	sm2_bn_from_bytes(s, sig->s);	//sm2_bn_print(stderr, 0, 4, "s", s);

	// check r, s in [1, n-1]
	if (sm2_bn_is_zero(r) == 1
		|| sm2_bn_cmp(r, SM2_N) >= 0
		|| sm2_bn_is_zero(s) == 1
		|| sm2_bn_cmp(s, SM2_N) >= 0) {
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
	if (sm2_bn_cmp(e, SM2_N) >= 0) {
		sm2_bn_sub(e, e, SM2_N);
	}
	if (sm2_bn_cmp(x, SM2_N) >= 0) {
		sm2_bn_sub(x, x, SM2_N);
	}
	sm2_fn_add(e, e, x);		//sm2_bn_print(stderr, 0, 4, "e + x (mod n)", e);

	// check if r == r'
	if (sm2_bn_cmp(e, r) != 0) {
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

int sm2_compute_z(uint8_t z[32], const SM2_POINT *pub, const char *id, size_t idlen)
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

	memcpy(&zin[18 + 32 * 4], pub->x, 32);
	memcpy(&zin[18 + 32 * 5], pub->y, 32);

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
	ctx->key = *key;
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

	if (!ctx || !sig || !siglen) {
		error_print();
		return -1;
	}
	sm3_finish(&ctx->sm3_ctx, dgst);
	if (sm2_sign(&ctx->key, dgst, sig, siglen) != 1) {
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

int sm2_verify_init(SM2_SIGN_CTX *ctx, const SM2_KEY *key, const char *id, size_t idlen)
{
	if (!ctx || !key) {
		error_print();
		return -1;
	}
	memset(ctx, 0, sizeof(*ctx));
	ctx->key.public_key = key->public_key;
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
	return 1;
}

int sm2_verify_update(SM2_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
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

int sm2_verify_finish(SM2_SIGN_CTX *ctx, const uint8_t *sig, size_t siglen)
{
	uint8_t dgst[SM3_DIGEST_SIZE];

	if (!ctx || !sig) {
		error_print();
		return -1;
	}
	sm3_finish(&ctx->sm3_ctx, dgst);
	if (sm2_verify(&ctx->key, dgst, sig, siglen) != 1) {
		error_print();
		return -1;
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
	if (sm2_point_is_on_curve(&C->point) != 1) {
		error_print();
		return -1;
	}
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

int sm2_do_ecdh(const SM2_KEY *key, const SM2_POINT *peer_public, SM2_POINT *out)
{
	/*
	if (sm2_point_is_on_curve(peer_public) != 1) {
		error_print();
		return -1;
	}
	*/
	if (sm2_point_mul(out, key->private_key, peer_public) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_ecdh(const SM2_KEY *key, const uint8_t *peer_public, size_t peer_public_len, SM2_POINT *out)
{
	SM2_POINT point;

	if (!key || !peer_public || !peer_public_len || !out) {
		error_print();
		return -1;
	}
	if (sm2_point_from_octets(&point, peer_public, peer_public_len) != 1) {
		error_print();
		return -1;
	}
	if (sm2_do_ecdh(key, &point, out) != 1) {
		error_print();
		return -1;
	}
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

	// e = H(M)
	sm2_bn_from_bytes(e, dgst);
	if (sm2_bn_cmp(e, SM2_N) >= 0) {
		sm2_bn_sub(e, e, SM2_N);
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

