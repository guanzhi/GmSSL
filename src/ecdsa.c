/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/asn1.h>
#include <gmssl/sha2.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include <gmssl/ecdsa.h>
#include <gmssl/bn.h>
#include <gmssl/sm2.h>


int ecdsa_signature_print_ex(FILE *fp, int fmt, int ind, const char *label, const ECDSA_SIGNATURE *sig)
{
	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	secp256r1_print(fp, fmt, ind, "r", sig->r);
	secp256r1_print(fp, fmt, ind, "s", sig->s);
	return 1;
}

int ecdsa_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *sigbuf, size_t siglen)
{
	ECDSA_SIGNATURE sig;

	if (ecdsa_signature_from_der(&sig, &sigbuf, &siglen) != 1) {
		error_print();
		return -1;
	}
	ecdsa_signature_print_ex(fp, fmt, ind, label, &sig);
	if (siglen) {
		error_print();
		return -1;
	}
	return 1;
}

int ecdsa_do_sign_ex(const SECP256R1_KEY *key, const secp256r1_t k, const uint8_t dgst[32], ECDSA_SIGNATURE *sig)
{
	secp256r1_t e;
	secp256r1_t x1;
	secp256r1_t y1;
	secp256r1_t k_inv;
	SECP256R1_POINT P;

	// e = hash(m)
	secp256r1_from_32bytes(e, dgst);
	secp256r1_modn(e, e);

	// (x1, y1) = k*G
	secp256r1_point_mul_generator(&P, k);
	secp256r1_point_get_xy(&P, x1, y1);

	// r = x1 mod n
	secp256r1_modn(sig->r, x1);

	// s = k^-1 * (e + d * r) mod n
	secp256r1_modn_inv(k_inv, k);
	secp256r1_modn_mul(sig->s, key->private_key, sig->r);
	secp256r1_modn_add(sig->s, sig->s, e);
	secp256r1_modn_mul(sig->s, sig->s, k_inv);

	return 1;
}

int ecdsa_do_sign(const SECP256R1_KEY *key, const uint8_t dgst[32], ECDSA_SIGNATURE *sig)
{
	secp256r1_t k;

	// rand k in [1, n-1]
	do {
		if (rand_bytes((uint8_t *)k, sizeof(k)) != 1) {
			error_print();
			return -1;
		}
	} while (secp256r1_is_zero(k) || secp256r1_cmp(k, SECP256R1_N) >= 0);

	if (ecdsa_do_sign_ex(key, k, dgst, sig) != 1) {
		error_print();
		return -1;
	}
	return 1;
}


int ecdsa_do_verify(const SECP256R1_KEY *key, const uint8_t dgst[32], const ECDSA_SIGNATURE *sig)
{
	secp256r1_t e;
	secp256r1_t w;
	secp256r1_t u1;
	secp256r1_t u2;
	secp256r1_t x1;
	secp256r1_t y1;
	SECP256R1_POINT P;
	SECP256R1_POINT Q;
	SECP256R1_POINT R;

	// check r, s in [1, n-1]
	if (secp256r1_is_zero(sig->r)
		|| secp256r1_cmp(sig->r, SECP256R1_N) >= 0
		|| secp256r1_is_zero(sig->s)
		|| secp256r1_cmp(sig->s, SECP256R1_N) >= 0) {
		error_print();
		return -1;
	}

	// e = hash(m)
	secp256r1_from_32bytes(e, dgst);
	secp256r1_modn(e, e);

	// w = s^-1 (mod n)
	secp256r1_modn_inv(w, sig->s);

	// u1 = e * w (mod n)
	secp256r1_modn_mul(u1, e, w);

	// u2 = r * w (mod n)
	secp256r1_modn_mul(u2, sig->r, w);

	// (x1, y1) = u1*G + u2*Q
	secp256r1_point_mul_generator(&P, u1);
	secp256r1_point_mul(&Q, u2, &key->public_key);
	secp256r1_point_add(&R, &P, &Q);
	secp256r1_point_get_xy(&R, x1, y1);

	// x1 = x1 mod n
	secp256r1_modn(x1, x1);

	if (secp256r1_cmp(x1, sig->r) != 0) {
		return 0;
	}
	return 1;
}

int ecdsa_signature_to_der(const ECDSA_SIGNATURE *sig, uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	uint8_t r[32];
	uint8_t s[32];

	if (!sig) {
		return 0;
	}

	secp256r1_to_32bytes(sig->r, r);
	secp256r1_to_32bytes(sig->s, s);

	if (asn1_integer_to_der(r, 32, NULL, &len) != 1
		|| asn1_integer_to_der(s, 32, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_integer_to_der(r, 32, out, outlen) != 1
		|| asn1_integer_to_der(s, 32, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int ecdsa_signature_from_der(ECDSA_SIGNATURE *sig, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	const uint8_t *r;
	const uint8_t *s;
	size_t dlen, rlen, slen;

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

	secp256r1_from_32bytes(sig->r, r);
	secp256r1_from_32bytes(sig->s, s);

	return 1;
}

int ecdsa_sign(const SECP256R1_KEY *key, const uint8_t dgst[32], uint8_t *sigbuf, size_t *siglen)
{
	ECDSA_SIGNATURE sig;

	if (ecdsa_do_sign(key, dgst, &sig) != 1) {
		error_print();
		return -1;
	}
	*siglen = 0;
	if (ecdsa_signature_to_der(&sig, &sigbuf, siglen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int ecdsa_sign_fixlen(const SECP256R1_KEY *key, const uint8_t dgst[32], size_t siglen, uint8_t *sig)
{
	unsigned int trys = 200;
	uint8_t buf[ECDSA_SIGNATURE_MAX_SIZE];
	size_t len;

	switch (siglen) {
	case ECDSA_SIGNATURE_COMPACT_SIZE:
	case ECDSA_SIGNATURE_TYPICAL_SIZE:
	case ECDSA_SIGNATURE_MAX_SIZE:
		break;
	default:
		error_print();
		return -1;
	}

	while (trys--) {
		if (ecdsa_sign(key, dgst, buf, &len) != 1) {
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


int ecdsa_verify(const SECP256R1_KEY *key, const uint8_t dgst[32], const uint8_t *sigbuf, size_t siglen)
{
	int ret;
	ECDSA_SIGNATURE sig;

	if (ecdsa_signature_from_der(&sig, &sigbuf, &siglen) != 1) {
		error_print();
		return -1;
	}
	if (siglen) {
		error_print();
		return -1;
	}
	if ((ret = ecdsa_do_verify(key, dgst, &sig)) < 0) {
		error_print();
		return -1;
	}
	return ret;
}

int ecdsa_sign_init(ECDSA_SIGN_CTX *ctx, const SECP256R1_KEY *key)
{
	if (!ctx || !key) {
		error_print();
		return -1;
	}
	memset(ctx, 0, sizeof(ECDSA_SIGN_CTX));

	ctx->key = *key;

	sha256_init(&ctx->sha256_ctx);

	return 1;
}

int ecdsa_sign_update(ECDSA_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	if (data && datalen) {
		sha256_update(&ctx->sha256_ctx, data, datalen);
	}
	return 1;
}

int ecdsa_sign_finish(ECDSA_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen)
{
	uint8_t dgst[32];

	if (!ctx || !sig || !siglen) {
		error_print();
		return -1;
	}

	sha256_finish(&ctx->sha256_ctx, dgst);

	if (ecdsa_sign(&ctx->key, dgst, sig, siglen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int ecdsa_sign_finish_fixlen(ECDSA_SIGN_CTX *ctx, size_t siglen, uint8_t *sig)
{
	uint8_t dgst[32];

	if (!ctx || !sig || !siglen) {
		error_print();
		return -1;
	}

	sha256_finish(&ctx->sha256_ctx, dgst);

	if (ecdsa_sign_fixlen(&ctx->key, dgst, siglen, sig) != 1) {
		error_print();
		return -1;
	}
	return 1;
}






int ecdsa_verify_init(ECDSA_SIGN_CTX *ctx, const SECP256R1_KEY *key, const uint8_t *sig, size_t siglen)
{
	if (!ctx || !key || !sig || !siglen) {
		error_print();
		return -1;
	}

	if (ecdsa_signature_from_der(&ctx->sig, &sig, &siglen) != 1) {
		error_print();
		return -1;
	}
	if (siglen) {
		error_print();
		return -1;
	}

	ctx->key = *key;

	sha256_init(&ctx->sha256_ctx);

	return 1;
}


int ecdsa_verify_update(ECDSA_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	if (data && datalen) {
		sha256_update(&ctx->sha256_ctx, data, datalen);
	}
	return 1;
}


int ecdsa_verify_finish(ECDSA_SIGN_CTX *ctx)
{
	uint8_t dgst[32];
	int ret;

	if (!ctx) {
		error_print();
		return -1;
	}

	sha256_finish(&ctx->sha256_ctx, dgst);

	if ((ret = ecdsa_do_verify(&ctx->key, dgst, &ctx->sig)) < 0) {
		error_print();
		return -1;
	}
	return ret;
}

