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
#include <gmssl/digest.h>
#include <gmssl/sha2.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include <gmssl/secp384r1_ecdsa.h>
#include <gmssl/bn.h>
#include <gmssl/sm2.h>


int secp384r1_ecdsa_signature_print_ex(FILE *fp, int fmt, int ind, const char *label, const SECP384R1_ECDSA_SIGNATURE *sig)
{
	format_print(fp, fmt, ind, "%s\n", label);
	ind += 4;
	if (secp384r1_print(fp, fmt, ind, "r", sig->r) != 1
		|| secp384r1_print(fp, fmt, ind, "s", sig->s) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp384r1_ecdsa_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *sigbuf, size_t siglen)
{
	SECP384R1_ECDSA_SIGNATURE sig;

	if (secp384r1_ecdsa_signature_from_der(&sig, &sigbuf, &siglen) != 1) {
		error_print();
		return -1;
	}
	secp384r1_ecdsa_signature_print_ex(fp, fmt, ind, label, &sig);
	if (siglen) {
		error_print();
		return -1;
	}
	return 1;
}

static int secp384r1_ecdsa_digest_to_e(secp384r1_t e, const uint8_t *dgst, size_t dgstlen)
{
	uint8_t buf[SHA384_DIGEST_SIZE];

	if (!dgst) {
		error_print();
		return -1;
	}
	if (dgstlen == SHA256_DIGEST_SIZE) {
		memset(buf, 0, SHA384_DIGEST_SIZE - SHA256_DIGEST_SIZE);
		memcpy(buf + SHA384_DIGEST_SIZE - SHA256_DIGEST_SIZE, dgst, SHA256_DIGEST_SIZE);
	} else if (dgstlen == SHA384_DIGEST_SIZE) {
		memcpy(buf, dgst, sizeof(buf));
	} else {
		error_print();
		return -1;
	}

	if (secp384r1_from_48bytes(e, buf) != 1
		|| secp384r1_modn(e, e) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp384r1_ecdsa_do_sign_ex(const SECP384R1_KEY *key, const secp384r1_t k,
	const uint8_t *dgst, size_t dgstlen, SECP384R1_ECDSA_SIGNATURE *sig)
{
	secp384r1_t e;
	secp384r1_t x1;
	secp384r1_t y1;
	secp384r1_t k_inv;
	SECP384R1_POINT P;

	// e = hash(m)
	if (secp384r1_ecdsa_digest_to_e(e, dgst, dgstlen) != 1) {
		error_print();
		return -1;
	}

	// (x1, y1) = k*G
	if (secp384r1_point_mul_generator(&P, k) != 1
		|| secp384r1_point_get_xy(&P, x1, y1) != 1) {
		error_print();
		return -1;
	}

	// r = x1 mod n
	if (secp384r1_modn(sig->r, x1) != 1) {
		error_print();
		return -1;
	}

	// s = k^-1 * (e + d * r) mod n
	if (secp384r1_modn_inv(k_inv, k) != 1
		|| secp384r1_modn_mul(sig->s, key->private_key, sig->r) != 1
		|| secp384r1_modn_add(sig->s, sig->s, e) != 1
		|| secp384r1_modn_mul(sig->s, sig->s, k_inv) != 1) {
		error_print();
		return -1;
	}

	return 1;
}

int secp384r1_ecdsa_do_sign(const SECP384R1_KEY *key,
	const uint8_t *dgst, size_t dgstlen, SECP384R1_ECDSA_SIGNATURE *sig)
{
	secp384r1_t k;

	// rand k in [1, n-1]
	do {
		if (rand_bytes((uint8_t *)k, sizeof(k)) != 1) {
			error_print();
			return -1;
		}
	} while (secp384r1_is_zero(k) || secp384r1_cmp(k, SECP384R1_N) >= 0);

	if (secp384r1_ecdsa_do_sign_ex(key, k, dgst, dgstlen, sig) != 1) {
		error_print();
		return -1;
	}
	return 1;
}


int secp384r1_ecdsa_do_verify(const SECP384R1_KEY *key,
	const uint8_t *dgst, size_t dgstlen, const SECP384R1_ECDSA_SIGNATURE *sig)
{
	secp384r1_t e;
	secp384r1_t w;
	secp384r1_t u1;
	secp384r1_t u2;
	secp384r1_t x1;
	secp384r1_t y1;
	SECP384R1_POINT P;
	SECP384R1_POINT Q;
	SECP384R1_POINT R;

	// check r, s in [1, n-1]
	if (secp384r1_is_zero(sig->r)
		|| secp384r1_cmp(sig->r, SECP384R1_N) >= 0
		|| secp384r1_is_zero(sig->s)
		|| secp384r1_cmp(sig->s, SECP384R1_N) >= 0) {
		error_print();
		return -1;
	}

	// e = hash(m)
	if (secp384r1_ecdsa_digest_to_e(e, dgst, dgstlen) != 1) {
		error_print();
		return -1;
	}

	// w = s^-1 (mod n)
	if (secp384r1_modn_inv(w, sig->s) != 1) {
		error_print();
		return -1;
	}

	// u1 = e * w (mod n)
	if (secp384r1_modn_mul(u1, e, w) != 1) {
		error_print();
		return -1;
	}

	// u2 = r * w (mod n)
	if (secp384r1_modn_mul(u2, sig->r, w) != 1) {
		error_print();
		return -1;
	}

	// (x1, y1) = u1*G + u2*Q
	if (secp384r1_point_mul_generator(&P, u1) != 1
		|| secp384r1_point_mul(&Q, u2, &key->public_key) != 1
		|| secp384r1_point_add(&R, &P, &Q) != 1) {
		error_print();
		return -1;
	}
	if (secp384r1_point_get_xy(&R, x1, y1) != 1) {
		return 0;
	}

	// x1 = x1 mod n
	if (secp384r1_modn(x1, x1) != 1) {
		error_print();
		return -1;
	}

	if (secp384r1_cmp(x1, sig->r) != 0) {
		return 0;
	}
	return 1;
}

int secp384r1_ecdsa_signature_to_der(const SECP384R1_ECDSA_SIGNATURE *sig, uint8_t **out, size_t *outlen)
{
	size_t len = 0;
	uint8_t r[48];
	uint8_t s[48];

	if (!sig) {
		return 0;
	}

	if (secp384r1_to_48bytes(sig->r, r) != 1
		|| secp384r1_to_48bytes(sig->s, s) != 1) {
		error_print();
		return -1;
	}

	if (asn1_integer_to_der(r, 48, NULL, &len) != 1
		|| asn1_integer_to_der(s, 48, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_integer_to_der(r, 48, out, outlen) != 1
		|| asn1_integer_to_der(s, 48, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp384r1_ecdsa_signature_from_der(SECP384R1_ECDSA_SIGNATURE *sig, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	const uint8_t *r;
	const uint8_t *s;
	uint8_t rbuf[48] = {0};
	uint8_t sbuf[48] = {0};
	size_t dlen, rlen, slen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_integer_from_der(&r, &rlen, &d, &dlen) != 1
		|| asn1_integer_from_der(&s, &slen, &d, &dlen) != 1
		|| asn1_length_le(rlen, 48) != 1
		|| asn1_length_le(slen, 48) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}

	memcpy(rbuf + sizeof(rbuf) - rlen, r, rlen);
	memcpy(sbuf + sizeof(sbuf) - slen, s, slen);
	if (secp384r1_from_48bytes(sig->r, rbuf) != 1
		|| secp384r1_from_48bytes(sig->s, sbuf) != 1) {
		error_print();
		return -1;
	}

	return 1;
}

int secp384r1_ecdsa_sign(const SECP384R1_KEY *key,
	const uint8_t *dgst, size_t dgstlen, uint8_t *sigbuf, size_t *siglen)
{
	SECP384R1_ECDSA_SIGNATURE sig;

	if (secp384r1_ecdsa_do_sign(key, dgst, dgstlen, &sig) != 1) {
		error_print();
		return -1;
	}
	*siglen = 0;
	if (secp384r1_ecdsa_signature_to_der(&sig, &sigbuf, siglen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp384r1_ecdsa_sign_fixlen(const SECP384R1_KEY *key,
	const uint8_t *dgst, size_t dgstlen, size_t siglen, uint8_t *sig)
{
	unsigned int trys = 200;
	uint8_t buf[SECP384R1_ECDSA_SIGNATURE_MAX_SIZE];
	size_t len;

	switch (siglen) {
	case SECP384R1_ECDSA_SIGNATURE_COMPACT_SIZE:
	case SECP384R1_ECDSA_SIGNATURE_TYPICAL_SIZE:
	case SECP384R1_ECDSA_SIGNATURE_MAX_SIZE:
		break;
	default:
		error_print();
		return -1;
	}

	while (trys--) {
		if (secp384r1_ecdsa_sign(key, dgst, dgstlen, buf, &len) != 1) {
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


int secp384r1_ecdsa_verify(const SECP384R1_KEY *key,
	const uint8_t *dgst, size_t dgstlen, const uint8_t *sigbuf, size_t siglen)
{
	int ret;
	SECP384R1_ECDSA_SIGNATURE sig;

	if (secp384r1_ecdsa_signature_from_der(&sig, &sigbuf, &siglen) != 1) {
		error_print();
		return -1;
	}
	if (siglen) {
		error_print();
		return -1;
	}
	if ((ret = secp384r1_ecdsa_do_verify(key, dgst, dgstlen, &sig)) < 0) {
		error_print();
		return -1;
	}
	return ret;
}

int secp384r1_ecdsa_sign_init(SECP384R1_ECDSA_SIGN_CTX *ctx, const SECP384R1_KEY *key, const DIGEST *digest)
{
	if (!ctx || !key) {
		error_print();
		return -1;
	}
	if (!digest) {
		digest = DIGEST_sha384();
	}
	memset(ctx, 0, sizeof(SECP384R1_ECDSA_SIGN_CTX));

	ctx->key = *key;

	if (digest_init(&ctx->digest_ctx, digest) != 1) {
		error_print();
		return -1;
	}

	return 1;
}

int secp384r1_ecdsa_sign_update(SECP384R1_ECDSA_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	if (digest_update(&ctx->digest_ctx, data, datalen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp384r1_ecdsa_sign_finish(SECP384R1_ECDSA_SIGN_CTX *ctx, uint8_t *sig, size_t *siglen)
{
	uint8_t dgst[DIGEST_MAX_SIZE];
	size_t dgstlen;

	if (!ctx || !sig || !siglen) {
		error_print();
		return -1;
	}

	if (digest_finish(&ctx->digest_ctx, dgst, &dgstlen) != 1) {
		error_print();
		return -1;
	}

	if (secp384r1_ecdsa_sign(&ctx->key, dgst, dgstlen, sig, siglen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int secp384r1_ecdsa_sign_finish_fixlen(SECP384R1_ECDSA_SIGN_CTX *ctx, size_t siglen, uint8_t *sig)
{
	uint8_t dgst[DIGEST_MAX_SIZE];
	size_t dgstlen;

	if (!ctx || !sig || !siglen) {
		error_print();
		return -1;
	}

	if (digest_finish(&ctx->digest_ctx, dgst, &dgstlen) != 1) {
		error_print();
		return -1;
	}

	if (secp384r1_ecdsa_sign_fixlen(&ctx->key, dgst, dgstlen, siglen, sig) != 1) {
		error_print();
		return -1;
	}
	return 1;
}






int secp384r1_ecdsa_verify_init(SECP384R1_ECDSA_SIGN_CTX *ctx, const SECP384R1_KEY *key, const DIGEST *digest,
	const uint8_t *sig, size_t siglen)
{
	if (!ctx || !key || !sig || !siglen) {
		error_print();
		return -1;
	}

	if (secp384r1_ecdsa_signature_from_der(&ctx->sig, &sig, &siglen) != 1) {
		error_print();
		return -1;
	}
	if (siglen) {
		error_print();
		return -1;
	}

	ctx->key = *key;

	if (!digest) {
		digest = DIGEST_sha384();
	}
	if (digest_init(&ctx->digest_ctx, digest) != 1) {
		error_print();
		return -1;
	}

	return 1;
}


int secp384r1_ecdsa_verify_update(SECP384R1_ECDSA_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	if (digest_update(&ctx->digest_ctx, data, datalen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}


int secp384r1_ecdsa_verify_finish(SECP384R1_ECDSA_SIGN_CTX *ctx)
{
	uint8_t dgst[DIGEST_MAX_SIZE];
	size_t dgstlen;
	int ret;

	if (!ctx) {
		error_print();
		return -1;
	}

	if (digest_finish(&ctx->digest_ctx, dgst, &dgstlen) != 1) {
		error_print();
		return -1;
	}

	if ((ret = secp384r1_ecdsa_do_verify(&ctx->key, dgst, dgstlen, &ctx->sig)) < 0) {
		error_print();
		return -1;
	}
	return ret;
}
