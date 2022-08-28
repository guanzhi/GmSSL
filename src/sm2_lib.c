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
#include <gmssl/mem.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/asn1.h>
#include <gmssl/error.h>
#include <gmssl/endian.h>

#define print_bn(str,a) sm2_bn_print(stderr,0,4,str,a)

int sm2_do_sign_ex(const SM2_KEY *key, int fixed_outlen, const uint8_t dgst[32], SM2_SIGNATURE *sig)
{
	SM2_JACOBIAN_POINT _P, *P = &_P;
	SM2_BN d;
	SM2_BN e;
	SM2_BN k;
	SM2_BN x;
	SM2_BN r;
	SM2_BN s;

retry:
	sm2_bn_from_bytes(d, key->private_key);

	// e = H(M)
	sm2_bn_from_bytes(e, dgst);	//print_bn("e", e);
					// e被重用了，注意retry的位置！

	// rand k in [1, n - 1]
	do {
		sm2_fn_rand(k);
	} while (sm2_bn_is_zero(k));
					//print_bn("k", k);

	// (x, y) = kG
	sm2_jacobian_point_mul_generator(P, k);
	sm2_jacobian_point_get_xy(P, x, NULL);
					//print_bn("x", x);


	// r = e + x (mod n)
	sm2_fn_add(r, e, x);		//print_bn("r = e + x (mod n)", r);

	/* if r == 0 or r + k == n re-generate k */
	if (sm2_bn_is_zero(r)) {
		goto retry;
	}
	sm2_bn_add(x, r, k);
	if (sm2_bn_cmp(x, SM2_N) == 0) {
		goto retry;
	}

	/* s = ((1 + d)^-1 * (k - r * d)) mod n */

	sm2_fn_mul(e, r, d);		//print_bn("r*d", e);
	sm2_fn_sub(k, k, e);		//print_bn("k-r*d", k);
	sm2_fn_add(e, SM2_ONE, d);	//print_bn("1 +d", e);
	sm2_fn_inv(e, e);		//print_bn("(1+d)^-1", e);
	sm2_fn_mul(s, e, k);		//print_bn("s = ((1 + d)^-1 * (k - r * d)) mod n", s);

	sm2_bn_to_bytes(r, sig->r);	//print_bn("r", r);
	sm2_bn_to_bytes(s, sig->s);	//print_bn("s", s);

	if (fixed_outlen) {
		uint8_t buf[72];
		uint8_t *p = buf;
		size_t len = 0;
		sm2_signature_to_der(sig, &p, &len);
		if (len != 71) {
			goto retry;
		}
	}

	gmssl_secure_clear(d, sizeof(d));
	gmssl_secure_clear(e, sizeof(e));
	gmssl_secure_clear(k, sizeof(k));
	gmssl_secure_clear(x, sizeof(x));
	return 1;
}

int sm2_do_sign(const SM2_KEY *key, const uint8_t dgst[32], SM2_SIGNATURE *sig)
{
	return sm2_do_sign_ex(key, 0, dgst, sig);
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

	// parse signature values
	sm2_bn_from_bytes(r, sig->r);	//print_bn("r", r);
	sm2_bn_from_bytes(s, sig->s);	//print_bn("s", s);
	if (sm2_bn_is_zero(r) == 1
		|| sm2_bn_cmp(r, SM2_N) >= 0
		|| sm2_bn_is_zero(s) == 1
		|| sm2_bn_cmp(s, SM2_N) >= 0) {
		error_print();
		return -1;
	}

	// parse public key
	sm2_jacobian_point_from_bytes(P, (const uint8_t *)&key->public_key);
					//print_point("P", P);

	// t = r + s (mod n)
	// check t != 0
	sm2_fn_add(t, r, s);		//print_bn("t = r + s (mod n)", t);
	if (sm2_bn_is_zero(t)) {
		error_print();
		return -1;
	}

	// Q = s * G + t * P
	sm2_jacobian_point_mul_sum(R, t, P, s);
	sm2_jacobian_point_get_xy(R, x, NULL);
					//print_bn("x", x);

	// e  = H(M)
	// r' = e + x (mod n)
	sm2_bn_from_bytes(e, dgst);	//print_bn("e = H(M)", e);
	sm2_fn_add(e, e, x);		//print_bn("e + x (mod n)", e);


	// check if r == r'
	if (sm2_bn_cmp(e, r) != 0) {
		return 0;
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
	memcpy(sig->r + 32 - rlen, r, rlen); // 需要测试当r, s是比较小的整数时
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

#define SM2_SIGNATURE_MAX_DER_SIZE 77

int sm2_sign_ex(const SM2_KEY *key, int fixed_outlen, const uint8_t dgst[32], uint8_t *sig, size_t *siglen)
{
	SM2_SIGNATURE signature;
	uint8_t *p;

	if (!key
		|| !dgst
		|| !sig
		|| !siglen) {
		error_print();
		return -1;
	}

	p = sig;
	*siglen = 0;
	if (sm2_do_sign_ex(key, fixed_outlen, dgst, &signature) != 1
		|| sm2_signature_to_der(&signature, &p, siglen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_sign(const SM2_KEY *key, const uint8_t dgst[32], uint8_t *sig, size_t *siglen)
{
	return sm2_sign_ex(key, 0, dgst, sig, siglen);
}

int sm2_verify(const SM2_KEY *key, const uint8_t dgst[32], const uint8_t *sig, size_t siglen)
{
	int ret;
	SM2_SIGNATURE signature;
	const uint8_t *p;
	size_t len;

	if (!key
		|| !dgst
		|| !sig
		|| !siglen) {
		error_print();
		return -1;
	}

	p = sig;
	if (sm2_signature_from_der(&signature, &p, &siglen) != 1
		|| asn1_length_is_zero(siglen) != 1) {
		error_print();
		return -1;
	}
	if ((ret = sm2_do_verify(key, dgst, &signature)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	return 1;
}

extern void sm3_compress_blocks(uint32_t digest[8], const uint8_t *data, size_t blocks);

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
	int ret;
	uint8_t dgst[SM3_DIGEST_SIZE];

	if (!ctx || !sig || !siglen) {
		error_print();
		return -1;
	}
	sm3_finish(&ctx->sm3_ctx, dgst);
	if ((ret = sm2_sign(&ctx->key, dgst, sig, siglen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	return 1;
}

int sm2_verify_init(SM2_SIGN_CTX *ctx, const SM2_KEY *key, const char *id, size_t idlen)
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
	int ret;
	uint8_t dgst[SM3_DIGEST_SIZE];

	if (!ctx || !sig) {
		error_print();
		return -1;
	}
	sm3_finish(&ctx->sm3_ctx, dgst);
	if ((ret = sm2_verify(&ctx->key, dgst, sig, siglen)) != 1) {
		if (ret < 0) error_print();
		return ret;
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

int sm2_do_encrypt_ex(const SM2_KEY *key, int fixed_outlen, const uint8_t *in, size_t inlen, SM2_CIPHERTEXT *out)
{
	SM2_BN k;
	SM2_JACOBIAN_POINT _P, *P = &_P;
	SM3_CTX sm3_ctx;
	uint8_t buf[64];
	int i;

retry:
	// rand k in [1, n - 1]
	sm2_bn_rand_range(k, SM2_N);
	if (sm2_bn_is_zero(k)) goto retry;

	// C1 = k * G = (x1, y1)
	sm2_jacobian_point_mul_generator(P, k);
	sm2_jacobian_point_to_bytes(P, (uint8_t *)&out->point);

	if (fixed_outlen) {
		size_t xlen = 0, ylen = 0;
		asn1_integer_to_der(out->point.x, 32, NULL, &xlen);
		if (xlen != 34) goto retry;
		asn1_integer_to_der(out->point.y, 32, NULL, &ylen);
		if (ylen != 34) goto retry;
	}

	// Q = k * P = (x2, y2)
	sm2_jacobian_point_from_bytes(P, (uint8_t *)&key->public_key);

	sm2_jacobian_point_mul(P, k, P);

	sm2_jacobian_point_to_bytes(P, buf);


	// t = KDF(x2 || y2, klen)
	sm2_kdf(buf, sizeof(buf), inlen, out->ciphertext);


	// C2 = M xor t
	for (i = 0; i < inlen; i++) {
		out->ciphertext[i] ^= in[i];
	}
	out->ciphertext_size = (uint32_t)inlen;

	// C3 = Hash(x2 || m || y2)
	sm3_init(&sm3_ctx);
	sm3_update(&sm3_ctx, buf, 32);
	sm3_update(&sm3_ctx, in, inlen);
	sm3_update(&sm3_ctx, buf + 32, 32);
	sm3_finish(&sm3_ctx, out->hash);

	return 1;
}

int sm2_do_encrypt(const SM2_KEY *key, const uint8_t *in, size_t inlen, SM2_CIPHERTEXT *out)
{
	return sm2_do_encrypt_ex(key, 0, in, inlen, out);
}

int sm2_do_decrypt(const SM2_KEY *key, const SM2_CIPHERTEXT *in, uint8_t *out, size_t *outlen)
{
	uint32_t inlen;
	SM2_BN d;
	SM2_JACOBIAN_POINT _P, *P = &_P;
	SM3_CTX sm3_ctx;
	uint8_t buf[64];
	uint8_t hash[32];
	int i;

	// FIXME: check SM2_CIPHERTEXT format

	// check C1
	sm2_jacobian_point_from_bytes(P, (uint8_t *)&in->point);
	//point_print(stdout, P, 0, 2);

	/*
	if (!sm2_jacobian_point_is_on_curve(P)) {
		fprintf(stderr, "%s %d: invalid ciphertext\n", __FILE__, __LINE__);
		return -1;
	}
	*/

	// d * C1 = (x2, y2)
	sm2_bn_from_bytes(d, key->private_key);
	sm2_jacobian_point_mul(P, d, P);
	sm2_bn_clean(d);
	sm2_jacobian_point_to_bytes(P, buf);

	// t = KDF(x2 || y2, klen)
	if ((inlen = in->ciphertext_size) <= 0) {
		fprintf(stderr, "%s %d: invalid ciphertext\n", __FILE__, __LINE__);
		return -1;
	}

	sm2_kdf(buf, sizeof(buf), inlen, out);

	// M = C2 xor t
	for (i = 0; i < inlen; i++) {
		out[i] ^= in->ciphertext[i];
	}
	*outlen = inlen;

	// u = Hash(x2 || M || y2)
	sm3_init(&sm3_ctx);
	sm3_update(&sm3_ctx, buf, 32);
	sm3_update(&sm3_ctx, out, inlen);
	sm3_update(&sm3_ctx, buf + 32, 32);
	sm3_finish(&sm3_ctx, hash);

	// check if u == C3
	if (memcmp(in->hash, hash, sizeof(hash)) != 0) {
		fprintf(stderr, "%s %d: invalid ciphertext\n", __FILE__, __LINE__);
		return -1;
	}

	return 1;
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
		|| asn1_integer_from_der(&y, &ylen, &d, &dlen) != 1
		|| asn1_octet_string_from_der(&hash, &hashlen, &d, &dlen) != 1
		|| asn1_octet_string_from_der(&c, &clen, &d, &dlen) != 1
		|| asn1_length_le(xlen, 32) != 1
		|| asn1_length_le(ylen, 32) != 1
		|| asn1_check(hashlen == 32) != 1
		|| asn1_length_le(clen, SM2_MAX_PLAINTEXT_SIZE) != 1
		|| asn1_length_is_zero(dlen) != 1) {
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
	int i;

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

int sm2_encrypt_ex(const SM2_KEY *key, int fixed_outlen, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	SM2_CIPHERTEXT C;

	if (!key || !in || !out || !outlen) {
		error_print();
		return -1;
	}
	if (inlen < SM2_MIN_PLAINTEXT_SIZE || inlen > SM2_MAX_PLAINTEXT_SIZE) {
		error_print();
		return -1;
	}
	if (sm2_do_encrypt_ex(key, fixed_outlen, in, inlen, &C) != 1) {
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

int sm2_encrypt(const SM2_KEY *key, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	return sm2_encrypt_ex(key, 0, in, inlen, out, outlen);
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

int sm2_ecdh(const SM2_KEY *key, const SM2_POINT *peer_public, SM2_POINT *out)
{
	if (!key || !peer_public || !out) {
		error_print();
		return -1;
	}
	if (sm2_point_mul(out, key->private_key, peer_public) != 1) {
		error_print();
		return -1;
	}
	return 1;
}
