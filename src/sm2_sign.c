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
#include <gmssl/sm2_z256.h>
#include <gmssl/sm3.h>
#include <gmssl/asn1.h>
#include <gmssl/error.h>
#include <gmssl/endian.h>


int sm2_do_sign(const SM2_KEY *key, const uint8_t dgst[32], SM2_SIGNATURE *sig)
{
	SM2_Z256_POINT P;
	sm2_z256_t d;
	sm2_z256_t d_inv;
	sm2_z256_t e;
	sm2_z256_t k;
	sm2_z256_t x;
	sm2_z256_t t;
	sm2_z256_t r;
	sm2_z256_t s;

	sm2_z256_from_bytes(d, key->private_key);

	// compute (d + 1)^-1 (mod n)
	sm2_z256_modn_add(d_inv, d, sm2_z256_one());
	if (sm2_z256_is_zero(d_inv)) {
		error_print();
		return -1;
	}
	sm2_z256_modn_inv(d_inv, d_inv);

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
	sm2_z256_modn_mul(t, r, d);
	sm2_z256_modn_sub(k, k, t);
	sm2_z256_modn_mul(s, d_inv, k);

	// check s != 0
	if (sm2_z256_is_zero(s)) {
		goto retry;
	}

	sm2_z256_to_bytes(r, sig->r);
	sm2_z256_to_bytes(s, sig->s);

	gmssl_secure_clear(d, sizeof(d));
	gmssl_secure_clear(d_inv, sizeof(d_inv));
	gmssl_secure_clear(k, sizeof(k));
	gmssl_secure_clear(t, sizeof(t));
	return 1;
}

int sm2_do_sign_pre_compute(uint64_t k[4], uint64_t x1[4])
{
	SM2_Z256_POINT P;

	// rand k in [1, n - 1]
	do {
		if (sm2_z256_rand_range(k, sm2_z256_order()) != 1) {
			error_print();
			return -1;
		}
	} while (sm2_z256_is_zero(k));

	// (x1, y1) = kG
	sm2_z256_point_mul_generator(&P, k);
	sm2_z256_point_get_xy(&P, x1, NULL);

	return 1;
}

int sm2_do_sign_fast_ex(const uint64_t d[4], const uint64_t k[4], const uint64_t x1[4], const uint8_t dgst[32], SM2_SIGNATURE *sig)
{
	SM2_Z256_POINT R;
	sm2_z256_t e;
	sm2_z256_t r;
	sm2_z256_t s;

	// e = H(M)
	sm2_z256_from_bytes(e, dgst);
	if (sm2_z256_cmp(e, sm2_z256_order()) >= 0) {
		sm2_z256_sub(e, e, sm2_z256_order());
	}

	// r = e + x1 (mod n)
	sm2_z256_modn_add(r, e, x1);

	// s = (k + r) * d' - r
	sm2_z256_modn_add(s, k, r);
	sm2_z256_modn_mul(s, s, d);
	sm2_z256_modn_sub(s, s, r);

	sm2_z256_to_bytes(r, sig->r);
	sm2_z256_to_bytes(s, sig->s);

	return 1;
}


// (x1, y1) = k * G
// r = e + x1
// s = (k - r * d)/(1 + d) = (k +r - r * d - r)/(1 + d) = (k + r - r(1 +d))/(1 + d) = (k + r)/(1 + d) - r
//	= -r + (k + r)*(1 + d)^-1
//	= -r + (k + r) * d'
int sm2_do_sign_fast(const uint64_t d[4], const uint8_t dgst[32], SM2_SIGNATURE *sig)
{
	SM2_Z256_POINT R;
	sm2_z256_t e;
	sm2_z256_t k;
	sm2_z256_t x1;
	sm2_z256_t r;
	sm2_z256_t s;

	const uint64_t *order = sm2_z256_order();

	// e = H(M)
	sm2_z256_from_bytes(e, dgst);
	if (sm2_z256_cmp(e, order) >= 0) {
		sm2_z256_sub(e, e, order);
	}

	/// <<<<<<<<<<<  这里的 (k, x1) 应该是从外部输入的！！，这样才是最快的。

	// rand k in [1, n - 1]
	do {
		if (sm2_z256_rand_range(k, sm2_z256_order()) != 1) {
			error_print();
			return -1;
		}
	} while (sm2_z256_is_zero(k));

	// (x1, y1) = kG
	sm2_z256_point_mul_generator(&R, k); // 这个函数要粗力度并行，这要怎么做？
	sm2_z256_point_get_xy(&R, x1, NULL);

	/// >>>>>>>>>>>>>>>>>>

	// r = e + x1 (mod n)
	sm2_z256_modn_add(r, e, x1);

	// 对于快速实现来说，只需要一次乘法

	// 如果 (k, x) 是预计算的，这意味着我们可以并行这个操作
	// 也就是随机产生一些k，然后执行粗力度并行的点乘


	// s = (k + r) * d' - r
	sm2_z256_modn_add(s, k, r);
	sm2_z256_modn_mul(s, s, d);
	sm2_z256_modn_sub(s, s, r);

	sm2_z256_to_bytes(r, sig->r);
	sm2_z256_to_bytes(s, sig->s);
	return 1;
}

// 这个其实并没有更快，无非就是降低了解析公钥椭圆曲线点的计算量，这个点要转换为内部的Mont格式
// 这里根本没有modn的乘法
int sm2_do_verify_fast(const SM2_Z256_POINT *P, const uint8_t dgst[32], const SM2_SIGNATURE *sig)
{
	SM2_Z256_POINT R;
	sm2_z256_t r;
	sm2_z256_t s;
	sm2_z256_t e;
	sm2_z256_t x;
	sm2_z256_t t;

	const uint64_t *order = sm2_z256_order();

	sm2_z256_from_bytes(r, sig->r);
	// check r in [1, n-1]
	if (sm2_z256_is_zero(r) == 1) {
		error_print();
		return -1;
	}
	if (sm2_z256_cmp(r, order) >= 0) {
		error_print();
		return -1;
	}

	sm2_z256_from_bytes(s, sig->s);
	// check s in [1, n-1]
	if (sm2_z256_is_zero(s) == 1) {
		error_print();
		return -1;
	}
	if (sm2_z256_cmp(s, order) >= 0) {
		error_print();
		return -1;
	}

	// e = H(M)
	sm2_z256_from_bytes(e, dgst);

	// t = r + s (mod n), check t != 0
	sm2_z256_modn_add(t, r, s);
	if (sm2_z256_is_zero(t)) {
		error_print();
		return -1;
	}

	// Q = s * G + t * P
	sm2_z256_point_mul_sum(&R, t, P, s);
	sm2_z256_point_get_xy(&R, x, NULL);

	// r' = e + x (mod n)
	if (sm2_z256_cmp(e, order) >= 0) {
		sm2_z256_sub(e, e, order);
	}
	if (sm2_z256_cmp(x, order) >= 0) {
		sm2_z256_sub(x, x, order);
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
	SM2_Z256_POINT _P, *P = &_P;
	SM2_Z256_POINT _R, *R = &_R;
	sm2_z256_t r;
	sm2_z256_t s;
	sm2_z256_t e;
	sm2_z256_t x;
	sm2_z256_t t;

	const uint64_t *order = sm2_z256_order();

	sm2_z256_print(stderr, 0, 4, "n", order);

	// parse public key
	sm2_z256_point_from_bytes(P, (const uint8_t *)&key->public_key);
	//sm2_z256_point_from_bytes(P, (const uint8_t *)&key->public_key);
					//sm2_jacobian_point_print(stderr, 0, 4, "P", P);

	// parse signature values
	sm2_z256_from_bytes(r, sig->r);	sm2_z256_print(stderr, 0, 4, "r", r);
	sm2_z256_from_bytes(s, sig->s);	sm2_z256_print(stderr, 0, 4, "s", s);

	// check r, s in [1, n-1]
	if (sm2_z256_is_zero(r) == 1) {
		error_print();
		return -1;
	}
	if (sm2_z256_cmp(r, order) >= 0) {
		sm2_z256_print(stderr, 0, 4, "err: r", r);
		sm2_z256_print(stderr, 0, 4, "err: order", order);
		error_print();
		return -1;
	}
	if (sm2_z256_is_zero(s) == 1) {
		error_print();
		return -1;
	}
	if (sm2_z256_cmp(s, order) >= 0) {

		sm2_z256_print(stderr, 0, 4, "err: s", s);
		sm2_z256_print(stderr, 0, 4, "err: order", order);

		printf(">>>>>\n");
		int r = sm2_z256_cmp(s, order);
		fprintf(stderr, "cmp ret = %d\n", r);
		printf(">>>>>\n");

		error_print();
		return -1;
	}

	// e = H(M)
	sm2_z256_from_bytes(e, dgst);	//sm2_bn_print(stderr, 0, 4, "e = H(M)", e);

	// t = r + s (mod n), check t != 0
	sm2_z256_modn_add(t, r, s);		//sm2_bn_print(stderr, 0, 4, "t = r + s (mod n)", t);
	if (sm2_z256_is_zero(t)) {
		error_print();
		return -1;
	}

	// Q = s * G + t * P
	sm2_z256_point_mul_sum(R, t, P, s);
	sm2_z256_point_get_xy(R, x, NULL);
					//sm2_bn_print(stderr, 0, 4, "x", x);

	// r' = e + x (mod n)
	if (sm2_z256_cmp(e, order) >= 0) {
		sm2_z256_sub(e, e, order);
	}
	if (sm2_z256_cmp(x, order) >= 0) {
		sm2_z256_sub(x, x, order);
	}
	sm2_z256_modn_add(e, e, x);		//sm2_bn_print(stderr, 0, 4, "e + x (mod n)", e);

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

int sm2_sign_init(SM2_SIGN_CTX *ctx, const SM2_KEY *key, const char *id, size_t idlen)
{
	size_t i;

	if (!ctx || !key) {
		error_print();
		return -1;
	}
	ctx->key = *key;

	// d' = (d + 1)^-1 (mod n)
	sm2_z256_from_bytes(ctx->sign_key, key->private_key);
	sm2_z256_modn_add(ctx->sign_key, ctx->sign_key, sm2_z256_one());
	sm2_z256_modn_inv(ctx->sign_key, ctx->sign_key);

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

	ctx->inited_sm3_ctx = ctx->sm3_ctx;

	// pre compute (k, x = [k]G.x)
	for (i = 0; i < 32; i++) {
		if (sm2_do_sign_pre_compute(ctx->pre_comp[i].k, ctx->pre_comp[i].x1) != 1) {
			error_print();
			return -1;
		}
	}
	ctx->num_pre_comp = 32;

	return 1;
}

int sm2_sign_ctx_reset(SM2_SIGN_CTX *ctx)
{
	ctx->sm3_ctx = ctx->inited_sm3_ctx;
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
		size_t i;
		for (i = 0; i < 32; i++) {
			if (sm2_do_sign_pre_compute(ctx->pre_comp[i].k, ctx->pre_comp[i].x1) != 1) {
				error_print();
				return -1;
			}
		}
		ctx->num_pre_comp = 32;
	}

	ctx->num_pre_comp--;
	if (sm2_do_sign_fast_ex(ctx->sign_key,
		ctx->pre_comp[ctx->num_pre_comp].k, ctx->pre_comp[ctx->num_pre_comp].x1,
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

int sm2_verify_init(SM2_SIGN_CTX *ctx, const SM2_KEY *key, const char *id, size_t idlen)
{
	if (!ctx || !key) {
		error_print();
		return -1;
	}
	memset(ctx, 0, sizeof(*ctx));
	ctx->key.public_key = key->public_key;

	sm2_z256_point_from_bytes((SM2_Z256_POINT *)&ctx->public_key, (const uint8_t *)&key->public_key);

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

	ctx->inited_sm3_ctx = ctx->sm3_ctx;

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
