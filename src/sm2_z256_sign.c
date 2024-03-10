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


typedef SM2_Z256 SM2_U256;

#define sm2_u256_one()				sm2_z256_one()
#define sm2_u256_order()			sm2_z256_order()
#define sm2_u256_from_bytes(a,in)		sm2_z256_from_bytes(a,in)
#define sm2_u256_to_bytes(a,out)		sm2_z256_to_bytes(a,out)
#define sm2_u256_print(fp,fmt,ind,label,a)	sm2_z256_print(fp,fmt,ind,label,a)

#define sm2_u256_is_zero(a)			sm2_z256_is_zero(a)
#define sm2_u256_cmp(a,b)			sm2_z256_cmp(a,b)
#define sm2_u256_add(r,a,b)			sm2_z256_add(r,a,b)
#define sm2_u256_sub(r,a,b)			sm2_z256_sub(r,a,b)

#define sm2_u256_modn_add(r,a,b)		sm2_z256_modn_add(r,a,b)
#define sm2_u256_modn_sub(r,a,b)		sm2_z256_modn_sub(r,a,b)
#define sm2_u256_modn_mul(r,a,b)		sm2_z256_modn_mul(r,a,b)
#define sm2_u256_modn_inv(r,a)			sm2_z256_modn_inv(r,a)
#define sm2_u256_modn_rand(r)			sm2_z256_modn_rand(r)


typedef SM2_Z256_POINT SM2_U256_POINT;

#define sm2_u256_point_from_bytes(P,in)		sm2_z256_point_from_bytes((P),(in))
#define sm2_u256_point_to_bytes(P,out)		sm2_z256_point_to_bytes((P),(out))
#define sm2_u256_point_is_on_curve(P)		sm2_z256_point_is_on_curve(P)
#define sm2_u256_point_mul_generator(R,k)	sm2_z256_point_mul_generator((R),(k))
#define sm2_u256_point_mul(R,k,P)		sm2_z256_point_mul((R),(k),(P))
#define sm2_u256_point_mul_sum(R,t,P,s)		sm2_z256_point_mul_sum((R),(t),(P),(s))
#define sm2_u256_point_get_xy(P,x,y)		sm2_z256_point_get_xy((P),(x),(y))


int sm2_do_sign(const SM2_KEY *key, const uint8_t dgst[32], SM2_SIGNATURE *sig)
{
	SM2_U256_POINT _P, *P = &_P;
	SM2_U256 d;
	SM2_U256 d_inv;
	SM2_U256 e;
	SM2_U256 k;
	SM2_U256 x;
	SM2_U256 t;
	SM2_U256 r;
	SM2_U256 s;

	const uint64_t *one = sm2_u256_one();
	const uint64_t *order = sm2_u256_order();

	sm2_u256_from_bytes(d, key->private_key);

	// compute (d + 1)^-1 (mod n)
	sm2_u256_modn_add(d_inv, d, one);	//sm2_bn_print(stderr, 0, 4, "(1+d)", d_inv);
	if (sm2_u256_is_zero(d_inv)) {
		error_print();
		return -1;
	}
	sm2_u256_modn_inv(d_inv, d_inv);	//sm2_bn_print(stderr, 0, 4, "(1+d)^-1", d_inv);

	// e = H(M)
	sm2_u256_from_bytes(e, dgst);	//sm2_bn_print(stderr, 0, 4, "e", e);

retry:

	// >>>>>>>>>> BEGIN PRECOMP


	// rand k in [1, n - 1]
	do {
		if (sm2_u256_modn_rand(k) != 1) {
			error_print();
			return -1;
		}
	} while (sm2_u256_is_zero(k));	//sm2_bn_print(stderr, 0, 4, "k", k);

	// (x, y) = kG
	sm2_u256_point_mul_generator(P, k);
	sm2_u256_point_get_xy(P, x, NULL);
					//sm2_bn_print(stderr, 0, 4, "x", x);


	// 如果我们提前计算了 (k, x) 那么我们在真正做签名的时候就可以利用到这个与计算的表了，直接从表中读取 (k, x)
	// 当然这些计算都可以放在sign_fast里面

	// >>>>>>>>>>> END PRECOMP

	// r = e + x (mod n)
	if (sm2_u256_cmp(e, order) >= 0) {
		sm2_u256_sub(e, e, order);
	}
	if (sm2_u256_cmp(x, order) >= 0) {
		sm2_u256_sub(x, x, order);
	}
	sm2_u256_modn_add(r, e, x);		//sm2_bn_print(stderr, 0, 4, "r = e + x (mod n)", r);

	// if r == 0 or r + k == n re-generate k
	sm2_u256_add(t, r, k);
	if (sm2_u256_is_zero(r) || sm2_u256_cmp(t, order) == 0) {
					//sm2_bn_print(stderr, 0, 4, "r + k", t);
		goto retry;
	}

	// s = ((1 + d)^-1 * (k - r * d)) mod n
	sm2_u256_modn_mul(t, r, d);		//sm2_bn_print(stderr, 0, 4, "r*d", t);
	sm2_u256_modn_sub(k, k, t);		//sm2_bn_print(stderr, 0, 4, "k-r*d", k);
	sm2_u256_modn_mul(s, d_inv, k);	//sm2_bn_print(stderr, 0, 4, "s = ((1 + d)^-1 * (k - r * d)) mod n", s);

	// check s != 0
	if (sm2_u256_is_zero(s)) {
		goto retry;
	}

	sm2_u256_to_bytes(r, sig->r);	//sm2_bn_print_bn(stderr, 0, 4, "r", r);
	sm2_u256_to_bytes(s, sig->s);	//sm2_bn_print_bn(stderr, 0, 4, "s", s);

	gmssl_secure_clear(d, sizeof(d));
	gmssl_secure_clear(d_inv, sizeof(d_inv ));
	gmssl_secure_clear(k, sizeof(k));
	gmssl_secure_clear(t, sizeof(t));
	return 1;
}

// k 和 x1 都是要参与计算的，因此我们返回的是内部格式
int sm2_do_sign_pre_compute(uint64_t k[4], uint64_t x1[4])
{
	SM2_Z256_POINT P;

	// rand k in [1, n - 1]
	do {
		if (sm2_z256_modn_rand(k) != 1) {
			error_print();
			return -1;
		}
	} while (sm2_z256_is_zero(k));

	// (x1, y1) = kG
	sm2_u256_point_mul_generator(&P, k); // 这个函数要粗力度并行，这要怎么做？
	sm2_u256_point_get_xy(&P, x1, NULL);

	return 1;
}

// 实际上这里只有一次mod n的乘法，用barret就可以了
int sm2_do_sign_fast_ex(const uint64_t d[4], const uint64_t k[4], const uint64_t x1[4], const uint8_t dgst[32], SM2_SIGNATURE *sig)
{
	SM2_Z256_POINT R;
	uint64_t e[4];
	uint64_t r[4];
	uint64_t s[4];

	const uint64_t *order = sm2_z256_order();

	// e = H(M)
	sm2_z256_from_bytes(e, dgst);
	if (sm2_z256_cmp(e, order) >= 0) {
		sm2_z256_sub(e, e, order);
	}

	// r = e + x1 (mod n)
	sm2_z256_modn_add(r, e, x1);

	// s = (k + r) * d' - r
	sm2_z256_modn_add(s, k, r);
	sm2_z256_modn_mul(s, s, d);
	sm2_z256_modn_sub(s, s, r);

	sm2_u256_to_bytes(r, sig->r);
	sm2_u256_to_bytes(s, sig->s);

	return 1;
}


// (x1, y1) = k * G
// r = e + x1
// s = (k - r * d)/(1 + d) = (k +r - r * d - r)/(1 + d) = (k + r - r(1 +d))/(1 + d) = (k + r)/(1 + d) - r
//	= -r + (k + r)*(1 + d)^-1
//	= -r + (k + r) * d'

// 这个函数是我们真正要调用的，甚至可以替代原来的函数
int sm2_do_sign_fast(const uint64_t d[4], const uint8_t dgst[32], SM2_SIGNATURE *sig)
{
	SM2_U256_POINT R;
	SM2_U256 e;
	SM2_U256 k;
	SM2_U256 x1;
	SM2_U256 r;
	SM2_U256 s;

	const uint64_t *order = sm2_u256_order();

	// e = H(M)
	sm2_u256_from_bytes(e, dgst);
	if (sm2_u256_cmp(e, order) >= 0) {
		sm2_u256_sub(e, e, order);
	}

	/// <<<<<<<<<<<  这里的 (k, x1) 应该是从外部输入的！！，这样才是最快的。

	// rand k in [1, n - 1]
	do {
		if (sm2_u256_modn_rand(k) != 1) {
			error_print();
			return -1;
		}
	} while (sm2_u256_is_zero(k));

	// (x1, y1) = kG
	sm2_u256_point_mul_generator(&R, k); // 这个函数要粗力度并行，这要怎么做？
	sm2_u256_point_get_xy(&R, x1, NULL);

	/// >>>>>>>>>>>>>>>>>>

	// r = e + x1 (mod n)
	sm2_u256_modn_add(r, e, x1);

	// 对于快速实现来说，只需要一次乘法

	// 如果 (k, x) 是预计算的，这意味着我们可以并行这个操作
	// 也就是随机产生一些k，然后执行粗力度并行的点乘


	// s = (k + r) * d' - r
	sm2_u256_modn_add(s, k, r);
	sm2_u256_modn_mul(s, s, d);
	sm2_u256_modn_sub(s, s, r);

	sm2_u256_to_bytes(r, sig->r);
	sm2_u256_to_bytes(s, sig->s);
	return 1;
}

// 这个其实并没有更快，无非就是降低了解析公钥椭圆曲线点的计算量，这个点要转换为内部的Mont格式
// 这里根本没有modn的乘法
int sm2_do_verify_fast(const SM2_Z256_POINT *P, const uint8_t dgst[32], const SM2_SIGNATURE *sig)
{
	SM2_U256_POINT R;
	SM2_U256 r;
	SM2_U256 s;
	SM2_U256 e;
	SM2_U256 x;
	SM2_U256 t;

	const uint64_t *order = sm2_u256_order();

	sm2_u256_from_bytes(r, sig->r);
	// check r in [1, n-1]
	if (sm2_u256_is_zero(r) == 1) {
		error_print();
		return -1;
	}
	if (sm2_u256_cmp(r, order) >= 0) {
		error_print();
		return -1;
	}

	sm2_u256_from_bytes(s, sig->s);
	// check s in [1, n-1]
	if (sm2_u256_is_zero(s) == 1) {
		error_print();
		return -1;
	}
	if (sm2_u256_cmp(s, order) >= 0) {
		error_print();
		return -1;
	}

	// e = H(M)
	sm2_u256_from_bytes(e, dgst);

	// t = r + s (mod n), check t != 0
	sm2_u256_modn_add(t, r, s);
	if (sm2_u256_is_zero(t)) {
		error_print();
		return -1;
	}

	// Q = s * G + t * P
	sm2_u256_point_mul_sum(&R, t, P, s);
	sm2_u256_point_get_xy(&R, x, NULL);

	// r' = e + x (mod n)
	if (sm2_u256_cmp(e, order) >= 0) {
		sm2_u256_sub(e, e, order);
	}
	if (sm2_u256_cmp(x, order) >= 0) {
		sm2_u256_sub(x, x, order);
	}
	sm2_u256_modn_add(e, e, x);

	// check if r == r'
	if (sm2_u256_cmp(e, r) != 0) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_do_verify(const SM2_KEY *key, const uint8_t dgst[32], const SM2_SIGNATURE *sig)
{
	SM2_U256_POINT _P, *P = &_P;
	SM2_U256_POINT _R, *R = &_R;
	SM2_U256 r;
	SM2_U256 s;
	SM2_U256 e;
	SM2_U256 x;
	SM2_U256 t;

	const uint64_t *order = sm2_u256_order();

	sm2_u256_print(stderr, 0, 4, "n", order);

	// parse public key
	sm2_u256_point_from_bytes(P, (const uint8_t *)&key->public_key);
	//sm2_u256_point_from_bytes(P, (const uint8_t *)&key->public_key);
					//sm2_jacobian_point_print(stderr, 0, 4, "P", P);

	// parse signature values
	sm2_u256_from_bytes(r, sig->r);	sm2_u256_print(stderr, 0, 4, "r", r);
	sm2_u256_from_bytes(s, sig->s);	sm2_u256_print(stderr, 0, 4, "s", s);

	// check r, s in [1, n-1]
	if (sm2_u256_is_zero(r) == 1) {
		error_print();
		return -1;
	}
	if (sm2_u256_cmp(r, order) >= 0) {
		sm2_u256_print(stderr, 0, 4, "err: r", r);
		sm2_u256_print(stderr, 0, 4, "err: order", order);
		error_print();
		return -1;
	}
	if (sm2_u256_is_zero(s) == 1) {
		error_print();
		return -1;
	}
	if (sm2_u256_cmp(s, order) >= 0) {

		sm2_u256_print(stderr, 0, 4, "err: s", s);
		sm2_u256_print(stderr, 0, 4, "err: order", order);

		printf(">>>>>\n");
		int r = sm2_u256_cmp(s, order);
		fprintf(stderr, "cmp ret = %d\n", r);
		printf(">>>>>\n");

		error_print();
		return -1;
	}

	// e = H(M)
	sm2_u256_from_bytes(e, dgst);	//sm2_bn_print(stderr, 0, 4, "e = H(M)", e);

	// t = r + s (mod n), check t != 0
	sm2_u256_modn_add(t, r, s);		//sm2_bn_print(stderr, 0, 4, "t = r + s (mod n)", t);
	if (sm2_u256_is_zero(t)) {
		error_print();
		return -1;
	}

	// Q = s * G + t * P
	sm2_u256_point_mul_sum(R, t, P, s);
	sm2_u256_point_get_xy(R, x, NULL);
					//sm2_bn_print(stderr, 0, 4, "x", x);

	// r' = e + x (mod n)
	if (sm2_u256_cmp(e, order) >= 0) {
		sm2_u256_sub(e, e, order);
	}
	if (sm2_u256_cmp(x, order) >= 0) {
		sm2_u256_sub(x, x, order);
	}
	sm2_u256_modn_add(e, e, x);		//sm2_bn_print(stderr, 0, 4, "e + x (mod n)", e);

	// check if r == r'
	if (sm2_u256_cmp(e, r) != 0) {
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

int sm2_do_encrypt_pre_compute(uint64_t k[4], uint8_t C1[64])
{
	SM2_Z256_POINT P;

	// rand k in [1, n - 1]
	do {
		if (sm2_z256_modn_rand(k) != 1) {
			error_print();
			return -1;
		}
	} while (sm2_z256_is_zero(k));

	// output C1 = k * G = (x1, y1)
	sm2_z256_point_mul_generator(&P, k);
	sm2_z256_point_to_bytes(&P, C1);

	return 1;
}

// 和签名不一样，加密的时候要生成 (k, (x1, y1)) ，也就是y坐标也是需要的
// 其中k是要参与计算的，但是 (x1, y1) 不参与计算，输出为 bytes 就可以了
int sm2_do_encrypt(const SM2_KEY *key, const uint8_t *in, size_t inlen, SM2_CIPHERTEXT *out)
{
	SM2_U256 k;
	SM2_U256_POINT _P, *P = &_P;
	SM2_U256_POINT _C1, *C1 = &_C1;
	SM2_U256_POINT _kP, *kP = &_kP;
	uint8_t x2y2[64];
	SM3_CTX sm3_ctx;

	if (!(SM2_MIN_PLAINTEXT_SIZE <= inlen && inlen <= SM2_MAX_PLAINTEXT_SIZE)) {
		error_print();
		return -1;
	}

	sm2_u256_point_from_bytes(P, (uint8_t *)&key->public_key);

	// S = h * P, check S != O
	// for sm2 curve, h == 1 and S == P
	// SM2_POINT can not present point at infinity, do do nothing here

retry:
	// rand k in [1, n - 1]
	// TODO: set rand_bytes output for testing		
	do {
		if (sm2_u256_modn_rand(k) != 1) {
			error_print();
			return -1;
		}
	} while (sm2_u256_is_zero(k));	//sm2_bn_print(stderr, 0, 4, "k", k);

	// output C1 = k * G = (x1, y1)
	sm2_u256_point_mul_generator(C1, k);
	sm2_u256_point_to_bytes(C1, (uint8_t *)&out->point);

	// k * P = (x2, y2)
	sm2_u256_point_mul(kP, k, P);
	sm2_u256_point_to_bytes(kP, x2y2);

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
	gmssl_secure_clear(kP, sizeof(SM2_U256_POINT));
	gmssl_secure_clear(x2y2, sizeof(x2y2));
	return 1;
}

int sm2_do_encrypt_fixlen(const SM2_KEY *key, const uint8_t *in, size_t inlen, int point_size, SM2_CIPHERTEXT *out)
{
	unsigned int trys = 200;
	SM2_U256 k;
	SM2_U256_POINT _P, *P = &_P;
	SM2_U256_POINT _C1, *C1 = &_C1;
	SM2_U256_POINT _kP, *kP = &_kP;
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

	sm2_u256_point_from_bytes(P, (uint8_t *)&key->public_key);

	// S = h * P, check S != O
	// for sm2 curve, h == 1 and S == P
	// SM2_POINT can not present point at infinity, do do nothing here

retry:
	// rand k in [1, n - 1]
	do {
		if (sm2_u256_modn_rand(k) != 1) {
			error_print();
			return -1;
		}
	} while (sm2_u256_is_zero(k));	//sm2_bn_print(stderr, 0, 4, "k", k);

	// output C1 = k * G = (x1, y1)
	sm2_u256_point_mul_generator(C1, k);
	sm2_u256_point_to_bytes(C1, (uint8_t *)&out->point);

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
	sm2_u256_point_mul(kP, k, P);
	sm2_u256_point_to_bytes(kP, x2y2);

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
	gmssl_secure_clear(kP, sizeof(SM2_U256_POINT));
	gmssl_secure_clear(x2y2, sizeof(x2y2));
	return 1;
}

int sm2_do_decrypt(const SM2_KEY *key, const SM2_CIPHERTEXT *in, uint8_t *out, size_t *outlen)
{
	int ret = -1;
	SM2_U256 d;
	SM2_U256_POINT _C1, *C1 = &_C1;
	uint8_t x2y2[64];
	SM3_CTX sm3_ctx;
	uint8_t hash[32];

	// check C1 is on sm2 curve
	sm2_u256_point_from_bytes(C1, (uint8_t *)&in->point);
	if (!sm2_u256_point_is_on_curve(C1)) {
		error_print();
		return -1;
	}

	// check if S = h * C1 is point at infinity
	// this will not happen, as SM2_POINT can not present point at infinity

	// d * C1 = (x2, y2)
	sm2_u256_from_bytes(d, key->private_key);
	sm2_u256_point_mul(C1, d, C1);

	// t = KDF(x2 || y2, klen) and check t is not all zeros
	sm2_u256_point_to_bytes(C1, x2y2);
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
	gmssl_secure_clear(C1, sizeof(SM2_U256_POINT));
	gmssl_secure_clear(x2y2, sizeof(x2y2));
	return ret;
}
