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
#include <stdint.h>
#include <gmssl/sm3.h>
#include <gmssl/sm2.h>


#ifndef GMSSL_SM9_Z256_H
#define GMSSL_SM9_Z256_H

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t sm9_z256_t[4]; 

#define SM9_Z256_HEX_SEP '\n'

#define sm9_z256_init(r)		sm9_z256_set_zero(r)
#define sm9_z256_clean(r)		sm9_z256_set_zero(r)

void sm9_z256_to_bits(const sm9_z256_t a, char bits[256]);
int  sm9_z256_rand_range(sm9_z256_t r, const sm9_z256_t range);
void sm9_z256_from_bytes(sm9_z256_t r, const uint8_t in[32]);
void sm9_z256_to_bytes(const sm9_z256_t a, uint8_t out[32]);
void sm9_z256_copy(sm9_z256_t r, const sm9_z256_t a);
void sm9_z256_copy_conditional(sm9_z256_t dst, const sm9_z256_t src, uint64_t move);
void sm9_z256_set_zero(sm9_z256_t r);
int  sm9_z256_cmp(const sm9_z256_t a, const sm9_z256_t b);
void sm9_z256_mul(uint64_t r[8], const sm9_z256_t a, const sm9_z256_t b);
int  sm9_z256_from_hex(sm9_z256_t r, const char *hex);
void sm9_z256_to_hex(const sm9_z256_t r, char hex[64]);
int  sm9_z256_equ_hex(const sm9_z256_t a, const char *hex);
void sm9_z256_print_bn(const char *prefix, const sm9_z256_t a);
int  sm9_z256_print(FILE *fp, int ind, int fmt, const char *label, const sm9_z256_t a);
int  sm9_z512_print(FILE *fp, int ind, int fmt, const char *label, const uint64_t a[8]);
uint64_t sm9_z256_equ(const sm9_z256_t a, const sm9_z256_t b);
uint64_t sm9_z256_is_zero(const sm9_z256_t a);
uint64_t sm9_z256_add(sm9_z256_t r, const sm9_z256_t a, const sm9_z256_t b);
uint64_t sm9_z256_sub(sm9_z256_t r, const sm9_z256_t a, const sm9_z256_t b);
uint64_t sm9_z512_add(uint64_t r[8], const uint64_t a[8], const uint64_t b[8]);

extern const sm9_z256_t SM9_Z256_P;
extern const sm9_z256_t SM9_Z256_N;


#define sm9_z256_fp_copy(r,a)	sm9_z256_copy((r),(a))
#define sm9_z256_fp_rand(r)		sm9_z256_rand_range((r), SM9_Z256_P)
#define sm9_z256_fp_equ(a,b)	sm9_z256_equ((a),(b))
#define sm9_z256_fp_is_zero(a)	sm9_z256_is_zero(a)
#define sm9_z256_fp_set_zero(a)	sm9_z256_set_zero(a)

void sm9_z256_fp_add(sm9_z256_t r, const sm9_z256_t a, const sm9_z256_t b);
void sm9_z256_fp_sub(sm9_z256_t r, const sm9_z256_t a, const sm9_z256_t b);
void sm9_z256_fp_dbl(sm9_z256_t r, const sm9_z256_t a);
void sm9_z256_fp_tri(sm9_z256_t r, const sm9_z256_t a);
void sm9_z256_fp_div2(sm9_z256_t r, const sm9_z256_t a);
void sm9_z256_fp_neg(sm9_z256_t r, const sm9_z256_t a);
#define sm9_z256_fp_mul(r,a,b)	sm9_z256_fp_mont_mul(r,a,b)
void sm9_z256_fp_mont_mul(sm9_z256_t r, const sm9_z256_t a, const sm9_z256_t b);
void sm9_z256_fp_to_mont(sm9_z256_t r, const sm9_z256_t a);
void sm9_z256_fp_from_mont(sm9_z256_t r, const sm9_z256_t a);
#define sm9_z256_fp_sqr(r,a)	sm9_z256_fp_mont_sqr(r,a)
void sm9_z256_fp_mont_sqr(sm9_z256_t r, const sm9_z256_t a);
void sm9_z256_fp_pow(sm9_z256_t r, const sm9_z256_t a, const sm9_z256_t e);
void sm9_z256_fp_inv(sm9_z256_t r, const sm9_z256_t a);
int  sm9_z256_fp_from_bytes(sm9_z256_t r, const uint8_t buf[32]);
void sm9_z256_fp_to_bytes(const sm9_z256_t r, uint8_t out[32]);
int  sm9_z256_fp_from_hex(sm9_z256_t r, const char hex[64]);
void sm9_z256_fp_to_hex(const sm9_z256_t r, char hex[64]);


#define sm9_z256_fn_init(r)		sm9_z256_set_zero(r)
#define sm9_z256_fn_clean(r)	sm9_z256_set_zero(r)
#define sm9_z256_fn_set_zero(r)	sm9_z256_set_zero(r)
#define sm9_z256_fn_set_one(r)	sm9_z256_set_one(r)
#define sm9_z256_fn_copy(r,a)	sm9_z256_copy((r),(a))
#define sm9_z256_fn_rand(r)		sm9_z256_rand_range((r), SM9_Z256_N)
#define sm9_z256_fn_is_zero(a)	sm9_z256_is_zero(a)
#define sm9_z256_fn_is_one(a)	sm9_z256_is_one(a)
#define sm9_z256_fn_equ(a,b)	sm9_z256_equ((a),(b))
#define sm9_z256_fn_to_bytes(a,out)	sm9_z256_to_bytes((a),(out))
#define sm9_z256_fn_to_hex(a,s)	sm9_z256_to_hex((a),(s))
#define sm9_z256_fn_print(fp,fmt,ind,label,a) sm9_z256_print(fp,fmt,ind,label,a)

void sm9_z256_fn_add(sm9_z256_t r, const sm9_z256_t a, const sm9_z256_t b);
void sm9_z256_fn_sub(sm9_z256_t r, const sm9_z256_t a, const sm9_z256_t b);
void sm9_z256_fn_mul(sm9_z256_t r, const sm9_z256_t a, const sm9_z256_t b);
void sm9_z256_fn_pow(sm9_z256_t r, const sm9_z256_t a, const sm9_z256_t e);
void sm9_z256_fn_inv(sm9_z256_t r, const sm9_z256_t a);
void sm9_z256_fn_from_hash(sm9_z256_t h, const uint8_t Ha[40]);
int  sm9_z256_fn_from_bytes(sm9_z256_t a, const uint8_t in[32]);


typedef sm9_z256_t sm9_z256_fp2[2];
extern const sm9_z256_fp2 SM9_FP2_ZERO;

#define sm9_z256_fp2_init(a)		sm9_z256_fp2_set_zero(a)
#define sm9_z256_fp2_clean(a)		sm9_z256_fp2_set_zero(a)
#define sm9_z256_fp2_set_zero(a)	sm9_z256_fp2_copy((a), SM9_Z256_FP2_ZERO)
#define sm9_z256_fp2_is_zero(a)		sm9_z256_fp2_equ((a), SM9_Z256_FP2_ZERO)

void sm9_z256_fp2_set_one(sm9_z256_fp2 r);
int  sm9_z256_fp2_is_one(const sm9_z256_fp2 r);
int  sm9_z256_fp2_equ(const sm9_z256_fp2 a, const sm9_z256_fp2 b);
void sm9_z256_fp2_copy(sm9_z256_fp2 r, const sm9_z256_fp2 a);
int  sm9_z256_fp2_rand(sm9_z256_fp2 r);
void sm9_z256_fp2_to_bytes(const sm9_z256_fp2 a, uint8_t buf[64]);
int  sm9_z256_fp2_from_bytes(sm9_z256_fp2 r, const uint8_t buf[64]);
int  sm9_z256_fp2_from_hex(sm9_z256_fp2 r, const char hex[129]);
void sm9_z256_fp2_to_hex(const sm9_z256_fp2 a, char hex[129]);
void sm9_z256_fp2_add(sm9_z256_fp2 r, const sm9_z256_fp2 a, const sm9_z256_fp2 b);
void sm9_z256_fp2_dbl(sm9_z256_fp2 r, const sm9_z256_fp2 a);
void sm9_z256_fp2_tri(sm9_z256_fp2 r, const sm9_z256_fp2 a);
void sm9_z256_fp2_sub(sm9_z256_fp2 r, const sm9_z256_fp2 a, const sm9_z256_fp2 b);
void sm9_z256_fp2_neg(sm9_z256_fp2 r, const sm9_z256_fp2 a);
void sm9_z256_fp2_a_mul_u(sm9_z256_fp2 r, sm9_z256_fp2 a);
void sm9_z256_fp2_mul(sm9_z256_fp2 r, const sm9_z256_fp2 a, const sm9_z256_fp2 b);
void sm9_z256_fp2_mul_u(sm9_z256_fp2 r, const sm9_z256_fp2 a, const sm9_z256_fp2 b);
void sm9_z256_fp2_mul_fp(sm9_z256_fp2 r, const sm9_z256_fp2 a, const sm9_z256_t k);
void sm9_z256_fp2_sqr(sm9_z256_fp2 r, const sm9_z256_fp2 a);
void sm9_z256_fp2_sqr_u(sm9_z256_fp2 r, const sm9_z256_fp2 a);
void sm9_z256_fp2_inv(sm9_z256_fp2 r, const sm9_z256_fp2 a);
void sm9_z256_fp2_div(sm9_z256_fp2 r, const sm9_z256_fp2 a, const sm9_z256_fp2 b);
void sm9_z256_fp2_div2(sm9_z256_fp2 r, const sm9_z256_fp2 a);


typedef sm9_z256_fp2 sm9_z256_fp4[2];
extern const sm9_z256_fp4 SM9_FP4_ZERO;
extern const sm9_z256_fp4 SM9_FP4_ONE;
extern const sm9_z256_fp4 SM9_FP4_U;
extern const sm9_z256_fp4 SM9_FP4_V;

#define sm9_z256_fp4_is_zero(a)	sm9_z256_fp4_equ((a), SM9_Z256_FP4_ZERO)

int  sm9_z256_fp4_equ(const sm9_z256_fp4 a, const sm9_z256_fp4 b);
int  sm9_z256_fp4_rand(sm9_z256_fp4 r);
void sm9_z256_fp4_copy(sm9_z256_fp4 r, const sm9_z256_fp4 a);
void sm9_z256_fp4_to_bytes(const sm9_z256_fp4 a, uint8_t buf[128]);
int  sm9_z256_fp4_from_bytes(sm9_z256_fp4 r, const uint8_t buf[128]);
int  sm9_z256_fp4_from_hex(sm9_z256_fp4 r, const char hex[65 * 4]);
void sm9_z256_fp4_to_hex(const sm9_z256_fp4 a, char hex[259]);
void sm9_z256_fp4_add(sm9_z256_fp4 r, const sm9_z256_fp4 a, const sm9_z256_fp4 b);
void sm9_z256_fp4_dbl(sm9_z256_fp4 r, const sm9_z256_fp4 a);
void sm9_z256_fp4_sub(sm9_z256_fp4 r, const sm9_z256_fp4 a, const sm9_z256_fp4 b);
void sm9_z256_fp4_neg(sm9_z256_fp4 r, const sm9_z256_fp4 a);
void sm9_z256_fp4_div2(sm9_z256_fp4 r, const sm9_z256_fp4 a);
void sm9_z256_fp4_a_mul_v(sm9_z256_fp4 r, sm9_z256_fp4 a);
void sm9_z256_fp4_mul(sm9_z256_fp4 r, const sm9_z256_fp4 a, const sm9_z256_fp4 b);
void sm9_z256_fp4_mul_fp(sm9_z256_fp4 r, const sm9_z256_fp4 a, const sm9_z256_t k);
void sm9_z256_fp4_mul_fp2(sm9_z256_fp4 r, const sm9_z256_fp4 a, const sm9_z256_fp2 b0);
void sm9_z256_fp4_mul_v(sm9_z256_fp4 r, const sm9_z256_fp4 a, const sm9_z256_fp4 b);
void sm9_z256_fp4_sqr(sm9_z256_fp4 r, const sm9_z256_fp4 a);
void sm9_z256_fp4_sqr_v(sm9_z256_fp4 r, const sm9_z256_fp4 a);
void sm9_z256_fp4_inv(sm9_z256_fp4 r, const sm9_z256_fp4 a);


typedef sm9_z256_fp4 sm9_z256_fp12[3];

#define sm9_fp12_init(r)	sm9_fp12_set_zero(r)
#define sm9_fp12_clean(r)	sm9_fp12_set_zero(r)

void sm9_z256_fp12_copy(sm9_z256_fp12 r, const sm9_z256_fp12 a);
int  sm9_z256_fp12_rand(sm9_z256_fp12 r);
void sm9_z256_fp12_set_zero(sm9_z256_fp12 r);
void sm9_z256_fp12_set_one(sm9_z256_fp12 r);
int  sm9_z256_fp12_from_hex(sm9_z256_fp12 r, const char hex[65 * 12 - 1]);
void sm9_z256_fp12_to_hex(const sm9_z256_fp12 a, char hex[65 * 12 - 1]);
void sm9_z256_fp12_to_bytes(const sm9_z256_fp12 a, uint8_t buf[32 * 12]);
void sm9_z256_fp12_print(const char *prefix, const sm9_z256_fp12 a);
void sm9_z256_fp12_set(sm9_z256_fp12 r, const sm9_z256_fp4 a0, const sm9_z256_fp4 a1, const sm9_z256_fp4 a2);
int  sm9_z256_fp12_equ(const sm9_z256_fp12 a, const sm9_z256_fp12 b);
void sm9_z256_fp12_add(sm9_z256_fp12 r, const sm9_z256_fp12 a, const sm9_z256_fp12 b);
void sm9_z256_fp12_dbl(sm9_z256_fp12 r, const sm9_z256_fp12 a);
void sm9_z256_fp12_tri(sm9_z256_fp12 r, const sm9_z256_fp12 a);
void sm9_z256_fp12_sub(sm9_z256_fp12 r, const sm9_z256_fp12 a, const sm9_z256_fp12 b);
void sm9_z256_fp12_neg(sm9_z256_fp12 r, const sm9_z256_fp12 a);
void sm9_z256_fp12_mul(sm9_z256_fp12 r, const sm9_z256_fp12 a, const sm9_z256_fp12 b);
void sm9_z256_fp12_sqr(sm9_z256_fp12 r, const sm9_z256_fp12 a);
void sm9_z256_fp12_inv(sm9_z256_fp12 r, const sm9_z256_fp12 a);
void sm9_z256_fp12_pow(sm9_z256_fp12 r, const sm9_z256_fp12 a, const sm9_z256_t k);


void sm9_z256_fp2_conjugate(sm9_z256_fp2 r, const sm9_z256_fp2 a);
void sm9_z256_fp2_frobenius(sm9_z256_fp2 r, const sm9_z256_fp2 a);
void sm9_z256_fp4_frobenius(sm9_z256_fp4 r, const sm9_z256_fp4 a);
void sm9_z256_fp4_conjugate(sm9_z256_fp4 r, const sm9_z256_fp4 a);
void sm9_z256_fp4_frobenius2(sm9_z256_fp4 r, const sm9_z256_fp4 a);
void sm9_z256_fp4_frobenius3(sm9_z256_fp4 r, const sm9_z256_fp4 a);
void sm9_z256_fp12_frobenius(sm9_z256_fp12 r, const sm9_z256_fp12 x);
void sm9_z256_fp12_frobenius2(sm9_z256_fp12 r, const sm9_z256_fp12 x);
void sm9_z256_fp12_frobenius3(sm9_z256_fp12 r, const sm9_z256_fp12 x);
void sm9_z256_fp12_frobenius6(sm9_z256_fp12 r, const sm9_z256_fp12 x);


typedef struct {
	sm9_z256_t X;
	sm9_z256_t Y;
	sm9_z256_t Z;
} SM9_Z256_POINT;

#define sm9_point_init(R)	sm9_point_set_infinity(R)
#define sm9_point_clean(R)	sm9_point_set_infinity(R)

void sm9_z256_point_from_hex(SM9_Z256_POINT *R, const char hex[65 * 2]);
int  sm9_z256_point_is_at_infinity(const SM9_Z256_POINT *P);
void sm9_z256_point_set_infinity(SM9_Z256_POINT *R);
void sm9_z256_point_copy(SM9_Z256_POINT *R, const SM9_Z256_POINT *P);
void sm9_z256_point_get_xy(const SM9_Z256_POINT *P, sm9_z256_t x, sm9_z256_t y);
int  sm9_z256_point_equ(const SM9_Z256_POINT *P, const SM9_Z256_POINT *Q);
int  sm9_z256_point_is_on_curve(const SM9_Z256_POINT *P);
void sm9_z256_point_dbl(SM9_Z256_POINT *R, const SM9_Z256_POINT *P);
void sm9_z256_point_neg(SM9_Z256_POINT *R, const SM9_Z256_POINT *P);
void sm9_z256_point_add(SM9_Z256_POINT *R, const SM9_Z256_POINT *P, const SM9_Z256_POINT *Q);
void sm9_z256_point_sub(SM9_Z256_POINT *R, const SM9_Z256_POINT *P, const SM9_Z256_POINT *Q);
void sm9_z256_point_mul(SM9_Z256_POINT *R, const sm9_z256_t k, const SM9_Z256_POINT *P);
void sm9_z256_point_mul_generator(SM9_Z256_POINT *R, const sm9_z256_t k);
int  sm9_z256_point_print(FILE *fp, int fmt, int ind, const char *label, const SM9_Z256_POINT *P);
int  sm9_z256_point_to_uncompressed_octets(const SM9_Z256_POINT *P, uint8_t octets[65]);
int  sm9_z256_point_from_uncompressed_octets(SM9_Z256_POINT *P, const uint8_t octets[65]);


typedef struct {
	sm9_z256_fp2 X;
	sm9_z256_fp2 Y;
	sm9_z256_fp2 Z;
} SM9_Z256_TWIST_POINT;

#define sm9_z256_twist_point_copy(R, P)	memcpy((R), (P), sizeof(SM9_Z256_TWIST_POINT))

int sm9_z256_twist_point_to_uncompressed_octets(const SM9_Z256_TWIST_POINT *P, uint8_t octets[129]);
int sm9_z256_twist_point_from_uncompressed_octets(SM9_Z256_TWIST_POINT *P, const uint8_t octets[129]);

int  sm9_z256_twist_point_print(FILE *fp, int fmt, int ind, const char *label, const SM9_Z256_TWIST_POINT *P);
void sm9_z256_twist_point_from_hex(SM9_Z256_TWIST_POINT *R, const char hex[65 * 4]);
int  sm9_z256_twist_point_is_at_infinity(const SM9_Z256_TWIST_POINT *P);
void sm9_z256_twist_point_set_infinity(SM9_Z256_TWIST_POINT *R);
void sm9_z256_twist_point_get_xy(const SM9_Z256_TWIST_POINT *P, sm9_z256_fp2 x, sm9_z256_fp2 y);
int  sm9_z256_twist_point_equ(const SM9_Z256_TWIST_POINT *P, const SM9_Z256_TWIST_POINT *Q);
int  sm9_z256_twist_point_is_on_curve(const SM9_Z256_TWIST_POINT *P);
void sm9_z256_twist_point_neg(SM9_Z256_TWIST_POINT *R, const SM9_Z256_TWIST_POINT *P);
void sm9_z256_twist_point_dbl(SM9_Z256_TWIST_POINT *R, const SM9_Z256_TWIST_POINT *P);
void sm9_z256_twist_point_add(SM9_Z256_TWIST_POINT *R, const SM9_Z256_TWIST_POINT *P, const SM9_Z256_TWIST_POINT *Q);
void sm9_z256_twist_point_sub(SM9_Z256_TWIST_POINT *R, const SM9_Z256_TWIST_POINT *P, const SM9_Z256_TWIST_POINT *Q);
void sm9_z256_twist_point_add_full(SM9_Z256_TWIST_POINT *R, const SM9_Z256_TWIST_POINT *P, const SM9_Z256_TWIST_POINT *Q);
void sm9_z256_twist_point_mul(SM9_Z256_TWIST_POINT *R, const sm9_z256_t k, const SM9_Z256_TWIST_POINT *P);
void sm9_z256_twist_point_mul_generator(SM9_Z256_TWIST_POINT *R, const sm9_z256_t k);


void sm9_z256_eval_g_tangent(sm9_z256_fp12 num, sm9_z256_fp12 den, const SM9_Z256_TWIST_POINT *P, const SM9_Z256_POINT *Q);
void sm9_z256_eval_g_line(sm9_z256_fp12 num, sm9_z256_fp12 den, const SM9_Z256_TWIST_POINT *T, const SM9_Z256_TWIST_POINT *P, const SM9_Z256_POINT *Q);
void sm9_z256_twist_point_pi1(SM9_Z256_TWIST_POINT *R, const SM9_Z256_TWIST_POINT *P);
void sm9_z256_twist_point_pi2(SM9_Z256_TWIST_POINT *R, const SM9_Z256_TWIST_POINT *P);
void sm9_z256_twist_point_neg_pi2(SM9_Z256_TWIST_POINT *R, const SM9_Z256_TWIST_POINT *P);
void sm9_z256_final_exponent_hard_part(sm9_z256_fp12 r, const sm9_z256_fp12 f);
void sm9_z256_final_exponent(sm9_z256_fp12 r, const sm9_z256_fp12 f);
void sm9_z256_pairing(sm9_z256_fp12 r, const SM9_Z256_TWIST_POINT *Q, const SM9_Z256_POINT *P);

int sm9_z256_hash1(sm9_z256_t h1, const char *id, size_t idlen, uint8_t hid);

/* private key extract algorithms */
#define SM9_HID_SIGN		0x01
#define SM9_HID_EXCH		0x02
#define SM9_HID_ENC		0x03

#define SM9_HASH1_PREFIX	0x01
#define SM9_HASH2_PREFIX	0x02

const char *sm9_oid_name(int oid);
int sm9_oid_from_name(const char *name);
int sm9_oid_to_der(int oid, uint8_t **out, size_t *outlen);
int sm9_oid_from_der(int *oid, const uint8_t **in, size_t *inlen);
int sm9_algor_to_der(int alg, int params, uint8_t **out, size_t *outlen);
int sm9_algor_from_der(int *alg, int *params, const uint8_t **in, size_t *inlen);


#define PEM_SM9_SIGN_MASTER_KEY		"ENCRYPTED SM9 SIGN MASTER KEY"
#define PEM_SM9_SIGN_MASTER_PUBLIC_KEY	"SM9 SIGN MASTER PUBLIC KEY"
#define PEM_SM9_SIGN_PRIVATE_KEY	"ENCRYPTED SM9 SIGN PRIVATE KEY"
#define PEM_SM9_ENC_MASTER_KEY		"ENCRYPTED SM9 ENC MASTER KEY"
#define PEM_SM9_ENC_MASTER_PUBLIC_KEY	"SM9 ENC MASTER PUBLIC KEY"
#define PEM_SM9_ENC_PRIVATE_KEY		"ENCRYPTED SM9 ENC PRIVATE KEY"


#define SM9_MAX_ID_SIZE		(SM2_MAX_ID_SIZE)

/*
SM9SignMasterKey ::= SEQUENCE {
	ks	INTEGER,
	Ppubs	BIT STRING -- uncompressed octets of twisted point }

SM9SignMasterPublicKey ::= SEQUENCE {
	Ppubs   BIT STRING -- uncompressed octets of twisted point }

SM9SignPrivateKey ::= SEQUENCE {
	ds	BIT STRING, -- uncompressed octets of ECPoint
	Ppubs	BIT STRING -- uncompressed octets of twisted point }
*/
typedef struct {
	SM9_Z256_TWIST_POINT Ppubs; // Ppubs = ks * P2
	sm9_z256_t ks;
} SM9_SIGN_MASTER_KEY;

typedef struct {
	SM9_Z256_TWIST_POINT Ppubs;
	SM9_Z256_POINT ds;
} SM9_SIGN_KEY;

int sm9_sign_master_key_generate(SM9_SIGN_MASTER_KEY *master);
int sm9_sign_master_key_extract_key(SM9_SIGN_MASTER_KEY *master, const char *id, size_t idlen, SM9_SIGN_KEY *key);

// algorthm,parameters = sm9,sm9sign
#define SM9_SIGN_MASTER_KEY_MAX_SIZE 171
int sm9_sign_master_key_to_der(const SM9_SIGN_MASTER_KEY *msk, uint8_t **out, size_t *outlen);
int sm9_sign_master_key_from_der(SM9_SIGN_MASTER_KEY *msk, const uint8_t **in, size_t *inlen);
int sm9_sign_master_key_info_encrypt_to_der(const SM9_SIGN_MASTER_KEY *msk, const char *pass, uint8_t **out, size_t *outlen);
int sm9_sign_master_key_info_decrypt_from_der(SM9_SIGN_MASTER_KEY *msk, const char *pass, const uint8_t **in, size_t *inlen);
int sm9_sign_master_key_info_encrypt_to_pem(const SM9_SIGN_MASTER_KEY *msk, const char *pass, FILE *fp);
int sm9_sign_master_key_info_decrypt_from_pem(SM9_SIGN_MASTER_KEY *msk, const char *pass, FILE *fp);
int sm9_sign_master_key_print(FILE *fp, int fmt, int ind, const char *label, const SM9_SIGN_MASTER_KEY *msk);

#define SM9_SIGN_MASTER_PUBLIC_KEY_SIZE 136
int sm9_sign_master_public_key_to_der(const SM9_SIGN_MASTER_KEY *mpk, uint8_t **out, size_t *outlen);
int sm9_sign_master_public_key_from_der(SM9_SIGN_MASTER_KEY *mpk, const uint8_t **in, size_t *inlen);
int sm9_sign_master_public_key_to_pem(const SM9_SIGN_MASTER_KEY *mpk, FILE *fp);
int sm9_sign_master_public_key_from_pem(SM9_SIGN_MASTER_KEY *mpk, FILE *fp);
int sm9_sign_master_public_key_print(FILE *fp, int fmt, int ind, const char *label, const SM9_SIGN_MASTER_KEY *mpk);

// algorithm,parameters = sm9sign,<null>
#define SM9_SIGN_KEY_SIZE 204
int sm9_sign_key_to_der(const SM9_SIGN_KEY *key, uint8_t **out, size_t *outlen);
int sm9_sign_key_from_der(SM9_SIGN_KEY *key, const uint8_t **in, size_t *inlen);
int sm9_sign_key_info_encrypt_to_der(const SM9_SIGN_KEY *key, const char *pass, uint8_t **out, size_t *outlen);
int sm9_sign_key_info_decrypt_from_der(SM9_SIGN_KEY *key, const char *pass, const uint8_t **in, size_t *inlen);
int sm9_sign_key_info_encrypt_to_pem(const SM9_SIGN_KEY *key, const char *pass, FILE *fp);
int sm9_sign_key_info_decrypt_from_pem(SM9_SIGN_KEY *key, const char *pass, FILE *fp);
int sm9_sign_key_print(FILE *fp, int fmt, int ind, const char *label, const SM9_SIGN_KEY *key);

/*
from GM/T 0080-2020 SM9 Cryptographic Alagorithm Application Specification
SM9Signature ::= SEQUENCE {
	h	OCTET STRING,
	S	BIT STRING -- uncompressed octets of ECPoint }
*/
typedef struct {
	sm9_z256_t h;
	SM9_Z256_POINT S;
} SM9_SIGNATURE;

int sm9_do_sign(const SM9_SIGN_KEY *key, const SM3_CTX *sm3_ctx, SM9_SIGNATURE *sig);
int sm9_do_verify(const SM9_SIGN_MASTER_KEY *mpk, const char *id, size_t idlen, const SM3_CTX *sm3_ctx, const SM9_SIGNATURE *sig);

#define SM9_SIGNATURE_SIZE 104
int sm9_signature_to_der(const SM9_SIGNATURE *sig, uint8_t **out, size_t *outlen);
int sm9_signature_from_der(SM9_SIGNATURE *sig, const uint8_t **in, size_t *inlen);
int sm9_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *sig, size_t siglen);

typedef struct {
	SM3_CTX sm3_ctx;
} SM9_SIGN_CTX;

int sm9_sign_init(SM9_SIGN_CTX *ctx);
int sm9_sign_update(SM9_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int sm9_sign_finish(SM9_SIGN_CTX *ctx, const SM9_SIGN_KEY *key, uint8_t *sig, size_t *siglen);
int sm9_verify_init(SM9_SIGN_CTX *ctx);
int sm9_verify_update(SM9_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);
int sm9_verify_finish(SM9_SIGN_CTX *ctx, const uint8_t *sig, size_t siglen,
	const SM9_SIGN_MASTER_KEY *mpk, const char *id, size_t idlen);


/*
SM9EncMasterKey ::= SEQUENCE {
	de	INTEGER,
	Ppube	BIT STRING -- uncompressed octets of ECPoint }

SM9EncMasterPublicKey ::= SEQUENCE {
	Ppube	BIT STRING -- uncompressed octets of ECPoint }

SM9EncPrivateKey ::= SEQUENCE {
	de	BIT STRING, -- uncompressed octets of twisted point
	Ppube	BIT STRING -- uncompressed octets of ECPoint }
*/

typedef struct {
	SM9_Z256_POINT Ppube; // Ppube = ke * P1
	sm9_z256_t ke;
} SM9_ENC_MASTER_KEY;

typedef struct {
	SM9_Z256_POINT Ppube;
	SM9_Z256_TWIST_POINT de;
} SM9_ENC_KEY;

int sm9_enc_master_key_generate(SM9_ENC_MASTER_KEY *master);
int sm9_enc_master_key_extract_key(SM9_ENC_MASTER_KEY *master, const char *id, size_t idlen, SM9_ENC_KEY *key);

// algorithm,parameters = sm9,sm9encrypt
#define SM9_ENC_MASTER_KEY_MAX_SIZE 105
int sm9_enc_master_key_to_der(const SM9_ENC_MASTER_KEY *msk, uint8_t **out, size_t *outlen);
int sm9_enc_master_key_from_der(SM9_ENC_MASTER_KEY *msk, const uint8_t **in, size_t *inlen);
int sm9_enc_master_key_info_encrypt_to_der(const SM9_ENC_MASTER_KEY *msk, const char *pass, uint8_t **out, size_t *outlen);
int sm9_enc_master_key_info_decrypt_from_der(SM9_ENC_MASTER_KEY *msk, const char *pass, const uint8_t **in, size_t *inlen);
int sm9_enc_master_key_info_encrypt_to_pem(const SM9_ENC_MASTER_KEY *msk, const char *pass, FILE *fp);
int sm9_enc_master_key_info_decrypt_from_pem(SM9_ENC_MASTER_KEY *msk, const char *pass, FILE *fp);
int sm9_enc_master_key_print(FILE *fp, int fmt, int ind, const char *label, const SM9_ENC_MASTER_KEY *msk);

#define SM9_ENC_MASTER_PUBLIC_KEY_SIZE 70
int sm9_enc_master_public_key_to_der(const SM9_ENC_MASTER_KEY *mpk, uint8_t **out, size_t *outlen);
int sm9_enc_master_public_key_from_der(SM9_ENC_MASTER_KEY *mpk, const uint8_t **in, size_t *inlen);
int sm9_enc_master_public_key_to_pem(const SM9_ENC_MASTER_KEY *mpk, FILE *fp);
int sm9_enc_master_public_key_from_pem(SM9_ENC_MASTER_KEY *mpk, FILE *fp);
int sm9_enc_master_public_key_print(FILE *fp, int fmt, int ind, const char *label, const SM9_ENC_MASTER_KEY *mpk);

// algorithm,parameters = sm9encrypt,<null>
#define SM9_ENC_KEY_SIZE 204
int sm9_enc_key_to_der(const SM9_ENC_KEY *key, uint8_t **out, size_t *outlen);
int sm9_enc_key_from_der(SM9_ENC_KEY *key, const uint8_t **in, size_t *inlen);
int sm9_enc_key_info_encrypt_to_der(const SM9_ENC_KEY *key, const char *pass, uint8_t **out, size_t *outlen);
int sm9_enc_key_info_decrypt_from_der(SM9_ENC_KEY *key, const char *pass, const uint8_t **in, size_t *inlen);
int sm9_enc_key_info_encrypt_to_pem(const SM9_ENC_KEY *key, const char *pass, FILE *fp);
int sm9_enc_key_info_decrypt_from_pem(SM9_ENC_KEY *key, const char *pass, FILE *fp);
int sm9_enc_key_print(FILE *fp, int fmt, int ind, const char *label, const SM9_ENC_KEY *key);

#define SM9_MAX_PRIVATE_KEY_SIZE (SM9_SIGN_KEY_SIZE) // MAX(SIGN_MASTER_KEY, SIGN_KEY, ENC_MASTER_KEY, ENC_KEY)
#define SM9_MAX_PRIVATE_KEY_INFO_SIZE 512
#define SM9_MAX_ENCED_PRIVATE_KEY_INFO_SIZE 1024

/*
from GM/T 0080-2020 SM9 Cryptographic Alagorithm Application Specification
SM9Cipher ::= SEQUENCE {
	EnType		INTEGER, -- 0 for XOR
	C1		BIT STRING, -- uncompressed octets of ECPoint
	C3		OCTET STRING, -- 32 bytes HMAC-SM3 tag
	CipherText	OCTET STRING }
*/

int sm9_kem_encrypt(const SM9_ENC_MASTER_KEY *mpk, const char *id, size_t idlen, size_t klen, uint8_t *kbuf, SM9_Z256_POINT *C);
int sm9_kem_decrypt(const SM9_ENC_KEY *key, const char *id, size_t idlen, const SM9_Z256_POINT *C, size_t klen, uint8_t *kbuf);
int sm9_do_encrypt(const SM9_ENC_MASTER_KEY *mpk, const char *id, size_t idlen,
	const uint8_t *in, size_t inlen, SM9_Z256_POINT *C1, uint8_t *c2, uint8_t c3[SM3_HMAC_SIZE]);
int sm9_do_decrypt(const SM9_ENC_KEY *key, const char *id, size_t idlen,
	const SM9_Z256_POINT *C1, const uint8_t *c2, size_t c2len, const uint8_t c3[SM3_HMAC_SIZE], uint8_t *out);

#define SM9_MAX_PLAINTEXT_SIZE 255
#define SM9_MAX_CIPHERTEXT_SIZE 367 // calculated in test_sm9_ciphertext()
int sm9_ciphertext_to_der(const SM9_Z256_POINT *C1, const uint8_t *c2, size_t c2len,
	const uint8_t c3[SM3_HMAC_SIZE], uint8_t **out, size_t *outlen);
int sm9_ciphertext_from_der(SM9_Z256_POINT *C1, const uint8_t **c2, size_t *c2len,
	const uint8_t **c3, const uint8_t **in, size_t *inlen);
int sm9_ciphertext_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *a, size_t alen);
int sm9_encrypt(const SM9_ENC_MASTER_KEY *mpk, const char *id, size_t idlen,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sm9_decrypt(const SM9_ENC_KEY *key, const char *id, size_t idlen,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);



#ifdef  __cplusplus
}
#endif
#endif
