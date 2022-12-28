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
#include <stdint.h>
#include <gmssl/sm3.h>
#include <gmssl/sm2.h>


#ifndef GMSSL_SM9_H
#define GMSSL_SM9_H

#ifdef __cplusplus
extern "C" {
#endif

/*
SM9 Public API

	SM9_SIGNATURE_SIZE
	SM9_MAX_PLAINTEXT_SIZE
	SM9_MAX_CIPHERTEXT_SIZE

	SM9_SIGN_MASTER_KEY
	sm9_sign_master_key_generate
	sm9_sign_master_key_extract_key
	sm9_sign_master_key_info_encrypt_to_der
	sm9_sign_master_key_info_decrypt_from_der
	sm9_sign_master_key_info_encrypt_to_pem
	sm9_sign_master_key_info_decrypt_from_pem
	sm9_sign_master_public_key_to_der
	sm9_sign_master_public_key_from_der
	sm9_sign_master_public_key_to_pem
	sm9_sign_master_public_key_from_pem

	SM9_SIGN_KEY
	sm9_sign_key_info_encrypt_to_der
	sm9_sign_key_info_decrypt_from_der
	sm9_sign_key_info_encrypt_to_pem
	sm9_sign_key_info_decrypt_from_pem

	SM9_SIGN_CTX
	sm9_sign_init
	sm9_sign_update
	sm9_sign_finish
	sm9_verify_init
	sm9_verify_update
	sm9_verify_finish

	SM9_ENC_MASTER_KEY
	sm9_enc_master_key_generate
	sm9_enc_master_key_extract_key
	sm9_enc_master_key_info_encrypt_to_der
	sm9_enc_master_key_info_decrypt_from_der
	sm9_enc_master_key_info_encrypt_to_pem
	sm9_enc_master_key_info_decrypt_from_pem
	sm9_enc_master_public_key_to_der
	sm9_enc_master_public_key_from_der
	sm9_enc_master_public_key_to_pem
	sm9_enc_master_public_key_from_pem

	SM9_ENC_KEY
	sm9_enc_key_info_encrypt_to_der
	sm9_enc_key_info_decrypt_from_der
	sm9_enc_key_info_encrypt_to_pem
	sm9_enc_key_info_decrypt_from_pem

	sm9_encrypt
	sm9_decrypt
*/

#define SM9_HEX_SEP '\n'

typedef uint64_t sm9_bn_t[8];

#define sm9_bn_init(r)		sm9_bn_set_zero(r)
#define sm9_bn_clean(r)		sm9_bn_set_zero(r)

void sm9_bn_set_zero(sm9_bn_t r);
void sm9_bn_set_one(sm9_bn_t r);
int  sm9_bn_is_zero(const sm9_bn_t a);
int  sm9_bn_is_one(const sm9_bn_t a);
void sm9_bn_set_word(sm9_bn_t r, uint32_t a);
void sm9_bn_copy(sm9_bn_t r, const sm9_bn_t a);
int  sm9_bn_rand_range(sm9_bn_t r, const sm9_bn_t range);
int  sm9_bn_equ(const sm9_bn_t a, const sm9_bn_t b);
int  sm9_bn_cmp(const sm9_bn_t a, const sm9_bn_t b);
void sm9_bn_add(sm9_bn_t r, const sm9_bn_t a, const sm9_bn_t b);
void sm9_bn_sub(sm9_bn_t ret, const sm9_bn_t a, const sm9_bn_t b);
void sm9_bn_to_bits(const sm9_bn_t a, char bits[256]);
void sm9_bn_to_bytes(const sm9_bn_t a, uint8_t out[32]);
void sm9_bn_from_bytes(sm9_bn_t r, const uint8_t in[32]);
void sm9_bn_to_hex(const sm9_bn_t a, char hex[64]);
int  sm9_bn_from_hex(sm9_bn_t r, const char hex[64]);
int  sm9_bn_print(FILE *fp, int fmt, int ind, const char *label, const sm9_bn_t a);
void sm9_print_bn(const char *prefix, const sm9_bn_t a); // 标准打印格式


typedef sm9_bn_t sm9_fp_t;

#define sm9_fp_init(r)		sm9_fp_set_zero(r)
#define sm9_fp_clean(f)		sm9_fp_set_zero(r)
#define sm9_fp_set_zero(r)	sm9_bn_set_zero(r)
#define sm9_fp_set_one(r)	sm9_bn_set_one(r)
#define sm9_fp_copy(r,a)	sm9_bn_copy((r),(a))
#define sm9_fp_rand(r)		sm9_bn_rand_range((r), SM9_P)
#define sm9_fp_is_zero(a)	sm9_bn_is_zero(a)
#define sm9_fp_is_one(a)	sm9_bn_is_one(a)
#define sm9_fp_equ(a,b)		sm9_bn_equ((a),(b))
#define sm9_fp_to_bytes(a,buf)	sm9_bn_to_bytes((a),(buf))
#define sm9_fp_to_hex(a,s)	sm9_bn_to_hex((a),(s))
#define sm9_fp_print(fp,fmt,ind,label,a) sm9_bn_print(fp,fmt,ind,label,a)

void sm9_fp_add(sm9_fp_t r, const sm9_fp_t a, const sm9_fp_t b);
void sm9_fp_sub(sm9_fp_t r, const sm9_fp_t a, const sm9_fp_t b);
void sm9_fp_dbl(sm9_fp_t r, const sm9_fp_t a);
void sm9_fp_tri(sm9_fp_t r, const sm9_fp_t a);
void sm9_fp_neg(sm9_fp_t r, const sm9_fp_t a);
void sm9_fp_mul(sm9_fp_t r, const sm9_fp_t a, const sm9_fp_t b);
void sm9_fp_sqr(sm9_fp_t r, const sm9_fp_t a);
void sm9_fp_pow(sm9_fp_t r, const sm9_fp_t a, const sm9_bn_t e);
void sm9_fp_inv(sm9_fp_t r, const sm9_fp_t a);
void sm9_fp_div2(sm9_fp_t r, const sm9_fp_t a);
int sm9_fp_from_bytes(sm9_fp_t r, const uint8_t buf[32]);
int sm9_fp_from_hex(sm9_fp_t r, const char hex[64]);


typedef sm9_bn_t sm9_fn_t;

#define sm9_fn_init(r)		sm9_fn_set_zero(r)
#define sm9_fn_clean(f)		sm9_fn_set_zero(r)
#define sm9_fn_set_zero(r)	sm9_bn_set_zero(r)
#define sm9_fn_set_one(r)	sm9_bn_set_one(r)
#define sm9_fn_copy(r,a)	sm9_bn_copy((r),(a))
#define sm9_fn_rand(r)		sm9_bn_rand_range((r), SM9_N)
#define sm9_fn_is_zero(a)	sm9_bn_is_zero(a)
#define sm9_fn_is_one(a)	sm9_bn_is_one(a)
#define sm9_fn_equ(a,b)		sm9_bn_equ((a),(b))
#define sm9_fn_to_bytes(a,out)	sm9_bn_to_bytes((a),(out))
#define sm9_fn_to_hex(a,s)	sm9_bn_to_hex((a),(s))
#define sm9_fn_print(fp,fmt,ind,label,a) sm9_bn_print(fp,fmt,ind,label,a)

void sm9_fn_add(sm9_fn_t r, const sm9_fn_t a, const sm9_fn_t b);
void sm9_fn_sub(sm9_fn_t r, const sm9_fn_t a, const sm9_fn_t b);
void sm9_fn_mul(sm9_fn_t r, const sm9_fn_t a, const sm9_fn_t b);
void sm9_fn_pow(sm9_fn_t r, const sm9_fn_t a, const sm9_bn_t e);
void sm9_fn_inv(sm9_fn_t r, const sm9_fn_t a);
void sm9_fn_from_hash(sm9_fn_t h, const uint8_t Ha[40]);
int  sm9_fn_from_bytes(sm9_fn_t a, const uint8_t in[32]);
int  sm9_fn_from_hex(sm9_fn_t r, const char hex[64]);


typedef uint64_t sm9_barrett_bn_t[9];

int  sm9_barrett_bn_cmp(const sm9_barrett_bn_t a, const sm9_barrett_bn_t b);
void sm9_barrett_bn_add(sm9_barrett_bn_t r, const sm9_barrett_bn_t a, const sm9_barrett_bn_t b);
void sm9_barrett_bn_sub(sm9_barrett_bn_t ret, const sm9_barrett_bn_t a, const sm9_barrett_bn_t b);


typedef sm9_fp_t sm9_fp2_t[2];
extern const sm9_fp2_t SM9_FP2_ZERO;
extern const sm9_fp2_t SM9_FP2_ONE;
extern const sm9_fp2_t SM9_FP2_U;

#define sm9_fp2_init(a)		sm9_fp2_set_zero(a)
#define sm9_fp2_clean(a)	sm9_fp2_set_zero(a)
#define sm9_fp2_set_zero(a)	sm9_fp2_copy((a), SM9_FP2_ZERO)
#define sm9_fp2_set_one(a)	sm9_fp2_copy((a), SM9_FP2_ONE)
#define sm9_fp2_set_u(a)	sm9_fp2_copy((a), SM9_FP2_U)
#define sm9_fp2_is_zero(a)	sm9_fp2_equ((a), SM9_FP2_ZERO)
#define sm9_fp2_is_one(a)	sm9_fp2_equ((a), SM9_FP2_ONE)

void sm9_fp2_set_fp(sm9_fp2_t r, const sm9_fp_t a);
void sm9_fp2_set(sm9_fp2_t r, const sm9_fp_t a0, const sm9_fp_t a1);
void sm9_fp2_copy(sm9_fp2_t r, const sm9_fp2_t a);
int  sm9_fp2_rand(sm9_fp2_t r);
int  sm9_fp2_equ(const sm9_fp2_t a, const sm9_fp2_t b);
void sm9_fp2_add(sm9_fp2_t r, const sm9_fp2_t a, const sm9_fp2_t b);
void sm9_fp2_dbl(sm9_fp2_t r, const sm9_fp2_t a);
void sm9_fp2_tri(sm9_fp2_t r, const sm9_fp2_t a);
void sm9_fp2_sub(sm9_fp2_t r, const sm9_fp2_t a, const sm9_fp2_t b);
void sm9_fp2_neg(sm9_fp2_t r, const sm9_fp2_t a);
void sm9_fp2_mul(sm9_fp2_t r, const sm9_fp2_t a, const sm9_fp2_t b);
void sm9_fp2_mul_u(sm9_fp2_t r, const sm9_fp2_t a, const sm9_fp2_t b);
void sm9_fp2_mul_fp(sm9_fp2_t r, const sm9_fp2_t a, const sm9_fp_t k);
void sm9_fp2_sqr(sm9_fp2_t r, const sm9_fp2_t a);
void sm9_fp2_sqr_u(sm9_fp2_t r, const sm9_fp2_t a);
void sm9_fp2_inv(sm9_fp2_t r, const sm9_fp2_t a);
void sm9_fp2_div(sm9_fp2_t r, const sm9_fp2_t a, const sm9_fp2_t b);
void sm9_fp2_div2(sm9_fp2_t r, const sm9_fp2_t a);
void sm9_fp2_to_hex(const sm9_fp2_t a, char hex[129]);
int  sm9_fp2_from_hex(sm9_fp2_t r, const char hex[129]);
int  sm9_fp2_print(FILE *fp, int fmt, int ind, const char *label, const sm9_fp2_t a);


typedef sm9_fp2_t sm9_fp4_t[2];
extern const sm9_fp4_t SM9_FP4_ZERO;
extern const sm9_fp4_t SM9_FP4_ONE;
extern const sm9_fp4_t SM9_FP4_U;
extern const sm9_fp4_t SM9_FP4_V;

#define sm9_fp4_init(a)		sm9_fp4_set_zero(a)
#define sm9_fp4_clean(a)	sm9_fp4_set_zero(a)
#define sm9_fp4_set_zero(a)	sm9_fp4_copy((a), SM9_FP4_ZERO)
#define sm9_fp4_set_one(a)	sm9_fp4_copy((a), SM9_FP4_ONE)
#define sm9_fp4_is_zero(a)	sm9_fp4_equ((a), SM9_FP4_ZERO)
#define sm9_fp4_is_one(a)	sm9_fp4_equ((a), SM9_FP4_ONE)

void sm9_fp4_set_u(sm9_fp4_t r);
void sm9_fp4_set_v(sm9_fp4_t r);
void sm9_fp4_set_fp(sm9_fp4_t r, const sm9_fp_t a);
void sm9_fp4_set_fp2(sm9_fp4_t r, const sm9_fp2_t a);
void sm9_fp4_set(sm9_fp4_t r, const sm9_fp2_t a0, const sm9_fp2_t a1);
void sm9_fp4_copy(sm9_fp4_t r, const sm9_fp4_t a);
int  sm9_fp4_rand(sm9_fp4_t r);
int  sm9_fp4_equ(const sm9_fp4_t a, const sm9_fp4_t b);
void sm9_fp4_add(sm9_fp4_t r, const sm9_fp4_t a, const sm9_fp4_t b);
void sm9_fp4_dbl(sm9_fp4_t r, const sm9_fp4_t a);
void sm9_fp4_sub(sm9_fp4_t r, const sm9_fp4_t a, const sm9_fp4_t b);
void sm9_fp4_neg(sm9_fp4_t r, const sm9_fp4_t a);
void sm9_fp4_mul(sm9_fp4_t r, const sm9_fp4_t a, const sm9_fp4_t b);
void sm9_fp4_mul_fp(sm9_fp4_t r, const sm9_fp4_t a, const sm9_fp_t k);
void sm9_fp4_mul_fp2(sm9_fp4_t r, const sm9_fp4_t a, const sm9_fp2_t b0);
void sm9_fp4_mul_v(sm9_fp4_t r, const sm9_fp4_t a, const sm9_fp4_t b);
void sm9_fp4_sqr(sm9_fp4_t r, const sm9_fp4_t a);
void sm9_fp4_sqr_v(sm9_fp4_t r, const sm9_fp4_t a);
void sm9_fp4_inv(sm9_fp4_t r, const sm9_fp4_t a);
void sm9_fp4_to_bytes(const sm9_fp4_t a, uint8_t buf[128]);
int  sm9_fp4_from_bytes(sm9_fp4_t r, const uint8_t buf[128]);
void sm9_fp4_to_hex(const sm9_fp4_t a, char hex[259]);
int  sm9_fp4_from_hex(sm9_fp4_t r, const char hex[259]);


typedef sm9_fp4_t sm9_fp12_t[3];

#define sm9_fp12_init(r)	sm9_fp12_set_zero(a)
#define sm9_fp12_clean(r)	sm9_fp12_set_zero(a)

void sm9_fp12_set_zero(sm9_fp12_t r);
void sm9_fp12_set_one(sm9_fp12_t r);
void sm9_fp12_set_u(sm9_fp12_t r);
void sm9_fp12_set_v(sm9_fp12_t r);
void sm9_fp12_set_w(sm9_fp12_t r);
void sm9_fp12_set_w_sqr(sm9_fp12_t r);
void sm9_fp12_set_fp(sm9_fp12_t r, const sm9_fp_t a);
void sm9_fp12_set_fp2(sm9_fp12_t r, const sm9_fp2_t a);
void sm9_fp12_set_fp4(sm9_fp12_t r, const sm9_fp4_t a);
void sm9_fp12_set(sm9_fp12_t r, const sm9_fp4_t a0, const sm9_fp4_t a1, const sm9_fp4_t a2);
void sm9_fp12_copy(sm9_fp12_t r, const sm9_fp12_t a);
int  sm9_fp12_rand(sm9_fp12_t r);
int  sm9_fp12_is_one(const sm9_fp12_t a);
int  sm9_fp12_is_zero(const sm9_fp12_t a);
int  sm9_fp12_equ(const sm9_fp12_t a, const sm9_fp12_t b);
void sm9_fp12_add(sm9_fp12_t r, const sm9_fp12_t a, const sm9_fp12_t b);
void sm9_fp12_dbl(sm9_fp12_t r, const sm9_fp12_t a);
void sm9_fp12_tri(sm9_fp12_t r, const sm9_fp12_t a);
void sm9_fp12_sub(sm9_fp12_t r, const sm9_fp12_t a, const sm9_fp12_t b);
void sm9_fp12_neg(sm9_fp12_t r, const sm9_fp12_t a);
void sm9_fp12_mul(sm9_fp12_t r, const sm9_fp12_t a, const sm9_fp12_t b);
void sm9_fp12_sqr(sm9_fp12_t r, const sm9_fp12_t a);
void sm9_fp12_inv(sm9_fp12_t r, const sm9_fp12_t a);
void sm9_fp12_pow(sm9_fp12_t r, const sm9_fp12_t a, const sm9_bn_t k);
void sm9_fp12_to_bytes(const sm9_fp12_t a, uint8_t buf[32 * 12]);
int  sm9_fp12_from_bytes(sm9_fp12_t r, const uint8_t in[32 * 12]);
void sm9_fp12_to_hex(const sm9_fp12_t a, char hex[65 * 12]);
int  sm9_fp12_from_hex(sm9_fp12_t r, const char hex[65 * 12]); // 这个明显是不对的
void sm9_fp12_print(const char *prefix, const sm9_fp12_t a);


void sm9_fp2_conjugate(sm9_fp2_t r, const sm9_fp2_t a);
void sm9_fp2_frobenius(sm9_fp2_t r, const sm9_fp2_t a);
void sm9_fp4_frobenius(sm9_fp4_t r, const sm9_fp4_t a);
void sm9_fp4_conjugate(sm9_fp4_t r, const sm9_fp4_t a);
void sm9_fp4_frobenius2(sm9_fp4_t r, const sm9_fp4_t a);
void sm9_fp4_frobenius3(sm9_fp4_t r, const sm9_fp4_t a);
void sm9_fp12_frobenius(sm9_fp12_t r, const sm9_fp12_t x);
void sm9_fp12_frobenius2(sm9_fp12_t r, const sm9_fp12_t x);
void sm9_fp12_frobenius3(sm9_fp12_t r, const sm9_fp12_t x);
void sm9_fp12_frobenius6(sm9_fp12_t r, const sm9_fp12_t x);


typedef struct {
	sm9_fp_t X;
	sm9_fp_t Y;
	sm9_fp_t Z;
} SM9_POINT;

#define sm9_point_init(R)	sm9_point_set_infinity(R)
#define sm9_point_clean(R)	sm9_point_set_infinity(R)

void sm9_point_set_infinity(SM9_POINT *R);
void sm9_point_copy(SM9_POINT *R, const SM9_POINT *P);
void sm9_point_get_xy(const SM9_POINT *P, sm9_fp_t x, sm9_fp_t y);
int  sm9_point_is_at_infinity(const SM9_POINT *P);
int  sm9_point_equ(const SM9_POINT *P, const SM9_POINT *Q);
int  sm9_point_is_on_curve(const SM9_POINT *P);
void sm9_point_dbl(SM9_POINT *R, const SM9_POINT *P);
void sm9_point_add(SM9_POINT *R, const SM9_POINT *P, const SM9_POINT *Q);
void sm9_point_neg(SM9_POINT *R, const SM9_POINT *P);
void sm9_point_sub(SM9_POINT *R, const SM9_POINT *P, const SM9_POINT *Q);
void sm9_point_mul(SM9_POINT *R, const sm9_bn_t k, const SM9_POINT *P);
void sm9_point_mul_generator(SM9_POINT *R, const sm9_bn_t k);
void sm9_point_from_hex(SM9_POINT *R, const char hex[65 * 2]);		
int sm9_point_to_uncompressed_octets(const SM9_POINT *P, uint8_t octets[65]);
int sm9_point_from_uncompressed_octets(SM9_POINT *P, const uint8_t octets[65]);
int sm9_point_print(FILE *fp, int fmt, int ind, const char *label, const SM9_POINT *P);


typedef struct {
	sm9_fp2_t X;
	sm9_fp2_t Y;
	sm9_fp2_t Z;
} SM9_TWIST_POINT;

#define sm9_twist_point_copy(R, P)	memcpy((R), (P), sizeof(SM9_TWIST_POINT))

int sm9_twist_point_to_uncompressed_octets(const SM9_TWIST_POINT *P, uint8_t octets[129]);
int sm9_twist_point_from_uncompressed_octets(SM9_TWIST_POINT *P, const uint8_t octets[129]);


void sm9_twist_point_from_hex(SM9_TWIST_POINT *R, const char hex[65 * 4]);
int  sm9_twist_point_is_at_infinity(const SM9_TWIST_POINT *P);
void sm9_twist_point_set_infinity(SM9_TWIST_POINT *R);
void sm9_twist_point_get_xy(const SM9_TWIST_POINT *P, sm9_fp2_t x, sm9_fp2_t y);

int  sm9_twist_point_equ(const SM9_TWIST_POINT *P, const SM9_TWIST_POINT *Q);
int  sm9_twist_point_is_on_curve(const SM9_TWIST_POINT *P);
void sm9_twist_point_neg(SM9_TWIST_POINT *R, const SM9_TWIST_POINT *P);
void sm9_twist_point_dbl(SM9_TWIST_POINT *R, const SM9_TWIST_POINT *P);
void sm9_twist_point_add(SM9_TWIST_POINT *R, const SM9_TWIST_POINT *P, const SM9_TWIST_POINT *Q);
void sm9_twist_point_sub(SM9_TWIST_POINT *R, const SM9_TWIST_POINT *P, const SM9_TWIST_POINT *Q);
void sm9_twist_point_add_full(SM9_TWIST_POINT *R, const SM9_TWIST_POINT *P, const SM9_TWIST_POINT *Q);
void sm9_twist_point_mul(SM9_TWIST_POINT *R, const sm9_bn_t k, const SM9_TWIST_POINT *P);
void sm9_twist_point_mul_generator(SM9_TWIST_POINT *R, const sm9_bn_t k);
int sm9_twist_point_print(FILE *fp, int fmt, int ind, const char *label, const SM9_TWIST_POINT *P);



void sm9_eval_g_tangent(sm9_fp12_t num, sm9_fp12_t den, const SM9_TWIST_POINT *P, const SM9_POINT *Q);
void sm9_eval_g_line(sm9_fp12_t num, sm9_fp12_t den, const SM9_TWIST_POINT *T, const SM9_TWIST_POINT *P, const SM9_POINT *Q);
void sm9_twist_point_pi1(SM9_TWIST_POINT *R, const SM9_TWIST_POINT *P);
void sm9_twist_point_pi2(SM9_TWIST_POINT *R, const SM9_TWIST_POINT *P);
void sm9_twist_point_neg_pi2(SM9_TWIST_POINT *R, const SM9_TWIST_POINT *P);
void sm9_final_exponent_hard_part(sm9_fp12_t r, const sm9_fp12_t f);
void sm9_final_exponent(sm9_fp12_t r, const sm9_fp12_t f);
void sm9_pairing(sm9_fp12_t r, const SM9_TWIST_POINT *Q, const SM9_POINT *P);


/* private key extract algorithms */
#define SM9_HID_SIGN		0x01
#define SM9_HID_EXCH		0x02
#define SM9_HID_ENC		0x03

#define SM9_HASH1_PREFIX	0x01
#define SM9_HASH2_PREFIX	0x02

int sm9_hash1(sm9_bn_t h1, const char *id, size_t idlen, uint8_t hid);


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
	SM9_TWIST_POINT Ppubs; // Ppubs = ks * P2
	sm9_fn_t ks;
} SM9_SIGN_MASTER_KEY;

typedef struct {
	SM9_TWIST_POINT Ppubs;
	SM9_POINT ds;
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
	sm9_fn_t h;
	SM9_POINT S;
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
	SM9_POINT Ppube; // Ppube = ke * P1
	sm9_fn_t ke;
} SM9_ENC_MASTER_KEY;

typedef struct {
	SM9_POINT Ppube;
	SM9_TWIST_POINT de;
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

int sm9_kem_encrypt(const SM9_ENC_MASTER_KEY *mpk, const char *id, size_t idlen, size_t klen, uint8_t *kbuf, SM9_POINT *C);
int sm9_kem_decrypt(const SM9_ENC_KEY *key, const char *id, size_t idlen, const SM9_POINT *C, size_t klen, uint8_t *kbuf);
int sm9_do_encrypt(const SM9_ENC_MASTER_KEY *mpk, const char *id, size_t idlen,
	const uint8_t *in, size_t inlen, SM9_POINT *C1, uint8_t *c2, uint8_t c3[SM3_HMAC_SIZE]);
int sm9_do_decrypt(const SM9_ENC_KEY *key, const char *id, size_t idlen,
	const SM9_POINT *C1, const uint8_t *c2, size_t c2len, const uint8_t c3[SM3_HMAC_SIZE], uint8_t *out);

#define SM9_MAX_PLAINTEXT_SIZE 255
#define SM9_MAX_CIPHERTEXT_SIZE 367 // calculated in test_sm9_ciphertext()
int sm9_ciphertext_to_der(const SM9_POINT *C1, const uint8_t *c2, size_t c2len,
	const uint8_t c3[SM3_HMAC_SIZE], uint8_t **out, size_t *outlen);
int sm9_ciphertext_from_der(SM9_POINT *C1, const uint8_t **c2, size_t *c2len,
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
