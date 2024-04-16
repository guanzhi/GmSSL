/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GMSSL_SM9_H
#define GMSSL_SM9_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <gmssl/sm3.h>
#include <gmssl/sm2.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef uint64_t sm9_z256_t[4];

void sm9_z256_set_one(sm9_z256_t r);
void sm9_z256_set_zero(sm9_z256_t r);
void sm9_z256_copy(sm9_z256_t r, const sm9_z256_t a);
void sm9_z256_copy_conditional(sm9_z256_t r, const sm9_z256_t a, uint64_t move);
int  sm9_z256_cmp(const sm9_z256_t a, const sm9_z256_t b);
uint64_t sm9_z256_is_zero(const sm9_z256_t a);
uint64_t sm9_z256_equ(const sm9_z256_t a, const sm9_z256_t b);
uint64_t sm9_z256_add(sm9_z256_t r, const sm9_z256_t a, const sm9_z256_t b);
uint64_t sm9_z256_sub(sm9_z256_t r, const sm9_z256_t a, const sm9_z256_t b);
void sm9_z256_mul(uint64_t r[8], const sm9_z256_t a, const sm9_z256_t b);
void sm9_z256_from_bytes(sm9_z256_t r, const uint8_t in[32]);
void sm9_z256_to_bytes(const sm9_z256_t a, uint8_t out[32]);
int  sm9_z256_from_hex(sm9_z256_t r, const char *hex);
void sm9_z256_to_hex(const sm9_z256_t r, char hex[64]);
int  sm9_z256_equ_hex(const sm9_z256_t a, const char *hex);
void sm9_z256_to_bits(const sm9_z256_t a, char bits[256]);
int  sm9_z256_rand_range(sm9_z256_t r, const sm9_z256_t range);
void sm9_z256_print_bn(const char *prefix, const sm9_z256_t a);
int  sm9_z256_print(FILE *fp, int ind, int fmt, const char *label, const sm9_z256_t a);

const uint64_t *sm9_z256_prime(void);

void sm9_z256_modp_add(sm9_z256_t r, const sm9_z256_t a, const sm9_z256_t b);
void sm9_z256_modp_sub(sm9_z256_t r, const sm9_z256_t a, const sm9_z256_t b);
void sm9_z256_modp_dbl(sm9_z256_t r, const sm9_z256_t a);
void sm9_z256_modp_tri(sm9_z256_t r, const sm9_z256_t a);
void sm9_z256_modp_haf(sm9_z256_t r, const sm9_z256_t a);
void sm9_z256_modp_neg(sm9_z256_t r, const sm9_z256_t a);

void sm9_z256_modp_to_mont(sm9_z256_t r, const sm9_z256_t a);
void sm9_z256_modp_from_mont(sm9_z256_t r, const sm9_z256_t a);
void sm9_z256_modp_mont_mul(sm9_z256_t r, const sm9_z256_t a, const sm9_z256_t b);
void sm9_z256_modp_mont_sqr(sm9_z256_t r, const sm9_z256_t a);
void sm9_z256_modp_mont_pow(sm9_z256_t r, const sm9_z256_t a, const sm9_z256_t e);
void sm9_z256_modp_mont_inv(sm9_z256_t r, const sm9_z256_t a);

const uint64_t *sm9_z256_order(void);

void sm9_z256_modn_add(sm9_z256_t r, const sm9_z256_t a, const sm9_z256_t b);
void sm9_z256_modn_sub(sm9_z256_t r, const sm9_z256_t a, const sm9_z256_t b);
void sm9_z256_modn_mul(sm9_z256_t r, const sm9_z256_t a, const sm9_z256_t b);
void sm9_z256_modn_pow(sm9_z256_t r, const sm9_z256_t a, const sm9_z256_t e);
void sm9_z256_modn_inv(sm9_z256_t r, const sm9_z256_t a);
void sm9_z256_modn_from_hash(sm9_z256_t h, const uint8_t Ha[40]);


typedef sm9_z256_t sm9_z256_fp2_t[2];

void sm9_z256_fp2_set_one(sm9_z256_fp2_t r);
void sm9_z256_fp2_set_zero(sm9_z256_fp2_t r);
int  sm9_z256_fp2_is_one(const sm9_z256_fp2_t a);
int  sm9_z256_fp2_is_zero(const sm9_z256_fp2_t a);
int  sm9_z256_fp2_equ(const sm9_z256_fp2_t a, const sm9_z256_fp2_t b);
void sm9_z256_fp2_copy(sm9_z256_fp2_t r, const sm9_z256_fp2_t a);
int  sm9_z256_fp2_rand(sm9_z256_fp2_t r);
void sm9_z256_fp2_to_bytes(const sm9_z256_fp2_t a, uint8_t buf[64]);
int  sm9_z256_fp2_from_bytes(sm9_z256_fp2_t r, const uint8_t buf[64]);
void sm9_z256_fp2_to_hex(const sm9_z256_fp2_t a, char hex[129]);
int  sm9_z256_fp2_from_hex(sm9_z256_fp2_t r, const char hex[129]);
void sm9_z256_fp2_add(sm9_z256_fp2_t r, const sm9_z256_fp2_t a, const sm9_z256_fp2_t b);
void sm9_z256_fp2_dbl(sm9_z256_fp2_t r, const sm9_z256_fp2_t a);
void sm9_z256_fp2_tri(sm9_z256_fp2_t r, const sm9_z256_fp2_t a);
void sm9_z256_fp2_sub(sm9_z256_fp2_t r, const sm9_z256_fp2_t a, const sm9_z256_fp2_t b);
void sm9_z256_fp2_neg(sm9_z256_fp2_t r, const sm9_z256_fp2_t a);
void sm9_z256_fp2_a_mul_u(sm9_z256_fp2_t r, sm9_z256_fp2_t a);
void sm9_z256_fp2_mul(sm9_z256_fp2_t r, const sm9_z256_fp2_t a, const sm9_z256_fp2_t b);
void sm9_z256_fp2_mul_u(sm9_z256_fp2_t r, const sm9_z256_fp2_t a, const sm9_z256_fp2_t b);
void sm9_z256_fp2_mul_fp(sm9_z256_fp2_t r, const sm9_z256_fp2_t a, const sm9_z256_t k);
void sm9_z256_fp2_sqr(sm9_z256_fp2_t r, const sm9_z256_fp2_t a);
void sm9_z256_fp2_sqr_u(sm9_z256_fp2_t r, const sm9_z256_fp2_t a);
void sm9_z256_fp2_inv(sm9_z256_fp2_t r, const sm9_z256_fp2_t a);
void sm9_z256_fp2_div(sm9_z256_fp2_t r, const sm9_z256_fp2_t a, const sm9_z256_fp2_t b);
void sm9_z256_fp2_haf(sm9_z256_fp2_t r, const sm9_z256_fp2_t a);
void sm9_z256_fp2_conjugate(sm9_z256_fp2_t r, const sm9_z256_fp2_t a);
void sm9_z256_fp2_frobenius(sm9_z256_fp2_t r, const sm9_z256_fp2_t a);


typedef sm9_z256_fp2_t sm9_z256_fp4_t[2];

int  sm9_z256_fp4_is_zero(const sm9_z256_fp4_t a);
int  sm9_z256_fp4_equ(const sm9_z256_fp4_t a, const sm9_z256_fp4_t b);
int  sm9_z256_fp4_rand(sm9_z256_fp4_t r);
void sm9_z256_fp4_copy(sm9_z256_fp4_t r, const sm9_z256_fp4_t a);
void sm9_z256_fp4_to_bytes(const sm9_z256_fp4_t a, uint8_t buf[128]);
int  sm9_z256_fp4_from_bytes(sm9_z256_fp4_t r, const uint8_t buf[128]);
int  sm9_z256_fp4_from_hex(sm9_z256_fp4_t r, const char hex[65 * 4]);
void sm9_z256_fp4_to_hex(const sm9_z256_fp4_t a, char hex[259]);
void sm9_z256_fp4_add(sm9_z256_fp4_t r, const sm9_z256_fp4_t a, const sm9_z256_fp4_t b);
void sm9_z256_fp4_dbl(sm9_z256_fp4_t r, const sm9_z256_fp4_t a);
void sm9_z256_fp4_sub(sm9_z256_fp4_t r, const sm9_z256_fp4_t a, const sm9_z256_fp4_t b);
void sm9_z256_fp4_neg(sm9_z256_fp4_t r, const sm9_z256_fp4_t a);
void sm9_z256_fp4_haf(sm9_z256_fp4_t r, const sm9_z256_fp4_t a);
void sm9_z256_fp4_a_mul_v(sm9_z256_fp4_t r, sm9_z256_fp4_t a);
void sm9_z256_fp4_mul(sm9_z256_fp4_t r, const sm9_z256_fp4_t a, const sm9_z256_fp4_t b);
void sm9_z256_fp4_mul_fp(sm9_z256_fp4_t r, const sm9_z256_fp4_t a, const sm9_z256_t k);
void sm9_z256_fp4_mul_fp2(sm9_z256_fp4_t r, const sm9_z256_fp4_t a, const sm9_z256_fp2_t b0);
void sm9_z256_fp4_mul_v(sm9_z256_fp4_t r, const sm9_z256_fp4_t a, const sm9_z256_fp4_t b);
void sm9_z256_fp4_sqr(sm9_z256_fp4_t r, const sm9_z256_fp4_t a);
void sm9_z256_fp4_sqr_v(sm9_z256_fp4_t r, const sm9_z256_fp4_t a);
void sm9_z256_fp4_inv(sm9_z256_fp4_t r, const sm9_z256_fp4_t a);
void sm9_z256_fp4_frobenius(sm9_z256_fp4_t r, const sm9_z256_fp4_t a);
void sm9_z256_fp4_conjugate(sm9_z256_fp4_t r, const sm9_z256_fp4_t a);
void sm9_z256_fp4_frobenius2(sm9_z256_fp4_t r, const sm9_z256_fp4_t a);
void sm9_z256_fp4_frobenius3(sm9_z256_fp4_t r, const sm9_z256_fp4_t a);


typedef sm9_z256_fp4_t sm9_z256_fp12_t[3];

void sm9_z256_fp12_set_one(sm9_z256_fp12_t r);
void sm9_z256_fp12_set_zero(sm9_z256_fp12_t r);
void sm9_z256_fp12_copy(sm9_z256_fp12_t r, const sm9_z256_fp12_t a);
int  sm9_z256_fp12_rand(sm9_z256_fp12_t r);
int  sm9_z256_fp12_from_hex(sm9_z256_fp12_t r, const char hex[65 * 12 - 1]);
void sm9_z256_fp12_to_hex(const sm9_z256_fp12_t a, char hex[65 * 12 - 1]);
void sm9_z256_fp12_to_bytes(const sm9_z256_fp12_t a, uint8_t buf[32 * 12]);
int  sm9_z256_fp12_from_bytes(sm9_z256_fp12_t r, const uint8_t buf[32 * 12]);

void sm9_z256_fp12_print(const char *prefix, const sm9_z256_fp12_t a);
void sm9_z256_fp12_set(sm9_z256_fp12_t r, const sm9_z256_fp4_t a0, const sm9_z256_fp4_t a1, const sm9_z256_fp4_t a2);
int  sm9_z256_fp12_equ(const sm9_z256_fp12_t a, const sm9_z256_fp12_t b);
void sm9_z256_fp12_add(sm9_z256_fp12_t r, const sm9_z256_fp12_t a, const sm9_z256_fp12_t b);
void sm9_z256_fp12_dbl(sm9_z256_fp12_t r, const sm9_z256_fp12_t a);
void sm9_z256_fp12_tri(sm9_z256_fp12_t r, const sm9_z256_fp12_t a);
void sm9_z256_fp12_sub(sm9_z256_fp12_t r, const sm9_z256_fp12_t a, const sm9_z256_fp12_t b);
void sm9_z256_fp12_neg(sm9_z256_fp12_t r, const sm9_z256_fp12_t a);
void sm9_z256_fp12_mul(sm9_z256_fp12_t r, const sm9_z256_fp12_t a, const sm9_z256_fp12_t b);
void sm9_z256_fp12_sqr(sm9_z256_fp12_t r, const sm9_z256_fp12_t a);
void sm9_z256_fp12_inv(sm9_z256_fp12_t r, const sm9_z256_fp12_t a);
void sm9_z256_fp12_pow(sm9_z256_fp12_t r, const sm9_z256_fp12_t a, const sm9_z256_t k);
void sm9_z256_fp12_frobenius(sm9_z256_fp12_t r, const sm9_z256_fp12_t x);
void sm9_z256_fp12_frobenius2(sm9_z256_fp12_t r, const sm9_z256_fp12_t x);
void sm9_z256_fp12_frobenius3(sm9_z256_fp12_t r, const sm9_z256_fp12_t x);
void sm9_z256_fp12_frobenius6(sm9_z256_fp12_t r, const sm9_z256_fp12_t x);


// E(F_p): y^2 = x^3 + 5

typedef struct {
	sm9_z256_t X; // is mont(X)
	sm9_z256_t Y; // is mont(Y)
	sm9_z256_t Z; // is mont(Z)
} SM9_Z256_POINT;

const SM9_Z256_POINT *sm9_z256_generator(void);

void sm9_z256_point_from_hex(SM9_Z256_POINT *R, const char hex[65 * 2]);
int  sm9_z256_point_is_at_infinity(const SM9_Z256_POINT *P);
void sm9_z256_point_set_infinity(SM9_Z256_POINT *R);
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
	uint64_t X[4];
	uint64_t Y[4];
} SM9_Z256_AFFINE_POINT;

void sm9_z256_point_copy_affine(SM9_Z256_POINT *R, const SM9_Z256_AFFINE_POINT *P);
void sm9_z256_point_add_affine(SM9_Z256_POINT *R, const SM9_Z256_POINT *P, const SM9_Z256_AFFINE_POINT *Q);
void sm9_z256_point_sub_affine(SM9_Z256_POINT *R, const SM9_Z256_POINT *P, const SM9_Z256_AFFINE_POINT *Q);


typedef struct {
	sm9_z256_fp2_t X;
	sm9_z256_fp2_t Y;
	sm9_z256_fp2_t Z;
} SM9_Z256_TWIST_POINT;

const SM9_Z256_TWIST_POINT *sm9_z256_twist_generator(void);

int sm9_z256_twist_point_to_uncompressed_octets(const SM9_Z256_TWIST_POINT *P, uint8_t octets[129]);
int sm9_z256_twist_point_from_uncompressed_octets(SM9_Z256_TWIST_POINT *P, const uint8_t octets[129]);

int  sm9_z256_twist_point_print(FILE *fp, int fmt, int ind, const char *label, const SM9_Z256_TWIST_POINT *P);
void sm9_z256_twist_point_from_hex(SM9_Z256_TWIST_POINT *R, const char hex[65 * 4]);
int  sm9_z256_twist_point_is_at_infinity(const SM9_Z256_TWIST_POINT *P);
void sm9_z256_twist_point_set_infinity(SM9_Z256_TWIST_POINT *R);
void sm9_z256_twist_point_get_xy(const SM9_Z256_TWIST_POINT *P, sm9_z256_fp2_t x, sm9_z256_fp2_t y);
int  sm9_z256_twist_point_equ(const SM9_Z256_TWIST_POINT *P, const SM9_Z256_TWIST_POINT *Q);
int  sm9_z256_twist_point_is_on_curve(const SM9_Z256_TWIST_POINT *P);
void sm9_z256_twist_point_neg(SM9_Z256_TWIST_POINT *R, const SM9_Z256_TWIST_POINT *P);
void sm9_z256_twist_point_dbl(SM9_Z256_TWIST_POINT *R, const SM9_Z256_TWIST_POINT *P);
void sm9_z256_twist_point_add(SM9_Z256_TWIST_POINT *R, const SM9_Z256_TWIST_POINT *P, const SM9_Z256_TWIST_POINT *Q);
void sm9_z256_twist_point_sub(SM9_Z256_TWIST_POINT *R, const SM9_Z256_TWIST_POINT *P, const SM9_Z256_TWIST_POINT *Q);
void sm9_z256_twist_point_add_full(SM9_Z256_TWIST_POINT *R, const SM9_Z256_TWIST_POINT *P, const SM9_Z256_TWIST_POINT *Q);
void sm9_z256_twist_point_mul(SM9_Z256_TWIST_POINT *R, const sm9_z256_t k, const SM9_Z256_TWIST_POINT *P);
void sm9_z256_twist_point_mul_generator(SM9_Z256_TWIST_POINT *R, const sm9_z256_t k);


void sm9_z256_eval_g_tangent(sm9_z256_fp12_t num, sm9_z256_fp12_t den, const SM9_Z256_TWIST_POINT *P, const SM9_Z256_POINT *Q);
void sm9_z256_eval_g_line(sm9_z256_fp12_t num, sm9_z256_fp12_t den, const SM9_Z256_TWIST_POINT *T, const SM9_Z256_TWIST_POINT *P, const SM9_Z256_POINT *Q);
void sm9_z256_twist_point_pi1(SM9_Z256_TWIST_POINT *R, const SM9_Z256_TWIST_POINT *P);
void sm9_z256_twist_point_pi2(SM9_Z256_TWIST_POINT *R, const SM9_Z256_TWIST_POINT *P);
void sm9_z256_twist_point_neg_pi2(SM9_Z256_TWIST_POINT *R, const SM9_Z256_TWIST_POINT *P);
void sm9_z256_final_exponent_hard_part(sm9_z256_fp12_t r, const sm9_z256_fp12_t f);
void sm9_z256_final_exponent(sm9_z256_fp12_t r, const sm9_z256_fp12_t f);
void sm9_z256_pairing(sm9_z256_fp12_t r, const SM9_Z256_TWIST_POINT *Q, const SM9_Z256_POINT *P);

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




// SM9 Key Exchange (To be continued)
#define SM9_EXCH_MASTER_KEY SM9_ENC_MASTER_KEY
#define SM9_EXCH_KEY SM9_ENC_KEY
#define sm9_exch_master_key_generate(msk) sm9_enc_master_key_generate(msk)
int sm9_exch_master_key_extract_key(SM9_EXCH_MASTER_KEY *master, const char *id, size_t idlen, SM9_EXCH_KEY *key);

int sm9_exch_step_1A(const SM9_EXCH_MASTER_KEY *mpk, const char *idB, size_t idBlen, SM9_Z256_POINT *RA, sm9_z256_t rA);
int sm9_exch_step_1B(const SM9_EXCH_MASTER_KEY *mpk, const char *idA, size_t idAlen, const char *idB, size_t idBlen,
	const SM9_EXCH_KEY *key, const SM9_Z256_POINT *RA, SM9_Z256_POINT *RB, uint8_t *sk, size_t klen);
int sm9_exch_step_2A(const SM9_EXCH_MASTER_KEY *mpk, const char *idA, size_t idAlen, const char *idB, size_t idBlen,
	const SM9_EXCH_KEY *key, const sm9_z256_t rA, const SM9_Z256_POINT *RA, const SM9_Z256_POINT *RB, uint8_t *sk, size_t klen);
int sm9_exch_step_2B();


#ifdef  __cplusplus
}
#endif
#endif
