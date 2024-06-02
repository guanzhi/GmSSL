/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#ifndef GMSSL_SM2_Z256_H
#define GMSSL_SM2_Z256_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif


// z256 means compact presentation of uint256
typedef uint64_t sm2_z256_t[4];
typedef uint64_t sm2_z512_t[8];


void sm2_z256_set_one(sm2_z256_t r);
void sm2_z256_set_zero(sm2_z256_t r);

int  sm2_z256_rand_range(sm2_z256_t r, const sm2_z256_t range);
void sm2_z256_copy(sm2_z256_t r, const sm2_z256_t a);
void sm2_z256_copy_conditional(sm2_z256_t dst, const sm2_z256_t src, uint64_t move);
void sm2_z256_from_bytes(sm2_z256_t r, const uint8_t in[32]);
void sm2_z256_to_bytes(const sm2_z256_t a, uint8_t out[32]);
int  sm2_z256_cmp(const sm2_z256_t a, const sm2_z256_t b);
uint64_t sm2_z256_is_zero(const sm2_z256_t a);
uint64_t sm2_z256_equ(const sm2_z256_t a, const sm2_z256_t b);
void sm2_z256_rshift(sm2_z256_t r, const sm2_z256_t a, unsigned int nbits);
uint64_t sm2_z256_add(sm2_z256_t r, const sm2_z256_t a, const sm2_z256_t b);
uint64_t sm2_z256_sub(sm2_z256_t r, const sm2_z256_t a, const sm2_z256_t b);
void sm2_z256_mul(sm2_z512_t r, const sm2_z256_t a, const sm2_z256_t b);
int  sm2_z256_get_booth(const sm2_z256_t a, unsigned int window_size, int i);
void sm2_z256_from_hex(sm2_z256_t r, const char *hex);
int  sm2_z256_equ_hex(const sm2_z256_t a, const char *hex);
int  sm2_z256_print(FILE *fp, int ind, int fmt, const char *label, const sm2_z256_t a);

void sm2_z256_modp_add(sm2_z256_t r, const sm2_z256_t a, const sm2_z256_t b);
void sm2_z256_modp_dbl(sm2_z256_t r, const sm2_z256_t a);
void sm2_z256_modp_tri(sm2_z256_t r, const sm2_z256_t a);
void sm2_z256_modp_sub(sm2_z256_t r, const sm2_z256_t a, const sm2_z256_t b);
void sm2_z256_modp_neg(sm2_z256_t r, const sm2_z256_t a);
void sm2_z256_modp_haf(sm2_z256_t r, const sm2_z256_t a);

void sm2_z256_modp_to_mont(const sm2_z256_t a, sm2_z256_t r);
void sm2_z256_modp_from_mont(sm2_z256_t r, const sm2_z256_t a);
void sm2_z256_modp_mont_mul(sm2_z256_t r, const sm2_z256_t a, const sm2_z256_t b);
void sm2_z256_modp_mont_sqr(sm2_z256_t r, const sm2_z256_t a);
void sm2_z256_modp_mont_exp(sm2_z256_t r, const sm2_z256_t a, const sm2_z256_t e);
void sm2_z256_modp_mont_inv(sm2_z256_t r, const sm2_z256_t a);
int  sm2_z256_modp_mont_sqrt(sm2_z256_t r, const sm2_z256_t a);

void sm2_z256_modn_add(sm2_z256_t r, const sm2_z256_t a, const sm2_z256_t b);
void sm2_z256_modn_sub(sm2_z256_t r, const sm2_z256_t a, const sm2_z256_t b);
void sm2_z256_modn_neg(sm2_z256_t r, const sm2_z256_t a);
void sm2_z256_modn_mul(sm2_z256_t r, const sm2_z256_t a, const sm2_z256_t b);
void sm2_z256_modn_sqr(sm2_z256_t r, const sm2_z256_t a);
void sm2_z256_modn_exp(sm2_z256_t r, const sm2_z256_t a, const sm2_z256_t e);
void sm2_z256_modn_inv(sm2_z256_t r, const sm2_z256_t a);

void sm2_z256_modn_to_mont(const sm2_z256_t a, sm2_z256_t r);
void sm2_z256_modn_from_mont(sm2_z256_t r, const sm2_z256_t a);
void sm2_z256_modn_mont_mul(sm2_z256_t r, const sm2_z256_t a, const sm2_z256_t b);
void sm2_z256_modn_mont_sqr(sm2_z256_t r, const sm2_z256_t a);
void sm2_z256_modn_mont_exp(sm2_z256_t r, const sm2_z256_t a, const sm2_z256_t e);
void sm2_z256_modn_mont_inv(sm2_z256_t r, const sm2_z256_t a);


typedef struct {
	sm2_z256_t X;
	sm2_z256_t Y;
	sm2_z256_t Z;
} SM2_Z256_POINT;

void sm2_z256_point_set_infinity(SM2_Z256_POINT *P);
int  sm2_z256_point_is_at_infinity(const SM2_Z256_POINT *P);
int  sm2_z256_point_to_bytes(const SM2_Z256_POINT *P, uint8_t out[64]);
int  sm2_z256_point_from_bytes(SM2_Z256_POINT *P, const uint8_t in[64]);
int  sm2_z256_point_from_hex(SM2_Z256_POINT *P, const char *hex);
int  sm2_z256_point_equ_hex(const SM2_Z256_POINT *P, const char *hex);
int  sm2_z256_point_is_on_curve(const SM2_Z256_POINT *P);
int  sm2_z256_point_equ(const SM2_Z256_POINT *P, const SM2_Z256_POINT *Q); // equivalent jacobian points
int  sm2_z256_point_get_xy(const SM2_Z256_POINT *P, uint64_t x[4], uint64_t y[4]);

void sm2_z256_point_dbl(SM2_Z256_POINT *R, const SM2_Z256_POINT *A);
void sm2_z256_point_add(SM2_Z256_POINT *r, const SM2_Z256_POINT *a, const SM2_Z256_POINT *b);
void sm2_z256_point_neg(SM2_Z256_POINT *R, const SM2_Z256_POINT *P);
void sm2_z256_point_sub(SM2_Z256_POINT *R, const SM2_Z256_POINT *A, const SM2_Z256_POINT *B);
void sm2_z256_point_get_affine(const SM2_Z256_POINT *P, uint64_t x[4], uint64_t y[4]);
int  sm2_z256_point_print(FILE *fp, int fmt, int ind, const char *label, const SM2_Z256_POINT *P);


typedef struct {
	sm2_z256_t x;
	sm2_z256_t y;
} SM2_Z256_AFFINE_POINT;

void sm2_z256_point_copy_affine(SM2_Z256_POINT *R, const SM2_Z256_AFFINE_POINT *P);
void sm2_z256_point_add_affine(SM2_Z256_POINT *r, const SM2_Z256_POINT *a, const SM2_Z256_AFFINE_POINT *b);
void sm2_z256_point_sub_affine(SM2_Z256_POINT *R, const SM2_Z256_POINT *A, const SM2_Z256_AFFINE_POINT *B);
int sm2_z256_point_affine_print(FILE *fp, int fmt, int ind, const char *label, const SM2_Z256_AFFINE_POINT *P);

void sm2_z256_point_mul_generator(SM2_Z256_POINT *R, const sm2_z256_t k);
void sm2_z256_point_mul_pre_compute(const SM2_Z256_POINT *P, SM2_Z256_POINT T[16]);
void sm2_z256_point_mul_ex(SM2_Z256_POINT *R, const sm2_z256_t k, const SM2_Z256_POINT P_table[16]);
void sm2_z256_point_mul(SM2_Z256_POINT *R, const sm2_z256_t k, const SM2_Z256_POINT *P);
void sm2_z256_point_mul_sum(SM2_Z256_POINT *R, const sm2_z256_t t, const SM2_Z256_POINT *P, const sm2_z256_t s);


const uint64_t *sm2_z256_prime(void);
const uint64_t *sm2_z256_order(void);
const uint64_t *sm2_z256_order_minus_one(void);
const uint64_t *sm2_z256_one(void);


enum {
	SM2_point_at_infinity = 0x00,
	SM2_point_compressed_y_even = 0x02,
	SM2_point_compressed_y_odd = 0x03,
	SM2_point_uncompressed = 0x04,
	SM2_point_uncompressed_y_even = 0x06,
	SM2_point_uncompressed_y_odd = 0x07,
};

int sm2_z256_point_from_x_bytes(SM2_Z256_POINT *P, const uint8_t x_bytes[32], int y_is_odd);
int sm2_z256_point_from_hash(SM2_Z256_POINT *R, const uint8_t *data, size_t datalen, int y_is_odd);
int sm2_z256_point_from_octets(SM2_Z256_POINT *P, const uint8_t *in, size_t inlen);

int sm2_z256_point_to_uncompressed_octets(const SM2_Z256_POINT *P, uint8_t out[65]);
int sm2_z256_point_to_compressed_octets(const SM2_Z256_POINT *P, uint8_t out[33]);

/*
RFC 5480 Elliptic Curve Cryptography Subject Public Key Information
ECPoint ::= OCTET STRING
*/
#define SM2_POINT_MAX_SIZE (2 + 65)
int sm2_z256_point_to_der(const SM2_Z256_POINT *P, uint8_t **out, size_t *outlen);
int sm2_z256_point_from_der(SM2_Z256_POINT *P, const uint8_t **in, size_t *inlen);
int sm2_z256_point_print(FILE *fp, int fmt, int ind, const char *label, const SM2_Z256_POINT *P);



#ifdef __cplusplus
}
#endif
#endif
