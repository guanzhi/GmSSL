/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#ifndef GMSSL_SECP384R1_H
#define GMSSL_SECP384R1_H


#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>


#ifdef __cplusplus
extern "C" {
#endif


// p = 2^384 - 2^128 - 2^96 + 2^32 - 1
//   = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF
// a = -3
// b = 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef
// x = 0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7
// y = 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f
// n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
// h = 1


typedef uint32_t secp384r1_t[12];

#define SECP384R1_K (sizeof(secp384r1_t)/sizeof(uint32_t))

extern const secp384r1_t SECP384R1_P;
extern const secp384r1_t SECP384R1_B;
extern const secp384r1_t SECP384R1_N;
extern const uint32_t SECP384R1_U_P[13];
extern const uint32_t SECP384R1_U_N[13];

int  secp384r1_is_zero(const secp384r1_t a);
int  secp384r1_is_one(const secp384r1_t a);
int  secp384r1_cmp(const secp384r1_t a, const secp384r1_t b);
int  secp384r1_set_zero(secp384r1_t r);
int  secp384r1_set_one(secp384r1_t r);
int  secp384r1_copy(secp384r1_t r, const secp384r1_t a);
int  secp384r1_to_48bytes(const secp384r1_t a, uint8_t out[48]);
int  secp384r1_from_48bytes(secp384r1_t r, const uint8_t in[48]);
int  secp384r1_print(FILE *fp, int fmt, int ind, const char *label, const secp384r1_t a);

int  secp384r1_modp_add(secp384r1_t r, const secp384r1_t a, const secp384r1_t b);
int  secp384r1_modp_dbl(secp384r1_t r, const secp384r1_t a);
int  secp384r1_modp_tri(secp384r1_t r, const secp384r1_t a);
int  secp384r1_modp_sub(secp384r1_t r, const secp384r1_t a, const secp384r1_t b);
int  secp384r1_modp_neg(secp384r1_t r, const secp384r1_t a);
int  secp384r1_modp_haf(secp384r1_t r, const secp384r1_t a);
int  secp384r1_modp_mul(secp384r1_t r, const secp384r1_t a, const secp384r1_t b);
int  secp384r1_modp_sqr(secp384r1_t r, const secp384r1_t a);
int  secp384r1_modp_exp(secp384r1_t r, const secp384r1_t a, const secp384r1_t e);
int  secp384r1_modp_inv(secp384r1_t r, const secp384r1_t a);

int  secp384r1_modn(secp384r1_t r, const secp384r1_t a);
int  secp384r1_modn_add(secp384r1_t r, const secp384r1_t a, const secp384r1_t b);
int  secp384r1_modn_dbl(secp384r1_t r, const secp384r1_t a);
int  secp384r1_modn_tri(secp384r1_t r, const secp384r1_t a);
int  secp384r1_modn_sub(secp384r1_t r, const secp384r1_t a, const secp384r1_t b);
int  secp384r1_modn_neg(secp384r1_t r, const secp384r1_t a);
int  secp384r1_modn_mul(secp384r1_t r, const secp384r1_t a, const secp384r1_t b);
int  secp384r1_modn_sqr(secp384r1_t r, const secp384r1_t a);
int  secp384r1_modn_exp(secp384r1_t r, const secp384r1_t a, const secp384r1_t e);
int  secp384r1_modn_inv(secp384r1_t r, const secp384r1_t a);


typedef struct {
	secp384r1_t X;
	secp384r1_t Y;
	secp384r1_t Z;
} SECP384R1_POINT;

const SECP384R1_POINT *secp384r1_generator(void);
#define SECP384R1_POINT_G (*secp384r1_generator())

int  secp384r1_point_set_infinity(SECP384R1_POINT *R);
int  secp384r1_point_is_at_infinity(const SECP384R1_POINT *P);
int  secp384r1_point_is_on_curve(const SECP384R1_POINT *P);
int  secp384r1_point_equ(const SECP384R1_POINT *P, const SECP384R1_POINT *Q);
int  secp384r1_point_set_xy(SECP384R1_POINT *R, const secp384r1_t x, const secp384r1_t y);
int  secp384r1_point_get_xy(const SECP384R1_POINT *P, secp384r1_t x, secp384r1_t y);
int  secp384r1_point_copy(SECP384R1_POINT *R, const SECP384R1_POINT *P);
int  secp384r1_point_dbl(SECP384R1_POINT *R, const SECP384R1_POINT *P);
int  secp384r1_point_add(SECP384R1_POINT *R, const SECP384R1_POINT *P, const SECP384R1_POINT *Q);
int  secp384r1_point_neg(SECP384R1_POINT *R, const SECP384R1_POINT *P);
int  secp384r1_point_sub(SECP384R1_POINT *R, const SECP384R1_POINT *P, const SECP384R1_POINT *Q);
int  secp384r1_point_mul(SECP384R1_POINT *R, const secp384r1_t k, const SECP384R1_POINT *P);
int  secp384r1_point_mul_generator(SECP384R1_POINT *R, const secp384r1_t k);
int  secp384r1_point_print(FILE *fp, int fmt, int ind, const char *label, const SECP384R1_POINT *P);
int  secp384r1_point_to_uncompressed_octets(const SECP384R1_POINT *P, uint8_t octets[97]);
int  secp384r1_point_from_uncompressed_octets(SECP384R1_POINT *P, const uint8_t octets[97]);


#ifdef __cplusplus
}
#endif
#endif
