/*
 *  Copyright 2014-2025 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GMSSL_KYBER_H
#define GMSSL_KYBER_H


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif



#define KYBER_Q 3329
#define KYBER_ZETA 17
#define KYBER_N 256
#define KYBER_ETA2 2
#define KYBER_POLY_NBYTES (256 * 12 / 8)

#define KYBER512_K		2
#define KYBER768_K		3
#define KYBER1024_K		4

#define KYBER512_ETA1		3
#define KYBER768_ETA1		2
#define KYBER1024_ETA1		2

#define KYBER512_DU	10
#define KYBER768_DU	10
#define KYBER1024_DU	11

#define KYBER512_DV	4
#define KYBER769_DV	4
#define KYBER1024_DV	5

#define KYBER_K		KYBER512_K
#define KYBER_ETA1	KYBER512_ETA1
#define KYBER_DU	KYBER512_DU
#define KYBER_DV	KYBER512_DV


#define KYBER_C1_SIZE	((256 * KYBER_DU)/8)
#define KYBER_C2_SIZE	((256 * KYBER_DV)/8)


#define KYBER_TEST


/*
CRYSTALS-Kyber Algorithm Specifications and Supporing Documentation (version 3.02)


			FIPS-202		90s

	XOF		SHAKE-128		AES256-CTR		MGF1-SM3
	H		SHA3-256		SHA256			SM3
	G		SHA3-512		SHA512			MGF1-SM3
	PRF(s,b)	SHAKE-256(s||b)		AES256-CTR		HKDF-SM3
	KDF		SHAKE-256		SHA256			HKDF-SM3

*/


typedef int16_t kyber_poly_t[256];

typedef struct {
	uint8_t t[KYBER_K][384];
	uint8_t rho[32];
} KYBER_CPA_PUBLIC_KEY;

typedef struct {
	KYBER_CPA_PUBLIC_KEY public_key;
	uint8_t s[KYBER_K][384];
} KYBER_CPA_PRIVATE_KEY;

typedef struct {
	uint8_t c1[KYBER_K][KYBER_C1_SIZE];
	uint8_t c2[KYBER_C2_SIZE];
} KYBER_CPA_CIPHERTEXT;

int kyber_cpa_public_key_to_bytes(const KYBER_CPA_PUBLIC_KEY *key, uint8_t **out, size_t *outlen);
int kyber_cpa_public_key_from_bytes(KYBER_CPA_PUBLIC_KEY *key, const uint8_t **in, size_t *inlen);
int kyber_cpa_private_key_to_bytes(const KYBER_CPA_PRIVATE_KEY *key, uint8_t **out, size_t *outlen);
int kyber_cpa_private_key_from_bytes(KYBER_CPA_PRIVATE_KEY *key, const uint8_t **in, size_t *inlen);

int kyber_cpa_ciphertext_to_bytes(const KYBER_CPA_CIPHERTEXT *ciphertext, uint8_t **out, size_t *outlen);
int kyber_cpa_ciphertext_from_bytes(KYBER_CPA_CIPHERTEXT *ciphertext, const uint8_t **in, size_t *inlen);

void kyber_h_hash(const uint8_t *in, size_t inlen, uint8_t out[32]);
void kyber_g_hash(const uint8_t *in, size_t inlen, uint8_t out[64]);


#define KYBER_FMT_POLY	1
#define KYBER_FMT_HEX	2

int kyber_poly_print(FILE *fp, int fmt, int ind, const char *label, const kyber_poly_t a);
void kyber_poly_set_zero(kyber_poly_t r);


int kyber_poly_rand(kyber_poly_t r);
int kyber_poly_uniform_sample(kyber_poly_t r, const uint8_t rho[32], uint8_t j, uint8_t i);
int kyber_poly_cbd_sample(kyber_poly_t r, int eta, const uint8_t secret[32], uint8_t n);
int kyber_poly_equ(const kyber_poly_t a, const kyber_poly_t b);
void kyber_poly_add(kyber_poly_t r, const kyber_poly_t a, const kyber_poly_t b);
void kyber_poly_sub(kyber_poly_t r, const kyber_poly_t a, const kyber_poly_t b);


int16_t zeta[256];

void init_zeta(void);

int kyber_poly_ntt(int16_t a[256]);
int kyber_poly_inv_ntt(int16_t a[256]);

int kyber_poly_ntt_mul(kyber_poly_t r, const kyber_poly_t a, const kyber_poly_t b);
void kyber_poly_copy(kyber_poly_t r, const kyber_poly_t a);

int kyber_poly_mul(kyber_poly_t r, const kyber_poly_t a, const kyber_poly_t b);

void kyber_poly_ntt_mul_scalar(kyber_poly_t r, int scalar, const kyber_poly_t a);

int kyber_poly_to_signed(const kyber_poly_t a, kyber_poly_t r);

int kyber_poly_from_signed(kyber_poly_t r, const kyber_poly_t a);
int kyber_poly_compress(const kyber_poly_t a, int dbits, kyber_poly_t z);
int kyber_poly_decompress(kyber_poly_t r, int dbits, const kyber_poly_t z);
int kyber_poly_encode12(const kyber_poly_t a, uint8_t out[384]);
int kyber_poly_decode12(kyber_poly_t r, const uint8_t in[384]);

int kyber_poly_encode10(const kyber_poly_t a, uint8_t out[320]);

int kyber_poly_decode10(kyber_poly_t r, const uint8_t in[320]);

int kyber_poly_encode4(const kyber_poly_t a, uint8_t out[128]);

void kyber_poly_decode4(kyber_poly_t r, const uint8_t in[128]);
void kyber_poly_decode1(kyber_poly_t r, const uint8_t in[32]);
int kyber_poly_encode1(const kyber_poly_t a, uint8_t out[32]);



int kyber_cpa_keygen(KYBER_CPA_PUBLIC_KEY *pk, KYBER_CPA_PRIVATE_KEY *sk);
int kyber_cpa_ciphertext_print(FILE *fp, int fmt, int ind, const char *label, const KYBER_CPA_CIPHERTEXT *c);
int kyber_cpa_ciphertext_print(FILE *fp, int fmt, int ind, const char *label, const KYBER_CPA_CIPHERTEXT *c);
int kyber_cpa_public_key_print(FILE *fp, int fmt, int ind, const char *label, const KYBER_CPA_PUBLIC_KEY *pk);
int kyber_cpa_private_key_print(FILE *fp, int fmt, int ind, const char *label, const KYBER_CPA_PRIVATE_KEY *sk);
int kyber_cpa_encrypt(const KYBER_CPA_PUBLIC_KEY *pk, const uint8_t in[32],
	const uint8_t rand[32], KYBER_CPA_CIPHERTEXT *out);
int kyber_cpa_decrypt(const KYBER_CPA_PRIVATE_KEY *sk, const KYBER_CPA_CIPHERTEXT *in, uint8_t out[32]);


typedef KYBER_CPA_PUBLIC_KEY KYBER_PUBLIC_KEY;


typedef struct {
	KYBER_CPA_PUBLIC_KEY pk;
	KYBER_CPA_PRIVATE_KEY sk;
	uint8_t pk_hash[32];
	uint8_t z[32];
} KYBER_PRIVATE_KEY;


#define KYBER_PUBLIC_KEY_SIZE	sizeof(KYBER_PUBLIC_KEY)
#define KYBER_PRIVATE_KEY_SIZE	sizeof(KYBER_PRIVATE_KEY)



typedef KYBER_CPA_CIPHERTEXT KYBER_CIPHERTEXT;

int kyber_ciphertext_print(FILE *fp, int fmt, int ind, const char *label, const KYBER_CIPHERTEXT *c);

int kyber_ciphertext_to_bytes(const KYBER_CIPHERTEXT *ciphertext, uint8_t **out, size_t *outlen);
int kyber_ciphertext_from_bytes(KYBER_CIPHERTEXT *ciphertext, const uint8_t **in, size_t *inlen);

void kyber_key_cleanup(KYBER_PRIVATE_KEY *key);

int kyber_key_generate(KYBER_PRIVATE_KEY *key);

// generate a single key
int kyber_keygen(KYBER_PUBLIC_KEY *pk, KYBER_PRIVATE_KEY *sk);


int kyber_private_key_print(FILE *fp, int fmt, int ind, const char *label, const KYBER_PRIVATE_KEY *sk);

int kyber_public_key_print(FILE *fp, int fmt, int ind, const char *label, const KYBER_PRIVATE_KEY *pk);
int kyber_encap(const KYBER_PUBLIC_KEY *pk, KYBER_CIPHERTEXT *c, uint8_t K[32]);
int kyber_decap(const KYBER_PRIVATE_KEY *sk, const KYBER_CIPHERTEXT *c, uint8_t K[32]);

int kyber_public_key_to_bytes(const KYBER_PRIVATE_KEY *key, uint8_t **out, size_t *outlen);
int kyber_public_key_from_bytes(KYBER_PRIVATE_KEY *key, const uint8_t **in, size_t *inlen);
int kyber_private_key_to_bytes(const KYBER_PRIVATE_KEY *key, uint8_t **out, size_t *outlen);
int kyber_private_key_from_bytes(KYBER_PRIVATE_KEY *key, const uint8_t **in, size_t *inlen);


#ifdef __cplusplus
}
#endif
#endif
