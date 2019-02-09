/* ====================================================================
 * Copyright (c) 2016 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#ifndef HEADER_SM9_LCL_H
#define HEADER_SM9_LCL_H

#include <openssl/err.h>
#include <openssl/sm9.h>
#include "../../e_os.h"

/* private key extract algorithms */
#define SM9_HID_SIGN		0x01
#define SM9_HID_EXCH		0x02
#define SM9_HID_ENC		0x03

#define SM9_HASH1		0x01
#define SM9_HASH2		0x02


/* Curve ID */
/* non-supersingular curve over Fp */
#define SM9_CID_TYPE0CURVE	0x10
/* supersingular curve over Fp */
#define SM9_CID_TYPE1CURVE	0x11
/* twist curve over Fp */
#define SM9_CID_TYPE2CURVE	0x12

/* Pairing Type */
#define SM9_EID_TATE		0x01
#define SM9_EID_WEIL		0x02
#define SM9_EID_ATE		0x03
#define SM9_EID_R_ATE		0x04

/* phi() with different embedded degree */
#define SM9_PHI_D2		0x02
#define SM9_PHI_D4		0x04
#define SM9_PHI_D6		0x06


#define SM9_MAX_PLAINTEXT_LENGTH	12800
#define SM9_MAX_CIPHERTEXT_LENGTH 	25600


#ifdef __cplusplus
extern "C" {
#endif


struct SM9_MASTER_KEY_st {
	/* public */
	ASN1_OBJECT *pairing;
	ASN1_OBJECT *scheme;
	ASN1_OBJECT *hash1;
	ASN1_OCTET_STRING *pointPpub;

	/* private */
	BIGNUM *masterSecret;

	int references;
	int flags;
	CRYPTO_EX_DATA ex_data;
	CRYPTO_RWLOCK *lock;
};

struct SM9_KEY_st {
	/* public */
	ASN1_OBJECT *pairing;
	ASN1_OBJECT *scheme;
	ASN1_OBJECT *hash1;
	ASN1_OCTET_STRING *pointPpub;
	ASN1_OCTET_STRING *identity;
	ASN1_OCTET_STRING *publicPoint;

	/* private */
	ASN1_OCTET_STRING *privatePoint;

	int references;
	int flags;
	CRYPTO_EX_DATA ex_data;
	CRYPTO_RWLOCK *lock;
};

struct SM9Ciphertext_st {
	ASN1_OCTET_STRING *pointC1; /* point over E(F_p) */
	ASN1_OCTET_STRING *c2; /* ciphertext */
	ASN1_OCTET_STRING *c3; /* mac-tag */
};

struct SM9Signature_st {
	BIGNUM *h; /* hash */
	ASN1_OCTET_STRING *pointS; /* point over E'(F_p^2) */
};

int SM9_hash1(const EVP_MD *md, BIGNUM **r,
	const char *id, size_t idlen, unsigned char hid,
	const BIGNUM *range, BN_CTX *ctx);

int SM9_hash2(const EVP_MD *md, BIGNUM **r,
	const unsigned char *data, size_t datalen,
	const unsigned char *elem, size_t elemlen,
	const BIGNUM *range, BN_CTX *ctx);

const BIGNUM *SM9_get0_prime(void);
const BIGNUM *SM9_get0_order(void);
const BIGNUM *SM9_get0_order_minus_one(void);
const BIGNUM *SM9_get0_loop_count(void);
const BIGNUM *SM9_get0_final_exponent(void);
const BIGNUM *SM9_get0_fast_final_exponent_p20(void);
const BIGNUM *SM9_get0_fast_final_exponent_p21(void);
const BIGNUM *SM9_get0_fast_final_exponent_p22(void);
const BIGNUM *SM9_get0_fast_final_exponent_p23(void);
const BIGNUM *SM9_get0_fast_final_exponent_p3(void);
const BIGNUM *SM9_get0_generator2_x0(void);
const BIGNUM *SM9_get0_generator2_x1(void);
const BIGNUM *SM9_get0_generator2_y0(void);
const BIGNUM *SM9_get0_generator2_y1(void);

typedef BIGNUM *fp2_t[2];
typedef fp2_t fp4_t[2];
typedef fp4_t fp12_t[3];
typedef struct point_t {
	fp2_t X;
	fp2_t Y;
	fp2_t Z;
} point_t;

int fp12_init(fp12_t a, BN_CTX *ctx);
int fp12_mul(fp12_t r, const fp12_t a, const fp12_t b, const BIGNUM *p, BN_CTX *ctx);
int fp12_pow(fp12_t r, const fp12_t a, const BIGNUM *k, const BIGNUM *p, BN_CTX *ctx);
int fp12_to_bin(const fp12_t a, unsigned char to[384]);
int fp12_print(const fp12_t a);
void fp12_cleanup(fp12_t a);

int point_init(point_t *P, BN_CTX *ctx);
int point_copy(point_t *R, const point_t *P);
void point_print(const point_t *P);
int point_equ(const point_t *P, const point_t *Q);
int point_is_on_curve(point_t *P, const BIGNUM *p, BN_CTX *ctx);
int point_to_octets(const point_t *P, unsigned char to[129], BN_CTX *ctx);
int point_from_octets(point_t *P, const unsigned char from[129], const BIGNUM *p, BN_CTX *ctx);
int point_add(point_t *R, const point_t *A, const point_t *B, const BIGNUM *p, BN_CTX *ctx);
int point_mul(point_t *R, const BIGNUM *k, const point_t *P, const BIGNUM *p, BN_CTX *ctx);
int point_mul_generator(point_t *R, const BIGNUM *k, const BIGNUM *p, BN_CTX *ctx);
void point_cleanup(point_t *P);

int rate_pairing(fp12_t r, const point_t *Q, const EC_POINT *P, BN_CTX *ctx);

int sm9_check_pairing(int nid);
int sm9_check_scheme(int nid);
int sm9_check_hash1(int nid);
int sm9_check_encrypt_scheme(int nid);
int sm9_check_sign_scheme(int nid);

#ifdef __cplusplus
}
#endif
#endif
