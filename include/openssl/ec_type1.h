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
/*
 * type1curve is supersingular curve E: y^2 = x^3 + 1 (mod p) over prime field.
 * p = 11 (mod 12)
 * a = 0
 * b = 1
 * G = (x, y)
 * n is the order of (x, y)
 * h = (p + 1)/n
 */

#ifndef HEADER_EC_TYPE1_H
#define HEADER_EC_TYPE1_H

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/bn_gfp2.h>

#ifdef __cplusplus
extern "C" {
#endif



EC_GROUP *EC_GROUP_new_type1curve(const BIGNUM *p, const BIGNUM *x,
	const BIGNUM *y, const BIGNUM *order, BN_CTX *ctx);

EC_GROUP *EC_GROUP_new_type1curve_ex(const BIGNUM *p, const BIGNUM *a,
	const BIGNUM *b, const unsigned char *point, size_t pointlen,
	const BIGNUM *order, const BIGNUM *cofactor, BN_CTX *bn_ctx);

int EC_GROUP_is_type1curve(const EC_GROUP *group, BN_CTX *ctx);

BN_GFP2 *EC_GROUP_get_type1curve_zeta(const EC_GROUP *group, BN_CTX *ctx);

BIGNUM *EC_GROUP_get_type1curve_eta(const EC_GROUP *group, BN_CTX *ctx);

/* compute tate pairing e(P, Q) over type1curve */
int EC_type1curve_tate(const EC_GROUP *group, BN_GFP2 *r,
	const EC_POINT *P, const EC_POINT *Q, BN_CTX *ctx);

/* compute tate pairing ratio e(P1, Q1)/e(P2, Q2) over type1curve*/
int EC_type1curve_tate_ratio(const EC_GROUP *group, BN_GFP2 *r,
	const EC_POINT *P1, const EC_POINT *Q1, const EC_POINT *P2,
	const EC_POINT *Q2, BN_CTX *bn_ctx);



#ifdef __cplusplus
}
#endif
#endif
