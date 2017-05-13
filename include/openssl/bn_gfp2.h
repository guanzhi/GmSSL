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

#ifndef HEADER_BN_GFP2_H
#define HEADER_BN_GFP2_H

#include <openssl/bn.h>

#ifdef __cplusplus
extern "C" {
#endif

/* element a in GF(p^2), where a = a0 + a1 * i, i^2 == -1 */
typedef struct {
	BIGNUM *a0;
	BIGNUM *a1;
} BN_GFP2;

BN_GFP2 *BN_GFP2_new(void);
void BN_GFP2_free(BN_GFP2 *a);
int BN_GFP2_copy(BN_GFP2 *r, const BN_GFP2 *a);
int BN_GFP2_one(BN_GFP2 *a);
int BN_GFP2_zero(BN_GFP2 *a);
int BN_GFP2_is_zero(const BN_GFP2 *a);
int BN_GFP2_equ(const BN_GFP2 *a, const BN_GFP2 *b);
int BN_GFP2_add(BN_GFP2 *r, const BN_GFP2 *a, const BN_GFP2 *b, const BIGNUM *p, BN_CTX *ctx);
int BN_GFP2_sub(BN_GFP2 *r, const BN_GFP2 *a, const BN_GFP2 *b, const BIGNUM *p, BN_CTX *ctx);
int BN_GFP2_mul(BN_GFP2 *r, const BN_GFP2 *a, const BN_GFP2 *b, const BIGNUM *p, BN_CTX *ctx);
int BN_GFP2_sqr(BN_GFP2 *r, const BN_GFP2 *a, const BIGNUM *p, BN_CTX *ctx);
int BN_GFP2_inv(BN_GFP2 *r, const BN_GFP2 *a, const BIGNUM *p, BN_CTX *ctx);
int BN_GFP2_div(BN_GFP2 *r, const BN_GFP2 *a, const BN_GFP2 *b, const BIGNUM *p, BN_CTX *ctx);
int BN_GFP2_exp(BN_GFP2 *r, const BN_GFP2 *a, const BIGNUM *k, const BIGNUM *p, BN_CTX *ctx);
int BN_GFP2_set_bn(BN_GFP2 *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int BN_GFP2_add_bn(BN_GFP2 *r, const BN_GFP2 *a, const BIGNUM *b, const BIGNUM *p,BN_CTX *ctx);
int BN_GFP2_sub_bn(BN_GFP2 *r, const BN_GFP2 *a, const BIGNUM *b, const BIGNUM *p, BN_CTX *ctx);
int BN_GFP2_mul_bn(BN_GFP2 *r, const BN_GFP2 *a, const BIGNUM *b, const BIGNUM *p, BN_CTX *ctx);
int BN_GFP2_div_bn(BN_GFP2 *r, const BN_GFP2 *a, const BIGNUM *b, const BIGNUM *p, BN_CTX *ctx);
int BN_bn2gfp2(const BIGNUM *bn, BN_GFP2 *gfp2, const BIGNUM *p, BN_CTX *ctx);
int BN_gfp22bn(const BN_GFP2 *gfp2, BIGNUM *bn, const BIGNUM *p, BN_CTX *ctx);
/*
 * Canonical a = a0 + a1 * i
 * If order is 0 then output a0, a1, else output a1, a0, |a0| = |a1| = |p|.
 */
int BN_GFP2_canonical(const BN_GFP2 *a, unsigned char *out, size_t *outlen,
	int order, const BIGNUM *p, BN_CTX *ctx);

#ifdef __cplusplus
}
#endif
#endif
