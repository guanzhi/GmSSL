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
 * this file is to implement elliptic curve operations over extension
 * fields
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/fppoint.h>

ASN1_SEQUENCE(FpPoint) = {
	ASN1_SIMPLE(FpPoint, x, BIGNUM),
	ASN1_SIMPLE(FpPoint, y, BIGNUM)
} ASN1_SEQUENCE_END(FpPoint)
IMPLEMENT_ASN1_FUNCTIONS(FpPoint)
IMPLEMENT_ASN1_DUP_FUNCTION(FpPoint)

int EC_POINT_cmp_fppoint(const EC_GROUP *group, const EC_POINT *a, const FpPoint *b,
	BN_CTX *bn_ctx)
{
	int ret = -1;
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;

	if (!group || !a || !b || !bn_ctx) {
		ECerr(EC_F_EC_POINT_CMP_FPPOINT, ERR_R_PASSED_NULL_PARAMETER);
		return -1;
	}

	BN_CTX_start(bn_ctx);
	x = BN_CTX_get(bn_ctx);
	y = BN_CTX_get(bn_ctx);

	if (!x || !y) {
		ECerr(EC_F_EC_POINT_CMP_FPPOINT, ERR_R_BN_LIB);
		goto end;
	}

	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field) {
		if (!EC_POINT_get_affine_coordinates_GFp(group, a, x, y, bn_ctx)) {
			ECerr(EC_F_EC_POINT_CMP_FPPOINT, ERR_R_EC_LIB);
			goto end;
		}
	} else {
		if (!EC_POINT_get_affine_coordinates_GF2m(group, a, x, y, bn_ctx)) {
			ECerr(EC_F_EC_POINT_CMP_FPPOINT, ERR_R_EC_LIB);
			goto end;
		}
	}

	if (BN_cmp(x, b->x) == 0 && BN_cmp(y, b->y) == 0) {
		ret = 0;
	} else {
		ret = 1;
	}

end:
	BN_CTX_end(bn_ctx);
	return ret;
}

