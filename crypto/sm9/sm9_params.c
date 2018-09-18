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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>


#include "bn_lcl.h"
#include "internal/cryptlib.h"


#define BN_SM9_BN256_TOP (256+BN_BITS2-1)/BN_BITS2
#define BN_SM9_TRACE_TOP (66+BN_BITS2-1)/BN_BITS2

#if BN_BITS == 64
static const BN_ULONG _sm9bn256v1_x2[][BN_SM9_BN256_TOP] = {
	{0xF9B7213BAF82D65BULL, 0xEE265948D19C17ABULL,
	 0xD2AAB97FD34EC120ULL, 0x3722755292130B08ULL},
	{0x54806C11D8806141ULL, 0xF1DD2C190F5E93C4ULL,
	 0x597B6027B441A01FULL, 0x85AEF3D078640C98ULL}
};

static const BN_ULONG _sm9bn256v1_y2[][BN_SM9_BN256_TOP] = {
	{0x6215BBA5C999A7C7ULL, 0x47EFBA98A71A0811ULL,
	 0x5F3170153D278FF2ULL, 0xA7CF28D519BE3DA6ULL},
	{0x856DC76B84EBEB96ULL, 0x0736A96FA347C8BDULL,
	 0x66BA0D262CBEE6EDULL, 0x17509B092E845C12ULL}
};

static const BN_ULONG _sm9bn256v1_trace[BN_SM9_TRACE_TOP] = {
	0x400000000215D93EULL, 0x02ULL,
};

#elif BN_BITS2 == 32
static const BN_ULONG _sm9bn256v1_x2[][BN_SM9_BN256_TOP] = {
	{0xAF82D65B, 0xF9B7213B, 0xD19C17AB, 0xEE265948,
	 0xD34EC120, 0xD2AAB97F, 0x92130B08, 0x37227552},
	{0xD8806141, 0x54806C11, 0x0F5E93C4, 0xF1DD2C19,
	 0xB441A01F, 0x597B6027, 0x78640C98, 0x85AEF3D0}
};

static const BN_ULONG _sm9bn256v1_y2[][BN_SM9_BN256_TOP] = {
	{0xC999A7C7, 0x6215BBA5, 0xA71A0811, 0x47EFBA98,
	 0x3D278FF2, 0x5F317015, 0x19BE3DA6, 0xA7CF28D5},
	{0x84EBEB96, 0x856DC76B, 0xA347C8BD, 0x0736A96F,
	 0x2CBEE6ED, 0x66BA0D26, 0x2E845C12, 0x17509B09}
};

static const BN_ULONG _sm9bn256v1_trace[BN_SM9_TRACE_TOP] = {
	0x0215D93E, 0x40000000, 0x02,
};

#else
# error "unsupported BN_BITS2"
#endif

static const BIGNUM _bignum_sm9bn256v1_x20 = {
	(BN_ULONG *)_sm9bn256v1_x2[0],
	BN_SM9_BN256_TOP,
	BN_SM9_BN256_TOP,
	0,
	BN_FLG_STATIC_DATA
};

static const BIGNUM _bignum_sm9bn256v1_x21 = {
	(BN_ULONG *)_sm9bn256v1_x2[1],
	BN_SM9_BN256_TOP,
	BN_SM9_BN256_TOP,
	0,
	BN_FLG_STATIC_DATA
};

static const BIGNUM _bignum_sm9bn256v1_y20 = {
	(BN_ULONG *)_sm9bn256v1_y2[0],
	BN_SM9_BN256_TOP,
	BN_SM9_BN256_TOP,
	0,
	BN_FLG_STATIC_DATA
};

static const BIGNUM _bignum_sm9bn256v1_y21 = {
	(BN_ULONG *)_sm9bn256v1_y2[1],
	BN_SM9_BN256_TOP,
	BN_SM9_BN256_TOP,
	0,
	BN_FLG_STATIC_DATA
};

static const BIGNUM _bignum_sm9bn256v1_trace = {
	(BN_ULONG *)_sm9bn256v1_trace, // IS THIS CORRECT??
	BN_SM9_TRACE_TOP,
	BN_SM9_TRACE_TOP,
	0,
	BN_FLG_STATIC_DATA
};

// we should not put it here
const point_t _sm9bn256v1_g2 = {
	{&_bignum_sm9bn256v1_x20, &_bignum_sm9bn256v1_x21},
	{&_bignum_sm9bn256v1_y20, &_bignum_sm9bn256v1_y21},
	{&_bignum_one, &_bignum_zero}
};





