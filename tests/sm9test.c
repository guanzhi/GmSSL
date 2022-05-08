/*
 * Copyright (c) 2016 - 2021 The GmSSL Project.  All rights reserved.
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
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/sm9.h>
#include <gmssl/error.h>
#include <gmssl/rand.h>


#define hex_iv 		"123456789abcdef00fedcba987654321123456789abcdef00fedcba987654321"
#define hex_fp_add 	"114efe24536598809df494ff7657484edff1812d51c3955b7d869149aa123d31"
#define hex_fp_sub 	"43cee97c9abed9be3efe7ffffc9d30abe1d643b9b27ea351460aabb2239d3fd4"
#define hex_fp_nsub 	"7271168367e4cd3397052b4ff8f19699401c4f9167fc4b8a9f64ef75bfb405a9"
#define hex_fp_dbl 	"551de7a0ee24723edcf314ff72f478fac1c7c4e7044238acc3913cfbcdaf7d05"
#define hex_fp_tri 	"248cdb7163e4d7e5606ac9d731a751d591b25db4f925dd9532a20de5c2de98c9"
#define hex_fp_div2 	"9df779e83d83d9c517bf85bbd4e833b289e7dfb214ecc1501cf8039cdde8d35f"
#define hex_fp_neg 	"30910c2f8a3f9a597c884b28414d2725301567320b1c5b1790ef2f160ad0e43c"
#define hex_fp_mul 	"9e4d19bb5d94a47352e6f53f4116b2a71b16a1113dc789b26528ee19f46b72e0"
#define hex_fp_sqr 	"46dc2a5b8853234b341d9c57f9c4ca5709e95bbfef25356812e884e4f38cd0d6"
#define hex_fp_pow 	"5679a8f0a46ada5b9d48008cde0b8b7a233f882c08afe8f08a36a20ac845bb1a"
#define hex_fp_inv 	"7d404b0027a93e3fa8f8bc7ee367a96814c42a3b69feb1845093406948a34753"

int test_sm9_fp() {
	sm9_fp_t x;
	sm9_fp_t y;
	sm9_fp_t r;
	int j = 1;
	
	sm9_bn_copy(x, SM9_P2->X[1]);
	sm9_bn_copy(y, SM9_Ppubs->Y[0]);
	
	sm9_fp_t iv = {0x87654321, 0x0fedcba9, 0x9abcdef0, 0x12345678, 0x87654321, 0x0fedcba9, 0x9abcdef0, 0x12345678};
	sm9_bn_from_hex(r, hex_iv); if (sm9_bn_cmp(r, iv) != 0) goto err; ++j;
	
	sm9_fp_add(r, x, y); if (!sm9_bn_equ_hex(r, hex_fp_add)) goto err; ++j;
	sm9_fp_sub(r, x, y); if (!sm9_bn_equ_hex(r, hex_fp_sub)) goto err; ++j;
	sm9_fp_sub(r, y, x); if (!sm9_bn_equ_hex(r, hex_fp_nsub)) goto err; ++j;
	sm9_fp_dbl(r, x);    if (!sm9_bn_equ_hex(r, hex_fp_dbl)) goto err; ++j;
	sm9_fp_tri(r, x);    if (!sm9_bn_equ_hex(r, hex_fp_tri)) goto err; ++j;
	sm9_fp_div2(r, x);   if (!sm9_bn_equ_hex(r, hex_fp_div2)) goto err; ++j;
	sm9_fp_neg(r, x);    if (!sm9_bn_equ_hex(r, hex_fp_neg)) goto err; ++j;
	sm9_fp_mul(r, x, y); if (!sm9_bn_equ_hex(r, hex_fp_mul)) goto err; ++j;
	sm9_fp_sqr(r, x);    if (!sm9_bn_equ_hex(r, hex_fp_sqr)) goto err; ++j;
	sm9_fp_pow(r, x, y); if (!sm9_bn_equ_hex(r, hex_fp_pow)) goto err; ++j;
	sm9_fp_inv(r, x);    if (!sm9_bn_equ_hex(r, hex_fp_inv)) goto err; ++j;
	
	printf("%s() ok\n", __FUNCTION__);
	return 1;
err:
	printf("sm9 test %d failed\n", j);
	error_print();
	return -1;
}



int main(void) {
	if (test_sm9_fp() != 1) goto err;

	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return -1;
}
