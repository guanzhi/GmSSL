/*
 * Copyright (c) 2014 - 2021 The GmSSL Project.  All rights reserved.
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
#include <assert.h>
#include <gmssl/hex.h>
#include <gmssl/gf128.h>

/*
a = de300f9301a499a965f8bf677e99e80d
b = 14b267838ec9ef1bb7b5ce8c19e34bc6
a + b = ca8268108f6d76b2d24d71eb677aa3cb
a - b = ca8268108f6d76b2d24d71eb677aa3cb
a * b = 28e63413cd53b01a3b469375781942c6
a * 2 = bc601f2603493352cbf17ecefd33d09d
*/

int main(void)
{
	gf128_t zero = gf128_from_hex("00000000000000000000000000000000");
	gf128_t one  = gf128_from_hex("00000000000000000000000000000001");
	gf128_t ones = gf128_from_hex("11111111111111111111111111111111");
	gf128_t a    = gf128_from_hex("de300f9301a499a965f8bf677e99e80d");
	gf128_t b    = gf128_from_hex("14b267838ec9ef1bb7b5ce8c19e34bc6");
	gf128_t r;

	/*
	r = gf128_add(a, b);
	gf128_print("a + b = ", r);

	r = gf128_mul(a, b);
	gf128_print("a * b = ", r);

	r = gf128_mul2(a);
	gf128_print("a * 2 = ", r);
	*/

	gf128_t H = gf128_from_hex("66e94bd4ef8a2c3b884cfa59ca342b2e");
	gf128_t C = gf128_from_hex("0388dace60b6a392f328c2b971b2fe78");
	gf128_t T = gf128_mul(C, H);


	gf128_print("C = ", C);
	gf128_print("H = ", H);
	gf128_print("C * H = ", T);





	return 0;
}
