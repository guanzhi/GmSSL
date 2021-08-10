/* 
 *   Copyright 2014-2021 The GmSSL Project Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
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
