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

/* GF(2^128) defined by f(x) = x^128 + x^7 + x^2 + x + 1
 * A + B mod f(x) = a xor b
 * A * 2 mod f(x)
 */

#ifndef GMSSL_GF128_H
#define GMSSL_GF128_H


#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif

#define GMSSL_HAVE_UINT128
#ifdef GMSSL_HAVE_UINT128
typedef unsigned __int128 gf128_t;
#else
typedef struct {
	uint64_t hi;
	uint64_t lo;
} gf128_t;
#endif

gf128_t gf128_from_hex(const char *s);
int gf128_equ_hex(gf128_t a, const char *s);

gf128_t gf128_zero(void);

gf128_t gf128_add(gf128_t a, gf128_t b);
gf128_t gf128_mul(gf128_t a, gf128_t b);
gf128_t gf128_mul2(gf128_t a);
gf128_t gf128_from_bytes(const uint8_t p[16]);
void gf128_to_bytes(gf128_t a, uint8_t p[16]);

void gf128_print(const char *s, gf128_t a);


#ifdef __cplusplus
}
#endif
#endif
