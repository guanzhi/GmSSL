/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdint.h>
#include <arm_neon.h>
#include <gmssl/gf128.h>

// this version is converted from the gf128_arm64.S by ChatGPT 4
// a little slower than the asm version

void gf128_mul(gf128_t r, const gf128_t a, const gf128_t b)
{
	// Prepare zero
	uint8x16_t v0;
	uint8x16_t vzero = veorq_u8(v0, v0);

	// Set f(x) = x^7 + x^2 + x + 1 (0x87) and prepare it by shifting right
	uint8x16_t v7 = vdupq_n_u8(0x87);
	uint64x2_t v7_shifted = vreinterpretq_u64_u8(v7);
	v7_shifted = vshrq_n_u64(v7_shifted, 56);

	// Load (a0, a1) and (b0, b1)
	uint8x16_t va = vld1q_u8((const uint8_t*) a);
	uint8x16_t vb = vld1q_u8((const uint8_t*) b);


	// c = a0 * b0
	poly64x2_t v3 = (poly64x2_t)vmull_p64(vget_low_p64(vreinterpretq_p64_u8(va)), vget_low_p64(vreinterpretq_p64_u8(vb)));

	// a0 + a1 and b0 + b1
	uint8x16_t va0a1 = vextq_u8(va, va, 8);
	va0a1 = veorq_u8(va0a1, va);
	uint8x16_t vb0b1 = vextq_u8(vb, vb, 8);
	vb0b1 = veorq_u8(vb0b1, vb);

	// d' = a1 * b1
	poly64x2_t v4 = (poly64x2_t)vmull_high_p64(vreinterpretq_p64_u8(va), vreinterpretq_p64_u8(vb));

	// e = (a0 + a1) * (b0 + b1) - a0 * b0 - a1 * b1
	poly64x2_t v5 = (poly64x2_t)vmull_p64(vget_low_p64(vreinterpretq_p64_u8(va0a1)), vget_low_p64(vreinterpretq_p64_u8(vb0b1)));
	v5 = veorq_u64(v5, v3);
	v5 = veorq_u64(v5, v4);

	// d = d' + e1
	uint8x16_t ve1 = vextq_u8(vreinterpretq_u8_u64(v5), vzero, 8);
	v4 = veorq_u64(v4, vreinterpretq_u64_u8(ve1));

	// w = d1 * f0
	poly64x2_t v6 = (poly64x2_t)vmull_high_p64(vreinterpretq_p64_u8(v4), v7_shifted);

	// (e0 + w0) * x^64
	v5 = veorq_u64(v5, v6);
	uint8x16_t ve0w0 = vextq_u8(vzero, vreinterpretq_u8_u64(v5), 8);

	// c = c + (e0 + w0) * x^64
	v3 = veorq_u64(v3, vreinterpretq_u64_u8(ve0w0));

	// (d0 + w1) * f0
	uint8x16_t vw1 = vextq_u8(vreinterpretq_u8_u64(v6), vzero, 8);
	v4 = veorq_u64(v4, vreinterpretq_u64_u8(vw1));
	v4 = (poly64x2_t)vmull_p64(vget_low_p64(vreinterpretq_p64_u64(v4)), vget_low_p64(v7_shifted));

	// c += (d0 + w1) * f0
	v3 = veorq_u64(v3, v4);

	// Output the result
	vst1q_u8((uint8_t*) r, vreinterpretq_u8_u64(v3));
}
