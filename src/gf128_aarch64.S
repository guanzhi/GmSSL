/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <gmssl/asm.h>


/* GF(2^128) defined by f(x) = x^128 + x^7 + x^2 + x + 1

	f0 = x^128 = x^7 + x^2 + x + 1
	ext([a0,a1],[b0,b1],8) => [a1,b0]

	  a * b
	= (a0 + a1 * x^64) + (b0 + b1 * x^64)
 	= a0 * b0 + (a0 * b1 + a1 * b0) * x^64 + a1 * b1 * x^128
	= a0 * b0 + ((a0 + a1)*(b0 + b1) - a0*b0 - a1*b1) * x^64 + a1 * b1 * x^128
	= c + e * x^64 + d' * x^128
	= c + e0 * x^64 + e1 * x^128 + d' * x^128
	= c + e0 * x^64 + (d' + e1) * f0
	= c + e0 * x^64 + d * f0
	= c + e0 * x^64 + (d0 + d1 * x^64) * f0
	= c + e0 * x^64 + d0 * f0 + (d1 * f0) * x^64		-- w = d1 * f0
	= c + e0 * x^64 + d0 * f0 + (w0 + w1 * x^64) * x^64
	= c + e0 * x^64 + d0 * f0 + w0 * x^64 + w1 * x^128
	= c + e0 * x^64 + w0 * x^64 + d0 * f0 + w1 * f0
	= c + (e0 + w0) * x^64 + (d0 + w1) * f0
*/
.text

.globl	func(gf128_mul)
.align	4

func(gf128_mul):
	// load (a0, a1)
	ld1	{v1.2d},[x1]
	// load (b0, b1)
	ld1	{v2.2d},[x2]

	// prepare zero
	eor	v0.16b, v0.16b, v0.16b

	// set f(x) = x^7 + x^2 + x + 1 (0x87)
	movi	v7.16b, #0x87
	ushr	v7.2d, v7.2d, #56

	// Multiply:  3*mul + 2*ext + 4*eor

	// c  = a0 * b0
	pmull	v3.1q, v1.1d, v2.1d

	// a0 + a1
	ext	v5.16b, v1.16b, v1.16b, #8
	eor	v5.16b, v5.16b, v1.16b

	// d' = a1 * b1
	pmull2	v4.1q, v1.2d, v2.2d

	// b0 + b1
	ext	v6.16b, v2.16b, v2.16b, #8
	eor	v6.16b, v6.16b, v2.16b

	// e = (a0 + a1) * (b0 + b1) - a0 * b0 - a1 * b1
	pmull	v5.1q, v5.1d, v6.1d
	eor	v5.16b, v5.16b, v3.16b
	eor	v5.16b, v5.16b, v4.16b

	// Reduce: 2*mul + 3*ext + 5*eor

	// d = d' + e1
	ext	v6.16b, v5.16b, v0.16b, #8
	eor	v4.16b, v4.16b, v6.16b

	// w = d1 * f0
	pmull2	v6.1q, v4.2d, v7.2d

	// (e0 + w0) * x^64
	eor	v5.16b, v5.16b, v6.16b
	ext	v5.16b, v0.16b, v5.16b, #8

	// c = c + (e0 + w0) * x^64
	eor	v3.16b, v3.16b, v5.16b

	// (d0 + w1) * f0
	ext	v6.16b, v6.16b, v6.16b, #8
	eor	v4.16b, v4.16b, v6.16b
	pmull	v4.1q, v4.1d, v7.1d

	// c += (d0 + w1) * f0
	eor	v3.16b, v3.16b, v4.16b

	// Output
	st1	{v3.2d}, [x0]

	ret


