/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#include <gmssl/asm.h>


.text

.align	5

Lmodp:
.quad	0xe56f9b27e351457d, 0x21f2934b1a7aeedb, 0xd603ab4ff58ec745, 0xb640000002a3a6f1

// mu = -p^-1 mod 2^64
Lmu:
.quad	0x892bc42c2f2ee42b

Lone:
.quad	1,0,0,0


// 2^512 mod p = 0x2ea795a656f62fbde479b522d6706e7b88f8105fae1a5d3f27dea312b417e2d2
Lsm9_z256_modp_2e512:
.quad	0x27dea312b417e2d2, 0x88f8105fae1a5d3f, 0xe479b522d6706e7b, 0x2ea795a656f62fbd



.align 4
__sm9_z256_modp_add:

	// (carry, a) = a + b
	adds	x14,x14,x4
	adcs	x15,x15,x5
	adcs	x16,x16,x6
	adcs	x17,x17,x7
	adc	x1,xzr,xzr

	// (borrow, b) = (carry, a) - p = a + b - p
	subs	x4,x14,x10
	sbcs	x5,x15,x11
	sbcs	x6,x16,x12
	sbcs	x7,x17,x13
	sbcs	xzr,x1,xzr

	// if borrow (lo), b is not the answer
	csel	x14,x14,x4,lo
	csel	x15,x15,x5,lo
	csel	x16,x16,x6,lo
	stp	x14,x15,[x0]
	csel	x17,x17,x7,lo
	stp	x16,x17,[x0,#16]
	ret


.globl func(sm9_z256_modp_add)
.align 4
func(sm9_z256_modp_add):

	// x29 (frame pointer) and x30 (link register)
	// x29,x30 should be saved before calling a (non-global) function
	stp	x29,x30,[sp,#-16]!
	add	x29,sp,#0

	ldp	x14,x15,[x1]
	ldp	x16,x17,[x1,#16]
	ldp	x4,x5,[x2]
	ldp	x6,x7,[x2,#16]

	ldr	x10,Lmodp
	ldr	x11,Lmodp+8
	ldr	x12,Lmodp+16
	ldr	x13,Lmodp+24

	bl	__sm9_z256_modp_add

	ldp	x29,x30,[sp],#16
	ret


.align	4
__sm9_z256_modp_sub:

	// load b
	ldp	x4,x5,[x2]
	ldp	x6,x7,[x2,#16]

	// borrow, r = a - b
	subs	x14,x14,x4
	sbcs	x15,x15,x5
	sbcs	x16,x16,x6
	sbcs	x17,x17,x7
	sbc	x1,xzr,xzr

	// b = r + p = a - b + p
	adds	x4,x14,x10
	adcs	x5,x15,x11
	adcs	x6,x16,x12
	adcs	x7,x17,x13

	// return (borrow == 0) ? r : (a - b + p)
	cmp	x1,xzr

	csel	x14,x14,x4,eq
	csel	x15,x15,x5,eq
	csel	x16,x16,x6,eq
	stp	x14,x15,[x0]
	csel	x17,x17,x7,eq
	stp	x16,x17,[x0,#16]
	ret


.globl	func(sm9_z256_modp_sub)
.align	4
func(sm9_z256_modp_sub):

	stp	x29,x30,[sp,#-16]!
	add	x29,sp,#0

	ldp	x14,x15,[x1]
	ldp	x16,x17,[x1,#16]

	ldr	x10,Lmodp
	ldr	x11,Lmodp+8
	ldr	x12,Lmodp+16
	ldr	x13,Lmodp+24

	bl	__sm9_z256_modp_sub

	ldp	x29,x30,[sp],#16
	ret


.globl	func(sm9_z256_modp_neg)
.align	4
func(sm9_z256_modp_neg):

	stp	x29,x30,[sp,#-16]!
	add	x29,sp,#0

	ldr	x10,Lmodp
	ldr	x11,Lmodp+8
	ldr	x12,Lmodp+16
	ldr	x13,Lmodp+24

	mov	x2,x1

	mov	x14,xzr
	mov	x15,xzr
	mov	x16,xzr
	mov	x17,xzr

	bl	__sm9_z256_modp_sub

	ldp	x29,x30,[sp],#16
	ret


// r = b - a
.align	4
__sm9_z256_modp_neg_sub:

	// load b
	ldp	x4,x5,[x2]
	ldp	x6,x7,[x2,#16]

	// borrow, a = b - a
	subs	x14,x4,x14
	sbcs	x15,x5,x15
	sbcs	x16,x6,x16
	sbcs	x17,x7,x17
	sbc	x1,xzr,xzr

	// b = a + p = b - a + p
	adds	x4,x14,x10
	adcs	x5,x15,x11
	adcs	x6,x16,x12
	adc	x7,x17,x13

	// return (borrow == 0) ? a : b
	cmp	x1,xzr
	csel	x14,x14,x10,eq
	csel	x15,x15,x11,eq
	csel	x16,x16,x12,eq
	stp	x14,x15,[x0]
	csel	x17,x17,x13,eq
	stp	x16,x17,[x0,#16]
	ret


.globl	func(sm9_z256_modp_dbl)
.align	4
func(sm9_z256_modp_dbl):
	stp	x29,x30,[sp,#-16]!
	add	x29,sp,#0

	ldp	x14,x15,[x1]
	ldp	x16,x17,[x1,#16]

	// load p
	ldr	x10,Lmodp
	ldr	x11,Lmodp+8
	ldr	x12,Lmodp+16
	ldr	x13,Lmodp+24

	// b = a
	mov	x4,x14
	mov	x5,x15
	mov	x6,x16
	mov	x7,x17

	bl	__sm9_z256_modp_add

	ldp	x29,x30,[sp],#16
	ret


.globl	func(sm9_z256_modp_tri)
.align	4
func(sm9_z256_modp_tri):

	stp	x29,x30,[sp,#-16]!
	add	x29,sp,#0

	ldp	x14,x15,[x1]
	ldp	x16,x17,[x1,#16]

	ldr	x10,Lmodp
	ldr	x11,Lmodp+8
	ldr	x12,Lmodp+16
	ldr	x13,Lmodp+24

	// b = a
	mov	x4,x14
	mov	x5,x15
	mov	x6,x16
	mov	x7,x17

	// backup a, __sm9_z256_modp_add change both inputs
	mov	x2,x14
	mov	x3,x15
	mov	x8,x16
	mov	x9,x17

	// a = a + b = 2a
	bl	__sm9_z256_modp_add

	// b = a
	mov	x4,x2
	mov	x5,x3
	mov	x6,x8
	mov	x7,x9

	// a = a + b = 2a + a = 3a
	bl	__sm9_z256_modp_add

	ldp	x29,x30,[sp],#16
	ret


.align	4
__sm9_z256_modp_haf:

	// b = a + p
	adds	x4,x14,x10
	adcs	x5,x15,x11
	adcs	x6,x16,x12
	adcs	x7,x17,x13
	adc	x1,xzr,xzr

	// a = (a is even) ? a : (a + p)
	tst	x14,#1
	csel	x14,x14,x4,eq
	csel	x15,x15,x5,eq
	csel	x16,x16,x6,eq
	csel	x17,x17,x7,eq
	csel	x1,xzr,x1,eq

	// a >>= 1
	lsr	x14,x14,#1
	orr	x14,x14,x15,lsl#63
	lsr	x15,x15,#1
	orr	x15,x15,x16,lsl#63
	lsr	x16,x16,#1
	orr	x16,x16,x17,lsl#63
	lsr	x17,x17,#1
	stp	x14,x15,[x0]
	orr	x17,x17,x1,lsl#63
	stp	x16,x17,[x0,#16]
	ret


.globl	func(sm9_z256_modp_haf)
.align	4

func(sm9_z256_modp_haf):
	stp	x29,x30,[sp,#-16]!
	add	x29,sp,#0

	ldp	x14,x15,[x1]
	ldp	x16,x17,[x1,#16]

	// load p
	ldr	x10,Lmodp
	ldr	x11,Lmodp+8
	ldr	x12,Lmodp+16
	ldr	x13,Lmodp+24

	bl	__sm9_z256_modp_haf

	ldp	x29,x30,[sp],#16
	ret


.align	4
__sm9_z256_modp_mont_mul:
	// x14,x15,x16,x17 as a0,a1,a2,a3
	// x4,x5,x6,x7 as b0,b1,b2,b3
	// x3 as b0,b1,b2,b3

	// c = b0 * a, len(c) = 5
	mul	x14,x4,x3
	umulh	x21,x4,x3
	mul	x15,x5,x3
	umulh	x22,x5,x3
	mul	x16,x6,x3
	umulh	x23,x6,x3
	mul	x17,x7,x3
	umulh	x24,x7,x3
	adds	x15,x15,x21
	adcs	x16,x16,x22
	adcs	x17,x17,x23
	adc	x19,xzr,x24

	// q = mu * c0 mod 2^64
	mul	x3,x9,x14

	// c = (c + q * p) // 2^64
	mul	x21,x10,x3
	mul	x22,x11,x3
	mul	x23,x12,x3
	mul	x24,x13,x3

	adds	x14,x14,x21
	adcs	x15,x15,x22
	adcs	x16,x16,x23
	adcs	x17,x17,x24
	adcs	x19,x19,xzr
	adc	x20,xzr,xzr

	umulh	x21,x10,x3
	umulh	x22,x11,x3
	umulh	x23,x12,x3
	umulh	x24,x13,x3

	adds	x14,x15,x21
	adcs	x15,x16,x22
	adcs	x16,x17,x23
	adcs	x17,x19,x24
	adc	x19,x20,xzr

	// load b1
	ldr	x3,[x2,#8]

	// c += a * b1
	// len(c) = 6
	mul	x21,x4,x3
	mul	x22,x5,x3
	mul	x23,x6,x3
	mul	x24,x7,x3

	adds	x14,x14,x21
	adcs	x15,x15,x22
	adcs	x16,x16,x23
	adcs	x17,x17,x24
	adcs	x19,x19,xzr
	adc	x20,xzr,xzr

	umulh	x21,x4,x3
	umulh	x22,x5,x3
	umulh	x23,x6,x3
	umulh	x24,x7,x3

	adds	x15,x15,x21
	adcs	x16,x16,x22
	adcs	x17,x17,x23
	adcs	x19,x19,x24
	adc	x20,x20,xzr

	// mu * c0 mod 2^64
	mul	x3,x9,x14

	// c = (c + q * p) // 2^64
	mul	x21,x10,x3
	mul	x22,x11,x3
	mul	x23,x12,x3
	mul	x24,x13,x3

	adds	x14,x14,x21
	adcs	x15,x15,x22
	adcs	x16,x16,x23
	adcs	x17,x17,x24
	adcs	x19,x19,xzr
	adc	x20,x20,xzr

	umulh	x21,x10,x3
	umulh	x22,x11,x3
	umulh	x23,x12,x3
	umulh	x24,x13,x3

	adds	x14,x15,x21
	adcs	x15,x16,x22
	adcs	x16,x17,x23
	adcs	x17,x19,x24
	adc	x19,x20,xzr

	// load b2
	ldr	x3,[x2,#16]

	// c += a * b1
	// len(c) = 6
	mul	x21,x4,x3
	mul	x22,x5,x3
	mul	x23,x6,x3
	mul	x24,x7,x3

	adds	x14,x14,x21
	adcs	x15,x15,x22
	adcs	x16,x16,x23
	adcs	x17,x17,x24
	adcs	x19,x19,xzr
	adc	x20,xzr,xzr

	umulh	x21,x4,x3
	umulh	x22,x5,x3
	umulh	x23,x6,x3
	umulh	x24,x7,x3

	adds	x15,x15,x21
	adcs	x16,x16,x22
	adcs	x17,x17,x23
	adcs	x19,x19,x24
	adc	x20,x20,xzr

	// mu * c0 mod 2^64
	mul	x3,x9,x14

	// c = (c + q * p) // 2^64
	mul	x21,x10,x3
	mul	x22,x11,x3
	mul	x23,x12,x3
	mul	x24,x13,x3

	adds	x14,x14,x21
	adcs	x15,x15,x22
	adcs	x16,x16,x23
	adcs	x17,x17,x24
	adcs	x19,x19,xzr
	adc	x20,x20,xzr

	umulh	x21,x10,x3
	umulh	x22,x11,x3
	umulh	x23,x12,x3
	umulh	x24,x13,x3

	adds	x14,x15,x21
	adcs	x15,x16,x22
	adcs	x16,x17,x23
	adcs	x17,x19,x24
	adc	x19,x20,xzr

	// load b3
	ldr	x3,[x2,#24]

	// c += a * b1
	mul	x21,x4,x3
	mul	x22,x5,x3
	mul	x23,x6,x3
	mul	x24,x7,x3

	adds	x14,x14,x21
	adcs	x15,x15,x22
	adcs	x16,x16,x23
	adcs	x17,x17,x24
	adcs	x19,x19,xzr
	adc	x20,xzr,xzr

	umulh	x21,x4,x3
	umulh	x22,x5,x3
	umulh	x23,x6,x3
	umulh	x24,x7,x3

	adds	x15,x15,x21
	adcs	x16,x16,x22
	adcs	x17,x17,x23
	adcs	x19,x19,x24
	adc	x20,x20,xzr

	// q = mu * c0 mod 2^64
	mul	x3,x9,x14

	// c = (c + q * p) // 2^64
	mul	x21,x10,x3
	mul	x22,x11,x3
	mul	x23,x12,x3
	mul	x24,x13,x3

	adds	x14,x14,x21
	adcs	x15,x15,x22
	adcs	x16,x16,x23
	adcs	x17,x17,x24
	adcs	x19,x19,xzr
	adc	x20,x20,xzr

	umulh	x21,x10,x3
	umulh	x22,x11,x3
	umulh	x23,x12,x3
	umulh	x24,x13,x3

	adds	x14,x15,x21
	adcs	x15,x16,x22
	adcs	x16,x17,x23
	adcs	x17,x19,x24
	adc	x19,x20,xzr

	// (borrow, t) = c - p
	// return borrow ? c : (c - p)

	subs	x21,x14,x10
	sbcs	x22,x15,x11
	sbcs	x23,x16,x12
	sbcs	x24,x17,x13
	sbcs	xzr,x19,xzr

	// if borrow
	csel    x14,x14,x21,lo
	csel    x15,x15,x22,lo
	csel    x16,x16,x23,lo
	csel    x17,x17,x24,lo

	// output
	stp	x14,x15,[x0]
	stp	x16,x17,[x0,#16]

	ret



.globl	func(sm9_z256_modp_mont_mul)
.align	4

func(sm9_z256_modp_mont_mul):

	stp	x29,x30,[sp,#-64]!
	add	x29,sp,#0
	stp	x19,x20,[sp,#16]
	stp	x21,x22,[sp,#32]
	stp	x23,x24,[sp,#48]

	// mu = -p^-1 mod 2^64
	ldr	x9,Lmu

	// load modp
	ldr	x10,Lmodp
	ldr	x11,Lmodp+8
	ldr	x12,Lmodp+16
	ldr	x13,Lmodp+24

	// load a
	ldp     x4,x5,[x1]
	ldp     x6,x7,[x1,#16]

	// load b0
	ldr	x3,[x2]

	bl	__sm9_z256_modp_mont_mul

	add	sp,x29,#0
	ldp	x19,x20,[x29,#16]
	ldp	x21,x22,[x29,#32]
	ldp	x23,x24,[x29,#48]
	ldp	x29,x30,[sp],#64
	ret


// mont(mont(a), 1) = aR * 1 * R^-1 (mod p) = a (mod p)
.globl	func(sm9_z256_modp_from_mont)

.align	4
func(sm9_z256_modp_from_mont):

	stp	x29,x30,[sp,#-64]!
	add	x29,sp,#0
	stp	x19,x20,[sp,#16]
	stp	x21,x22,[sp,#32]
	stp	x23,x24,[sp,#48]

	// mu = -p^-1 mod 2^64
	ldr	x9,Lmu

	// load p
	ldr	x10,Lmodp
	ldr	x11,Lmodp+8
	ldr	x12,Lmodp+16
	ldr	x13,Lmodp+24

	// load a
	ldp     x4,x5,[x1]
	ldp     x6,x7,[x1,#16]

	// b = {1,0,0,0}
	adr     x2,Lone

	// b0 = 1
	mov	x3,#1

	bl	__sm9_z256_modp_mont_mul

	add	sp,x29,#0
	ldp	x19,x20,[x29,#16]
	ldp	x21,x22,[x29,#32]
	ldp	x23,x24,[x29,#48]
	ldp	x29,x30,[sp],#64
	ret


// mont(a) = a * 2^256 (mod p) = mont_mul(a, 2^512 mod p)
.globl  func(sm9_z256_modp_to_mont)
.align	6

func(sm9_z256_modp_to_mont):

	stp	x29,x30,[sp,#-64]!
	add	x29,sp,#0
	stp	x19,x20,[sp,#16]
	stp	x21,x22,[sp,#32]
	stp	x23,x24,[sp,#48]

	// mu = -p^-1 mod 2^64
	ldr	x9,Lmu

	// load modp
	ldr	x10,Lmodp
	ldr	x11,Lmodp+8
	ldr	x12,Lmodp+16
	ldr	x13,Lmodp+24

	// swap args x0,x1 = x1,x0
	mov	x3,x1
	mov	x1,x0
	mov	x0,x3

	// load a
	ldp     x4,x5,[x1]
	ldp     x6,x7,[x1,#16]

	// load b = 2^512 mod p
	adr     x2,Lsm9_z256_modp_2e512
	// load b0
	ldr     x3,Lsm9_z256_modp_2e512

	bl	__sm9_z256_modp_mont_mul

	add	sp,x29,#0
	ldp	x19,x20,[x29,#16]
	ldp	x21,x22,[x29,#32]
	ldp	x23,x24,[x29,#48]
	ldp	x29,x30,[sp],#64
	ret


// x4,x5,x6,x7			: a0,a1,a2,a3
// x21,x22,x23,x24		: temp
// x14,x15,x16,x17,x19,x20	: product

.align	4
__sm9_z256_modp_mont_sqr:

	// L(a0*a0) H(a0*a0) L(a1*a1) H(a1*a1) L(a2*a2) H(a2*a2) L(a3*a3) H(a3*a3)
	// 2*       L(a0*a1) L(a0*a2) L(a0*a3)
	// 2*                H(a0*a1) H(a0*a2) H(a0*a3)
	// 2*                L(a1*a2) L(a1*a3)
	// 2*                         H(a1*a2) H(a1*a3)

	mul	x15,x5,x4
	umulh	x22,x5,x4
	mul	x16,x6,x4
	umulh	x23,x6,x4
	mul	x17,x7,x4
	umulh	x19,x7,x4

	adds	x16,x16,x22
					mul	x21,x6,x5
					umulh	x22,x6,x5
	adcs	x17,x17,x23
					mul	x23,x7,x5
					umulh	x24,x7,x5
	adc	x19,x19,xzr

	mul	x20,x7,x6		// a[3]*a[2]
	umulh	x1,x7,x6

	adds	x22,x22,x23		// accumulate high parts of multiplication
	mul	x14,x4,x4		// a[0]*a[0]
	adc	x23,x24,xzr		// can't overflow

	adds	x17,x17,x21		// accumulate low parts of multiplication
	umulh	x4,x4,x4
	adcs	x19,x19,x22
	mul	x22,x5,x5		// a[1]*a[1]
	adcs	x20,x20,x23
	umulh	x5,x5,x5
	adc	x1,x1,xzr		// can't overflow

	adds	x15,x15,x15	// acc[1-6]*=2
	mul	x23,x6,x6		// a[2]*a[2]
	adcs	x16,x16,x16
	umulh	x6,x6,x6
	adcs	x17,x17,x17
	mul	x24,x7,x7		// a[3]*a[3]
	adcs	x19,x19,x19
	umulh	x7,x7,x7
	adcs	x20,x20,x20
	adcs	x1,x1,x1
	adc	x2,xzr,xzr

	adds	x15,x15,x4		// +a[i]*a[i]
	adcs	x16,x16,x22
	adcs	x17,x17,x5
	adcs	x19,x19,x23
	adcs	x20,x20,x6
	adcs	x1,x1,x24
	adc	x2,x2,x7


	// Now:  x2, x1, x20, x19, x17, x16, x15, x14 is a^2

	// round 0

	// q = mu * c0 mod 2^64
	mul	x3,x9,x14

	// C = (C + q*p) // 2^64
	mul	x21,x10,x3
	mul	x22,x11,x3
	mul	x23,x12,x3
	mul	x24,x13,x3
	adds	x14,x14,x21
	adcs	x14,x15,x22
	adcs	x15,x16,x23
	adcs	x16,x17,x24
	adc	x17,xzr,xzr
	umulh	x21,x10,x3
	umulh	x22,x11,x3
	umulh	x23,x12,x3
	umulh	x24,x13,x3
	adds	x14,x14,x21
	adcs	x15,x15,x22
	adcs	x16,x16,x23
	adc	x17,x17,x24

	// round 1

	// q = mu * c0 mod 2^64
	mul	x3,x9,x14

	// C = (C + q*p) // 2^64
	mul	x21,x10,x3
	mul	x22,x11,x3
	mul	x23,x12,x3
	mul	x24,x13,x3
	adds	x14,x14,x21
	adcs	x14,x15,x22
	adcs	x15,x16,x23
	adcs	x16,x17,x24
	adc	x17,xzr,xzr
	umulh	x21,x10,x3
	umulh	x22,x11,x3
	umulh	x23,x12,x3
	umulh	x24,x13,x3
	adds	x14,x14,x21
	adcs	x15,x15,x22
	adcs	x16,x16,x23
	adc	x17,x17,x24


	// round 2

	// q = mu * c0 mod 2^64
	mul	x3,x9,x14

	// C = (C + q*p) // 2^64
	mul	x21,x10,x3
	mul	x22,x11,x3
	mul	x23,x12,x3
	mul	x24,x13,x3
	adds	x14,x14,x21
	adcs	x14,x15,x22
	adcs	x15,x16,x23
	adcs	x16,x17,x24
	adc	x17,xzr,xzr
	umulh	x21,x10,x3
	umulh	x22,x11,x3
	umulh	x23,x12,x3
	umulh	x24,x13,x3
	adds	x14,x14,x21
	adcs	x15,x15,x22
	adcs	x16,x16,x23
	adc	x17,x17,x24

	// round 3


	// q = mu * c0 mod 2^64
	mul	x3,x9,x14

	// C = (C + q*p) // 2^64
	mul	x21,x10,x3
	mul	x22,x11,x3
	mul	x23,x12,x3
	mul	x24,x13,x3
	adds	x14,x14,x21
	adcs	x14,x15,x22
	adcs	x15,x16,x23
	adcs	x16,x17,x24
	adc	x17,xzr,xzr
	umulh	x21,x10,x3
	umulh	x22,x11,x3
	umulh	x23,x12,x3
	umulh	x24,x13,x3
	adds	x14,x14,x21
	adcs	x15,x15,x22
	adcs	x16,x16,x23
	adc	x17,x17,x24

	// add upper half
	adds	x14,x14,x19
	adcs	x15,x15,x20
	adcs	x16,x16,x1
	adcs	x17,x17,x2
	adc	x19,xzr,xzr

	// if c >= p, c = c - p
	subs	x21,x14,x10
	sbcs	x22,x15,x11
	sbcs	x23,x16,x12
	sbcs	x24,x17,x13
	sbcs	xzr,x19,xzr

	csel    x14,x14,x21,lo
	csel    x15,x15,x22,lo
	csel    x16,x16,x23,lo
	csel    x17,x17,x24,lo

	stp	x14,x15,[x0]
	stp	x16,x17,[x0,#16]

	ret


.globl	func(sm9_z256_modp_mont_sqr)
.align	4

func(sm9_z256_modp_mont_sqr):
	stp	x29,x30,[sp,#-64]!
	add	x29,sp,#0
	stp	x19,x20,[sp,#16]
	stp	x21,x22,[sp,#32]
	stp	x23,x24,[sp,#48]

	// mu = -p^-1 mod 2^64
	ldr	x9,Lmu

	// load modp
	ldr	x10,Lmodp
	ldr	x11,Lmodp+8
	ldr	x12,Lmodp+16
	ldr	x13,Lmodp+24

	// load a
	ldp	x4,x5,[x1]
	ldp	x6,x7,[x1,#16]

	bl	__sm9_z256_modp_mont_sqr

	add	sp,x29,#0
	ldp	x19,x20,[x29,#16]
	ldp	x21,x22,[x29,#32]
	ldp	x23,x24,[x29,#48]
	ldp	x29,x30,[sp],#64
	ret

