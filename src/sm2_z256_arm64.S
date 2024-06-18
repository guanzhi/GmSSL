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

#define neg_p1	0xffffffff
#define neg_p3	0x100000000

Lneg_p:
.quad	1, neg_p1, 0, neg_p3


// 2^512 mod p
Lz256_2e512modp:
.quad	0x0000000200000003, 0x00000002ffffffff, 0x0000000100000001, 0x0000000400000002

Lone:
.quad	1,0,0,0


Lmodn:
.quad	0x53bbf40939d54123, 0x7203df6b21c6052b, 0xffffffffffffffff, 0xfffffffeffffffff



.align 4
__sm2_z256_modp_add:

	// carry, a = a + b
	adds	x14,x14,x8
	adcs	x15,x15,x9
	adcs	x16,x16,x10
	adcs	x17,x17,x11
	adc	x1,xzr,xzr

	// carry, b = a + (2^256 - p) = (a + b - p) + 2^256
	adds	x8,x14,#1
	adcs	x9,x15,x12
	adcs	x10,x16,xzr
	adcs	x11,x17,x13
	adc	x1,x1,xzr

	cmp	x1,xzr

	// if carry == 0, i.e. (a + b - p) < 0, return a == (a + b)
	// else return b == (a + b - p)
	csel    x14,x14,x8,eq
	csel    x15,x15,x9,eq
	csel    x16,x16,x10,eq
	csel    x17,x17,x11,eq

	stp	x14,x15,[x0]
	stp	x16,x17,[x0,#16]

	ret


.globl	func(sm2_z256_modp_add)
.align 4

func(sm2_z256_modp_add):

	stp	x29,x30,[sp,#-16]!
	add	x29,sp,#0

	// load a
	ldp	x14,x15,[x1]
	ldp	x16,x17,[x1,#16]

	// load b
	ldp	x8,x9,[x2]
	ldp	x10,x11,[x2,#16]

	// load modp
	mov	x12,#neg_p1
	mov	x13,#neg_p3

	bl	__sm2_z256_modp_add

	ldp	x29,x30,[sp],#16
	ret


.globl	func(sm2_z256_modp_dbl)
.align	4

func(sm2_z256_modp_dbl):
	stp	x29,x30,[sp,#-16]!
	add	x29,sp,#0

	// load a
	ldp	x14,x15,[x1]
	ldp	x16,x17,[x1,#16]

	// b = a
	mov	x8,x14
	mov	x9,x15
	mov	x10,x16
	mov	x11,x17

	// set (2^256 - p)
	mov	x12,#neg_p1
	mov	x13,#neg_p3

	bl	__sm2_z256_modp_add

	ldp	x29,x30,[sp],#16
	ret


.globl	func(sm2_z256_modp_tri)
.align	4
func(sm2_z256_modp_tri):
	stp	x29,x30,[sp,#-16]!
	add	x29,sp,#0

	ldp	x14,x15,[x1]
	ldp	x16,x17,[x1,#16]

	// load (2^256 - p)
	mov	x12,#neg_p1
	mov	x13,#neg_p3

	// b = a
	mov	x8,x14
	mov	x9,x15
	mov	x10,x16
	mov	x11,x17

	// c = a
	mov	x4,x14
	mov	x5,x15
	mov	x6,x16
	mov	x7,x17

	// a = a + b = 2a
	bl	__sm2_z256_modp_add

	// b = c = a
	mov	x8,x4
	mov	x9,x5
	mov	x10,x6
	mov	x11,x7

	// a = a + b = 2a + a = 3a
	bl	__sm2_z256_modp_add

	ldp	x29,x30,[sp],#16
	ret


// a - b (mod p)
.align	4
__sm2_z256_modp_sub:

	ldp	x8,x9,[x2]
	ldp	x10,x11,[x2,#16]

	// a = a - b
	subs	x14,x14,x8
	sbcs	x15,x15,x9
	sbcs	x16,x16,x10
	sbcs	x17,x17,x11
	sbc	x1,xzr,xzr

	// b = a - (2^256 - p) = a - b + p - 2^256
	subs	x8,x14,#1
	sbcs	x9,x15,x12
	sbcs	x10,x16,xzr
	sbcs	x11,x17,x13

	cmp	x1,xzr
	csel    x14,x14,x8,eq
	csel    x15,x15,x9,eq
	csel    x16,x16,x10,eq
	stp	x14,x15,[x0]
	csel    x17,x17,x11,eq
	stp	x16,x17,[x0,#16]
	ret


// b - a (mod p)
.align	4
__sm2_z256_modp_neg_sub:

	ldp	x8,x9,[x2]
	ldp	x10,x11,[x2,#16]

	// a = b - a
	subs	x14,x8,x14
	sbcs	x15,x9,x15
	sbcs	x16,x10,x16
	sbcs	x17,x11,x17
	sbc	x1,xzr,xzr

	// b = a - (2^256 - p) = b - a + p - 2^256
	subs	x8,x14,#1
	sbcs	x9,x15,x12
	sbcs	x10,x16,xzr
	sbcs	x11,x17,x13

	cmp	x1,xzr
	csel    x14,x14,x8,eq
	csel    x15,x15,x9,eq
	csel    x16,x16,x10,eq
	stp	x14,x15,[x0]
	csel    x17,x17,x11,eq
	stp	x16,x17,[x0,#16]
	ret


.globl	func(sm2_z256_modp_sub)
.align	4
func(sm2_z256_modp_sub):
	stp	x29,x30,[sp,#-16]!
	add	x29,sp,#0

	ldp	x14,x15,[x1]
	ldp	x16,x17,[x1,#16]

	mov	x12,#neg_p1
	mov	x13,#neg_p3

	bl	__sm2_z256_modp_sub

	ldp	x29,x30,[sp],#16
	ret


.globl	func(sm2_z256_modp_neg)

.align	4
func(sm2_z256_modp_neg):
	stp	x29,x30,[sp,#-16]!
	add	x29,sp,#0

	mov	x2,x1

	mov	x14,xzr
	mov	x15,xzr
	mov	x16,xzr
	mov	x17,xzr

	mov	x12,#neg_p1
	mov	x13,#neg_p3

	bl	__sm2_z256_modp_sub

	ldp	x29,x30,[sp],#16
	ret


.align	4
__sm2_z256_modp_mont_mul:

	// a * b0
	mul	x14,x4,x3		// a[0]*b[0]
	umulh	x8,x4,x3
	mul	x15,x5,x3		// a[1]*b[0]
	umulh	x9,x5,x3
	mul	x16,x6,x3		// a[2]*b[0]
	umulh	x10,x6,x3
	mul	x17,x7,x3		// a[3]*b[0]
	umulh	x11,x7,x3

	ldr	x3,[x2,#8]		// b[1]

	adds	x15,x15,x8
	adcs	x16,x16,x9
	adcs	x17,x17,x10
	adc	x19,xzr,x11
	mov	x20,xzr

	lsl	x10,x14,#32
	lsr	x11,x14,#32


	// p = 2^256 - 2^224 - 2^96 + 2^64 - 1

	// R = 2^64

	// p * a0 = (a0 * R^4 + a0 * R^1) - (a0 * 2^32 * R^192 + a0 * 2^32 * R + a0)

	//   [     a4     ][     a3     ][     a2     ][     a1     ][     a0     ]
	//   [     a0     ]      0              0      [     a0     ]       0
	// - [   a0>>32   ][    a0<<32  ][   a0 >> 32  ][    a0<<32 ][     a0     ]


	//  这里 x10 = a0 << 32
	//       x11 = a0 >> 32

	//subs	x10,x14,x8
	//sbc	x11,x14,x9
	subs	x8,x14,x10
	sbcs	x9,xzr,x11
	sbcs	x10,xzr,x10
	sbc	x11,x14,x11


	adds	x14,x15,x8
				mul	x8,x4,x3		// lo(a[0]*b[i])
	adcs	x15,x16,x9
				mul	x9,x5,x3		// lo(a[1]*b[i])
	adcs	x16,x17,x10
				mul	x10,x6,x3		// lo(a[2]*b[i])
	adcs	x17,x19,x11
				mul	x11,x7,x3		// lo(a[3]*b[i])
	adc	x19,x20,xzr

	adds	x14,x14,x8
				umulh	x8,x4,x3		// hi(a[0]*b[i])
	adcs	x15,x15,x9
				umulh	x9,x5,x3		// hi(a[1]*b[i])
	adcs	x16,x16,x10
				umulh	x10,x6,x3		// hi(a[2]*b[i])
	adcs	x17,x17,x11
				umulh	x11,x7,x3		// hi(a[3]*b[i])
	adc	x19,x19,xzr


	ldr	x3,[x2,#8*(1+1)]	// b[1+1]

	adds	x15,x15,x8		// accumulate high parts of multiplication
	adcs	x16,x16,x9
	adcs	x17,x17,x10
	adcs	x19,x19,x11
	adc	x20,xzr,xzr

	lsl	x10,x14,#32
	lsr	x11,x14,#32


	subs	x8,x14,x10
	sbcs	x9,xzr,x11
	sbcs	x10,xzr,x10
	sbc	x11,x14,x11


	adds	x14,x15,x8		// +=acc[0]<<96 and omit acc[0]
	mul	x8,x4,x3		// lo(a[0]*b[i])
	adcs	x15,x16,x9
	mul	x9,x5,x3		// lo(a[1]*b[i])
	adcs	x16,x17,x10		// +=acc[0]*0xffff0001
	mul	x10,x6,x3		// lo(a[2]*b[i])
	adcs	x17,x19,x11
	mul	x11,x7,x3		// lo(a[3]*b[i])
	adc	x19,x20,xzr

	adds	x14,x14,x8		// accumulate low parts of multiplication
	umulh	x8,x4,x3		// hi(a[0]*b[i])
	adcs	x15,x15,x9
	umulh	x9,x5,x3		// hi(a[1]*b[i])
	adcs	x16,x16,x10
	umulh	x10,x6,x3		// hi(a[2]*b[i])
	adcs	x17,x17,x11
	umulh	x11,x7,x3		// hi(a[3]*b[i])
	adc	x19,x19,xzr



	ldr	x3,[x2,#8*(2+1)]	// b[2+1]
	adds	x15,x15,x8		// accumulate high parts of multiplication
	adcs	x16,x16,x9
	adcs	x17,x17,x10
	adcs	x19,x19,x11
	adc	x20,xzr,xzr

	lsl	x10,x14,#32		// t0
	lsr	x11,x14,#32		// t1

	subs	x8,x14,x10
	sbcs	x9,xzr,x11
	sbcs	x10,xzr,x10
	sbc	x11,x14,x11


	adds	x14,x15,x8		// +=acc[0]<<96 and omit acc[0]
	mul	x8,x4,x3		// lo(a[0]*b[i])
	adcs	x15,x16,x9
	mul	x9,x5,x3		// lo(a[1]*b[i])
	adcs	x16,x17,x10		// +=acc[0]*0xffff0001
	mul	x10,x6,x3		// lo(a[2]*b[i])
	adcs	x17,x19,x11
	mul	x11,x7,x3		// lo(a[3]*b[i])
	adc	x19,x20,xzr

	adds	x14,x14,x8		// accumulate low parts of multiplication
	umulh	x8,x4,x3		// hi(a[0]*b[i])
	adcs	x15,x15,x9
	umulh	x9,x5,x3		// hi(a[1]*b[i])
	adcs	x16,x16,x10
	umulh	x10,x6,x3		// hi(a[2]*b[i])
	adcs	x17,x17,x11
	umulh	x11,x7,x3		// hi(a[3]*b[i])
	adc	x19,x19,xzr
	adds	x15,x15,x8		// accumulate high parts of multiplication
	adcs	x16,x16,x9
	adcs	x17,x17,x10
	adcs	x19,x19,x11
	adc	x20,xzr,xzr

	lsl	x10,x14,#32		// t0
	lsr	x11,x14,#32		// t1
	// last reduction

	subs	x8,x14,x10
	sbcs	x9,xzr,x11
	sbcs	x10,xzr,x10
	sbc	x11,x14,x11

	adds	x14,x15,x8		// +=acc[0]<<96 and omit acc[0]
	adcs	x15,x16,x9
	adcs	x16,x17,x10		// +=acc[0]*0xffff0001
	adcs	x17,x19,x11
	adc	x19,x20,xzr

	// if a > p : return a - p
	// else: return a

	// carry, b = a + (2^256 - p)
	adds	x8,x14,#1
	adcs	x9,x15,x12
	adcs	x10,x16,xzr
	adcs	x11,x17,x13
	adc	x19,x19,xzr

	cmp	x19,xzr

	// 如果 a + 2^256 - p 没有进位，说明 a < p, a - p 是个负数，说明我们直接返回a
	// 如果进位了，那么返回b
	csel    x14,x14,x8,eq
	csel    x15,x15,x9,eq
	csel    x16,x16,x10,eq
	csel    x17,x17,x11,eq

	stp	x14,x15,[x0]
	stp	x16,x17,[x0,#16]
	ret


.globl	func(sm2_z256_modp_mont_mul)

.align	4
func(sm2_z256_modp_mont_mul):

	stp	x29,x30,[sp,#-32]!
	add	x29,sp,#0
	stp	x19,x20,[sp,#16]

	// load a
	ldp	x4,x5,[x1]
	ldp	x6,x7,[x1,#16]

	// load b0
	ldr	x3,[x2]

	// load modp
	mov	x12,#neg_p1
	mov	x13,#neg_p3

	bl	__sm2_z256_modp_mont_mul

	ldp	x19,x20,[sp,#16]
	ldp	x29,x30,[sp],#32
	ret


.align	4
__sm2_z256_modp_mont_sqr:
	//  |  |  |  |  |  |a1*a0|  |
	//  |  |  |  |  |a2*a0|  |  |
	//  |  |a3*a2|a3*a0|  |  |  |
	//  |  |  |  |a2*a1|  |  |  |
	//  |  |  |a3*a1|  |  |  |  |
	// *|  |  |  |  |  |  |  | 2|
	// +|a3*a3|a2*a2|a1*a1|a0*a0|
	//  |--+--+--+--+--+--+--+--|
	//  |A7|A6|A5|A4|A3|A2|A1|A0|, where Ax is , i.e. follow 
	//
	//  "can't overflow" below mark carrying into high part of
	//  multiplication result, which can't overflow, because it
	//  can never be all ones.

	mul	x15,x5,x4		// a[1]*a[0]
	umulh	x9,x5,x4
	mul	x16,x6,x4		// a[2]*a[0]
	umulh	x10,x6,x4
	mul	x17,x7,x4		// a[3]*a[0]
	umulh	x19,x7,x4

	adds	x16,x16,x9		// accumulate high parts of multiplication
	mul	x8,x6,x5		// a[2]*a[1]
	umulh	x9,x6,x5
	adcs	x17,x17,x10
	mul	x10,x7,x5		// a[3]*a[1]
	umulh	x11,x7,x5
	adc	x19,x19,xzr		// can't overflow

	mul	x20,x7,x6		// a[3]*a[2]
	umulh	x1,x7,x6

	adds	x9,x9,x10		// accumulate high parts of multiplication
	mul	x14,x4,x4		// a[0]*a[0]
	adc	x10,x11,xzr		// can't overflow

	adds	x17,x17,x8		// accumulate low parts of multiplication
	umulh	x4,x4,x4
	adcs	x19,x19,x9
	mul	x9,x5,x5		// a[1]*a[1]
	adcs	x20,x20,x10
	umulh	x5,x5,x5
	adc	x1,x1,xzr		// can't overflow

	adds	x15,x15,x15	// acc[1-6]*=2
	mul	x10,x6,x6		// a[2]*a[2]
	adcs	x16,x16,x16
	umulh	x6,x6,x6
	adcs	x17,x17,x17
	mul	x11,x7,x7		// a[3]*a[3]
	adcs	x19,x19,x19
	umulh	x7,x7,x7
	adcs	x20,x20,x20
	adcs	x1,x1,x1
	adc	x2,xzr,xzr

	adds	x15,x15,x4		// +a[i]*a[i]
	adcs	x16,x16,x9
	adcs	x17,x17,x5
	adcs	x19,x19,x10
	adcs	x20,x20,x6


	lsl	x10,x14,#32					
	adcs	x1,x1,x11
	lsr	x11,x14,#32					
	adc	x2,x2,x7


	// Now:  x2, x1, x20, x19, x17, x16, x15, x14 就是 a^2 的结果


	subs	x8,x14,x10
	sbcs	x9,xzr,x11
	sbcs	x10,xzr,x10
	sbc	x11,x14,x11

	adds	x14,x15,x8		// +=acc[0]<<96 and omit acc[0]
	adcs	x15,x16,x9
	adcs	x16,x17,x10		// +=acc[0]*0xffff0001
	adc	x17,x11,xzr		// can't overflow

	lsl	x10,x14,#32
	lsr	x11,x14,#32

	subs	x8,x14,x10
	sbcs	x9,xzr,x11
	sbcs	x10,xzr,x10
	sbc	x11,x14,x11


	adds	x14,x15,x8		// +=acc[0]<<96 and omit acc[0]
	adcs	x15,x16,x9
	adcs	x16,x17,x10		// +=acc[0]*0xffff0001
	adc	x17,x11,xzr		// can't overflow

	lsl	x10,x14,#32					
	lsr	x11,x14,#32					

	subs	x8,x14,x10
	sbcs	x9,xzr,x11
	sbcs	x10,xzr,x10
	sbc	x11,x14,x11

	adds	x14,x15,x8		// +=acc[0]<<96 and omit acc[0]
	adcs	x15,x16,x9
	adcs	x16,x17,x10		// +=acc[0]*0xffff0001
	adc	x17,x11,xzr		// can't overflow

	lsl	x10,x14,#32					
	lsr	x11,x14,#32					

	subs	x8,x14,x10
	sbcs	x9,xzr,x11
	sbcs	x10,xzr,x10
	sbc	x11,x14,x11

	adds	x14,x15,x8		// +=acc[0]<<96 and omit acc[0]
	adcs	x15,x16,x9
	adcs	x16,x17,x10		// +=acc[0]*0xffff0001
	adc	x17,x11,xzr		// can't overflow

	adds	x14,x14,x19	// accumulate upper half
	adcs	x15,x15,x20
	adcs	x16,x16,x1
	adcs	x17,x17,x2
	adc	x19,xzr,xzr

	// carry, b = a + (2^256 - p)
	adds	x8,x14,#1
	adcs	x9,x15,x12
	adcs	x10,x16,xzr
	adcs	x11,x17,x13
	adc	x19,x19,xzr

	cmp	x19,xzr

	// 如果 a + 2^256 - p 没有进位，说明 a < p, a - p 是个负数，说明我们直接返回a
	// 如果进位了，那么返回b
	csel    x14,x14,x8,eq
	csel    x15,x15,x9,eq
	csel    x16,x16,x10,eq
	csel    x17,x17,x11,eq

	stp	x14,x15,[x0]
	stp	x16,x17,[x0,#16]


	// 如果要用于连续平方，最好最后的输出是x4,x5,x6,x7，并且不需要输出到[x0]内存上

	ret


.globl	func(sm2_z256_modp_mont_sqr)
.align	4

func(sm2_z256_modp_mont_sqr):
	stp	x29,x30,[sp,#-32]!
	add	x29,sp,#0
	stp	x19,x20,[sp,#16]

	ldp	x4,x5,[x1]
	ldp	x6,x7,[x1,#16]

	// load modp
	mov	x12,#neg_p1
	mov	x13,#neg_p3

	bl	__sm2_z256_modp_mont_sqr

	ldp	x19,x20,[sp,#16]
	ldp	x29,x30,[sp],#32
	ret



// 计算r = r^(2^n) 也就是连续做n次平方
// 这个函数调用__sm2_z256_modp_mont_sqr，输入是x4,x5,x6,x7, 输出是x14,x15,x16,x17，并且写入到[x0]
// 但是对于连续的平方，实际上我们不需要写到内存里，而且需要保证输入输出是一样的，需要对mont_sqr函数做一定的调整
// 当然不调整的话开销也不算大
.globl	func(sm2_z256_modp_mont_esq)
.align	4

func(sm2_z256_modp_mont_esq):
	stp     x29,x30,[sp,#-32]!
	add     x29,sp,#0
	stp     x19,x20,[sp,#16]

	ldp     x4,x5,[x0]
	ldp     x6,x7,[x0,#16]

	// load modp
	mov	x12,#neg_p1
	mov	x13,#neg_p3

	// x1 在sqr中已经被用了，因此就不能再用了，x18没有用过，这里实际上没有节省什么计算
	mov	x3, x1
22:

	// 这个函数的输入是x4,x5,x6,x7
	bl	__sm2_z256_modp_mont_sqr
	// 结束之后还应该继续把值放到x4,x5,x6,x7中

	mov	x4,x14
	mov	x5,x15
	mov	x6,x16
	mov	x7,x17

	subs	x3, x3, #1
	b.ne	22b

	ldp     x19,x20,[sp,#16]
	ldp     x29,x30,[sp],#32
	ret



// mont(a) = a * 2^256 (mod p) = mont_mul(a, 2^512 mod p)
.globl	func(sm2_z256_modp_to_mont)

.align	6
func(sm2_z256_modp_to_mont):
	stp	x29,x30,[sp,#-32]!
	add	x29,sp,#0
	stp	x19,x20,[sp,#16]

	mov	x3,x1
	mov	x1,x0
	mov	x0,x3

	adr	x2,Lz256_2e512modp
	ldr	x3,Lz256_2e512modp

	ldp	x4,x5,[x1]
	ldp	x6,x7,[x1,#16]

	mov	x12,#neg_p1
	mov	x13,#neg_p3

	bl	__sm2_z256_modp_mont_mul

	ldp	x19,x20,[sp,#16]
	ldp	x29,x30,[sp],#32
	ret


// 这个函数中参与运算的b == 1，因此应该有更快的实现，但是似乎这个计算使用量不大
// 因此没必要专门优化
// mont(mont(a), 1) = aR * 1 * R^-1 (mod p) = a (mod p)
.globl	func(sm2_z256_modp_from_mont)

.align	4
func(sm2_z256_modp_from_mont):
	stp	x29,x30,[sp,#-32]!
	add	x29,sp,#0
	stp	x19,x20,[sp,#16]

	ldp	x4,x5,[x1]
	ldp	x6,x7,[x1,#16]

	// load modp
	mov	x12,#neg_p1
	mov	x13,#neg_p3

	// load b = {1,0,0,0}
	adr	x2,Lone
	// load b1 = 1
	mov	x3,#1

	bl	__sm2_z256_modp_mont_mul

	ldp	x19,x20,[sp,#16]
	ldp	x29,x30,[sp],#32

	ret


.align	4
__sm2_z256_modp_haf:

	// a - (2^256 - p) == a + p - 2^256
	subs	x8,x14,#1
	sbcs	x9,x15,x12
	sbcs	x10,x16,xzr
	sbcs	x11,x17,x13
	// (a + p - 2^256) + 2^256
	adcs	x1,xzr,xzr

	// r = (a is even) ? a : (a - (2^256 - p) + 2^256)
	tst	x14,#1
	csel	x14,x14,x8,eq
	csel	x15,x15,x9,eq
	csel	x16,x16,x10,eq
	csel	x17,x17,x11,eq
	csel	x1,xzr,x1,eq

	// r = r >> 1
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


.globl	func(sm2_z256_modp_haf)

.align	4
func(sm2_z256_modp_haf):
	stp	x29,x30,[sp,#-16]!
	add	x29,sp,#0

	ldp	x14,x15,[x1]
	ldp	x16,x17,[x1,#16]

	mov	x12,#neg_p1
	mov	x13,#neg_p3

	bl	__sm2_z256_modp_haf

	ldp	x29,x30,[sp],#16
	ret



.globl	func(sm2_z256_point_dbl)

.align	5
func(sm2_z256_point_dbl):

	stp	x29,x30,[sp,#-96]!
	add	x29,sp,#0
	stp	x19,x20,[sp,#16]
	stp	x21,x22,[sp,#32]
	sub	sp,sp,#32*4 //还是准备了4个临时变量

Ldouble_shortcut:
	// Jacobian点一共3个元素
	// 0-16,16-32
	// 32-48,48-64
	// 64-80,80-96

	// x14-x17 = Y

	ldp	x14,x15,[x1,#32]
	mov	x21,x0
	ldp	x16,x17,[x1,#48]
	mov	x22,x1

	// x21, x22 分别保存了x0,x1，也就是说 x21 = out, x22 = in
	// 为什么保存了x0,x1，难道这两个值被重复使用了吗？
	// 每个 __foo 都需要将输出写到 x0 的地址上

	// load modp
	mov     x12,#neg_p1
	mov     x13,#neg_p3

	// x8-x11 = x14-x17 = Y
	mov	x8,x14


	mov	x9,x15
						// x4-x7 = Z  sqr 确实是将 x4-x7 作为输入参数的
									// x22 == x1
						ldp	x4,x5,[x22,#64]	// forward load for p256_sqr_mont
	mov	x10,x16
	mov	x11,x17
						ldp	x6,x7,[x22,#64+16]


	// S = T[0]
	add	x0,sp,#0

	// 此时没有把输出写入到输出地址
	// 我们可以


	// 1. S = 2Y
	bl	__sm2_z256_modp_add	// p256_mul_by_2(S, in_y);



	// Zsqr = T[2]
	add	x0,sp,#64

	// 2. Zsqr = Z1^2
	bl	__sm2_z256_modp_mont_sqr	// p256_sqr_mont(Zsqr, in_z);
			

	// x8-x11 = X
	ldp	x8,x9,[x22]
	ldp	x10,x11,[x22,#16]

	// x4-x7 = x14-x17 这是什么值
	mov	x4,x14		// put Zsqr aside for p256_sub
	mov	x5,x15
	mov	x6,x16
	mov	x7,x17

	// t1 = M

	// M = T[1]
	add	x0,sp,#32

	// 6. M = X1 + Zsqr = X1 + Z1^2
	bl	__sm2_z256_modp_add	// p256_add(M, Zsqr, in_x);


	add	x2,x22,#0
	mov	x14,x4		// restore Zsqr
	mov	x15,x5

						ldp	x4,x5,[sp,#0]	// forward load for p256_sqr_mont
	mov	x16,x6
	mov	x17,x7
						ldp	x6,x7,[sp,#0+16]
	add	x0,sp,#64


	// 7. Zsqr = X - Z^2
	bl	__sm2_z256_modp_neg_sub	// p256_sub(Zsqr, in_x, Zsqr);

	add	x0,sp,#0

	// 3. S = S^2 = 4*Y1^2
	bl	__sm2_z256_modp_mont_sqr	// p256_sqr_mont(S, S);

	ldr	x3,[x22,#32]
	ldp	x4,x5,[x22,#64]
	ldp	x6,x7,[x22,#64+16]
	add	x2,x22,#32
	add	x0,sp,#96


	// tmp0 = Z*Y

	// 4. Z3 = Z1 * Y1
	bl	__sm2_z256_modp_mont_mul	// p256_mul_mont(tmp0, in_z, in_y);
	// 算完之后已经把结果写到内存了
	// 因此还必须再把数据读到寄存器才能继续算

	mov	x8,x14
	mov	x9,x15
	ldp	x4,x5,[sp,#0]	// forward load for p256_sqr_mont
	mov	x10,x16
	mov	x11,x17
	ldp	x6,x7,[sp,#0+16]
	add	x0,x21,#64


			
//	mov	x0,x21 // 现在第一个位置就是一个z256了				
//	add	sp,x29,#0		
//	ldp	x19,x20,[x29,#16]	
//	ldp	x21,x22,[x29,#32]	
//	ldp	x29,x30,[sp],#96	
//	ret				

	// Z3 = 2YZ
	bl	__sm2_z256_modp_add	// p256_mul_by_2(res_z, tmp0);

	add	x0,sp,#96
	bl	__sm2_z256_modp_mont_sqr	// p256_sqr_mont(tmp0, S);

	ldr	x3,[sp,#64]		// forward load for p256_mul_mont
	ldp	x4,x5,[sp,#32]
	ldp	x6,x7,[sp,#32+16]
	add	x0,x21,#32
	bl	__sm2_z256_modp_haf	// p256_div_by_2(res_y, tmp0);

	add	x2,sp,#64
	add	x0,sp,#32
	bl	__sm2_z256_modp_mont_mul	// p256_mul_mont(M, M, Zsqr);

	mov	x8,x14		// duplicate M
	mov	x9,x15
	mov	x10,x16
	mov	x11,x17
	mov	x4,x14		// put M aside
	mov	x5,x15
	mov	x6,x16
	mov	x7,x17
	add	x0,sp,#32
	bl	__sm2_z256_modp_add
	mov	x8,x4			// restore M
	mov	x9,x5
	ldr	x3,[x22]		// forward load for p256_mul_mont
	mov	x10,x6
	ldp	x4,x5,[sp,#0]
	mov	x11,x7
	ldp	x6,x7,[sp,#0+16]
	bl	__sm2_z256_modp_add	// p256_mul_by_3(M, M);

	add	x2,x22,#0
	add	x0,sp,#0
	bl	__sm2_z256_modp_mont_mul	// p256_mul_mont(S, S, in_x);

	mov	x8,x14
	mov	x9,x15
	ldp	x4,x5,[sp,#32]	// forward load for p256_sqr_mont
	mov	x10,x16
	mov	x11,x17
	ldp	x6,x7,[sp,#32+16]
	add	x0,sp,#96
	bl	__sm2_z256_modp_add	// p256_mul_by_2(tmp0, S);

	add	x0,x21,#0			// 输出X
	bl	__sm2_z256_modp_mont_sqr	// p256_sqr_mont(res_x, M);

	add	x2,sp,#96

	bl	__sm2_z256_modp_sub	// p256_sub(res_x, res_x, tmp0);

	add	x2,sp,#0
	add	x0,sp,#0
	bl	__sm2_z256_modp_neg_sub	// p256_sub(S, S, res_x);

	ldr	x3,[sp,#32]
	mov	x4,x14		// copy S
	mov	x5,x15
	mov	x6,x16
	mov	x7,x17
	add	x2,sp,#32
	bl	__sm2_z256_modp_mont_mul	// p256_mul_mont(S, S, M);

	add	x2,x21,#32
	add	x0,x21,#32		// 这里输出的是Y


	bl	__sm2_z256_modp_sub	// p256_sub(res_y, S, res_y);


	add	sp,x29,#0		// destroy frame
	ldp	x19,x20,[x29,#16]
	ldp	x21,x22,[x29,#32]
	ldp	x29,x30,[sp],#96

	ret


											


.globl	func(sm2_z256_point_add)

.align	5
func(sm2_z256_point_add):
	stp	x29,x30,[sp,#-96]!
	add	x29,sp,#0
	stp	x19,x20,[sp,#16]
	stp	x21,x22,[sp,#32]
	stp	x23,x24,[sp,#48]
	stp	x25,x26,[sp,#64]
	stp	x27,x28,[sp,#80]
	sub	sp,sp,#32*12

	ldp	x4,x5,[x2,#64]	// in2_z
	ldp	x6,x7,[x2,#64+16]
	mov	x21,x0
	mov	x22,x1
	mov	x23,x2

	// load modp
	mov	x12,#neg_p1
	mov	x13,#neg_p3
	//ldr	x12,Lpoly+8			
	//ldr	x13,Lpoly+24		

	orr	x8,x4,x5
	orr	x10,x6,x7
	orr	x25,x8,x10
	cmp	x25,#0
	csetm	x25,ne		// ~in2infty
	add	x0,sp,#192
	bl	__sm2_z256_modp_mont_sqr	// p256_sqr_mont(Z2sqr, in2_z);

	ldp	x4,x5,[x22,#64]	// in1_z
	ldp	x6,x7,[x22,#64+16]
	orr	x8,x4,x5
	orr	x10,x6,x7
	orr	x24,x8,x10
	cmp	x24,#0
	csetm	x24,ne		// ~in1infty
	add	x0,sp,#128
	bl	__sm2_z256_modp_mont_sqr	// p256_sqr_mont(Z1sqr, in1_z);

	ldr	x3,[x23,#64]
	ldp	x4,x5,[sp,#192]
	ldp	x6,x7,[sp,#192+16]
	add	x2,x23,#64
	add	x0,sp,#320
	bl	__sm2_z256_modp_mont_mul	// p256_mul_mont(S1, Z2sqr, in2_z);

	ldr	x3,[x22,#64]
	ldp	x4,x5,[sp,#128]
	ldp	x6,x7,[sp,#128+16]
	add	x2,x22,#64
	add	x0,sp,#352
	bl	__sm2_z256_modp_mont_mul	// p256_mul_mont(S2, Z1sqr, in1_z);

	ldr	x3,[x22,#32]
	ldp	x4,x5,[sp,#320]
	ldp	x6,x7,[sp,#320+16]
	add	x2,x22,#32
	add	x0,sp,#320
	bl	__sm2_z256_modp_mont_mul	// p256_mul_mont(S1, S1, in1_y);

	ldr	x3,[x23,#32]
	ldp	x4,x5,[sp,#352]
	ldp	x6,x7,[sp,#352+16]
	add	x2,x23,#32
	add	x0,sp,#352
	bl	__sm2_z256_modp_mont_mul	// p256_mul_mont(S2, S2, in2_y);

	add	x2,sp,#320
	ldr	x3,[sp,#192]	// forward load for p256_mul_mont
	ldp	x4,x5,[x22]
	ldp	x6,x7,[x22,#16]
	add	x0,sp,#160
	bl	__sm2_z256_modp_sub	// p256_sub(R, S2, S1);

	orr	x14,x14,x15	// see if result is zero
	orr	x16,x16,x17
	orr	x26,x14,x16	// ~is_equal(S1,S2)

	add	x2,sp,#192
	add	x0,sp,#256
	bl	__sm2_z256_modp_mont_mul	// p256_mul_mont(U1, in1_x, Z2sqr);

	ldr	x3,[sp,#128]
	ldp	x4,x5,[x23]
	ldp	x6,x7,[x23,#16]
	add	x2,sp,#128
	add	x0,sp,#288
	bl	__sm2_z256_modp_mont_mul	// p256_mul_mont(U2, in2_x, Z1sqr);

	add	x2,sp,#256
	ldp	x4,x5,[sp,#160]	// forward load for p256_sqr_mont
	ldp	x6,x7,[sp,#160+16]
	add	x0,sp,#96
	bl	__sm2_z256_modp_sub	// p256_sub(H, U2, U1);

	orr	x14,x14,x15	// see if result is zero
	orr	x16,x16,x17
	orr	x14,x14,x16	// ~is_equal(U1,U2)

	mvn	x27,x24	// -1/0 -> 0/-1
	mvn	x28,x25	// -1/0 -> 0/-1
	orr	x14,x14,x27
	orr	x14,x14,x28
	orr	x14,x14,x26
	cbnz	x14,Ladd_proceed	// if(~is_equal(U1,U2) | in1infty | in2infty | ~is_equal(S1,S2))

Ladd_double:
	mov	x1,x22
	mov	x0,x21
	ldp	x23,x24,[x29,#48]
	ldp	x25,x26,[x29,#64]
	ldp	x27,x28,[x29,#80]
	add	sp,sp,#32*(12-4)	// difference in stack frames
	b	Ldouble_shortcut

.align	4
Ladd_proceed:
	add	x0,sp,#192
	bl	__sm2_z256_modp_mont_sqr	// p256_sqr_mont(Rsqr, R);

	ldr	x3,[x22,#64]
	ldp	x4,x5,[sp,#96]
	ldp	x6,x7,[sp,#96+16]
	add	x2,x22,#64
	add	x0,sp,#64
	bl	__sm2_z256_modp_mont_mul	// p256_mul_mont(res_z, H, in1_z);

	ldp	x4,x5,[sp,#96]
	ldp	x6,x7,[sp,#96+16]
	add	x0,sp,#128
	bl	__sm2_z256_modp_mont_sqr	// p256_sqr_mont(Hsqr, H);

	ldr	x3,[x23,#64]
	ldp	x4,x5,[sp,#64]
	ldp	x6,x7,[sp,#64+16]
	add	x2,x23,#64
	add	x0,sp,#64
	bl	__sm2_z256_modp_mont_mul	// p256_mul_mont(res_z, res_z, in2_z);

	ldr	x3,[sp,#96]
	ldp	x4,x5,[sp,#128]
	ldp	x6,x7,[sp,#128+16]
	add	x2,sp,#96
	add	x0,sp,#224
	bl	__sm2_z256_modp_mont_mul	// p256_mul_mont(Hcub, Hsqr, H);

	ldr	x3,[sp,#128]
	ldp	x4,x5,[sp,#256]
	ldp	x6,x7,[sp,#256+16]
	add	x2,sp,#128
	add	x0,sp,#288
	bl	__sm2_z256_modp_mont_mul	// p256_mul_mont(U2, U1, Hsqr);

	mov	x8,x14
	mov	x9,x15
	mov	x10,x16
	mov	x11,x17
	add	x0,sp,#128
	bl	__sm2_z256_modp_add	// p256_mul_by_2(Hsqr, U2);

	add	x2,sp,#192
	add	x0,sp,#0
	bl	__sm2_z256_modp_neg_sub	// p256_sub(res_x, Rsqr, Hsqr);

	add	x2,sp,#224
	bl	__sm2_z256_modp_sub	//  p256_sub(res_x, res_x, Hcub);

	add	x2,sp,#288
	ldr	x3,[sp,#224]		// forward load for p256_mul_mont
	ldp	x4,x5,[sp,#320]
	ldp	x6,x7,[sp,#320+16]
	add	x0,sp,#32
	bl	__sm2_z256_modp_neg_sub	// p256_sub(res_y, U2, res_x);

	add	x2,sp,#224
	add	x0,sp,#352
	bl	__sm2_z256_modp_mont_mul	// p256_mul_mont(S2, S1, Hcub);

	ldr	x3,[sp,#160]
	ldp	x4,x5,[sp,#32]
	ldp	x6,x7,[sp,#32+16]
	add	x2,sp,#160
	add	x0,sp,#32
	bl	__sm2_z256_modp_mont_mul	// p256_mul_mont(res_y, res_y, R);

	add	x2,sp,#352
	bl	__sm2_z256_modp_sub	// p256_sub(res_y, res_y, S2);

	ldp	x4,x5,[sp,#0]		// res
	ldp	x6,x7,[sp,#0+16]
	ldp	x8,x9,[x23]		// in2
	ldp	x10,x11,[x23,#16]
	ldp	x14,x15,[x22,#0]	// in1
	cmp	x24,#0			// ~, remember?
	ldp	x16,x17,[x22,#0+16]
	csel	x8,x4,x8,ne
	csel	x9,x5,x9,ne
	ldp	x4,x5,[sp,#0+0+32]	// res
	csel	x10,x6,x10,ne
	csel	x11,x7,x11,ne
	cmp	x25,#0			// ~, remember?
	ldp	x6,x7,[sp,#0+0+48]
	csel	x14,x8,x14,ne
	csel	x15,x9,x15,ne
	ldp	x8,x9,[x23,#0+32]	// in2
	csel	x16,x10,x16,ne
	csel	x17,x11,x17,ne
	ldp	x10,x11,[x23,#0+48]
	stp	x14,x15,[x21,#0]
	stp	x16,x17,[x21,#0+16]
	ldp	x14,x15,[x22,#32]	// in1
	cmp	x24,#0			// ~, remember?
	ldp	x16,x17,[x22,#32+16]
	csel	x8,x4,x8,ne
	csel	x9,x5,x9,ne
	ldp	x4,x5,[sp,#0+32+32]	// res
	csel	x10,x6,x10,ne
	csel	x11,x7,x11,ne
	cmp	x25,#0			// ~, remember?
	ldp	x6,x7,[sp,#0+32+48]
	csel	x14,x8,x14,ne
	csel	x15,x9,x15,ne
	ldp	x8,x9,[x23,#32+32]	// in2
	csel	x16,x10,x16,ne
	csel	x17,x11,x17,ne
	ldp	x10,x11,[x23,#32+48]
	stp	x14,x15,[x21,#32]
	stp	x16,x17,[x21,#32+16]
	ldp	x14,x15,[x22,#64]	// in1
	cmp	x24,#0			// ~, remember?
	ldp	x16,x17,[x22,#64+16]
	csel	x8,x4,x8,ne
	csel	x9,x5,x9,ne
	csel	x10,x6,x10,ne
	csel	x11,x7,x11,ne
	cmp	x25,#0			// ~, remember?
	csel	x14,x8,x14,ne
	csel	x15,x9,x15,ne
	csel	x16,x10,x16,ne
	csel	x17,x11,x17,ne
	stp	x14,x15,[x21,#64]
	stp	x16,x17,[x21,#64+16]

Ladd_done:
	add	sp,x29,#0		// destroy frame
	ldp	x19,x20,[x29,#16]
	ldp	x21,x22,[x29,#32]
	ldp	x23,x24,[x29,#48]
	ldp	x25,x26,[x29,#64]
	ldp	x27,x28,[x29,#80]
	ldp	x29,x30,[sp],#96
	ret




.globl	func(sm2_z256_point_add_affine)

.align	5
func(sm2_z256_point_add_affine):

	stp	x29,x30,[sp,#-80]!
	add	x29,sp,#0
	stp	x19,x20,[sp,#16]
	stp	x21,x22,[sp,#32]
	stp	x23,x24,[sp,#48]
	stp	x25,x26,[sp,#64]
	sub	sp,sp,#32*10

	mov	x21,x0
	mov	x22,x1
	mov	x23,x2

	// load modp
	mov	x12,#neg_p1
	mov	x13,#neg_p3

	ldp	x4,x5,[x1,#64]	// in1_z
	ldp	x6,x7,[x1,#64+16]
	orr	x8,x4,x5
	orr	x10,x6,x7
	orr	x24,x8,x10
	cmp	x24,#0
	csetm	x24,ne		// ~in1infty

	ldp	x14,x15,[x2]	// in2_x
	ldp	x16,x17,[x2,#16]
	ldp	x8,x9,[x2,#32]	// in2_y
	ldp	x10,x11,[x2,#48]
	orr	x14,x14,x15
	orr	x16,x16,x17
	orr	x8,x8,x9
	orr	x10,x10,x11
	orr	x14,x14,x16
	orr	x8,x8,x10
	orr	x25,x14,x8
	cmp	x25,#0
	csetm	x25,ne		// ~in2infty

	add	x0,sp,#128
	bl	__sm2_z256_modp_mont_sqr	// p256_sqr_mont(Z1sqr, in1_z);

	mov	x4,x14
	mov	x5,x15
	mov	x6,x16
	mov	x7,x17
	ldr	x3,[x23]
	add	x2,x23,#0
	add	x0,sp,#96
	bl	__sm2_z256_modp_mont_mul	// p256_mul_mont(U2, Z1sqr, in2_x);

	add	x2,x22,#0
	ldr	x3,[x22,#64]	// forward load for p256_mul_mont
	ldp	x4,x5,[sp,#128]
	ldp	x6,x7,[sp,#128+16]
	add	x0,sp,#160
	bl	__sm2_z256_modp_sub	// p256_sub(H, U2, in1_x);

	add	x2,x22,#64
	add	x0,sp,#128
	bl	__sm2_z256_modp_mont_mul	// p256_mul_mont(S2, Z1sqr, in1_z);

	ldr	x3,[x22,#64]
	ldp	x4,x5,[sp,#160]
	ldp	x6,x7,[sp,#160+16]
	add	x2,x22,#64
	add	x0,sp,#64
	bl	__sm2_z256_modp_mont_mul	// p256_mul_mont(res_z, H, in1_z);

	ldr	x3,[x23,#32]
	ldp	x4,x5,[sp,#128]
	ldp	x6,x7,[sp,#128+16]
	add	x2,x23,#32
	add	x0,sp,#128
	bl	__sm2_z256_modp_mont_mul	// p256_mul_mont(S2, S2, in2_y);

	add	x2,x22,#32
	ldp	x4,x5,[sp,#160]	// forward load for p256_sqr_mont
	ldp	x6,x7,[sp,#160+16]
	add	x0,sp,#192
	bl	__sm2_z256_modp_sub	// p256_sub(R, S2, in1_y);

	add	x0,sp,#224
	bl	__sm2_z256_modp_mont_sqr	// p256_sqr_mont(Hsqr, H);

	ldp	x4,x5,[sp,#192]
	ldp	x6,x7,[sp,#192+16]
	add	x0,sp,#288
	bl	__sm2_z256_modp_mont_sqr	// p256_sqr_mont(Rsqr, R);

	ldr	x3,[sp,#160]
	ldp	x4,x5,[sp,#224]
	ldp	x6,x7,[sp,#224+16]
	add	x2,sp,#160
	add	x0,sp,#256
	bl	__sm2_z256_modp_mont_mul	// p256_mul_mont(Hcub, Hsqr, H);

	ldr	x3,[x22]
	ldp	x4,x5,[sp,#224]
	ldp	x6,x7,[sp,#224+16]
	add	x2,x22,#0
	add	x0,sp,#96
	bl	__sm2_z256_modp_mont_mul	// p256_mul_mont(U2, in1_x, Hsqr);

	mov	x8,x14
	mov	x9,x15
	mov	x10,x16
	mov	x11,x17
	add	x0,sp,#224
	bl	__sm2_z256_modp_add	// p256_mul_by_2(Hsqr, U2);

	add	x2,sp,#288
	add	x0,sp,#0
	bl	__sm2_z256_modp_neg_sub	// p256_sub(res_x, Rsqr, Hsqr);

	add	x2,sp,#256
	bl	__sm2_z256_modp_sub	//  p256_sub(res_x, res_x, Hcub);

	add	x2,sp,#96
	ldr	x3,[x22,#32]	// forward load for p256_mul_mont
	ldp	x4,x5,[sp,#256]
	ldp	x6,x7,[sp,#256+16]
	add	x0,sp,#32
	bl	__sm2_z256_modp_neg_sub	// p256_sub(res_y, U2, res_x);

	add	x2,x22,#32
	add	x0,sp,#128
	bl	__sm2_z256_modp_mont_mul	// p256_mul_mont(S2, in1_y, Hcub);

	ldr	x3,[sp,#192]
	ldp	x4,x5,[sp,#32]
	ldp	x6,x7,[sp,#32+16]
	add	x2,sp,#192
	add	x0,sp,#32
	bl	__sm2_z256_modp_mont_mul	// p256_mul_mont(res_y, res_y, R);

	add	x2,sp,#128
	bl	__sm2_z256_modp_sub	// p256_sub(res_y, res_y, S2);

	ldp	x4,x5,[sp,#0]		// res
	ldp	x6,x7,[sp,#0+16]
	ldp	x8,x9,[x23]		// in2
	ldp	x10,x11,[x23,#16]
	ldp	x14,x15,[x22,#0]	// in1
	cmp	x24,#0			// ~, remember?
	ldp	x16,x17,[x22,#0+16]
	csel	x8,x4,x8,ne
	csel	x9,x5,x9,ne
	ldp	x4,x5,[sp,#0+0+32]	// res
	csel	x10,x6,x10,ne
	csel	x11,x7,x11,ne
	cmp	x25,#0			// ~, remember?
	ldp	x6,x7,[sp,#0+0+48]
	csel	x14,x8,x14,ne
	csel	x15,x9,x15,ne
	ldp	x8,x9,[x23,#0+32]	// in2
	csel	x16,x10,x16,ne
	csel	x17,x11,x17,ne
	ldp	x10,x11,[x23,#0+48]
	stp	x14,x15,[x21,#0]
	stp	x16,x17,[x21,#0+16]


	adr	x23,Lneg_p-64
	ldp	x14,x15,[x22,#32]	// in1
	cmp	x24,#0			// ~, remember?
	ldp	x16,x17,[x22,#32+16]
	csel	x8,x4,x8,ne
	csel	x9,x5,x9,ne
	ldp	x4,x5,[sp,#0+32+32]	// res
	csel	x10,x6,x10,ne
	csel	x11,x7,x11,ne
	cmp	x25,#0			// ~, remember?
	ldp	x6,x7,[sp,#0+32+48]
	csel	x14,x8,x14,ne
	csel	x15,x9,x15,ne
	ldp	x8,x9,[x23,#32+32]	// in2
	csel	x16,x10,x16,ne
	csel	x17,x11,x17,ne
	ldp	x10,x11,[x23,#32+48]
	stp	x14,x15,[x21,#32]
	stp	x16,x17,[x21,#32+16]
	ldp	x14,x15,[x22,#64]	// in1
	cmp	x24,#0			// ~, remember?
	ldp	x16,x17,[x22,#64+16]
	csel	x8,x4,x8,ne
	csel	x9,x5,x9,ne
	csel	x10,x6,x10,ne
	csel	x11,x7,x11,ne
	cmp	x25,#0			// ~, remember?
	csel	x14,x8,x14,ne
	csel	x15,x9,x15,ne
	csel	x16,x10,x16,ne
	csel	x17,x11,x17,ne
	stp	x14,x15,[x21,#64]
	stp	x16,x17,[x21,#64+16]

	add	sp,x29,#0		// destroy frame
	ldp	x19,x20,[x29,#16]
	ldp	x21,x22,[x29,#32]
	ldp	x23,x24,[x29,#48]
	ldp	x25,x26,[x29,#64]
	ldp	x29,x30,[sp],#80
	ret





.align 4
__sm2_z256_modn_add:

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


.globl func(sm2_z256_modn_add)
.align 4
func(sm2_z256_modn_add):

	stp	x29,x30,[sp,#-16]!
	add	x29,sp,#0

	ldp	x14,x15,[x1]
	ldp	x16,x17,[x1,#16]
	ldp	x4,x5,[x2]
	ldp	x6,x7,[x2,#16]

	ldr	x10,Lmodn
	ldr	x11,Lmodn+8
	ldr	x12,Lmodn+16
	ldr	x13,Lmodn+24

	bl	__sm2_z256_modn_add

	ldp	x29,x30,[sp],#16
	ret


.align	4
__sm2_z256_modn_sub:

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


.globl	func(sm2_z256_modn_sub)
.align	4
func(sm2_z256_modn_sub):

	stp	x29,x30,[sp,#-16]!
	add	x29,sp,#0

	ldp	x14,x15,[x1]
	ldp	x16,x17,[x1,#16]

	ldr	x10,Lmodn
	ldr	x11,Lmodn+8
	ldr	x12,Lmodn+16
	ldr	x13,Lmodn+24

	bl	__sm2_z256_modn_sub

	ldp	x29,x30,[sp],#16
	ret


.globl	func(sm2_z256_modn_neg)
.align	4
func(sm2_z256_modn_neg):

	stp	x29,x30,[sp,#-16]!
	add	x29,sp,#0

	ldr	x10,Lmodn
	ldr	x11,Lmodn+8
	ldr	x12,Lmodn+16
	ldr	x13,Lmodn+24

	mov	x2,x1

	mov	x14,xzr
	mov	x15,xzr
	mov	x16,xzr
	mov	x17,xzr

	bl	__sm2_z256_modn_sub

	ldp	x29,x30,[sp],#16
	ret


.align	4
__sm2_z256_modn_mont_mul:
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



// mu = -n^-1 mod 2^64
// sage: n = 0xfffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123
// sage: mu = -(IntegerModRing(2^64)(n))^-1
Lmodn_mu:
.quad	0x327f9e8872350975


.globl	func(sm2_z256_modn_mont_mul)
.align	4

func(sm2_z256_modn_mont_mul):

	stp	x29,x30,[sp,#-64]!
	add	x29,sp,#0
	stp	x19,x20,[sp,#16]
	stp	x21,x22,[sp,#32]
	stp	x23,x24,[sp,#48]

	// mu = -n^-1 mod 2^64
	ldr	x9,Lmodn_mu

	// load modp
	ldr	x10,Lmodn
	ldr	x11,Lmodn+8
	ldr	x12,Lmodn+16
	ldr	x13,Lmodn+24

	// load a
	ldp     x4,x5,[x1]
	ldp     x6,x7,[x1,#16]

	// load b0
	ldr	x3,[x2]

	bl	__sm2_z256_modn_mont_mul

	add	sp,x29,#0
	ldp	x19,x20,[x29,#16]
	ldp	x21,x22,[x29,#32]
	ldp	x23,x24,[x29,#48]
	ldp	x29,x30,[sp],#64
	ret



// mont(mont(a), 1) = aR * 1 * R^-1 (mod p) = a (mod p)
.globl	func(sm2_z256_modn_from_mont)

.align	4
func(sm2_z256_modn_from_mont):

	stp	x29,x30,[sp,#-64]!
	add	x29,sp,#0
	stp	x19,x20,[sp,#16]
	stp	x21,x22,[sp,#32]
	stp	x23,x24,[sp,#48]

	// mu = -p^-1 mod 2^64
	ldr	x9,Lmodn_mu

	// load p
	ldr	x10,Lmodn
	ldr	x11,Lmodn+8
	ldr	x12,Lmodn+16
	ldr	x13,Lmodn+24

	// load a
	ldp     x4,x5,[x1]
	ldp     x6,x7,[x1,#16]

	// b = {1,0,0,0}
	adr     x2,Lone
	// b0 = 1
	mov	x3,#1

	bl	__sm2_z256_modn_mont_mul

	add	sp,x29,#0
	ldp	x19,x20,[x29,#16]
	ldp	x21,x22,[x29,#32]
	ldp	x23,x24,[x29,#48]
	ldp	x29,x30,[sp],#64
	ret



// 2^512 mod n = 0x1eb5e412a22b3d3b620fc84c3affe0d43464504ade6fa2fa901192af7c114f20
Lsm2_z256_modn_2e512:
.quad	0x901192af7c114f20, 0x3464504ade6fa2fa, 0x620fc84c3affe0d4, 0x1eb5e412a22b3d3b

// mont(a) = a * 2^256 (mod p) = mont_mul(a, 2^512 mod p)
.globl  func(sm2_z256_modn_to_mont)
.align	6

func(sm2_z256_modn_to_mont):

	stp	x29,x30,[sp,#-64]!
	add	x29,sp,#0
	stp	x19,x20,[sp,#16]
	stp	x21,x22,[sp,#32]
	stp	x23,x24,[sp,#48]

	// mu = -p^-1 mod 2^64
	ldr	x9,Lmodn_mu

	// load modp
	ldr	x10,Lmodn
	ldr	x11,Lmodn+8
	ldr	x12,Lmodn+16
	ldr	x13,Lmodn+24

	// swap args x0,x1 = x1,x0
	mov	x3,x1
	mov	x1,x0
	mov	x0,x3

	// load a
	ldp     x4,x5,[x1]
	ldp     x6,x7,[x1,#16]

	// load b = 2^512 mod p
	adr     x2,Lsm2_z256_modn_2e512
	// load b0
	ldr     x3,Lsm2_z256_modn_2e512

	bl	__sm2_z256_modn_mont_mul

	add	sp,x29,#0
	ldp	x19,x20,[x29,#16]
	ldp	x21,x22,[x29,#32]
	ldp	x23,x24,[x29,#48]
	ldp	x29,x30,[sp],#64
	ret


.align	4
__sm2_z256_modn_mont_sqr:

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


.globl	func(sm2_z256_modn_mont_sqr)
.align	4

func(sm2_z256_modn_mont_sqr):
	stp	x29,x30,[sp,#-64]!
	add	x29,sp,#0
	stp	x19,x20,[sp,#16]
	stp	x21,x22,[sp,#32]
	stp	x23,x24,[sp,#48]

	// mu = -p^-1 mod 2^64
	ldr	x9,Lmodn_mu

	// load modp
	ldr	x10,Lmodn
	ldr	x11,Lmodn+8
	ldr	x12,Lmodn+16
	ldr	x13,Lmodn+24

	// load a
	ldp	x4,x5,[x1]
	ldp	x6,x7,[x1,#16]

	bl	__sm2_z256_modn_mont_sqr

	add	sp,x29,#0
	ldp	x19,x20,[x29,#16]
	ldp	x21,x22,[x29,#32]
	ldp	x23,x24,[x29,#48]
	ldp	x29,x30,[sp],#64
	ret

