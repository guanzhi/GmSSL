/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#include <gmssl/asm.h>

.align	7

LFK:
.long	0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc

LCK:
.long	0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269
.long	0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9
.long	0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249
.long	0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9
.long	0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229
.long	0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299
.long	0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209
.long	0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279

LSBOX:
.byte	0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7
.byte	0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05
.byte	0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3
.byte	0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99
.byte	0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a
.byte	0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62
.byte	0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95
.byte	0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6
.byte	0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba
.byte	0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8
.byte	0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b
.byte	0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35
.byte	0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2
.byte	0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87
.byte	0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52
.byte	0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e
.byte	0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5
.byte	0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1
.byte	0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55
.byte	0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3
.byte	0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60
.byte	0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f
.byte	0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f
.byte	0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51
.byte	0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f
.byte	0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8
.byte	0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd
.byte	0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0
.byte	0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e
.byte	0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84
.byte	0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20
.byte	0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48

// X0, X1, X2, X3 => X1, X2, X3, X0
Llshift:
.byte	4,5,6,7,  8,9,10,11,  12,13,14,15,  0,1,2,3


.globl	func(sm4_set_encrypt_key)
.align	4

func(sm4_set_encrypt_key):

	// load const v16..v31 = SBox
	adr	x3, LSBOX
	ld1	{v16.16b,v17.16b,v18.16b,v19.16b}, [x3], #64
	ld1	{v20.16b,v21.16b,v22.16b,v23.16b}, [x3], #64
	ld1	{v24.16b,v25.16b,v26.16b,v27.16b}, [x3], #64
	ld1	{v28.16b,v29.16b,v30.16b,v31.16b}, [x3]

	// load const v15 = [64, 64, ...]
	movi	v15.16b, #64

	// load const v14 = lshift index
	adr	x3, Llshift
	ld1	{v14.2d}, [x3]

	// load const v13 = FK
	adr	x3, LFK
	ld1	{v13.2d}, [x3]

	// load const x5 = CK address
	adr	x15, LCK

	// load user_key v1 = X0,X1,X2,X3
	ld1	{v1.4s}, [x1]
	rev32	v1.16b, v1.16b

	// X = X ^ FK
	eor	v1.16b, v1.16b, v13.16b

	// x4(w4) as X4, x5(w5) as tmp

	// rounds = 32
	mov	x6, #32

1:
	// w4 = X1 ^ X2 ^ X3 ^ CK[0]
	mov	w4, v1.s[1]
	mov	w5, v1.s[2]
	eor	w4, w4, w5
	mov	w5, v1.s[3]
	eor	w4, w4, w5
	ldr	w5, [x15], #4
	eor	w4, w4, w5

	// sbox lookup, X4 = w4 = v3[0] = sbox(v2[0])
	mov	v2.s[0], w4
	tbl	v3.16b, {v16.16b,v17.16b,v18.16b,v19.16b}, v2.16b
	sub	v2.16b, v2.16b, v15.16b
	tbx	v3.16b, {v20.16b,v21.16b,v22.16b,v23.16b}, v2.16b
	sub	v2.16b, v2.16b, v15.16b
	tbx	v3.16b, {v24.16b,v25.16b,v26.16b,v27.16b}, v2.16b
	sub	v2.16b, v2.16b, v15.16b
	tbx	v3.16b, {v28.16b,v29.16b,v30.16b,v31.16b}, v2.16b
	mov	w4, v3.s[0]

	// X4 = X0 ^ X4 ^ (X4 <<< 13) ^ (X4 <<< 23)
	mov	w5, v1.s[0]
	eor	w5, w4, w5
	eor	w5, w5, w4, ror #32-23
	eor	w4, w5, w4, ror #32-13

	// output rk[i]
	str	w4, [x0], #4

	// X1,X2,X3,X0 = X0,X1,X2,X3
	mov	v1.s[0], w4
	tbl	v1.16b, {v1.16b}, v14.16b

	// if --rounds != 0, goto label(1)
	subs	x6, x6, #1
	b.ne	1b

	ret


.globl	func(sm4_set_decrypt_key)
.align	4

func(sm4_set_decrypt_key):

	// load const v16..v31 = SBox
	adr	x3,LSBOX
	ld1	{v16.16b,v17.16b,v18.16b,v19.16b},[x3],#64
	ld1	{v20.16b,v21.16b,v22.16b,v23.16b},[x3],#64
	ld1	{v24.16b,v25.16b,v26.16b,v27.16b},[x3],#64
	ld1	{v28.16b,v29.16b,v30.16b,v31.16b},[x3]

	// load const v15 = [64, 64, ...]
	movi	v15.16b, #64

	// load const v14 = lshift index
	adr	x3,Llshift
	ld1	{v14.2d},[x3]

	// load const v13 = FK
	adr	x3,LFK
	ld1	{v13.2d},[x3]

	// load const x5 = CK address
	adr	x15,LCK

	// load user_key v1 = X0,X1,X2,X3
	ld1	{v1.4s}, [x1]
	rev32	v1.16b, v1.16b

	// X = X ^ FK
	eor	v1.16b, v1.16b, v13.16b

	// x4(w4) as X4, x5(w5) as tmp

	// rounds = 32
	mov	x6, #32

	// set rk offset (31 * 4 = 124)
	add     x0, x0, 124

2:
	// w4 = X1 ^ X2 ^ X3 ^ CK[0]
	mov	w4, v1.s[1]
	mov	w5, v1.s[2]
	eor	w4, w4, w5
	mov	w5, v1.s[3]
	eor	w4, w4, w5
	ldr	w5, [x15], #4
	eor	w4, w4, w5

	// sbox lookup, X4 = w4 = v3[0] = sbox(v2[0])
	mov	v2.s[0], w4
	tbl	v3.16b, {v16.16b,v17.16b,v18.16b,v19.16b},v2.16b
	sub	v2.16b, v2.16b, v15.16b
	tbx	v3.16b, {v20.16b,v21.16b,v22.16b,v23.16b},v2.16b
	sub	v2.16b, v2.16b, v15.16b
	tbx	v3.16b, {v24.16b,v25.16b,v26.16b,v27.16b},v2.16b
	sub	v2.16b, v2.16b, v15.16b
	tbx	v3.16b, {v28.16b,v29.16b,v30.16b,v31.16b},v2.16b
	mov	w4, v3.s[0]

	// X4 = X0 ^ X4 ^ (X4 <<< 13) ^ (X4 <<< 23)
	mov	w5, v1.s[0]
	eor	w5, w4, w5
	eor	w5, w5, w4, ror #32-23
	eor	w4, w5, w4, ror #32-13

	// output rk[31 - i]
	str	w4, [x0], #-4

	// X1,X2,X3,X0 = X0,X1,X2,X3
	mov	v1.s[0], w4
	tbl	v1.16b,{v1.16b},v14.16b

	// if --rounds != 0, goto label(1)
	subs	x6, x6, #1
	b.ne	2b

	ret


.globl	func(sm4_encrypt)

.align	5
func(sm4_encrypt):

	// load sbox
	adr	x3, LSBOX
	ld1	{v16.16b,v17.16b,v18.16b,v19.16b}, [x3], #64
	ld1	{v20.16b,v21.16b,v22.16b,v23.16b}, [x3], #64
	ld1	{v24.16b,v25.16b,v26.16b,v27.16b}, [x3], #64
	ld1	{v28.16b,v29.16b,v30.16b,v31.16b}, [x3]

	// load const v15 = [64, 64, ...]
	movi	v15.16b, #64

	// load input block
	ld1	{v1.4s}, [x1]
	rev32	v1.16b, v1.16b

	// w10,w11,w12,w13 = X0,X1,X2,X3
	mov	w10, v1.s[0]
	mov	w11, v1.s[1]
	mov	w12, v1.s[2]
	mov	w13, v1.s[3]

	// w8,w9 as tmp

	// round = 32
	mov	w6, #32
3:
	// load rk[i]
	ldr	w3,[x0],4

	// X4 = (X2 ^ X3) ^ (RK[0] ^ X1)
	eor	w8, w12, w13
	eor	w9, w3, w11
	eor	w8, w8, w9

	// sbox lookup, X4 = SBOX(X4)
	mov	v2.s[0], w8
	tbl	v3.16b, {v16.16b,v17.16b,v18.16b,v19.16b}, v2.16b
	sub	v2.16b, v2.16b, v15.16b
	tbx	v3.16b, {v20.16b,v21.16b,v22.16b,v23.16b}, v2.16b
	sub	v2.16b, v2.16b, v15.16b
	tbx	v3.16b, {v24.16b,v25.16b,v26.16b,v27.16b}, v2.16b
	sub	v2.16b, v2.16b, v15.16b
	tbx	v3.16b, {v28.16b,v29.16b,v30.16b,v31.16b}, v2.16b
	mov	w3, v3.s[0]

	// X0 = X0 ^ X4 ^ (X4 <<< 2) ^ (X4 <<< 10) ^ (X4 <<< 18) ^ (X <<< 24)
	eor	w8, w3, w3, ror #32-2
	eor	w8, w8, w3, ror #32-10
	eor	w8, w8, w3, ror #32-18
	eor	w8, w8, w3, ror #32-24
	eor	w8, w8, w10

	mov	w10, w11
	mov	w11, w12
	mov	w12, w13
	mov	w13, w8

	subs	w6, w6, #1
	b.ne    3b

	// output X3,X2,X1,X0
	mov	v1.s[0], w13
	mov	v1.s[1], w12
	mov	v1.s[2], w11
	mov	v1.s[3], w10

	rev32	v1.16b, v1.16b

	st1	{v1.4s}, [x2]

	ret

