/*
 *  Copyright 2025 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#include <gmssl/asm.h>

.text

Lsm2_z256_modn_2e512:
.quad   0x901192af7c114f20, 0x3464504ade6fa2fa, 0x620fc84c3affe0d4, 0x1eb5e412a22b3d3b

Lone:
.quad   1,0,0,0

/*
   (t0, t1, t2, t3) = (t0, t1, t2, t3) + (a4, a5, a6, a7)
 */
.align	5
__sm2_z256_modp_add:
	add.d	$t0, $t0, $a4
	add.d	$t1, $t1, $a5
	add.d	$t2, $t2, $a6
	add.d	$t3, $t3, $a7

	sltu	$a2, $t0, $a4
	addi.d	$t4, $t0, 1
	sltu	$t5, $t1, $a5
	sltu	$t6, $t2, $a6

	add.d	$t1, $t1, $a2
	sltu	$a1, $t4, $t0
	sltu	$a2, $t1, $a2
	add.d	$t7, $t8, $a1		//no carry

	or	$a2, $a2, $t5
	add.d	$t5, $t1, $t7
	sltu	$t7, $t3, $a7
	sltu	$a1, $t5, $t1

	add.d	$t2, $t2, $a2
	sltu	$a2, $t2, $a2
	or	$a2, $a2, $t6
	add.d	$t6, $t2, $a1

	add.d	$t3, $t3, $a2
	sltu	$a1, $t6, $t2		//no carry
	sltu	$a2, $t3, $a2
	add.d	$a1, $a3, $a1

	or	$a2, $a2, $t7
	add.d	$t7, $a1, $t3
	sltu	$a1, $t7, $t3
	add.d	$a2, $a2, $a1

	masknez	$t0, $t0, $a2
	maskeqz	$t4, $t4, $a2
	masknez	$t1, $t1, $a2
	maskeqz	$t5, $t5, $a2

	or	$t0, $t0, $t4
	or	$t1, $t1, $t5
	masknez	$t2, $t2, $a2
	maskeqz	$t6, $t6, $a2

	masknez	$t3, $t3, $a2
	maskeqz	$t7, $t7, $a2
	or	$t2, $t2, $t6
	or	$t3, $t3, $t7

	jr	$ra

/*
	(t0, t1, t2, t3) = (t0, t1, t2, t3)*2
 */
.align	5
__sm2_z256_modp_dbl:
	srli.d	$a1, $t0, 63
	srli.d	$t6, $t1, 63
	srli.d	$t5, $t2, 63
	slli.d	$t0, $t0, 1

	srli.d	$a2, $t3, 63
		addi.d	$t4, $t0, 1
	alsl.d	$t1, $t1, $a1, 1
	alsl.d	$t2, $t2, $t6, 1

	alsl.d	$t3, $t3, $t5, 1
	sltu	$a1, $t4, $t0
	add.d	$t5, $t1, $t8	//no carry
	add.d	$t5, $t5, $a1

	add.d	$t7, $t3, $a3	//no carry
	sltu	$a1, $t5, $t1
	add.d	$t6, $t2, $a1
	sltu	$a1, $t6, $t2

	add.d	$t7, $t7, $a1
	sltu	$a1, $t7, $t3
	add.d	$a2, $a2, $a1

	masknez	$t0, $t0, $a2
	maskeqz	$t4, $t4, $a2
	masknez	$t1, $t1, $a2
	maskeqz	$t5, $t5, $a2

	or	$t0, $t0, $t4
	or	$t1, $t1, $t5
	masknez	$t2, $t2, $a2
	maskeqz	$t6, $t6, $a2

	masknez	$t3, $t3, $a2
	maskeqz	$t7, $t7, $a2
	or	$t2, $t2, $t6
	or	$t3, $t3, $t7

	jr	$ra


// a - b (mod p)
// (t0, t1, t2, t3) = (t0, t1, t2, t3) - (a4, a5, a6, a7)
.align	5
__sm2_z256_modp_sub:
	sltu	$a2, $t0, $a4
	sub.d	$t0, $t0, $a4
	sltu	$a1, $t1, $a5
	sub.d	$t1, $t1, $a5

	sltu	$t5, $t1, $a2
	sub.d	$t1, $t1, $a2
	li.d	$t4, 1
	or	$a2, $a1, $t5

	sltu	$a1, $t2, $a6
	sub.d	$t2, $t2, $a6
	sltu	$t6, $t2, $a2
	sub.d	$t2, $t2, $a2

	or	$a2, $t6, $a1
	sub.d	$a1, $t3, $a7
	sltu	$t6, $t3, $a7
	sub.d	$t3, $a1, $a2

	sltu	$a2, $a1, $a2
	or	$a2, $a2, $t6
	maskeqz	$t4, $t4, $a2
	maskeqz	$t5, $t8, $a2

	maskeqz	$t7, $a3, $a2
	sltu	$a1, $t0, $t4
	sub.d	$t0, $t0, $t4
	add.d	$a1, $a1, $t5	//no carry

	sltu	$a2, $t1, $a1
	sub.d	$t1, $t1, $a1
	sltu	$a1, $t2, $a2
	sub.d	$t2, $t2, $a2

	add.d	$a1, $a1, $t7	//no carry
	sub.d	$t3, $t3, $a1
	jr	$ra

// b - a (mod p)
.align	5
__sm2_z256_modp_neg_sub:
	sltu	$a2, $a4, $t0
	sub.d	$t0, $a4, $t0
	sltu	$a1, $a5, $t1
	sub.d	$t1, $a5, $t1

	sltu	$t5, $t1, $a2
	sub.d	$t1, $t1, $a2
	li.d	$t4, 1
	or	$a2, $a1, $t5

	sltu	$a1, $a6, $t2
	sub.d	$t2, $a6, $t2
	sltu	$t6, $t2, $a2
	sub.d	$t2, $t2, $a2

	or	$a2, $t6, $a1
	sub.d	$a1, $a7, $t3
	sltu	$t6, $a7, $t3
	sub.d	$t3, $a1, $a2

	sltu	$a2, $a1, $a2
	or	$a2, $a2, $t6
	maskeqz	$t4, $t4, $a2
	maskeqz	$t5, $t8, $a2

	maskeqz	$t7, $a3, $a2
	sltu	$a1, $t0, $t4
	sub.d	$t0, $t0, $t4
	add.d	$a1, $a1, $t5	//no carry

	sltu	$a2, $t1, $a1
	sub.d	$t1, $t1, $a1
	sltu	$a1, $t2, $a2
	sub.d	$t2, $t2, $a2

	add.d	$a1, $a1, $t7	//no carry
	sub.d	$t3, $t3, $a1
	jr	$ra

.align	5
__sm2_z256_modp_haf:
	andi	$a2, $t0, 1
	li.d	$t4, 1
	maskeqz	$t4, $t4, $a2
	maskeqz	$t5, $t8, $a2

	maskeqz $t7, $a3, $a2
	sltu	$a1, $t0, $t4
	sub.d	$t0, $t0, $t4
	add.d	$t5, $t5, $a1	//no carry

	srli.d	$t0, $t0, 1
	sltu	$a1, $t1, $t5
	sub.d	$t1, $t1, $t5
	sltu	$t6, $t2, $a1

	bstrins.d	$t0, $t1, 63, 63
	sub.d	$t2, $t2, $a1
	srli.d	$t1, $t1, 1
	add.d	$t7, $t6, $t7	//no carry

	bstrins.d	$t1, $t2, 63, 63
	srli.d	$t2, $t2, 1
	sub.d	$a1, $t3, $t7
	sltu	$t7, $t7, $t3	//~carry

	bstrins.d	$t2, $a1, 63, 63
	srli.d	$t3, $a1, 1
	maskeqz	$t7, $t7, $a2
	bstrins.d	$t3, $t7, 63, 63

	jr	$ra

/*
 (t0,t1,t2,t3) = (a4,a5,a6,a7) * (t0,t1,t2,t3)
  a4,a5,a6,a7 not clobber
  s0,s1,s2,s3 clobber
*/
.align	5
__sm2_z256_modp_mont_mul:
	mul.d	$t7, $a4, $t0
	mulh.du	$t4, $a4, $t0
	mul.d	$a1, $a5, $t0
	mul.d	$s2, $a6, $t0

	mulh.du	$t5, $a5, $t0
	mulh.du	$t6, $a6, $t0
	mul.d	$s3, $a7, $t0
	mulh.du	$t0, $a7, $t0

	add.d	$t4, $t4, $a1
	add.d	$t5, $t5, $s2
	add.d	$t6, $t6, $s3
	slli.d	$s0, $t7, 32	//s0 and s1 never overflow

	sltu	$a1, $t4, $a1
	srli.d	$s1, $t7, 32
	sltu	$a2, $t7, $s0
	add.d	$t5, $a1, $t5	//no carry

	sltu	$a1, $t5, $s2
	add.d	$t6, $t6, $a1
	sub.d	$s2, $t7, $s0
	add.d	$a2, $s1, $a2	//no carry, since s1 never overflow

	sltu	$a1, $t6, $s3
	sub.d	$s3, $zero, $a2
	sltu	$a2, $zero, $a2
	sub.d	$s1, $t7, $s1

	add.d	$a1, $t0, $a1	//first round = (a1,t6,t5,t4,t7)
	add.d	$a2, $s0, $a2
	add.d	$t0, $t4, $s2	//t0 = t4 + s2
	add.d	$t4, $t5, $s3


	sub.d	$s0, $zero, $a2
	sltu	$a2, $zero, $a2
	sltu	$t7, $t0, $s2
	sltu	$t5, $t4, $s3

	sub.d	$s1, $s1, $a2	//1st round (s2,s3,s0,s1)
	add.d	$t6, $t6, $s0
	mul.d	$s2, $a4, $t1
	mul.d	$s3, $a5, $t1

	add.d	$t4, $t4, $t7
	sltu	$a2, $t6, $s0
	mul.d	$s0, $a6, $t1
	add.d	$a1, $a1, $s1

	sltu	$t7, $t4, $t7
	or	$t5, $t5, $t7
	sltu	$t7, $a1, $s1
	mul.d	$s1, $a7, $t1	//2nd round lo=(s2,s3,s0,s1)

	add.d	$t5, $t6, $t5
	sltu	$t6, $t5, $t6
	or	$t6, $t6, $a2
	add.d	$t6, $t6, $a1

	add.d	$t0, $t0, $s2
	add.d	$t4, $t4, $s3
	sltu	$a1, $t6, $a1
	or	$a1, $a1, $t7	//1st round (a1,t6,t5,t4,t0)

	sltu	$t7, $t0, $s2
	sltu	$a2, $t4, $s3
	mulh.du	$s2, $a4, $t1
	mulh.du	$s3, $a5, $t1

	add.d	$t4, $t4, $t7
	sltu	$t7, $t4, $t7
	add.d	$t5, $t5, $s0
	add.d	$t6, $t6, $s1

	or	$t7, $t7, $a2
	sltu	$a2, $t5, $s0
	add.d	$t5, $t5, $t7
	mulh.du	$s0, $a6, $t1

	sltu	$t7, $t5, $t7
	or	$t7, $t7, $a2
	sltu	$a2, $t6, $s1
	mulh.du	$s1, $a7, $t1	//2nd round hi=(s2,s3,s0,s1)

	add.d	$t6, $t6, $t7
	sltu	$t7, $t6, $t7
	add.d	$t1, $t4, $s2
	add.d	$t5, $t5, $s3

	or	$t7, $t7, $a2
	add.d	$a1, $a1, $t7
	sltu	$t4, $t1, $s2
	slli.d	$s2, $t0, 32

	add.d	$t5, $t5, $t4
	add.d	$t6, $t6, $s0
	sltu	$t7, $t0, $s2
	sltu	$t4, $t5, $s3

	add.d	$t6, $t6, $t4
	srli.d	$s3, $t0, 32
	add.d	$a1, $a1, $s1
	add.d	$t7, $t7, $s3

	sltu	$t4, $t6, $s0
	sub.d	$s0, $t0, $s2
	sub.d	$s3, $t0, $s3
	add.d	$a1, $a1, $t4

	sltu	$a2, $a1, $s1	//2nd round =(a2,a1,t6,t5,t1,t0)
	sub.d	$s1, $zero, $t7
	sltu	$t7, $zero, $t7
	add.d	$t7, $t7, $s2


	add.d	$t0, $t1, $s0	//3rd round from (s0,s1,s2,s3)
	add.d	$t1, $t5, $s1
	sub.d	$s2, $zero, $t7
	sltu	$t7, $zero, $t7

	sltu	$t4, $t0, $s0
	sltu	$t5, $t1, $s1
	sub.d	$s3, $s3, $t7	//2nd round (s0,s1,s2,s3)
	add.d	$t6, $t6, $s2

	mul.d	$s0, $a4, $t2
	mul.d	$s1, $a5, $t2
	add.d	$t1, $t1, $t4
	sltu	$t7, $t6, $s2

	sltu	$t4, $t1, $t4
	mul.d	$s2, $a6, $t2
	or	$t5, $t5, $t4
	add.d	$a1, $a1, $s3

	add.d	$t5, $t6, $t5
	sltu	$t6, $t5, $t6
	sltu	$t4, $a1, $s3
	mul.d	$s3, $a7, $t2

	or	$t6, $t6, $t7
	add.d	$t6, $a1, $t6
	sltu	$a1, $t6, $a1
	or	$a1, $a1, $t4


	add.d	$t0, $t0, $s0
	add.d	$t1, $t1, $s1
	add.d	$a1, $a2, $a1
	sltu	$t7, $t0, $s0

	sltu	$t4, $t1, $s1
	mulh.du	$s0, $a4, $t2
	mulh.du	$s1, $a5, $t2
	add.d	$t1, $t1, $t7

	add.d	$t5, $t5, $s2
	sltu	$t7, $t1, $t7
	sltu	$a2, $t5, $s2
	mulh.du	$s2, $a6, $t2

	or	$t4, $t4, $t7
	add.d	$t6, $t6, $s3
	sltu	$t7, $t6, $s3
	mulh.du	$s3, $a7, $t2

	add.d	$t2, $t5, $t4
	sltu	$t4, $t2, $t4
	or	$t4, $t4, $a2
	add.d	$t6, $t6, $t4

	sltu	$t4, $t6, $t4
	or	$t4, $t4, $t7
	add.d	$t1, $t1, $s0
	add.d	$t2, $t2, $s1

	add.d	$a1, $a1, $t4
	sltu	$t4, $t1, $s0
	slli.d	$s0, $t0, 32
	add.d	$t2, $t2, $t4

	sltu	$t4, $t2, $s1
	srli.d	$s1, $t0, 32
	sltu	$t5, $t0, $s0
	add.d	$t6, $t6, $s2

	add.d	$t6, $t6, $t4
	sltu	$t4, $t6, $s2
	add.d	$a1, $a1, $s3
	add.d	$t5, $t5, $s1

	sub.d	$s2, $t0, $s0
	sub.d	$s1, $t0, $s1
	add.d	$a1, $a1, $t4
	sltu	$a2, $a1, $s3	//3rd round = (a2,a1,t6,t2,t1,t0)

	sub.d	$s3, $zero, $t5
	sltu	$t5, $zero, $t5
	add.d	$t5, $t5, $s0
	sub.d	$s0, $zero, $t5

	add.d	$t0, $t1, $s2
	add.d	$t1, $t2, $s3
	sltu	$t5, $zero, $t5
	sub.d	$s1, $s1, $t5	//2nd round = (s2,s3,s0,s1)

	sltu	$t4, $t0, $s2
	sltu	$t7, $t1, $s3
	mul.d	$s2, $a4, $t3
	mul.d	$s3, $a5, $t3

	add.d	$t1, $t1, $t4
	add.d	$t2, $t6, $s0

	sltu	$t4, $t1, $t4
	add.d	$t6, $a1, $s1
	sltu	$t5, $t2, $s0
	mul.d	$s0, $a6, $t3

	or	$t4, $t7, $t4
	sltu	$t7, $t6, $s1
	mul.d	$s1, $a7, $t3
	add.d	$t2, $t2, $t4


	sltu	$t4, $t2, $t4
	or	$t4, $t5, $t4
	add.d	$t0, $t0, $s2
	add.d	$t1, $t1, $s3

	add.d	$t6, $t6, $t4
	sltu	$t4, $t6, $t4
	sltu	$t5, $t0, $s2
	mulh.du	$s2, $a4, $t3

	or	$t4, $t7, $t4
	sltu	$t7, $t1, $s3
	mulh.du	$s3, $a5, $t3
	add.d	$t1, $t1, $t5

	sltu	$t5, $t1, $t5
	add.d	$t2, $t2, $s0
	add.d	$t6, $t6, $s1
	add.d	$a1, $a2, $t4

	or	$t5, $t5, $t7
	sltu	$t7, $t2, $s0
	mulh.du	$s0, $a6, $t3
	add.d	$t2, $t2, $t5

	sltu	$t4, $t6, $s1
	sltu	$t5, $t2, $t5
	mulh.du	$s1, $a7, $t3
	or	$t5, $t5, $t7

	add.d	$t1, $t1, $s2
	add.d	$t3, $t6, $t5
	sltu	$t5, $t3, $t5
	add.d	$t2, $t2, $s3

	sltu	$t6, $t1, $s2
	or	$t5, $t5, $t4
	add.d	$t2, $t2, $t6
	slli.d	$s2, $t0, 32

	sltu	$t6, $t2, $s3
	srli.d	$s3, $t0, 32
	add.d	$t3, $t3, $s0
	add.d	$a1, $a1, $t5	// = (a1,t3,t2,t1,t0)

	add.d	$t3, $t3, $t6
	sltu	$t4, $t0, $s2
	sltu	$a2, $t3, $s0
	sub.d	$s0, $t0, $s2

	add.d	$a1, $a1, $s1
	add.d	$t4, $t4, $s3
	sub.d	$s3, $t0, $s3

	add.d	$a1, $a1, $a2
	sltu	$a2, $a1, $s1
	sub.d	$s1, $zero, $t4
	sltu	$t4, $zero, $t4

	add.d	$t4, $t4, $s2
	add.d	$t0, $t1, $s0
	add.d	$t1, $t2, $s1
	sub.d	$s2, $zero, $t4

	sltu	$t4, $zero, $t4
	add.d	$t2, $t3, $s2
	sltu	$t7, $t0, $s0
	sltu	$s0, $t1, $s1

	sub.d	$s3, $s3,$t4	// = (s0,s1,s2,s3)
	add.d	$t1, $t1, $t7
	sltu	$t7, $t1, $t7
	addi.d	$t4, $t0, 1

	or	$s0, $t7, $s0
	add.d	$t5, $t1, $t8
	sltu	$t7, $t4, $t0
	add.d	$t5, $t5, $t7

	sltu	$s1, $t2, $s2
	add.d	$t2, $t2, $s0
	sltu	$t7, $t5, $t1
	add.d	$t3, $a1, $s3

	add.d	$t6, $t2, $t7
	sltu	$s0, $t2, $s0
	sltu	$s2, $t3, $s3
	sltu	$t7, $t6, $t2

	or	$s0, $s0, $s1
	add.d	$t3, $t3, $s0
	add.d	$t7, $t7, $a3

	sltu	$s0, $t3, $s0
	add.d	$t7, $t7, $t3

	or	$s0, $s0, $s2
	add.d	$a1, $s0, $a2
	sltu	$a2, $t7, $t3
	add.d	$a2, $a1, $a2

	masknez	$t0, $t0, $a2
	maskeqz	$t4, $t4, $a2
	masknez	$t1, $t1, $a2
	maskeqz	$t5, $t5, $a2

	or	$t0, $t0, $t4
	or	$t1, $t1, $t5
	masknez	$t2, $t2, $a2
	maskeqz	$t6, $t6, $a2

	masknez	$t3, $t3, $a2
	maskeqz	$t7, $t7, $a2
	or	$t2, $t2, $t6
	or	$t3, $t3, $t7

	jr	$ra

/*
 *(t0, t1, t2, t3) = (t0, t1, t2, t3)^2
 * a4, a5, a6, a7 clobbered
 * s5, s6, s7, s8 not clobbered
*/
.align	5
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
	mulh.du $a1, $t1, $t0
	mul.d   $a5, $t1, $t0
	mulh.du $s2, $t2, $t0
	mul.d   $a6, $t2, $t0

	mulh.du $s3, $t3, $t0
	mul.d   $a7, $t3, $t0
	mulh.du $a4, $t2, $t1
	mul.d   $s1, $t2, $t1

	add.d   $a6, $a6, $a1
	sltu    $s0, $a6, $a1
	mulh.du $a1, $t3, $t1
	mul.d   $a2, $t3, $t1

	add.d   $s2, $s2, $s0
	add.d   $a7, $a7, $s2
	mul.d   $t4, $t2, $t2
	mulh.du $t5, $t2, $t2

	sltu    $s0, $a7, $s2
	mulh.du $s2, $t3, $t2
	add.d   $s3, $s3, $s0
	mul.d   $t6, $t3, $t3

	add.d   $a4, $a4, $a2
	sltu    $s0, $a4, $a2
	mul.d   $a2, $t3, $t2
	mulh.du $t7, $t3, $t3

	add.d   $a1, $a1, $s0
	mul.d   $t2, $t1, $t1
	mulh.du $t3, $t1, $t1
	add.d   $a7, $a7, $s1

	sltu    $s0, $a7, $s1
	mulh.du $t1, $t0, $t0
	mul.d   $t0, $t0, $t0
	add.d   $a4, $s3, $a4

	sltu    $s1, $a4, $s3
	add.d   $a4, $a4, $s0
	add.d   $s3, $a1, $a2
	sltu    $s0, $a4, $s0

	sltu    $a2, $s3, $a1
	or      $s0, $s0, $s1
	srli.d  $a1, $a5, 63
	slli.d  $a5, $a5, 1

	add.d   $s3, $s3, $s0
	sltu    $s0, $s3, $s0
	or      $s0, $s0, $a2
	srli.d  $s1, $a7, 63

	add.d   $s2, $s2, $s0

	srli.d  $s0, $a6, 63
	alsl.d  $a6, $a6, $a1, 1
	srli.d  $a1, $a4, 63

	alsl.d  $a7, $a7, $s0, 1
	alsl.d  $a4, $a4, $s1, 1
	srli.d  $s0, $s3, 63
	srli.d  $s1, $s2, 63

	alsl.d  $s3, $s3, $a1, 1
	alsl.d  $s2, $s2, $s0, 1
	add.d   $t1, $t1, $a5
	add.d   $t2, $t2, $a6

	sltu    $a5, $t1, $a5
	sltu    $a6, $t2, $a6
	add.d   $t4, $t4, $a4
	add.d   $t6, $t6, $s2

	add.d   $t7, $t7, $s1
	add.d   $t2, $t2, $a5
	sltu    $a4, $t4, $a4
	sltu    $s2, $t6, $s2

	sltu    $s0, $t2, $a5
	or      $s0, $s0, $a6
	/* 1st round */
	slli.d	$a5, $t0, 32
	srli.d	$a6, $t0, 32

	add.d   $t3, $t3, $s0
	sltu	$s1, $t0, $a5
	sub.d	$a2, $t0, $a5
	add.d   $t3, $t3, $a7

	sltu    $s0, $t3, $a7
	add.d	$s1, $s1, $a6
	add.d   $t4, $t4, $s0
	sub.d	$a6, $t0, $a6

	sltu    $s0, $t4, $s0
	sub.d	$a7, $zero, $s1
	sltu	$s1, $zero, $s1
	or      $s0, $s0, $a4

	add.d	$s1, $s1, $a5
	add.d   $t5, $t5, $s0
	add.d   $t5, $t5, $s3
	sltu    $s0, $t5, $s3

	sub.d	$a5, $zero, $s1
	sltu	$s1, $zero, $s1
	add.d	$t6, $t6, $s0
	sltu	$s0, $t6, $s0

	or	$s0, $s0, $s2
	sub.d	$a6, $a6, $s1	//(a2,a7,a5,a6)
	add.d	$t7, $t7, $s0
	/*(t0, t1, t2, t3, t4, t5, t6, t7) = (t0, t1, t2, t3)^2 */
	add.d	$t0, $t1, $a2

	sltu	$a2, $t0, $a2
	add.d	$t1, $t2, $a7
	add.d	$t2, $t3, $a5
		/* 2nd round */
	slli.d	$s2, $t0, 32

	sltu	$a7, $t1, $a7
	sltu	$a5, $t2, $a5
	add.d	$t1, $t1, $a2
	srli.d	$s3, $t0, 32

	sltu	$a4, $t1, $a2
	sltu	$a1, $t0, $s2
	sub.d	$s0, $t0, $s2
	or	$a4, $a4, $a7

	add.d	$a1, $a1, $s3
	sub.d	$s3, $t0, $s3
	add.d	$t2, $t2, $a4
	sltu	$a4, $t2, $a4

	or	$a4, $a4, $a5
	sub.d	$s1, $zero, $a1
	sltu	$a1, $zero, $a1
	add.d	$t3, $a6, $a4		//1st round end

	add.d	$a1, $a1, $s2
	add.d	$t0, $t1, $s0
	add.d	$t1, $t2, $s1
	sub.d	$s2, $zero, $a1

	add.d	$t2, $t3, $s2
	sltu	$a1, $zero, $a1
	sltu	$a2, $t0, $s0
	sltu	$a5, $t1, $s1

	sltu	$a7, $t2, $s2
	sub.d	$s3, $s3, $a1	//(s0,s1,s2,s3)
	/* 3rd round */
	slli.d	$s0, $t0, 32
	add.d	$t1, $t1, $a2

	srli.d	$s1, $t0, 32
	sltu	$a2, $t1, $a2
	sltu	$a1, $t0, $s0
	or	$a2, $a2, $a5

	add.d	$t2, $t2, $a2
	sub.d	$s2, $t0, $s0
	add.d	$a1, $a1, $s1
	sltu	$a2, $t2, $a2

	or	$a2, $a2, $a7
	sub.d	$s1, $t0, $s1
	add.d	$t3, $s3, $a2		//2nd round end
	sub.d	$s3, $zero, $a1

	sltu	$a1, $zero, $a1
	add.d	$t0, $t1, $s2
	add.d	$t1, $t2, $s3
	add.d	$a1, $a1, $s0

	sub.d	$s0, $zero, $a1
	sltu	$a2, $t0, $s2
	sltu	$a5, $t1, $s3
	sltu	$a1, $zero, $a1

	add.d	$t2, $t3, $s0
	sub.d	$s1, $s1, $a1	//(s2,s3,s0,s1)
	add.d	$t1, $t1, $a2
		/* 4th round */
	slli.d	$s2, $t0, 32

	sltu	$a7, $t2, $s0
	srli.d	$s3, $t0, 32
	sltu	$a2, $t1, $a2

	or	$a2, $a2, $a5
	sltu	$a1, $t0, $s2
	sub.d	$s0, $t0, $s2
	add.d	$t2, $t2, $a2

	sltu	$a2, $t2, $a2
	add.d	$a1, $a1, $s3
	sub.d	$s3, $t0, $s3
	or	$a2, $a2, $a7

	add.d	$t3, $s1, $a2	//3rd round end
	sub.d	$s1, $zero, $a1
	sltu	$a1, $zero, $a1
	add.d	$t0, $t1, $s0

	sltu	$a2, $t0, $s0
	add.d	$a1, $a1, $s2
	add.d	$t1, $t2, $s1
	sub.d	$s2, $zero, $a1


	sltu	$a5, $t1, $s1
	add.d	$t1, $t1, $a2
	sltu	$a1, $zero, $a1
	add.d	$t2, $t3, $s2

	sltu	$a2, $t1, $a2
	sub.d	$s3, $s3, $a1	//(s0,s1,s2,s3)
	or	$a2, $a2, $a5
	add.d	$t0, $t0, $t4	//sum of upper

	sltu	$a7, $t2, $s2
	add.d	$t1, $t1, $t5
	sltu	$t4, $t0, $t4
	add.d	$t2, $t2, $a2

	sltu	$a2, $t2, $a2
	add.d	$t2, $t2, $t6
	sltu	$t5, $t1, $t5
	add.d	$t1, $t1, $t4

	or	$a2, $a2, $a7
	sltu	$t6, $t2, $t6
	sltu	$s0, $t1, $t4
	addi.d	$t4, $t0, 1

	add.d	$t3, $s3, $a2	//4th round end
	sltu	$a1, $t4, $t0
	or	$s0, $s0, $t5
	add.d	$t5, $t1, $t8

	add.d	$t2, $t2, $s0
	add.d	$t3, $t3, $t7
	add.d	$t5, $t5, $a1
	sltu	$a1, $t5, $t1

	sltu	$s1, $t3, $t7
	sltu	$s0, $t2, $s0
	or	$s0, $s0, $t6
	add.d	$t6, $t2, $a1

	add.d	$t3, $t3, $s0
	sltu	$s0, $t3, $s0
	sltu	$a1, $t6, $t2
	add.d	$t7, $a3, $a1

	or	$a2, $s0, $s1
	add.d	$t7, $t7, $t3
	sltu	$a1, $t7, $t3
	add.d	$a2, $a2, $a1

	masknez	$t0, $t0, $a2
	maskeqz	$t4, $t4, $a2
	masknez	$t1, $t1, $a2
	maskeqz	$t5, $t5, $a2

	or	$t0, $t0, $t4
	or	$t1, $t1, $t5
	masknez	$t2, $t2, $a2
	maskeqz	$t6, $t6, $a2

	masknez	$t3, $t3, $a2
	maskeqz	$t7, $t7, $a2
	or	$t2, $t2, $t6
	or	$t3, $t3, $t7

	jr	$ra

.globl	func(sm2_z256_modp_add)
.align	5

func(sm2_z256_modp_add):
	addi.d	$sp, $sp, -16
	li.d	$a3, -1
	ld.d	$a4, $a2, 0
	ld.d	$a5, $a2, 8

	ld.d	$a6, $a2, 16
	ld.d	$a7, $a2, 24
	srli.d	$t8, $a3, 32
	st.d	$ra, $sp, 8

	ld.d	$t0, $a1, 0
	ld.d	$t1, $a1, 8
	ld.d	$t2, $a1, 16
	ld.d	$t3, $a1, 24

	addi.d	$a3, $t8, 1
	bl	__sm2_z256_modp_add
	ld.d	$ra, $sp, 8

	st.d	$t0, $a0, 0
	st.d	$t1, $a0, 8
	st.d	$t2, $a0, 16

	st.d	$t3, $a0, 24
	addi.d	$sp, $sp,16
	jr	$ra

.globl	func(sm2_z256_modp_dbl)
.align	5
func(sm2_z256_modp_dbl):
	addi.d	$sp, $sp, -16
	li.d	$a3, -1
	ld.d	$t0, $a1, 0
	ld.d	$t1, $a1, 8

	ld.d	$t2, $a1, 16
	ld.d	$t3, $a1, 24
	srli.d	$t8, $a3, 32
	st.d	$ra, $sp, 8

	addi.d	$a3, $t8, 1
	bl	__sm2_z256_modp_dbl
	ld.d	$ra, $sp, 8

	st.d	$t0, $a0, 0
	st.d	$t1, $a0, 8
	st.d	$t2, $a0, 16

	st.d	$t3, $a0, 24
	addi.d	$sp, $sp,16
	jr	$ra


.globl	func(sm2_z256_modp_tri)
.align	5
func(sm2_z256_modp_tri):
	addi.d	$sp, $sp, -16
	li.d	$a3, -1
	ld.d	$t0, $a1, 0
	ld.d	$t1, $a1, 8

	srli.d	$t8, $a3, 32
	st.d	$ra, $sp, 8
	ld.d	$t2, $a1, 16
	ld.d	$t3, $a1, 24

	addi.d	$a3, $t8, 1
	move	$a4, $t0
	move	$a5, $t1

	move	$a6, $t2
	move	$a7, $t3
	bl	__sm2_z256_modp_dbl
	bl	__sm2_z256_modp_add

	ld.d	$ra, $sp, 8
	st.d	$t0, $a0, 0
	st.d	$t1, $a0, 8

	st.d	$t2, $a0, 16
	st.d	$t3, $a0, 24
	addi.d	$sp, $sp,16
	jr	$ra

.globl	func(sm2_z256_modp_mont_mul)
.align	5
func(sm2_z256_modp_mont_mul):
	addi.d	$sp, $sp, -48
	li.d	$a3, -1
	ld.d	$a4, $a1, 0
	ld.d	$a5, $a1, 8

	ld.d	$a6, $a1, 16
	srli.d	$t8, $a3, 32
	ld.d	$a7, $a1, 24
	ld.d	$t0, $a2, 0

	ld.d	$t1, $a2, 8
	ld.d	$t2, $a2, 16
	ld.d	$t3, $a2, 24
	st.d	$ra, $sp, 40

	st.d	$s0, $sp, 32
	st.d	$s1, $sp, 24
	st.d	$s2, $sp, 16
	st.d	$s3, $sp, 8

	addi.d	$a3, $t8, 1
	bl	__sm2_z256_modp_mont_mul
	st.d	$t0, $a0, 0
	st.d	$t1, $a0, 8

	st.d	$t2, $a0, 16
	st.d	$t3, $a0, 24
	ld.d	$ra, $sp, 40
	ld.d	$s0, $sp, 32

	ld.d	$s1, $sp, 24
	ld.d	$s2, $sp, 16
	ld.d	$s3, $sp, 8
	addi.d	$sp, $sp, 48

	jr	$ra

// mont(a) = a * 2^256 (mod p) = mont_mul(a, 2^512 mod p)
.globl  func(sm2_z256_modp_to_mont)
.align	5

func(sm2_z256_modp_to_mont):
	addi.d	$sp, $sp, -48
	li.d	$a3, -1
	ld.d	$a4, $a0, 0
	ld.d	$a5, $a0, 8

	lu32i.d	$t1, 2
	srli.d	$t8, $a3, 32
	ld.d	$a6, $a0, 16
	ld.d	$a7, $a0, 24

	li.d	$t0, 3
	bstrins.d	$t1, $t8, 31, 0
	li.d	$t2, 1
	li.d	$t3, 2

	lu32i.d	$t0, 2
	lu32i.d	$t2, 1
	lu32i.d	$t3, 4
	st.d	$ra, $sp, 40

	st.d	$s0, $sp, 32
	st.d	$s1, $sp, 24
	st.d	$s2, $sp, 16
	st.d	$s3, $sp, 8

	addi.d	$a3, $t8, 1
	move	$a0, $a1
	bl	__sm2_z256_modp_mont_mul
	st.d	$t0, $a0, 0
	st.d	$t1, $a0, 8

	st.d	$t2, $a0, 16
	st.d	$t3, $a0, 24

	ld.d	$ra, $sp, 40
	ld.d	$s0, $sp, 32
	ld.d	$s1, $sp, 24
	ld.d	$s2, $sp, 16
	ld.d	$s3, $sp, 8
	addi.d	$sp, $sp, 48

	jr	$ra

.globl	func(sm2_z256_modp_from_mont)

.align	5
func(sm2_z256_modp_from_mont):
	addi.d	$sp, $sp, -48
	li.d	$a3, -1
	ld.d	$a4, $a1, 0
	ld.d	$a5, $a1, 8

	srli.d	$t8, $a3, 32
	ld.d	$a6, $a1, 16
	ld.d	$a7, $a1, 24
	st.d	$ra, $sp, 40

	st.d	$s0, $sp, 32
	st.d	$s1, $sp, 24
	st.d	$s2, $sp, 16
	st.d	$s3, $sp, 8

	li.d	$t0, 1
	li.d	$t1, 0
	li.d	$t2, 0
	li.d	$t3, 0

	addi.d	$a3, $t8, 1
	bl	__sm2_z256_modp_mont_mul
	st.d	$t0, $a0, 0
	st.d	$t1, $a0, 8

	st.d	$t2, $a0, 16
	st.d	$t3, $a0, 24

	ld.d	$ra, $sp, 40
	ld.d	$s0, $sp, 32
	ld.d	$s1, $sp, 24
	ld.d	$s2, $sp, 16
	ld.d	$s3, $sp, 8
	addi.d	$sp, $sp, 48

	jr	$ra

.globl	func(sm2_z256_modp_mont_sqr)
.align	5
func(sm2_z256_modp_mont_sqr):
	addi.d	$sp, $sp, -48
	li.d	$a3, -1
	ld.d	$t0, $a1, 0
	ld.d	$t1, $a1, 8

	ld.d	$t2, $a1, 16
	ld.d	$t3, $a1, 24
	srli.d	$t8, $a3, 32
	st.d	$ra, $sp, 40

	addi.d	$a3, $t8, 1
	st.d	$s0, $sp, 32
	st.d	$s1, $sp, 24
	st.d	$s2, $sp, 16

	st.d	$s3, $sp, 8
	bl	__sm2_z256_modp_mont_sqr
	ld.d	$ra, $sp, 40
	ld.d	$s0, $sp, 32

	ld.d	$s1, $sp, 24
	ld.d	$s2, $sp, 16
	ld.d	$s3, $sp, 8
	st.d	$t0, $a0, 0

	st.d	$t1, $a0, 8
	st.d	$t2, $a0, 16
	st.d	$t3, $a0, 24
	addi.d	$sp, $sp, 48

	jr	$ra

.globl	func(sm2_z256_modp_sub)
.align	5
func(sm2_z256_modp_sub):
	addi.d	$sp, $sp, -16
	li.d	$a3, -1
	ld.d	$a4, $a2, 0
	ld.d	$a5, $a2, 8

	ld.d	$a6, $a2, 16
	ld.d	$a7, $a2, 24
	srli.d	$t8, $a3, 32
	st.d	$ra, $sp, 8

	ld.d	$t0, $a1, 0
	ld.d	$t1, $a1, 8
	ld.d	$t2, $a1, 16
	ld.d	$t3, $a1, 24

	addi.d	$a3, $t8, 1
	bl	__sm2_z256_modp_sub
	ld.d	$ra, $sp, 8

	st.d	$t0, $a0, 0
	st.d	$t1, $a0, 8
	st.d	$t2, $a0, 16

	st.d	$t3, $a0, 24
	addi.d	$sp, $sp,16
	jr	$ra

.globl	func(sm2_z256_modp_neg)

.align	5
func(sm2_z256_modp_neg):
	ld.d	$a4, $a1, 0
	ld.d	$a5, $a1, 8
	ld.d	$a6, $a1, 16
	ld.d	$a7, $a1, 24

	li.d	$t2, -1
	li.d	$t3, -1
	slli.d	$t1, $t2, 32
	lu32i.d	$t3, -2

	sltu	$t4, $t2, $a4
	sub.d	$t0, $t2, $a4
	sub.d	$t1, $t1, $t4
	st.d	$t0, $a0, 0

	sltu	$t4, $t1, $a5
	sub.d	$t1, $t1, $a5
	sub.d	$t2, $t2, $t4
	st.d	$t1, $a0, 8

	sltu	$t4, $t2, $a6
	sub.d	$t3, $t3, $a7
	sub.d	$t2, $t2, $a6
	sub.d	$t3, $t3, $t4

	st.d	$t2, $a0, 16
	st.d	$t3, $a0, 24

	jr	$ra

.globl	func(sm2_z256_modp_haf)

.align	5
func(sm2_z256_modp_haf):
	addi.d	$sp, $sp, -16
	li.d	$a3, -1
	ld.d	$t0, $a1, 0
	ld.d	$t1, $a1, 8

	srli.d	$t8, $a3, 32
	st.d	$ra, $sp, 8
	ld.d	$t2, $a1, 16
	ld.d	$t3, $a1, 24

	addi.d	$a3, $t8, 1
	bl	__sm2_z256_modp_haf
	ld.d	$ra, $sp, 8
	st.d	$t0, $a0, 0

	st.d	$t1, $a0, 8
	st.d	$t2, $a0, 16
	st.d	$t3, $a0, 24
	addi.d	$sp, $sp, 16

	jr	$ra

.globl	func(sm2_z256_modn_add)

.align	5
func(sm2_z256_modn_add):
	ld.d	$t0, $a1, 0
	ld.d	$t1, $a1, 8
	ld.d	$t4, $a2, 0
	ld.d	$t5, $a2, 8

	ld.d	$t2, $a1, 16
	ld.d	$t3, $a1, 24
	ld.d	$t6, $a2, 16
	ld.d	$t7, $a2, 24

	lu12i.w	$a3, 0x39d54
	lu12i.w	$a4, 0x21c60
	ori	$a3, $a3, 0x123
	ori	$a4, $a4, 0x52b

	add.d	$t0, $t0, $t4
	add.d	$t1, $t1, $t5
	lu32i.d	$a3, -265207
	lu32i.d	$a4, 0x3df6b

	sltu	$t4, $t0, $t4
	sltu	$t5, $t1, $t5
	lu52i.d	$a3, $a3, 0x53b
	lu52i.d	$a4, $a4, 0x720

	add.d	$t1, $t1, $t4
	add.d	$t2, $t2, $t6
	sltu	$a1, $t0, $a3
	sub.d	$a3, $t0, $a3

	sltu	$t4, $t1, $t4
	sltu	$t6, $t2, $t6
	add.d	$a4, $a4, $a1

	add.d	$t5, $t5, $t4
	add.d	$t3, $t3, $t7
	sltu	$a2, $t1, $a4
	sub.d	$a4, $t1, $a4

	add.d	$t2, $t2, $t5
	sltu	$t7, $t3, $t7
	li.d	$a6, -1

	sltu	$t5, $t2, $t5
	sltui	$a1, $t2, -1
	addi.d	$a5, $t2, 1
	add.d	$t6, $t5, $t6

	sltu	$a7, $a5, $a2
	add.d	$t3, $t3, $t6
	lu32i.d	$a6, -2
	sub.d	$a5, $a5, $a2

	add.d	$a1, $a1, $a7
	sltu	$t6, $t3, $t6

	add.d	$a6, $a6, $a1
	add.d	$t8, $t6, $t7
	sltu	$a2, $t3, $a6
	sub.d	$a6, $t3, $a6

	sltu	$t8, $t8, $a2

	maskeqz	$t4, $t0, $t8
	masknez	$t0, $a3, $t8
	maskeqz	$t5, $t1, $t8
	masknez	$t1, $a4, $t8

	maskeqz	$t2, $t2, $t8
	masknez	$t6, $a5, $t8
	maskeqz	$t7, $t3, $t8
	masknez	$t3, $a6, $t8

	or	$t0, $t0, $t4
	or	$t1, $t1, $t5
	or	$t2, $t2, $t6
	or	$t3, $t3, $t7

	st.d	$t0, $a0, 0
	st.d	$t1, $a0, 8
	st.d	$t2, $a0, 16
	st.d	$t3, $a0, 24

	jr	$ra

.globl  func(sm2_z256_modn_sub)

.align  5
func(sm2_z256_modn_sub):
	ld.d	$t0, $a1, 0
	ld.d	$t1, $a1, 8
	ld.d	$t4, $a2, 0
	ld.d	$t5, $a2, 8

	ld.d	$t2, $a1, 16
	ld.d	$t3, $a1, 24
	ld.d	$t6, $a2, 16
	ld.d	$t7, $a2, 24

	lu12i.w	$a3, -236885
	lu12i.w	$a4, -138337
	ori	$a3, $a3, 0xedd
	ori	$a4, $a4, 0xad4

	sltu	$a1, $t0, $t4
	sub.d	$t0, $t0, $t4
	sltu	$a2, $t1, $t5
	sub.d	$t1, $t1, $t5

	sltu	$t5, $t1, $a1
	sub.d	$t1, $t1, $a1
	sltu	$a1, $t2, $t6
	sub.d	$t2, $t2, $t6

	add.d	$t5, $t5, $a2
	li.d	$a5, 1
	sltu	$a2, $t3, $t7
	sub.d	$t3, $t3, $t7

	sltu	$t6, $t2, $t5
	sub.d	$t2, $t2, $t5
	lu32i.d	$a3, 0x40bf6
	lu32i.d	$a4, -253804

	add.d	$t6, $a1, $t6
	slli.d	$a5, $a5, 32
	lu52i.d	$a3, $a3, -1340
	lu52i.d	$a4, $a4, -1825

	sltu	$t7, $t3, $t6
	sub.d	$t3, $t3, $t6
	add.d	$t8, $t7, $a2
	maskeqz	$a3, $a3, $t8

	maskeqz	$a4, $a4, $t8
	maskeqz	$a5, $a5, $t8
	sltu	$a1, $t0, $a3
	sub.d	$t0, $t0, $a3

	add.d	$a4, $a4, $a1
	st.d	$t0, $a0, 0
	sltu	$a1, $t1, $a4
	sub.d	$t1, $t1, $a4

	st.d	$t1, $a0, 8
	sltu	$a2, $t2, $a1
	sub.d	$t2, $t2, $a1

	add.d	$a5, $a5, $a2
	sub.d	$t3, $t3, $a5
	st.d	$t2, $a0, 16
	st.d	$t3, $a0, 24

	jr	$ra

.globl	func(sm2_z256_modn_neg)

.align	5
func(sm2_z256_modn_neg):
	ld.d	$t0, $a1, 0
	ld.d	$t1, $a1, 8
	lu12i.w	$a3, 0x39d54
	lu12i.w	$a4, 0x21c60

	ld.d	$t2, $a1, 16
	ld.d	$t3, $a1, 24
	ori	$a3, $a3, 0x123
	ori	$a4, $a4, 0x52b

	lu32i.d	$a3, -265207
	lu32i.d	$a4, 0x3df6b
	li.d	$a5, -1
	li.d	$a6, -1

	lu52i.d	$a3, $a3, 0x53b
	lu52i.d	$a4, $a4, 0x720
	lu32i.d	$a6, -2

	sltu	$t4, $a3, $t0
	sub.d	$t0, $a3, $t0

	sub.d	$a4, $a4, $t4
	st.d	$t0, $a0, 0

	sltu	$t5, $a4, $t1
	sub.d	$t1, $a4, $t1

	sub.d	$a5, $a5, $t5
	st.d	$t1, $a0, 8

	sltu	$t6, $a5, $t2
	sub.d	$t3, $a6, $t3

	sub.d	$t2, $a5, $t2
	sub.d	$t3, $t3, $t6

	st.d	$t2, $a0, 16
	st.d	$t3, $a0, 24
	jr	$ra

.align	5
__sm2_z256_modn_mont_mul:
	add.d	$s1, $s1, $t5
	ld.d	$s5, $a2, 8
	sltu	$a7, $s1, $t5
	mul.d	$t5, $a3, $t4

	/* Add 1 to the high part of multiplication result(mulh.du)
	   would not cause overflow. */
	add.d	$a7, $t6, $a7
	mul.d	$t6, $a4, $t4

	add.d	$s2, $s2, $a7
	mul.d	$t8, $a6, $t4

	sltu	$a7, $s2, $a7
	add.d	$s0, $s0, $t5

	add.d	$a7, $t7, $a7
	mul.d	$t7, $a5, $t4
	sltu	$s6, $s0, $t5
	mulh.du	$t5, $a3, $t4

	add.d	$s3, $s3, $a7
	add.d	$s1, $s1, $t6

	sltu	$a7, $s3, $a7
	sltu	$s7, $s1, $t6
	mulh.du	$t6, $a4, $t4
	add.d	$s1, $s1, $s6

	add.d	$s2, $s2, $t7
	add.d	$s4, $s4, $a7
	add.d	$s3, $s3, $t8
	sltu	$s6, $s1, $s6

	sltu	$s8, $s2, $t7
	mulh.du	$t7, $a5, $t4
	sltu	$fp, $s3, $t8
	mulh.du	$t8, $a6, $t4

	add.d	$s6, $s6, $s7
	add.d	$s0, $s1, $t5

	add.d	$s2, $s2, $s6
	sltu	$a7, $s0, $t5
	mul.d	$t5, $t0, $s5

	sltu	$s6, $s2, $s6
	add.d	$a7, $t6, $a7

	add.d	$s6, $s6, $s8
	mul.d	$t6, $t1, $s5

	add.d	$s3, $s3, $s6
	add.d	$s1, $s2, $a7

	sltu	$s6, $s3, $s6
	sltu	$a7, $s1, $a7

	add.d	$s6, $s6, $fp
	add.d	$a7, $t7, $a7
	mul.d	$t7, $t2, $s5
	add.d	$s0, $s0, $t5

	add.d	$s4, $s4, $s6
	add.d	$s2, $s3, $a7
	sltu	$s7, $s0, $t5
	mulh.du	$t5, $t0, $s5

	sltu	$a7, $s2, $a7
	add.d	$s1, $s1, $t6
	sltu	$t4, $s4, $s6

	add.d	$a7, $t8, $a7
	mul.d	$t8, $t3, $s5
	sltu	$s8, $s1, $t6
	mulh.du	$t6, $t1, $s5

	add.d	$s3, $s4, $a7
	add.d	$s1, $s1, $s7
	add.d	$s2, $s2, $t7

	sltu	$s7, $s1, $s7
	sltu	$a7, $s3, $a7
	sltu	$s6, $s2, $t7
	mulh.du	$t7, $t2, $s5

	add.d	$fp, $s8, $s7
	add.d	$s4, $t4, $a7
	mul.d	$t4, $a1, $s0
	add.d	$s3, $s3, $t8

	#ROUND 1
	add.d	$s2, $s2, $fp
	sltu	$s7, $s3, $t8
	mulh.du	$t8, $t3, $s5
	add.d	$s1, $s1, $t5

	sltu	$s8, $s2, $fp
	sltu	$a7, $s1, $t5

	add.d	$s6, $s6, $s8
	mul.d	$t5, $a3, $t4
	add.d	$a7, $t6, $a7
	mul.d	$t6, $a4, $t4

	add.d	$s3, $s3, $s6
	add.d	$s2, $s2, $a7

	sltu	$s6, $s3, $s6
	sltu	$a7, $s2, $a7

	add.d	$s6, $s7, $s6
	add.d	$a7, $t7, $a7

	mul.d	$t7, $a5, $t4
	add.d	$s4, $s4, $s6
	add.d	$s3, $s3, $a7
	add.d	$s0, $s0, $t5

	sltu	$s5, $s4, $s6
	sltu	$a7, $s3, $a7
	sltu	$s8, $s0, $t5
	mulh.du	$t5, $a3, $t4

	ld.d	$fp, $a2, 16
	add.d	$a7, $a7, $t8
	mul.d	$t8, $a6, $t4
	add.d	$s1, $s1, $t6

	add.d	$s4, $s4, $a7
	add.d	$s2, $s2, $t7
	sltu	$s6, $s1, $t6
	mulh.du	$t6, $a4, $t4

	sltu	$a7, $s4, $a7
	sltu	$s7, $s2, $t7
	add.d	$s1, $s1, $s8
	mulh.du	$t7, $a5, $t4

	add.d	$s5, $s5, $a7
	add.d	$s3, $s3, $t8
	sltu	$s8, $s1, $s8
	add.d	$s0, $s1, $t5

	add.d	$s8, $s8, $s6
	sltu	$s6, $s3, $t8
	mulh.du	$t8, $a6, $t4
	sltu	$a7, $s0, $t5

	mul.d	$t5, $t0, $fp
	add.d	$s2, $s2, $s8
	add.d	$a7, $t6, $a7
	mul.d	$t6, $t1, $fp

	sltu	$s8, $s2, $s8
	add.d	$s1, $s2, $a7

	add.d	$s7, $s8, $s7
	sltu	$a7, $s1, $a7

	add.d	$s3, $s3, $s7
	add.d	$a7, $t7, $a7
	mul.d	$t7, $t2, $fp

	sltu	$s7, $s3, $s7
	add.d	$s2, $s3, $a7
	add.d	$s0, $s0, $t5
	add.d	$s1, $s1, $t6

	add.d	$s7, $s7, $s6
	sltu	$a7, $s2, $a7
	sltu	$s8, $s0, $t5
	mulh.du	$t5, $t0, $fp

	mul.d	$t4, $a1, $s0
	add.d	$s4, $s4, $s7
	add.d	$a7, $t8, $a7
	mul.d	$t8, $t3, $fp

	sltu	$s6, $s1, $t6
	mulh.du	$t6, $t1, $fp
	sltu	$s7, $s4, $s7
	add.d	$s3, $s4, $a7

	add.d	$s1, $s1, $s8
	add.d	$s5, $s5, $s7
	sltu	$a7, $s3, $a7
	add.d	$s2, $s2, $t7

	sltu	$s8, $s1, $s8
	add.d	$s4, $s5, $a7
	sltu	$s7, $s2, $t7
	mulh.du	$t7, $t2, $fp

	#ROUND 2
	add.d	$s8, $s6, $s8
	add.d	$s1, $s1, $t5

	add.d	$s3, $s3, $t8
	add.d	$s2, $s2, $s8
	sltu	$a7, $s1, $t5
	mul.d	$t5, $a3, $t4

	sltu	$s6, $s3, $t8
	mulh.du	$t8, $t3, $fp
	sltu	$s8, $s2, $s8
	add.d	$a7, $t6, $a7

	mul.d	$t6, $a4, $t4
	add.d	$s7, $s7, $s8
	add.d	$s2, $s2, $a7

	add.d	$s3, $s3, $s7
	sltu	$a7, $s2, $a7

	sltu	$s7, $s3, $s7
	add.d	$a7, $t7, $a7
	mul.d	$t7, $a5, $t4
	add.d	$s0, $s0, $t5

	add.d	$s6, $s6, $s7
	add.d	$s3, $s3, $a7

	add.d	$s4, $s4, $s6
	sltu	$a7, $s3, $a7

	ld.d	$a2, $a2, 24
	sltu	$s5, $s4, $s6
	add.d	$a7, $t8, $a7
	mul.d	$t8, $a6, $t4

	sltu	$s6, $s0, $t5
	mulh.du	$t5, $a3, $t4
	add.d	$s1, $s1, $t6
	add.d	$s4, $s4, $a7

	sltu	$s8, $s1, $t6
	add.d	$s1, $s1, $s6
	mulh.du	$t6, $a4, $t4
	add.d	$s2, $s2, $t7

	sltu	$a7, $s4, $a7
	sltu	$s7, $s2, $t7
	mulh.du	$t7, $a5, $t4

	sltu	$s6, $s1, $s6
	add.d	$s3, $s3, $t8
	add.d	$s0, $s1, $t5
	add.d	$s5, $s5, $a7

	add.d	$s8, $s6, $s8
	sltu	$s6, $s3, $t8
	mulh.du	$t8, $a6, $t4
	sltu	$a7, $s0, $t5

	mul.d	$t5, $t0, $a2
	add.d	$s2, $s2, $s8
	add.d	$a7, $t6, $a7
	mul.d	$t6, $t1, $a2

	sltu	$fp, $s2, $s8
	add.d	$s1, $s2, $a7

	add.d	$s7, $fp, $s7
	sltu	$a7, $s1, $a7

	add.d	$s3, $s3, $s7
	add.d	$a7, $t7, $a7
	mul.d	$t7, $t2, $a2

	sltu	$s7, $s3, $s7
	add.d	$s2, $s3, $a7
	add.d	$s0, $s0, $t5

	add.d	$s7, $s7, $s6
	sltu	$a7, $s2, $a7
	sltu	$s8, $s0, $t5
	mulh.du	$t5, $t0, $a2

	add.d	$s4, $s4, $s7
	add.d	$a7, $t8, $a7
	mul.d	$t8, $t3, $a2
	add.d	$s1, $s1, $t6

	mul.d	$a1, $a1, $s0
	sltu	$s6, $s4, $s7
	add.d	$s3, $s4, $a7
	sltu	$s7, $s1, $t6

	mulh.du	$t6, $t1, $a2
	add.d	$s5, $s5, $s6
	sltu	$a7, $s3, $a7
	add.d	$s2, $s2, $t7

	add.d	$s1, $s1, $s8
	add.d	$s4, $s5, $a7
	sltu	$s6, $s2, $t7
	mulh.du	$t7, $t2, $a2

	#ROUND 3
	sltu	$s8, $s1, $s8
	add.d	$s1, $s1, $t5

	add.d	$s3, $s3, $t8
	add.d	$s8, $s7, $s8
	sltu	$a7, $s1, $t5
	mul.d	$t5, $a3, $a1

	sltu	$s7, $s3, $t8
	mulh.du	$t8, $t3, $a2
	add.d	$s2, $s2, $s8
	add.d	$a7, $t6, $a7

	mul.d	$t6, $a4, $a1
	sltu	$s8, $s2, $s8
	add.d	$s2, $s2, $a7

	add.d	$s8, $s6, $s8
	sltu	$a7, $s2, $a7

	add.d	$s3, $s3, $s8
	add.d	$a7, $t7, $a7
	mul.d	$t7, $a5, $a1
	add.d	$s0, $s0, $t5

	sltu	$s8, $s3, $s8
	add.d	$s3, $s3, $a7
	sltu	$s6, $s0, $t5
	mulh.du	$t5, $a3, $a1

	add.d	$s8, $s7, $s8
	sltu	$a7, $s3, $a7
	add.d	$s1, $s1, $t6

	add.d	$s4, $s4, $s8
	add.d	$a7, $t8, $a7
	mul.d	$t8, $a6, $a1
	sltu	$s7, $s1, $t6

	mulh.du	$t6, $a4, $a1
	sltu	$s5, $s4, $s8
	add.d	$s4, $s4, $a7
	add.d	$s1, $s1, $s6

	sltu	$a7, $s4, $a7
	sltu	$s6, $s1, $s6
	add.d	$s2, $s2, $t7

	add.d	$s5, $s5, $a7
	add.d	$s7, $s7, $s6
	sltu	$s6, $s2, $t7
	mulh.du	$t7, $a5, $a1

	add.d	$s2, $s2, $s7
	add.d	$s0, $s1, $t5

	sltu	$s8, $s2, $s7
	add.d	$s3, $s3, $t8
	sltu	$a7, $s0, $t5
	sltu	$t4, $s0, $a3

	add.d	$s8, $s6, $s8
	sltu	$s6, $s3, $t8
	mulh.du	$t8, $a6, $a1
	add.d	$a7, $t6, $a7

	add.d	$s3, $s3, $s8
	add.d	$s1, $s2, $a7
	sub.d	$t0, $s0, $a3
	add.d	$a4, $a4, $t4

	sltu	$s8, $s3, $s8
	sltu	$a7, $s1, $a7
	sltu	$t5, $s1, $a4
	sub.d	$t1, $s1, $a4

	add.d	$s8, $s6, $s8
	add.d	$a7, $t7, $a7

	add.d	$s4, $s4, $s8
	add.d	$s2, $s3, $a7

	sltu	$s8, $s4, $s8
	sltu	$a7, $s2, $a7
	sltu	$t6, $s2, $a5
	sub.d	$t2, $s2, $a5

	add.d	$s5, $s5, $s8
	add.d	$a7, $t8, $a7
	sltu	$a1, $t2, $t5
	sub.d	$t2, $t2, $t5

	add.d	$s3, $s4, $a7
	add.d	$t6, $t6, $a1

	sltu	$a7, $s3, $a7
	add.d	$a6, $a6, $t6

	add.d	$s4, $s5, $a7
	sltu	$t7, $s3, $a6
	sub.d	$t3, $s3, $a6

	sltu	$t8, $s4, $t7

	maskeqz	$t4, $s0, $t8
	masknez	$t0, $t0, $t8
	maskeqz	$t5, $s1, $t8
	masknez	$t1, $t1, $t8

	maskeqz	$t6, $s2, $t8
	masknez	$t2, $t2, $t8
	maskeqz	$t7, $s3, $t8
	masknez	$t3, $t3, $t8

	or	$t0, $t0, $t4
	or	$t1, $t1, $t5
	or	$t2, $t2, $t6
	or	$t3, $t3, $t7

	st.d	$t0, $a0, 0
	st.d	$t1, $a0, 8
	st.d	$t2, $a0, 16
	st.d	$t3, $a0, 24

	jr	$ra

.globl	func(sm2_z256_modn_mont_mul)

.align	5
func(sm2_z256_modn_mont_mul):
	addi.d	$sp, $sp, -96
	ld.d	$t4, $a2, 0

	ld.d	$t0, $a1, 0
	ld.d	$t1, $a1, 8
	ld.d	$t2, $a1, 16
	ld.d	$t3, $a1, 24

	st.d	$ra, $sp, 0
	st.d	$s0, $sp, 8
	st.d	$s1, $sp, 16
	st.d	$s2, $sp, 24
	st.d	$s3, $sp, 32
	st.d	$s4, $sp, 40
	st.d	$s5, $sp, 48
	st.d	$s6, $sp, 56
	st.d	$s7, $sp, 64
	st.d	$s8, $sp, 72
	st.d	$fp, $sp, 80

	lu12i.w	$a1, 0x72350
	lu12i.w	$a3, 0x39d54
	lu12i.w	$a4, 0x21c60
	li.d	$a5, -1

	ori	$a1, $a1, 0x975
	ori	$a3, $a3, 0x123
	ori	$a4, $a4, 0x52b

	li.d	$a6, -1
	lu32i.d	$a1, -24952
	lu32i.d	$a3, -265207
	lu32i.d	$a4, 0x3df6b

	lu32i.d	$a6, -2
	lu52i.d	$a1, $a1, 0x327
	lu52i.d	$a3, $a3, 0x53b
	lu52i.d	$a4, $a4, 0x720

	mul.d	$s0, $t0, $t4
	mulh.du	$t5, $t0, $t4
	mul.d	$s1, $t1, $t4
	mulh.du	$t6, $t1, $t4

	mul.d	$s2, $t2, $t4
	mulh.du	$t7, $t2, $t4
	mul.d	$s3, $t3, $t4
	mulh.du	$s4, $t3, $t4

	mul.d	$t4, $a1, $s0

	bl __sm2_z256_modn_mont_mul

	ld.d	$ra, $sp, 0
	ld.d	$s0, $sp, 8
	ld.d	$s1, $sp, 16
	ld.d	$s2, $sp, 24
	ld.d	$s3, $sp, 32
	ld.d	$s4, $sp, 40
	ld.d	$s5, $sp, 48
	ld.d	$s6, $sp, 56
	ld.d	$s7, $sp, 64
	ld.d	$s8, $sp, 72
	ld.d	$fp, $sp, 80
	addi.d	$sp, $sp, 96
	jr	$ra

.globl	func(sm2_z256_modn_from_mont)

.align	5
func(sm2_z256_modn_from_mont):
	addi.d	$sp, $sp, -96

	ld.d	$t0, $a1, 0
	ld.d	$t1, $a1, 8
	ld.d	$t2, $a1, 16
	ld.d	$t3, $a1, 24

	st.d	$ra, $sp, 0
	st.d	$s0, $sp, 8
	st.d	$s1, $sp, 16
	st.d	$s2, $sp, 24
	st.d	$s3, $sp, 32
	st.d	$s4, $sp, 40
	st.d	$s5, $sp, 48
	st.d	$s6, $sp, 56
	st.d	$s7, $sp, 64
	st.d	$s8, $sp, 72
	st.d	$fp, $sp, 80

	la.local	$a2, Lone

	lu12i.w	$a1, 0x72350
	lu12i.w	$a3, 0x39d54
	lu12i.w	$a4, 0x21c60
	li.d	$a5, -1

	ld.d	$t4, $a2, 0
	ori	$a1, $a1, 0x975
	ori	$a3, $a3, 0x123
	ori	$a4, $a4, 0x52b

	li.d	$a6, -1
	lu32i.d	$a1, -24952
	lu32i.d	$a3, -265207
	lu32i.d	$a4, 0x3df6b

	lu32i.d	$a6, -2
	lu52i.d	$a1, $a1, 0x327
	lu52i.d	$a3, $a3, 0x53b
	lu52i.d	$a4, $a4, 0x720

	mul.d	$s0, $t0, $t4
	mulh.du	$t5, $t0, $t4
	mul.d	$s1, $t1, $t4
	mulh.du	$t6, $t1, $t4

	mul.d	$s2, $t2, $t4
	mulh.du	$t7, $t2, $t4
	mul.d	$s3, $t3, $t4
	mulh.du	$s4, $t3, $t4

	mul.d	$t4, $a1, $s0

	bl __sm2_z256_modn_mont_mul

	ld.d	$ra, $sp, 0
	ld.d	$s0, $sp, 8
	ld.d	$s1, $sp, 16
	ld.d	$s2, $sp, 24
	ld.d	$s3, $sp, 32
	ld.d	$s4, $sp, 40
	ld.d	$s5, $sp, 48
	ld.d	$s6, $sp, 56
	ld.d	$s7, $sp, 64
	ld.d	$s8, $sp, 72
	ld.d	$fp, $sp, 80
	addi.d	$sp, $sp, 96
	jr	$ra

// mont(a) = a * 2^256 (mod p) = mont_mul(a, 2^512 mod p)
.globl	func(sm2_z256_modn_to_mont)
.align	5

func(sm2_z256_modn_to_mont):
	addi.d	$sp, $sp, -96

	ld.d	$t0, $a0, 0
	ld.d	$t1, $a0, 8
	ld.d	$t2, $a0, 16
	ld.d	$t3, $a0, 24

	st.d	$ra, $sp, 0
	st.d	$s0, $sp, 8
	st.d	$s1, $sp, 16
	st.d	$s2, $sp, 24
	st.d	$s3, $sp, 32
	st.d	$s4, $sp, 40
	st.d	$s5, $sp, 48
	st.d	$s6, $sp, 56
	st.d	$s7, $sp, 64
	st.d	$s8, $sp, 72
	st.d	$fp, $sp, 80

	move	$a0, $a1
	la.local	$a2, Lsm2_z256_modn_2e512


	lu12i.w	$a1, 0x72350
	lu12i.w	$a3, 0x39d54
	lu12i.w	$a4, 0x21c60
	li.d	$a5, -1

	ld.d	$t4, $a2, 0
	ori	$a1, $a1, 0x975
	ori	$a3, $a3, 0x123
	ori	$a4, $a4, 0x52b

	li.d	$a6, -1
	lu32i.d	$a1, -24952
	lu32i.d	$a3, -265207
	lu32i.d	$a4, 0x3df6b

	lu32i.d	$a6, -2
	lu52i.d	$a1, $a1, 0x327
	lu52i.d	$a3, $a3, 0x53b
	lu52i.d	$a4, $a4, 0x720

	mul.d	$s0, $t0, $t4
	mulh.du	$t5, $t0, $t4
	mul.d	$s1, $t1, $t4
	mulh.du	$t6, $t1, $t4

	mul.d	$s2, $t2, $t4
	mulh.du	$t7, $t2, $t4
	mul.d	$s3, $t3, $t4
	mulh.du	$s4, $t3, $t4

	mul.d	$t4, $a1, $s0

	bl __sm2_z256_modn_mont_mul

	ld.d	$ra, $sp, 0
	ld.d	$s0, $sp, 8
	ld.d	$s1, $sp, 16
	ld.d	$s2, $sp, 24
	ld.d	$s3, $sp, 32
	ld.d	$s4, $sp, 40
	ld.d	$s5, $sp, 48
	ld.d	$s6, $sp, 56
	ld.d	$s7, $sp, 64
	ld.d	$s8, $sp, 72
	ld.d	$fp, $sp, 80
	addi.d	$sp, $sp, 96
	jr	$ra

.globl	func(sm2_z256_modn_mont_sqr)
.align	5

func(sm2_z256_modn_mont_sqr):
	addi.d	$sp, $sp, -80

	ld.d	$t0, $a1, 0
	ld.d	$t1, $a1, 8
	ld.d	$t2, $a1, 16
	ld.d	$t3, $a1, 24

	st.d	$ra, $sp, 0
	st.d	$s0, $sp, 8
	st.d	$s1, $sp, 16
	st.d	$s2, $sp, 24
	st.d	$s3, $sp, 32
	st.d	$s4, $sp, 40
	st.d	$s5, $sp, 48
	st.d	$s6, $sp, 56
	st.d	$s7, $sp, 64
	st.d	$s8, $sp, 72

	lu12i.w	$a1, 0x72350
	lu12i.w	$a3, 0x39d54
	lu12i.w	$a4, 0x21c60
	li.d	$a5, -1

	ori	$a1, $a1, 0x975
	ori	$a3, $a3, 0x123
	ori	$a4, $a4, 0x52b
	mul.d	$s0, $t0, $t0

	li.d	$a6, -1
	lu32i.d	$a1, -24952
	mul.d	$s1, $t1, $t0
	mulh.du	$t8, $t1, $t0

	lu32i.d	$a3, -265207
	lu32i.d	$a4, 0x3df6b
	mul.d	$s2, $t2, $t0
	mulh.du	$t5, $t2, $t0

	lu32i.d	$a6, -2
	lu52i.d	$a1, $a1, 0x327
	mul.d	$s3, $t3, $t0
	mulh.du	$s4, $t3, $t0

	lu52i.d	$a3, $a3, 0x53b
	lu52i.d	$a4, $a4, 0x720
	mul.d	$t6, $t2, $t1
	mulh.du	$t7, $t2, $t1

	add.d	$s2, $s2, $t8
	mul.d	$t4, $t3, $t1
	srli.d	$s8, $s1, 63
	mulh.du	$t0, $t0, $t0

	sltu	$a2, $s2, $t8
	mulh.du	$t8, $t3, $t1
	slli.d	$s1, $s1, 1
	mul.d	$s5, $t3, $t2

	add.d	$a2, $t5, $a2
	mulh.du	$s6, $t3, $t2
	srli.d	$s7, $s2, 63
	alsl.d	$s2, $s2, $s8, 1

	add.d	$s3, $s3, $a2
	add.d	$t7, $t4, $t7

	sltu	$a2, $s3, $a2
	add.d	$s3, $s3, $t6
	sltu	$ra, $t7, $t4
	add.d	$s1, $s1, $t0

	add.d	$s4, $s4, $a2
	mul.d	$t4, $a1, $s0
	sltu	$a2, $s3, $t6
	mul.d	$t6, $t1, $t1

	mulh.du	$t1, $t1, $t1
	add.d	$s4, $s4, $a2
	sltu	$a7, $s1, $t0
	mul.d	$t0, $t2, $t2

	srli.d	$s8, $s3, 63
	alsl.d	$s3, $s3, $s7, 1
	sltu	$a2, $s4, $a2
	add.d	$s4, $s4, $t7

	add.d	$t8, $ra, $t8
	add.d	$s2, $s2, $a7
	sltu	$t7, $s4, $t7
	srli.d	$s7, $s4, 63
	alsl.d	$s4, $s4, $s8, 1

	add.d	$s5, $s5, $t8
	add.d	$a2, $a2, $t7
	sltu	$a7, $s2, $a7
	add.d	$s2, $s2, $t6

	sltu	$t7, $s5, $t8
	add.d	$s5, $s5, $a2
	sltu	$t8, $s2, $t6
	mul.d	$t6, $a3, $t4

	sltu	$a2, $s5, $a2
	add.d	$s4, $s4, $t0
	mul.d	$t5, $t3, $t3
	add.d	$t8, $a7, $t8

	mulh.du	$t3, $t3, $t3
	add.d	$a2, $a2, $t7
	add.d	$t8, $t1, $t8
	mul.d	$t1, $a4, $t4

	sltu	$a7, $s4, $t0
	mulh.du	$t0, $a3, $t4
	add.d	$s6, $s6, $a2
	srli.d	$s8, $s5, 63

	alsl.d	$s5, $s5, $s7, 1
	add.d	$s3, $s3, $t8
	add.d	$s0, $s0, $t6
	mulh.du	$t7, $t2, $t2

	srli.d	$s7, $s6, 63
	sltu	$t8, $s3, $t8
	sltu	$ra, $s0, $t6
	add.d	$s0, $s1, $t1

	alsl.d	$s6, $s6, $s8, 1
	mul.d	$t2, $a5, $t4
	add.d	$s7, $s7, $t3
	mul.d	$t3, $a6, $t4

	add.d	$s4, $s4, $t8
	sltu	$a2, $s0, $s1
	add.d	$s0, $s0, $ra
	mulh.du	$t1, $a4, $t4

	sltu	$t8, $s4, $t8
	sltu	$ra, $s0, $ra
	add.d	$s0, $s0, $t0
	add.d	$s6, $s6, $t5

	add.d	$a7, $t8, $a7
	mul.d	$t8, $a1, $s0
	add.d	$s1, $s2, $t2

	add.d	$a7, $t7, $a7
	sltu	$s8, $s1, $s2
	add.d	$s2, $s3, $t3
	mulh.du	$t3, $a6, $t4

	add.d	$s5, $s5, $a7
	mulh.du	$t2, $a5, $t4
	add.d	$a2, $ra, $a2
	sltu	$t7, $s6, $t5

	mul.d	$t4, $a3, $t8
	sltu	$a7, $s5, $a7
	add.d	$s1, $s1, $a2
	sltu	$ra, $s2, $s3

	sltu	$t0, $s0, $t0
	mul.d	$t5, $a4, $t8
	add.d	$s6, $s6, $a7
	sltu	$a2, $s1, $a2

	add.d	$t0, $t1, $t0
	sltu	$a7, $s6, $a7
	add.d	$a2, $a2, $s8
	add.d	$a7, $a7, $t7

	add.d	$s1, $s1, $t0
	mul.d	$t6, $a5, $t8
	add.d	$s2, $s2, $a2
	add.d	$s7, $s7, $a7

	sltu	$t0, $s1, $t0
	mul.d	$t7, $a6, $t8
	add.d	$s0, $s0, $t4
	mulh.du	$t1, $a3, $t8

	add.d	$t0, $t2, $t0
	mulh.du	$t2, $a4, $t8
	sltu	$a7, $s0, $t4
	add.d	$s0, $s1, $t5

	#sqr_round0
	sltu	$a2, $s2, $a2
	add.d	$s2, $s2, $t0
	sltu	$s8, $s0, $t5
	add.d	$s0, $s0, $a7

	add.d	$s3, $a2, $ra
	sltu	$t0, $s2, $t0
	sltu	$a2, $s0, $a7
	add.d	$s0, $s0, $t1

	add.d	$t0, $t3, $t0
	mulh.du	$t3, $a5, $t8
	sltu	$t1, $s0, $t1
	mul.d	$t4, $a1, $s0

	add.d	$s1, $s2, $t6
	add.d	$s3, $s3, $t0
	add.d	$a2, $a2, $s8
	add.d	$t1, $t2, $t1

	#sqr_round1
	sltu	$a7, $s1, $t6
	add.d	$s2, $s3, $t7
	add.d	$s1, $s1, $a2
	mulh.du	$ra, $a6, $t8

	sltu	$a2, $s1, $a2
	add.d	$s1, $s1, $t1

	sltu	$s8, $s2, $s3
	sltu	$t1, $s1, $t1
	add.d	$a2, $a2, $a7
	mul.d	$t5, $a3, $t4

	add.d	$s2, $s2, $a2
	mul.d	$t6, $a4, $t4
	add.d	$t1, $t3, $t1
	mul.d	$t7, $a5, $t4

	sltu	$a2, $s2, $a2
	mul.d	$t8, $a6, $t4
	add.d	$s0, $s0, $t5
	mulh.du	$t0, $a3, $t4

	add.d	$s3, $a2, $s8
	mulh.du	$t2, $a4, $t4
	sltu	$a2, $s0, $t5
	add.d	$s0, $s1, $t6

	add.d	$s2, $s2, $t1
	mulh.du	$t3, $a5, $t4
	sltu	$a7, $s0, $t6
	add.d	$s0, $s0, $a2

	sltu	$t1, $s2, $t1
	mulh.du	$t4, $a6, $t4
	sltu	$a2, $s0, $a2
	add.d	$s0, $s0, $t0

	add.d	$t1, $ra, $t1
	add.d	$a2, $a2, $a7
	sltu	$t0, $s0, $t0
	mul.d	$s8, $a1, $s0

	add.d	$s3, $s3, $t1
	add.d	$s1, $s2, $t7
	add.d	$s2, $s3, $t8
	add.d	$t0, $t2, $t0

	#sqr_round2
	sltu	$a7, $s1, $t7
	add.d	$s1, $s1, $a2
	sltu	$ra, $s2, $s3

	sltu	$a2, $s1, $a2
	add.d	$s1, $s1, $t0

	add.d	$a2, $a2, $a7
	mul.d	$t5, $a3, $s8
	sltu	$t0, $s1, $t0
	mul.d	$t6, $a4, $s8

	add.d	$s2, $s2, $a2
	mul.d	$t7, $a5, $s8
	add.d	$t0, $t3, $t0
	mul.d	$t8, $a6, $s8

	sltu	$a2, $s2, $a2
	mulh.du	$t1, $a3, $s8
	add.d	$s2, $s2, $t0
	mulh.du $t2, $a4, $s8

	add.d	$s3, $a2, $ra
	mulh.du	$t3, $a5, $s8
	sltu	$t0, $s2, $t0
	add.d	$s0, $s0, $t5

	add.d	$t0, $t4, $t0
	mulh.du	$s8, $a6, $s8
	sltu	$a2, $s0, $t5
	add.d	$s0, $s1, $t6

	add.d	$s3, $s3, $t0
	sltu	$a7, $s0, $t6
	add.d	$s0, $s0, $a2
	add.d	$s1, $s2, $t7

	#sqr_round3
	sltu	$a2, $s0, $a2
	sltu	$ra, $s1, $t7
	add.d	$s2, $s3, $t8
	add.d	$s0, $s0, $t1

	add.d	$a2, $a2, $a7
	sltu	$a7, $s2, $s3
	sltu	$a1, $s0, $t1
	add.d	$s0, $s0, $s4

	add.d	$s1, $s1, $a2
	add.d	$a1, $t2, $a1
	sltu	$t7, $s0, $s4
	sltu	$t4, $s0, $a3

	sltu	$a2, $s1, $a2
	add.d	$s1, $s1, $a1
	sub.d	$t0, $s0, $a3
	add.d	$a4, $a4, $t4

	add.d	$a2, $a2, $ra
	sltu	$a1, $s1, $a1
	add.d	$s1, $s1, $s5

	add.d	$s2, $s2, $a2
	add.d	$a1, $t3, $a1
	sltu	$t8, $s1, $s5
	add.d	$s1, $s1, $t7

	sltu	$a2, $s2, $a2
	add.d	$s2, $s2, $a1
	sltu	$t7, $s1, $t7
	sltu	$t4, $s1, $a4

	add.d	$s3, $a2, $a7
	sltu	$a1, $s2, $a1
	add.d	$t7, $t7, $t8
	add.d	$s2, $s2, $s6

	add.d	$a1, $s8, $a1
	sltu	$t8, $s2, $s6
	add.d	$s2, $s2, $t7
	sub.d	$t1, $s1, $a4

	add.d	$s3, $s3, $a1
	sltu	$a2, $s2, $t7
	sltu	$t5, $s2, $a5
	sub.d	$t2, $s2, $a5

	add.d 	$a2, $a2, $t8
	add.d	$s3, $s3, $s7
	sltu	$t6, $t2, $t4
	sub.d	$t2, $t2, $t4

	sltu	$a7, $s3, $s7
	add.d	$s3, $s3, $a2
	add.d	$t4, $t5, $t6

	sltu	$a2, $s3, $a2
	add.d	$a6, $a6, $t4

	add.d	$s4, $a2, $a7
	sltu	$t4, $s3, $a6
	sub.d	$t3, $s3, $a6
	sltu	$t8, $s4, $t4

	maskeqz	$t4, $s0, $t8
	masknez	$t0, $t0, $t8
	maskeqz	$t5, $s1, $t8
	masknez	$t1, $t1, $t8

	maskeqz	$t6, $s2, $t8
	masknez	$t2, $t2, $t8
	maskeqz	$t7, $s3, $t8
	masknez	$t3, $t3, $t8

	or	$t0, $t0, $t4
	or	$t1, $t1, $t5
	or	$t2, $t2, $t6
	or	$t3, $t3, $t7

	st.d	$t0, $a0, 0
	st.d	$t1, $a0, 8
	st.d	$t2, $a0, 16
	st.d	$t3, $a0, 24

	ld.d	$ra, $sp, 0
	ld.d	$s0, $sp, 8
	ld.d	$s1, $sp, 16
	ld.d	$s2, $sp, 24
	ld.d	$s3, $sp, 32
	ld.d	$s4, $sp, 40
	ld.d	$s5, $sp, 48
	ld.d	$s6, $sp, 56
	ld.d	$s7, $sp, 64
	ld.d	$s8, $sp, 72
	addi.d	$sp, $sp, 80

	jr	$ra
