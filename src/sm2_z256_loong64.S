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

.globl	func(sm2_z256_point_dbl)

.align	5
func(sm2_z256_point_dbl):
	addi.d	$sp, $sp, -208
	li.d	$a3, -1
	st.d	$ra, $sp, 200
	st.d	$s0, $sp, 192

	srli.d	$t8, $a3, 32
	st.d	$s1, $sp, 184
	st.d	$s2, $sp, 176
	st.d	$s3, $sp, 168

	addi.d	$a3, $t8, 1
	st.d	$s4, $sp, 160
	move	$s4, $a1
	st.d	$s5, $sp, 152

	st.d	$s6, $sp, 144
	st.d	$s7, $sp, 136
	st.d	$s8, $sp, 128
.Ldbl_sct:
	ld.d	$a4, $s4, 32

	ld.d	$a5, $s4, 40
	ld.d	$a6, $s4, 48
	ld.d	$a7, $s4, 56
	ld.d	$t0, $s4, 64

	ld.d	$t1, $s4, 72
	ld.d	$t2, $s4, 80
	ld.d	$t3, $s4, 88

	// Y1=(a4, a5, a6, a7)

	// Z1 = (s5,s6,s7,s8)
	move	$s5, $t0
	move	$s6, $t1

	move	$s7, $t2
	move	$s8, $t3

	//4. Z3 = (t0,t1,t2,t3) = Z1*Y1
	bl	__sm2_z256_modp_mont_mul

	//5. Z3 = (t0,t1,t2,t3) = 2*Z1*Y1
	bl	__sm2_z256_modp_dbl

	//save Z3
	st.d	$t0, $a0, 64
	st.d	$t1, $a0, 72
	//move Y1
	move	$t0, $a4
	move	$t1, $a5

	st.d	$t2, $a0, 80
	st.d	$t3, $a0, 88
	move	$t2, $a6
	move	$t3, $a7

	//move Z1
	move	$a4, $s5
	move	$a5, $s6
	move	$a6, $s7
	move	$a7, $s8

	//1. S = (t0,t1,t2,t3) = Y1*2
	bl	__sm2_z256_modp_dbl

	//3. S = (t0,t1,t2,t3) = S^2 = 4Y1^2
	bl	__sm2_z256_modp_mont_sqr
	//save S
	st.d	$t0, $sp, 0
	st.d	$t1, $sp, 8
	st.d	$t2, $sp, 16
	st.d	$t3, $sp, 24

	//8. S = (t0,t1,t2,t3) = S^2 = 16Y1^4
	bl	__sm2_z256_modp_mont_sqr

	//9. S = (t0,t1,t2,t3) = 8Y1^4
	bl	__sm2_z256_modp_haf
	//save Y3, done
	st.d	$t0, $a0, 32
	st.d	$t1, $a0, 40
	st.d	$t2, $a0, 48
	st.d	$t3, $a0, 56

	//reload Z1
	move	$t0, $s5
	move	$t1, $s6
	move	$t2, $s7
	move	$t3, $s8

	//2. Zsqr = (t0,t1,t2,t3) = Z1^2
	bl	__sm2_z256_modp_mont_sqr

	move	$s5, $t0
	ld.d	$a4, $s4, 0
	move	$s6, $t1
	ld.d	$a5, $s4, 8

	move	$s7, $t2
	ld.d	$a6, $s4, 16
	move	$s8, $t3
	ld.d	$a7, $s4, 24

	// X1 = (a4,a5,a6,a7)
	//6. M = (t0,t1,t2,t3) = X1+Zsqr
	bl	__sm2_z256_modp_add

	//save M
	st.d	$t0, $sp, 32
	//reload Zsqr
	move	$t0, $s5
	st.d	$t1, $sp, 40
	move	$t1, $s6

	st.d	$t2, $sp, 48
	move	$t2, $s7
	st.d	$t3, $sp, 56
	move	$t3, $s8

	//7. Zsqr = (t0,t1,t2,t3)= X1-Zsqr

	bl	__sm2_z256_modp_neg_sub

	//save Zsqr
	st.d	$t0, $sp, 64
	st.d	$t1, $sp, 72
	//reload S
	ld.d	$t0, $sp, 0
	ld.d	$t1, $sp, 8

	st.d	$t2, $sp, 80
	st.d	$t3, $sp, 88
	ld.d	$t2, $sp, 16
	ld.d	$t3, $sp, 24

	//12. S = S*X1 = 4*X1*Y1^2
	bl	__sm2_z256_modp_mont_mul
	//save S
	st.d	$t0, $sp, 0
	st.d	$t1, $sp, 8
	st.d	$t2, $sp, 16
	st.d	$t3, $sp, 24


	//13. tmp0 = 2*S = 8*X1*Y1^2
	bl	__sm2_z256_modp_dbl
	//save tmp0
	st.d	$t0, $sp, 96
	st.d	$t1, $sp, 104
	//load M
	ld.d	$a4, $sp, 32
	ld.d	$a5, $sp, 40
	st.d	$t2, $sp, 112
	st.d	$t3, $sp, 120
	ld.d	$a6, $sp, 48
	ld.d	$a7, $sp, 56
	//load Zsqr
	ld.d	$t0, $sp, 64
	ld.d	$t1, $sp, 72
	ld.d	$t2, $sp, 80
	ld.d	$t3, $sp, 88

	//10. M = (t0,t1,t2,t3) = M*Zsqr = X1^2-Z1^4
	bl	__sm2_z256_modp_mont_mul

	move	$a4, $t0
	move	$a5, $t1
	move	$a6, $t2
	move	$a7, $t3


	bl	__sm2_z256_modp_dbl
	//11. M = (t0,t1,t2,t3) = 3*(X1^2-Z1^4)
	bl	__sm2_z256_modp_add
	st.d	$t0, $sp, 32
	st.d	$t1, $sp, 40
	st.d	$t2, $sp, 48
	st.d	$t3, $sp, 56

	//14. X3 = M^2 = (3*(X1^2-Z1^4))^2
	bl	__sm2_z256_modp_mont_sqr
	//load tmp0
	ld.d	$a4, $sp, 96
	ld.d	$a5, $sp, 104
	ld.d	$a6, $sp, 112
	ld.d	$a7, $sp, 120

	//15. X3 = X3-tmp0 = (3*(X1^2-Z1^4))^2 - 8*X1*Y1^2
	bl	__sm2_z256_modp_sub

	st.d	$t0, $a0, 0
	st.d	$t1, $a0, 8
	st.d	$t2, $a0, 16
	st.d	$t3, $a0, 24

	//reload S
	ld.d	$a4, $sp, 0
	ld.d	$a5, $sp, 8
	ld.d	$a6, $sp, 16
	ld.d	$a7, $sp, 24

	//16. S = S - X3 = 4*X1*Y1^2 - X3
	bl	__sm2_z256_modp_neg_sub

	//reload M
	ld.d	$a4, $sp, 32
	ld.d	$a5, $sp, 40
	ld.d	$a6, $sp, 48
	ld.d	$a7, $sp, 56

	//17. S = S * M = 3* (*X1^2 - Z^4)*(4*X1*Y1^2 - X3)
	bl	__sm2_z256_modp_mont_mul

	ld.d	$a4, $a0, 32
	ld.d	$a5, $a0, 40
	ld.d	$a6, $a0, 48
	ld.d	$a7, $a0, 56

	bl	__sm2_z256_modp_sub

	st.d	$t0, $a0, 32
	st.d	$t1, $a0, 40
	st.d	$t2, $a0, 48
	st.d	$t3, $a0, 56


	ld.d	$ra, $sp, 200
	ld.d	$s0, $sp, 192
	ld.d	$s1, $sp, 184
	ld.d	$s2, $sp, 176

	ld.d	$s3, $sp, 168
	ld.d	$s4, $sp, 160
	ld.d	$s5, $sp, 152

	ld.d	$s6, $sp, 144
	ld.d	$s7, $sp, 136
	ld.d	$s8, $sp, 128

	addi.d	$sp, $sp, 208
	jr	$ra

.globl	func(sm2_z256_point_add_affine)
.align	5

func(sm2_z256_point_add_affine):
	addi.d	$sp, $sp, -272

	//in1_z
	ld.d	$t0, $a1, 64
	ld.d	$t1, $a1, 72
	ld.d	$t2, $a1, 80
	ld.d	$t3, $a1, 88

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

	li.d	$a3, -1
	move	$s8, $a1
	move	$fp, $a2
	or	$s0, $t0, $t1

	or	$s1, $t2, $t3
	srli.d	$t8, $a3, 32
	move	$s4, $t0
	move	$s5, $t1

	or		$a1, $s0, $s1  // zero or not, used in maskeqz and masknez.
	move	$s6, $t2
	move	$s7, $t3
	addi.d	$a3, $t8, 1

	st.d	$a1, $sp, 256
	bl	__sm2_z256_modp_mont_sqr  // p256_sqr_mont(Z1sqr, in1_z);
	move	$a4, $t0
	move	$a5, $t1
	move	$a6, $t2
	move	$a7, $t3

	# in1_z
	move	$t0, $s4
	move	$t1, $s5
	move	$t2, $s6
	move	$t3, $s7

	bl	__sm2_z256_modp_mont_mul  // p256_mul_mont(S2, Z1sqr, in1_z);

	ld.d	$t4, $fp, 32
	ld.d	$t5, $fp, 40
	ld.d	$t6, $fp, 48
	ld.d	$t7, $fp, 56

	// store S2 and load in2_x
	st.d	$t0, $sp, 96
	ld.d	$t0, $fp, 0
	st.d	$t1, $sp, 104
	ld.d	$t1, $fp, 8

	st.d	$t2, $sp, 112
	ld.d	$t2, $fp, 16
	st.d	$t3, $sp, 120
	ld.d	$t3, $fp, 24

	or	$t4, $t4, $t5
	or	$t5, $t6, $t7
	or	$s0, $t0, $t1
	or	$s1, $t2, $t3

	or 	$t4, $t4, $t5
	or	$t5, $s0, $s1
	or	$a2, $t4, $t5
	st.d	$a2, $sp, 264

	bl	__sm2_z256_modp_mont_mul // p256_mul_mont(U2, Z1sqr, in2_x);

	// in1_x
	ld.d	$a4, $s8, 0
	ld.d	$a5, $s8, 8
	ld.d	$a6, $s8, 16
	ld.d	$a7, $s8, 24

	bl	__sm2_z256_modp_sub // p256_sub(H, U2, in1_x);

	// in1_z
	move	$a4, $s4
	move	$a5, $s5
	move	$a6, $s6
	move	$a7, $s7

	move	$s4, $t0
	move	$s5, $t1
	move	$s6, $t2
	move	$s7, $t3

	bl	__sm2_z256_modp_mont_mul  // p256_mul_mont(res_z, H, in1_z);

	ld.d	$a1, $sp, 256
	ld.d	$a2, $sp, 264
	li.d	$t4, 1

	// store res_z
	st.d	$t0, $sp, 128
	st.d	$t1, $sp, 136
	st.d	$t2, $sp, 144
	st.d	$t3, $sp, 152

	// SM2_Z256_MODP_MONT_ONE {0x1, 0xffffffff, 0x0, 0x100000000}
	maskeqz	$t0, $t0, $a1
	masknez	$t4, $t4, $a1
	maskeqz	$t1, $t1, $a1
	masknez	$t5, $t8, $a1

	maskeqz	$t2, $t2, $a1
	maskeqz	$t3, $t3, $a1
	masknez	$t7, $a3, $a1

	or	$t0, $t0, $t4
	or	$t1, $t1, $t5
	or	$t3, $t3, $t7

	maskeqz	$t0, $t0, $a2
	masknez	$t4, $a4, $a2
	maskeqz	$t1, $t1, $a2
	masknez	$t5, $a5, $a2

	maskeqz	$t2, $t2, $a2
	masknez	$t6, $a6, $a2
	maskeqz	$t3, $t3, $a2
	masknez	$t7, $a7, $a2

	or	$t0, $t0, $t4
	or	$t1, $t1, $t5
	or	$t2, $t2, $t6
	or	$t3, $t3, $t7

	// store r->Z
	st.d	$t0, $a0, 64
	st.d	$t1, $a0, 72
	st.d	$t2, $a0, 80
	st.d	$t3, $a0, 88

	// H
	move	$t0, $s4
	move	$t1, $s5
	move	$t2, $s6
	move	$t3, $s7

	bl	__sm2_z256_modp_mont_sqr  // p256_sqr_mont(Hsqr, H);

	// Hsqr
	move	$a4, $t0
	move	$a5, $t1
	move	$a6, $t2
	move	$a7, $t3

	// H
	move	$t0, $s4
	move	$t1, $s5
	move	$t2, $s6
	move	$t3, $s7
	bl	__sm2_z256_modp_mont_mul  // p256_mul_mont(Hcub, Hsqr, H);

	//store Hcub and load in1_x
	st.d	$t0, $sp, 160
	st.d	$t1, $sp, 168
	ld.d	$t0, $s8, 0
	ld.d	$t1, $s8, 8

	st.d	$t2, $sp, 176
	st.d	$t3, $sp, 184
	ld.d	$t2, $s8, 16
	ld.d	$t3, $s8, 24
	bl	__sm2_z256_modp_mont_mul  // p256_mul_mont(U2, in1_x, Hsqr);

	// store U2
	st.d	$t0, $sp, 192
	st.d	$t1, $sp, 200
	move	$a4, $t0
	move	$a5, $t1

	st.d	$t2, $sp, 208
	st.d	$t3, $sp, 216
	move	$a6, $t2
	move	$a7, $t3

	bl	__sm2_z256_modp_add	// p256_mul_by_2(Hsqr, U2);

	// store Hsqr and load S2
	move	$s4, $t0
	move	$s5, $t1
	ld.d	$t0, $sp, 96
	ld.d	$t1, $sp, 104

	move	$s6, $t2
	move	$s7, $t3
	ld.d	$t2, $sp, 112
	ld.d	$t3, $sp, 120

	// in2_y
	ld.d	$a4, $fp, 32
	ld.d	$a5, $fp, 40
	ld.d	$a6, $fp, 48
	ld.d	$a7, $fp, 56
	bl	__sm2_z256_modp_mont_mul  // p256_mul_mont(S2, S2, in2_y);

	// in1_y
	ld.d	$a4, $s8, 32
	ld.d	$a5, $s8, 40
	ld.d	$a6, $s8, 48
	ld.d	$a7, $s8, 56
	bl	__sm2_z256_modp_sub	// p256_sub(R, S2, in1_y);

	//store R
	st.d	$t0, $sp, 224
	st.d	$t1, $sp, 232
	st.d	$t2, $sp, 240
	st.d	$t3, $sp, 248

	bl	__sm2_z256_modp_mont_sqr  // p256_sqr_mont(Rsqr, R);

	// Rsrq
	move	$a4, $t0
	move	$a5, $t1
	move	$a6, $t2
	move	$a7, $t3

	// Hsqr
	move	$t0, $s4
	move	$t1, $s5
	move	$t2, $s6
	move	$t3, $s7

	bl	__sm2_z256_modp_neg_sub	// p256_sub(res_x, Rsqr, Hsqr);

	// Hcub
	ld.d	$a4, $sp, 160
	ld.d	$a5, $sp, 168
	ld.d	$a6, $sp, 176
	ld.d	$a7, $sp, 184
	bl	__sm2_z256_modp_sub	//  p256_sub(res_x, res_x, Hcub);
	// Store res_x
	move	$s4, $t0
	move	$s5, $t1
	move	$s6, $t2
	move	$s7, $t3

	// in1_y
	ld.d	$t0, $s8, 32
	ld.d	$t1, $s8, 40
	ld.d	$t2, $s8, 48
	ld.d	$t3, $s8, 56

	bl	__sm2_z256_modp_mont_mul  // p256_mul_mont(S2, in1_y, Hcub);
	// load U2
	ld.d	$a4, $sp, 192
	ld.d	$a5, $sp, 200
	ld.d	$a6, $sp, 208
	ld.d	$a7, $sp, 216

	// Store S2 and get res_x
	st.d	$t0, $sp, 96
	st.d	$t1, $sp, 104
	move 	$t0, $s4
	move	$t1, $s5

	st.d	$t2, $sp, 112
	st.d	$t3, $sp, 120
	move	$t2, $s6
	move	$t3, $s7

	bl	__sm2_z256_modp_neg_sub	// p256_sub(res_y, U2, res_x);

	// R
	ld.d	$a4, $sp, 224
	ld.d	$a5, $sp, 232
	ld.d	$a6, $sp, 240
	ld.d	$a7, $sp, 248
	bl	__sm2_z256_modp_mont_mul  // p256_mul_mont(res_y, res_y, R);

	// S2
	ld.d	$a4, $sp, 96
	ld.d	$a5, $sp, 104
	ld.d	$a6, $sp, 112
	ld.d	$a7, $sp, 120

	bl	__sm2_z256_modp_sub	// p256_sub(res_y, res_y, S2);
	// directly use res_y stored t0-t3

	ld.d	$a1, $sp, 256
	ld.d	$a2, $sp, 264

	// in2
	ld.d	$a4, $fp, 0
	ld.d	$a5, $fp, 8
	ld.d	$a6, $fp, 16
	ld.d	$a7, $fp, 24

	// in1
	ld.d	$t4, $s8, 0
	ld.d	$t5, $s8, 8
	ld.d	$t6, $s8, 16
	ld.d	$t7, $s8, 24

	// res_x is stored in s4-s7
	maskeqz	$s0, $s4, $a1
	masknez	$a4, $a4, $a1
	maskeqz	$s1, $s5, $a1
	masknez	$a5, $a5, $a1

	maskeqz	$s2, $s6, $a1
	masknez	$a6, $a6, $a1
	maskeqz	$s3, $s7, $a1
	masknez	$a7, $a7, $a1

	or	$s0, $s0, $a4
	or	$s1, $s1, $a5
	or	$s2, $s2, $a6
	or	$s3, $s3, $a7

	// in2
	ld.d	$a4, $fp, 32
	ld.d	$a5, $fp, 40
	ld.d	$a6, $fp, 48
	ld.d	$a7, $fp, 56

	maskeqz	$s0, $s0, $a2
	masknez	$t4, $t4, $a2
	maskeqz	$s1, $s1, $a2
	masknez	$t5, $t5, $a2

	maskeqz	$s2, $s2, $a2
	masknez	$t6, $t6, $a2
	maskeqz	$s3, $s3, $a2
	masknez	$t7, $t7, $a2

	or	$s0, $s0, $t4
	or	$s1, $s1, $t5
	or	$s2, $s2, $t6
	or	$s3, $s3, $t7

	// in1
	ld.d	$t4, $s8, 32
	ld.d	$t5, $s8, 40
	ld.d	$t6, $s8, 48
	ld.d	$t7, $s8, 56

	st.d	$s0, $a0, 0
	st.d	$s1, $a0, 8
	st.d	$s2, $a0, 16
	st.d	$s3, $a0, 24

	maskeqz	$t0, $t0, $a1
	masknez	$a4, $a4, $a1
	maskeqz	$t1, $t1, $a1
	masknez	$a5, $a5, $a1

	maskeqz	$t2, $t2, $a1
	masknez	$a6, $a6, $a1
	maskeqz	$t3, $t3, $a1
	masknez	$a7, $a7, $a1

	or	$t0, $t0, $a4
	or	$t1, $t1, $a5
	or	$t2, $t2, $a6
	or	$t3, $t3, $a7

	maskeqz	$t0, $t0, $a2
	masknez	$t4, $t4, $a2
	maskeqz	$t1, $t1, $a2
	masknez	$t5, $t5, $a2

	maskeqz	$t2, $t2, $a2
	masknez	$t6, $t6, $a2
	maskeqz	$t3, $t3, $a2
	masknez	$t7, $t7, $a2

	or	$t0, $t0, $t4
	or	$t1, $t1, $t5
	or	$t2, $t2, $t6
	or	$t3, $t3, $t7

	st.d	$t0, $a0, 32
	st.d	$t1, $a0, 40
	st.d	$t2, $a0, 48
	st.d	$t3, $a0, 56

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
	addi.d	$sp, $sp, 272

	jr	$ra

.globl	func(sm2_z256_point_add)
.align	5

func(sm2_z256_point_add):
	addi.d	$sp, $sp, -464
	li.d	$a3, -1
	ld.d	$t0, $a2, 64
	ld.d	$t1, $a2, 72

	ld.d	$t2, $a2, 80
	ld.d	$t3, $a2, 88
	srli.d	$t8, $a3, 32
	st.d	$ra, $sp, 456

	st.d	$s0, $sp, 448
	st.d	$s1, $sp, 440
	st.d	$s2, $sp, 432
	addi.d	$a3, $t8, 1

	st.d	$s3, $sp, 424
	st.d	$s4, $sp, 416
	st.d	$s5, $sp, 408
	st.d	$s6, $sp, 400

	move	$s4, $a1
	move	$s5, $a2
	or	$t4, $t0, $t1
	or	$t5, $t2, $t3

	or	$s6, $t4, $t5			//in2infty
	st.d	$s7, $sp, 392
	st.d	$s8, $sp, 384
	bl	__sm2_z256_modp_mont_sqr	// p256_sqr_mont(Z2sqr, in2_z);

	// save Z2sqr
	st.d	$t0, $sp, 192
	st.d	$t1, $sp, 200
	st.d	$t2, $sp, 208
	st.d	$t3, $sp, 216

	//reload in2_z
	ld.d	$a4, $s5, 64
	ld.d	$a5, $s5, 72
	ld.d	$a6, $s5, 80
	ld.d	$a7, $s5, 88

	bl	__sm2_z256_modp_mont_mul	// p256_mul_mont(S1, Z2sqr, in2_z)

	//load in1_y
	ld.d	$a4, $s4, 32
	ld.d	$a5, $s4, 40
	ld.d	$a6, $s4, 48
	ld.d	$a7, $s4, 56

	bl	__sm2_z256_modp_mont_mul	// p256_mul_mont(S1, $S1, in1_y)

	//save S1
	st.d	$t0, $sp, 320
	st.d	$t1, $sp, 328
	st.d	$t2, $sp, 336
	st.d	$t3, $sp, 344


	ld.d	$t0, $s4, 64
	ld.d	$t1, $s4, 72
	ld.d	$t2, $s4, 80
	ld.d	$t3, $s4, 88

	or	$t4, $t0, $t1
	or	$t5, $t2, $t3
	or	$s7, $t4, $t5			//in1infty
	bl	__sm2_z256_modp_mont_sqr	// p256_sqr_mont(Z1sqr, in1_z);

	// save Z1sqr
	st.d	$t0, $sp, 128
	st.d	$t1, $sp, 136
	st.d	$t2, $sp, 144
	st.d	$t3, $sp, 152

	//reload in1_z
	ld.d	$a4, $s4, 64
	ld.d	$a5, $s4, 72
	ld.d	$a6, $s4, 80
	ld.d	$a7, $s4, 88

	bl	__sm2_z256_modp_mont_mul	// p256_mul_mont(S2, Z1sqr, in1_z)

	//load in2_y
	ld.d	$a4, $s5, 32
	ld.d	$a5, $s5, 40
	ld.d	$a6, $s5, 48
	ld.d	$a7, $s5, 56

	bl	__sm2_z256_modp_mont_mul	// p256_mul_mont(S2, S2, in2_y)

	//save S2
	st.d	$t0, $sp, 352
	st.d	$t1, $sp, 360
	st.d	$t2, $sp, 368
	st.d	$t3, $sp, 376

	//reload S1
	ld.d	$a4, $sp, 320
	ld.d	$a5, $sp, 328
	ld.d	$a6, $sp, 336
	ld.d	$a7, $sp, 344

	bl	__sm2_z256_modp_sub		//p256_sub(R, S2, S1)

	//save R
	st.d	$t0, $sp, 160
	st.d	$t1, $sp, 168
	st.d	$t2, $sp, 176
	st.d	$t3, $sp, 184

	or	$t4, $t0, $t1
	or	$t5, $t2, $t3
	or	$s8, $t4, $t5

	ld.d	$t0, $s4, 0
	ld.d	$t1, $s4, 8
	ld.d	$t2, $s4, 16
	ld.d	$t3, $s4, 24

	ld.d	$a4, $sp, 192
	ld.d	$a5, $sp, 200
	ld.d	$a6, $sp, 208
	ld.d	$a7, $sp, 216

	bl	__sm2_z256_modp_mont_mul		//p256_mul_mont(U1, in1_x, Z2sqr)

	//save U1
	st.d	$t0, $sp, 256
	st.d	$t1, $sp, 264
	st.d	$t2, $sp, 272
	st.d	$t3, $sp, 280

	ld.d	$t0, $s5, 0
	ld.d	$t1, $s5, 8
	ld.d	$t2, $s5, 16
	ld.d	$t3, $s5, 24

	ld.d	$a4, $sp, 128
	ld.d	$a5, $sp, 136
	ld.d	$a6, $sp, 144
	ld.d	$a7, $sp, 152

	bl	__sm2_z256_modp_mont_mul		//p256_mul_mont(U2, in2_x, Z1sqr)

	//save U2
	st.d	$t0, $sp, 288
	st.d	$t1, $sp, 296
	st.d	$t2, $sp, 304
	st.d	$t3, $sp, 312

	//reload U1
	ld.d	$a4, $sp, 256
	ld.d	$a5, $sp, 264
	ld.d	$a6, $sp, 272
	ld.d	$a7, $sp, 280

	bl	__sm2_z256_modp_sub			//p256_sub(H, U2, U1)

	//save H
	st.d	$t0, $sp, 96
	st.d	$t1, $sp, 104
	or	$t4, $t0, $t1
	or	$t5, $t2, $t3

	st.d	$t2, $sp, 112
	st.d	$t3, $sp, 120
	or	$t6, $s6, $s7
	or	$t4, $t4, $t5

	or	$t6, $t6, $s8
	or	$t4, $t4, $t6
	bne	$t6, $zero, .Lpadd
.Lpadd_dbl:
	addi.d	$sp, $sp, 248
	b	.Ldbl_sct

.Lpadd:
	bl	__sm2_z256_modp_mont_sqr		//p256_sqr_mont(Hsqr, H)
	//save Hsqr
	st.d	$t0, $sp, 128
	st.d	$t1, $sp, 136
	st.d	$t2, $sp, 144
	st.d	$t3, $sp, 152

	//reload R
	ld.d	$t0, $sp, 160
	ld.d	$t1, $sp, 168
	ld.d	$t2, $sp, 176
	ld.d	$t3, $sp, 184

	bl	__sm2_z256_modp_mont_sqr		//p256_sqr_mont(Rsqr, R)

	//store Rsqr
	st.d	$t0, $sp, 192
	st.d	$t1, $sp, 200
	st.d	$t2, $sp, 208
	st.d	$t3, $sp, 216

	//reload H
	ld.d	$a4, $sp, 96
	ld.d	$a5, $sp, 104
	ld.d	$a6, $sp, 112
	ld.d	$a7, $sp, 120

	//reload Hsqr
	ld.d	$t0, $sp, 128
	ld.d	$t1, $sp, 136
	ld.d	$t2, $sp, 144
	ld.d	$t3, $sp, 152

	bl	__sm2_z256_modp_mont_mul		//p256_mul_mont(Hcub, Hsqr, H)

	//save Hcub
	st.d	$t0, $sp, 224
	st.d	$t1, $sp, 232
	st.d	$t2, $sp, 240
	st.d	$t3, $sp, 248

	//reload in1_z
	ld.d	$t0, $s4, 64
	ld.d	$t1, $s4, 72
	ld.d	$t2, $s4, 80
	ld.d	$t3, $s4, 88

	bl	__sm2_z256_modp_mont_mul		//p256_mul_mont(res_z, H, in1_z)

	//reload in2_z
	ld.d	$a4, $s5, 64
	ld.d	$a5, $s5, 72
	ld.d	$a6, $s5, 80
	ld.d	$a7, $s5, 88

	bl	__sm2_z256_modp_mont_mul		//p256_mul_mont(res_z, res_z, in2_z)

	//reload in2_z
	ld.d	$t4, $s5, 64
	ld.d	$t5, $s5, 72
	maskeqz	$t0, $t0, $s7
	maskeqz	$t1, $t1, $s7

	ld.d	$t6, $s5, 80
	ld.d	$t7, $s5, 88
	maskeqz	$t2, $t2, $s7
	maskeqz	$t3, $t3, $s7


	//reload in1_z
	ld.d	$a4, $s4, 64
	ld.d	$a5, $s4, 72
	masknez	$t4, $t4, $s7
	masknez	$t5, $t5, $s7

	ld.d	$a6, $s4, 80
	ld.d	$a7, $s4, 88
	or	$t0, $t0, $t4
	or	$t1, $t1, $t5

	masknez	$t6, $t6, $s7
	masknez	$t7, $t7, $s7
	or	$t2, $t2, $t6
	or	$t3, $t3, $t7


	maskeqz	$t0, $t0, $s6
	masknez	$a4, $a4, $s6
	maskeqz	$t1, $t1, $s6
	masknez	$a5, $a5, $s6

	or	$t0, $t0, $a4
	or	$t1, $t1, $a5
	//reload Hsqr
	ld.d	$a4, $sp, 128
	ld.d	$a5, $sp, 136

	maskeqz	$t2, $t2, $s6
	masknez	$a6, $a6, $s6

	st.d	$t0, $a0, 64
	st.d	$t1, $a0, 72
	maskeqz	$t3, $t3, $s6
	masknez	$a7, $a7, $s6

	//reload U1
	ld.d	$t0, $sp, 256
	ld.d	$t1, $sp, 264
	or	$t2, $t2, $a6
	or	$t3, $t3, $a7

	st.d	$t2, $a0, 80
	st.d	$t3, $a0, 88
	ld.d	$a6, $sp, 144
	ld.d	$a7, $sp, 152

	ld.d	$t2, $sp, 272
	ld.d	$t3, $sp, 280

	bl	__sm2_z256_modp_mont_mul		//p256_mul_mont(U2, U1, Hsqr)

	//store U2
	st.d	$t0, $sp, 288
	st.d	$t1, $sp, 296
	st.d	$t2, $sp, 304
	st.d	$t3, $sp, 312


	bl	__sm2_z256_modp_dbl	//p256_mul_by_2(Hsqr, U2)

	//reload Rsqr
	ld.d	$a4, $sp, 192
	ld.d	$a5, $sp, 200
	ld.d	$a6, $sp, 208
	ld.d	$a7, $sp, 216

	bl	__sm2_z256_modp_neg_sub	//p256_sub(res_x, Rsqr, Hsqr)


	//reload Hcub
	ld.d	$a4, $sp, 224
	ld.d	$a5, $sp, 232
	ld.d	$a6, $sp, 240
	ld.d	$a7, $sp, 248

	bl	__sm2_z256_modp_sub	//p256_sub(res_x, res_x, Hcub)

	//reload in2_x
	ld.d	$t4, $s5, 0
	ld.d	$t5, $s5, 8
	//store res_x
	st.d	$t0, $sp, 0
	st.d	$t1, $sp, 8
	maskeqz	$t0, $t0, $s7
	maskeqz	$t1, $t1, $s7

	ld.d	$t6, $s5, 16
	ld.d	$t7, $s5, 24
	st.d	$t2, $sp, 16
	st.d	$t3, $sp, 24
	maskeqz	$t2, $t2, $s7
	maskeqz	$t3, $t3, $s7

	//reload in1_x
	ld.d	$a4, $s4, 0
	ld.d	$a5, $s4, 8
	masknez	$t4, $t4, $s7
	masknez	$t5, $t5, $s7

	ld.d	$a6, $s4, 16
	ld.d	$a7, $s4, 24
	or	$t0, $t0, $t4
	or	$t1, $t1, $t5
	masknez	$t6, $t6, $s7
	masknez	$t7, $t7, $s7

	or	$t2, $t2, $t6
	or	$t3, $t3, $t7
	maskeqz	$t0, $t0, $s6
	maskeqz	$t1, $t1, $s6

	masknez	$a4, $a4, $s6
	masknez	$a5, $a5, $s6

	or	$t0, $t0, $a4
	or	$t1, $t1, $a5
	st.d	$t0, $a0, 0
	st.d	$t1, $a0, 8
	maskeqz	$t2, $t2, $s6
	maskeqz	$t3, $t3, $s6
	//reload U2
	ld.d	$a4, $sp, 288
	ld.d	$a5, $sp, 296
	//reload res_x
	ld.d	$t0, $sp, 0
	ld.d	$t1, $sp, 8

	masknez	$a6, $a6, $s6
	masknez	$a7, $a7, $s6
	or	$t2, $t2, $a6
	or	$t3, $t3, $a7
	ld.d	$a6, $sp, 304
	ld.d	$a7, $sp, 312
	st.d	$t2, $a0, 16
	st.d	$t3, $a0, 24

	ld.d	$t2, $sp, 16
	ld.d	$t3, $sp, 24


	bl	__sm2_z256_modp_neg_sub	//p256_sub(res_y, U2, res_x);

	//reload R
	ld.d	$a4, $sp, 160
	ld.d	$a5, $sp, 168
	ld.d	$a6, $sp, 176
	ld.d	$a7, $sp, 184

	bl	__sm2_z256_modp_mont_mul	//p256_mul_mont(res_y, res_y, R)

	//store res_y
	st.d	$t0, $sp, 32
	st.d	$t1, $sp, 40
	st.d	$t2, $sp, 48
	st.d	$t3, $sp, 56

	//reload Hcub
	ld.d	$a4, $sp, 224
	ld.d	$a5, $sp, 232
	ld.d	$a6, $sp, 240
	ld.d	$a7, $sp, 248

	//reload S1
	ld.d	$t0, $sp, 320
	ld.d	$t1, $sp, 328
	ld.d	$t2, $sp, 336
	ld.d	$t3, $sp, 344

	bl	__sm2_z256_modp_mont_mul	//p256_mul_mont(S2, S1, Hcub)

	//reload res_y

	ld.d	$a4, $sp, 32
	ld.d	$a5, $sp, 40
	ld.d	$a6, $sp, 48
	ld.d	$a7, $sp, 56


	bl	__sm2_z256_modp_neg_sub	//p256_sub(res_y, res_y, S2)

	//reload in2_y
	ld.d	$t4, $s5, 32
	ld.d	$t5, $s5, 40
	maskeqz	$t0, $t0, $s7
	maskeqz	$t1, $t1, $s7

	ld.d	$t6, $s5, 48
	ld.d	$t7, $s5, 56
	maskeqz	$t2, $t2, $s7
	maskeqz	$t3, $t3, $s7


	//reload in1_y
	ld.d	$a4, $s4, 32
	ld.d	$a5, $s4, 40
	masknez	$t4, $t4, $s7
	masknez	$t5, $t5, $s7

	ld.d	$a6, $s4, 48
	ld.d	$a7, $s4, 56
	or	$t0, $t0, $t4
	or	$t1, $t1, $t5

	masknez	$t6, $t6, $s7
	masknez	$t7, $t7, $s7
	or	$t2, $t2, $t6
	or	$t3, $t3, $t7

	maskeqz	$t0, $t0, $s6
	masknez	$a4, $a4, $s6
	maskeqz	$t1, $t1, $s6
	masknez	$a5, $a5, $s6

	or	$t0, $t0, $a4
	or	$t1, $t1, $a5
	maskeqz	$t2, $t2, $s6
	masknez	$a6, $a6, $s6
	st.d	$t0, $a0, 32
	st.d	$t1, $a0, 40

	maskeqz	$t3, $t3, $s6
	masknez	$a7, $a7, $s6
	or	$t2, $t2, $a6
	or	$t3, $t3, $a7
	st.d	$t2, $a0, 48
	st.d	$t3, $a0, 56

	ld.d	$ra, $sp, 456
	ld.d	$s0, $sp, 448
	ld.d	$s1, $sp, 440
	ld.d	$s2, $sp, 432

	ld.d	$s3, $sp, 424
	ld.d	$s4, $sp, 416
	ld.d	$s5, $sp, 408

	ld.d	$s6, $sp, 400
	ld.d	$s7, $sp, 392
	ld.d	$s8, $sp, 384
	addi.d	$sp, $sp, 464

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
