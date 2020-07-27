/*
 * Copyright (c) 2014 - 2020 The GmSSL Project.  All rights reserved.
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

const SM9_P = 0xb640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457dn;

const SM9_N = 0xb640000002a3a6f1d603ab4ff58ec74449f2934b18ea8beee56ee19cd69ecf25n;

const SM9_P1 = {
	X : 0x93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDDn,
	Y : 0x21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616n,
	Z : 1n,
};

const SM9_P2 = {
	X : [0x3722755292130b08d2aab97fd34ec120ee265948d19c17abf9b7213baf82d65bn,
	     0x85aef3d078640c98597b6027b441a01ff1dd2c190f5e93c454806c11d8806141n],
	Y : [0xa7cf28d519be3da65f3170153d278ff247efba98a71a08116215bba5c999a7c7n,
	     0x17509b092e845c1266ba0d262cbee6ed0736a96fa347c8bd856dc76b84ebeb96n],
	Z : [1n, 0n],
}

const SM9_Ppubs = {
	X : [0x29DBA116152D1F786CE843ED24A3B573414D2177386A92DD8F14D65696EA5E32n,
	     0x9F64080B3084F733E48AFF4B41B565011CE0711C5E392CFB0AB1B6791B94C408n],
	Y : [0x41E00A53DDA532DA1A7CE027B7A46F741006E85F5CDFF0730E75C05FB4E3216Dn,
	     0x69850938ABEA0112B57329F447E3A0CBAD3E2FDB1A77F335E89E1408D0EF1C25n],
	Z : [1n, 0n],
}

function fp_new() {
	return 0n;
}

function fp_zero() {
	return 0n;
}

function fp_one() {
	return 1n;
}

function fp_from_hex(s) {
	return BigInt("0x" + s);
}

function fp_is_zero(a) {
	return a == 0n;
}

function fp_is_one(a) {
	return a == 1n;
}

function fp_equ(a, b) {
	return a == b;
}

function fp_add(a, b) {
	return (a + b) % SM9_P;
}

function fp_dbl(a) {
	return (a + a) % SM9_P;
}

function fp_tri(a) {
	return (a + a + a) % SM9_P;
}

function fp_div2(a) {
	if (a % 2n == 1n)
		a += SM9_P;
	return a/2n;
}

function fp_sub(a, b) {
	if (a >= b) {
		return a - b;
	} else {
		return SM9_P + a - b;
	}
}

function fp_neg(a) {
	if (a == 0n)
		return 0n;
	return SM9_P - a;
}

function fp_mul(a, b) {
	return (a * b) % SM9_P;
}

function fp_sqr(a) {
	return (a * a) % SM9_P;
}

function fp_inv(a) {
	let u = a;
	let v = SM9_P;
	let x1 = 1n;
	let x2 = 0n;
	let q = 0n;
	let r = 0n;
	let x = 0n;

	while (u != 1) {
		q = v / u;
		r = v - q * u;
		x = x2 - q * x1;
		v = u;
		u = r;
		x2 = x1;
		x1 = x;
	}

	if (x1 < 0)
		return x1 + SM9_P;
	else
		return x1 % SM9_P;
}

function fp2_new() {
	return [0n, 0n];
}

function fp2_set_hex(a, s) {
	a[0] = fp_from_hex(s[0]);
	a[1] = fp_from_hex(s[1]);
}

function fp2_from_hex(s) {
	let r = fp2_new();
	fp2_set_hex(r, s);
	return r;
}

function fp2_is_zero(a) {
	return a[0] == 0n
		&& a[1] == 0n;
}

function fp2_is_one(a) {
	return a[0] == 1n
		&& a[1] == 0n;
}

function fp2_set_zero(a) {
	a[0] = 0n;
	a[1] = 0n;
}

function fp2_set_one(a) {
	a[0] = 1n;
	a[1] = 0n;
}

function fp2_copy(r, a) {
	r[0] = a[0];
	r[1] = a[1];
}

function fp2_set(a, a0, a1) {
	a[0] = a0;
	a[1] = a1;
}

function fp2_set_u(a) {
	a[0] = 0n;
	a[1] = 1n;
}

function fp2_set_5u(a) {
	a[0] = 0n;
	a[1] = 5n;
}

function fp2_set_bn(a, a0) {
	a[0] = a0 % SM9_P;
	a[1] = 0n;
}

function fp2_equ(a, b) {
	return a[0] == b[0] && a[1] == b[1];
}

function fp2_add(r, a, b) {
	r[0] = fp_add(a[0], b[0]);
	r[1] = fp_add(a[1], b[1]);
}

function fp2_dbl(r, a) {
	r[0] = fp_dbl(a[0]);
	r[1] = fp_dbl(a[1]);
}

function fp2_tri(r, a) {
	let t = fp2_new();
	fp2_dbl(t, a);
	fp2_add(r, t, a);
}

function fp2_div2(r, a) {
	r[0] = fp_div2(a[0]);
	r[1] = fp_div2(a[1]);
}

function fp2_sub(r, a, b) {
	r[0] = fp_sub(a[0], b[0]);
	r[1] = fp_sub(a[1], b[1]);
}

function fp2_neg(r, a) {
	r[0] = fp_neg(a[0]);
	r[1] = fp_neg(a[1]);
}

function fp2_mul(r, a, b) {
	let r0 = fp_sub(fp_mul(a[0], b[0]), fp_dbl(fp_mul(a[1], b[1])));
	let r1 = fp_add(fp_mul(a[0], b[1]), fp_mul(a[1], b[0]));
	r[0] = r0;
	r[1] = r1;
}

function fp2_mul_u(r, a, b) {
	let r0 = fp_neg(fp_dbl(fp_add(fp_mul(a[0], b[1]), fp_mul(a[1], b[0]))));
	let r1 = fp_sub(fp_mul(a[0], b[0]), fp_dbl(fp_mul(a[1], b[1])));
	r[0] = r0;
	r[1] = r1;
}

function fp2_mul_fp(r, a, k) {
	r[0] = fp_mul(a[0], k);
	r[1] = fp_mul(a[1], k);
}

function fp2_sqr(r, a) {
	let r0 = fp_sub(fp_sqr(a[0]), fp_dbl(fp_sqr(a[1])));
	let r1 = fp_dbl(fp_mul(a[0], a[1]));
	r[0] = r0;
	r[1] = r1;
}

function fp2_sqr_u(r, a) {
	let r0 = fp_neg(fp_dbl(fp_dbl(fp_mul(a[0], a[1]))));
	let r1 = fp_sub(fp_sqr(a[0]), fp_dbl(fp_sqr(a[1])));
	r[0] = r0;
	r[1] = r1;
}

function fp2_inv(r, a) {
	if (fp_is_zero(a[0])) {
		r[0] = fp_zero();
		r[1] = fp_neg(fp_inv(fp_dbl(a[1])));

	} else if (fp_is_zero(a[1])) {
		r[0] = fp_inv(a[0]);
		r[1] = fp_zero();

	} else {
		let k = fp_inv(fp_add(fp_sqr(a[0]), fp_dbl(fp_sqr(a[1]))));
		r[0] = fp_mul(a[0], k);
		r[1] = fp_neg(fp_mul(a[1], k));
	}
}

function fp2_div(r, a, b) {
	let t = fp2_new();
	fp2_inv(t, b);
	fp2_mul(r, a, t);
}

function fp4_new() {
	return [fp2_new(), fp2_new()];
}

function fp4_set_hex(r, s) {
	fp2_set_hex(r[0], s.slice(0, 2));
	fp2_set_hex(r[1], s.slice(2, 4));
}

function fp4_from_hex(s) {
	let r = fp4_new();
	fp4_set_hex(r, s);
	return r;
}

function fp4_is_zero(a) {
	return fp2_is_zero(a[0])
		&& fp2_is_zero(a[1]);
}

function fp4_is_one(a) {
	return fp2_is_one(a[0])
		&& fp2_is_zero(a[1]);
}

function fp4_set_zero(a) {
	fp2_set_zero(a[0]);
	fp2_set_zero(a[1]);
}

function fp4_set_one(a) {
	fp2_set_one(a[0]);
	fp2_set_zero(a[1]);
}

function fp4_set_bn(r, a) {
	fp2_set_bn(r[0], a);
	fp2_set_zero(r[1]);
}

function fp4_set_fp2(r, a) {
	fp2_copy(r[0], a);
	fp2_set_zero(r[1]);
}

function fp4_set(r, a0, a1) {
	fp2_copy(r[0], a0);
	fp2_copy(r[1], a1);
}

function fp4_copy(r, a) {
	fp2_copy(r[0], a[0]);
	fp2_copy(r[1], a[1]);
}

function fp4_set_u(r) {
	fp2_set_u(r[0]);
	fp2_set_zero(r[1]);
}

function fp4_set_v(r) {
	fp2_set_zero(r[0]);
	fp2_set_one(r[1]);
}

function fp4_equ(a, b) {
	return fp2_equ(a[0], b[0])
		&& fp2_equ(a[1], b[1]);
}

function fp4_add(r, a, b) {
	fp2_add(r[0], a[0], b[0]);
	fp2_add(r[1], a[1], b[1]);
}

function fp4_dbl(r, a) {
	fp2_dbl(r[0], a[0]);
	fp2_dbl(r[1], a[1]);
}

function fp4_sub(r, a, b) {
	fp2_sub(r[0], a[0], b[0]);
	fp2_sub(r[1], a[1], b[1]);
}

function fp4_neg(r, a) {
	fp2_neg(r[0], a[0]);
	fp2_neg(r[1], a[1]);
}

function fp4_mul(r, a, b) {
	let r0 = fp2_new();
	let r1 = fp2_new();
	let t = fp2_new();

	fp2_mul(r0, a[0], b[0]);
	fp2_mul_u(t, a[1], b[1]);
	fp2_add(r0, r0, t);

	fp2_mul(r1, a[0], b[1]);
	fp2_mul(t, a[1], b[0]);
	fp2_add(r1, r1, t);

	fp2_copy(r[0], r0);
	fp2_copy(r[1], r1);
}

function fp4_mul_fp(r, a, k) {
	fp2_mul_fp(r[0], a[0], k);
	fp2_mul_fp(r[1], a[1], k);
}

function fp4_mul_fp2(r, a, b) {
	fp2_mul(r[0], a[0], b);
	fp2_mul(r[1], a[1], b);
}

function fp4_mul_v(r, a, b) {
	let r0 = fp2_new();
	let r1 = fp2_new();
	let t = fp2_new();

	fp2_mul_u(r0, a[0], b[1]);
	fp2_mul_u(t, a[1], b[0]);
	fp2_add(r0, r0, t);

	fp2_mul(r1, a[0], b[0]);
	fp2_mul_u(t, a[1], b[1]);
	fp2_add(r1, r1, t);

	fp2_copy(r[0], r0);
	fp2_copy(r[1], r1);
}

function fp4_sqr(r, a) {
	let r0 = fp2_new();
	let r1 = fp2_new();
	let t = fp2_new();

	fp2_sqr(r0, a[0]);
	fp2_sqr_u(t, a[1]);
	fp2_add(r0, r0, t);

	fp2_mul(r1, a[0], a[1]);
	fp2_dbl(r1, r1);
	fp2_copy(r[0], r0);
	fp2_copy(r[1], r1);
}

function fp4_sqr_v(r, a) {
	let r0 = fp2_new();
	let r1 = fp2_new();
	let t = fp2_new();

	fp2_mul_u(t, a[0], a[1]);
	fp2_dbl(r0, t);

	fp2_sqr(r1, a[0]);
	fp2_sqr_u(t, a[1]);
	fp2_add(r1, r1, t);

	fp2_copy(r[0], r0);
	fp2_copy(r[1], r1);
}

function fp4_inv(r, a) {
	let r0 = fp2_new();
	let r1 = fp2_new();
	let k = fp2_new();

	fp2_sqr_u(k, a[1]);
	fp2_sqr(r0, a[0]);
	fp2_sub(k, k, r0);
	fp2_inv(k, k);

	fp2_mul(r0, a[0], k);
	fp2_neg(r0, r0);

	fp2_mul(r1, a[1], k);

	fp2_copy(r[0], r0);
	fp2_copy(r[1], r1);
}

function fp12_new() {
	return [fp4_new(),
		fp4_new(),
		fp4_new()];
}

function fp12_set_hex(r, s) {
	fp4_set_hex(r[0], s.slice(0, 4));
	fp4_set_hex(r[1], s.slice(4, 8));
	fp4_set_hex(r[2], s.slice(8, 12));
}

function fp12_from_hex(s) {
	let r = fp12_new();
	fp12_set_hex(r, s);
	return r;
}

function fp12_is_zero(a) {
	return fp4_is_zero(a[0])
		&& fp4_is_zero(a[1])
		&& fp4_is_zero(a[2]);
}

function fp12_is_one(a) {
	return fp4_is_one(a[0])
		&& fp4_is_zero(a[1])
		&& fp4_is_zero(a[2]);
}

function fp12_set_zero(a) {
	fp4_set_zero(a[0]);
	fp4_set_zero(a[1]);
	fp4_set_zero(a[2]);
}

function fp12_set_one(a) {
	fp4_set_one(a[0]);
	fp4_set_zero(a[1]);
	fp4_set_zero(a[2]);
}

function fp12_copy(r, a) {
	fp4_copy(r[0], a[0]);
	fp4_copy(r[1], a[1]);
	fp4_copy(r[2], a[2]);
}

function fp12_set(r, a0, a1, a2) {
	fp4_copy(r[0], a0);
	fp4_copy(r[1], a1);
	fp4_copy(r[2], a2);
}

function fp12_set_fp4(r, a) {
	fp4_copy(r[0], a);
	fp4_set_zero(r[1]);
	fp4_set_zero(r[2]);
}

function fp12_set_fp2(r, a) {
	fp4_set_fp2(r[0], a);
	fp4_set_zero(r[1]);
	fp4_set_zero(r[2]);
}

function fp12_set_bn(r, a) {
	fp4_set_bn(r[0], a);
	fp4_set_zero(r[1]);
	fp4_set_zero(r[2]);
}

function fp12_set_u(r) {
	fp4_set_u(r[0]);
	fp4_set_zero(r[1]);
	fp4_set_zero(r[2]);
}

function fp12_set_v(r) {
	fp4_set_v(r[0]);
	fp4_set_zero(r[1]);
	fp4_set_zero(r[2]);
}

function fp12_set_w(r) {
	fp4_set_zero(r[0]);
	fp4_set_one(r[1]);
	fp4_set_zero(r[2]);
}

function fp12_set_w_sqr(r) {
	fp4_set_zero(r[0]);
	fp4_set_zero(r[1]);
	fp4_set_one(r[2]);
}

function fp12_equ(a, b) {
	return fp4_equ(a[0], b[0])
		&& fp4_equ(a[1], b[1])
		&& fp4_equ(a[2], b[2]);
}

function fp12_add(r, a, b) {
	fp4_add(r[0], a[0], b[0]);
	fp4_add(r[1], a[1], b[1]);
	fp4_add(r[2], a[2], b[2]);
}

function fp12_dbl(r, a) {
	fp4_dbl(r[0], a[0]);
	fp4_dbl(r[1], a[1]);
	fp4_dbl(r[2], a[2]);
}

function fp12_tri(r, a) {
	let t = fp12_new();
	fp12_dbl(t, a);
	fp12_add(r, t, a);
}

function fp12_sub(r, a, b) {
	fp4_sub(r[0], a[0], b[0]);
	fp4_sub(r[1], a[1], b[1]);
	fp4_sub(r[2], a[2], b[2]);
}

function fp12_neg(r, a) {
	fp4_neg(r[0], a[0]);
	fp4_neg(r[1], a[1]);
	fp4_neg(r[2], a[2]);
}

function fp12_mul(r, a, b) {
	let r0 = fp12_new();
	let r1 = fp12_new();
	let r2 = fp12_new();
	let t = fp12_new();

	fp4_mul(r0, a[0], b[0]);
	fp4_mul_v(t, a[1], b[2]);
	fp4_add(r0, r0, t);
	fp4_mul_v(t, a[2], b[1]);
	fp4_add(r0, r0, t);

	fp4_mul(r1, a[0], b[1]);
	fp4_mul(t, a[1], b[0]);
	fp4_add(r1, r1, t);
	fp4_mul_v(t, a[2], b[2]);
	fp4_add(r1, r1, t);

	fp4_mul(r2, a[0], b[2]);
	fp4_mul(t, a[1], b[1]);
	fp4_add(r2, r2, t);
	fp4_mul(t, a[2], b[0]);
	fp4_add(r2, r2, t);

	fp4_copy(r[0], r0);
	fp4_copy(r[1], r1);
	fp4_copy(r[2], r2);
}

function fp12_sqr(r, a, b) {
	let r0 = fp12_new();
	let r1 = fp12_new();
	let r2 = fp12_new();
	let t = fp12_new();

	fp4_sqr(r0, a[0]);
	fp4_mul_v(t, a[1], a[2]);
	fp4_dbl(t, t);
	fp4_add(r0, r0, t);

	fp4_mul(r1, a[0], a[1]);
	fp4_dbl(r1, r1);
	fp4_sqr_v(t, a[2]);
	fp4_add(r1, r1, t);

	fp4_mul(r2, a[0], a[2]);
	fp4_dbl(r2, r2);
	fp4_sqr(t, a[1]);
	fp4_add(r2, r2, t);

	fp4_copy(r[0], r0);
	fp4_copy(r[1], r1);
	fp4_copy(r[2], r2);
}

function fp12_inv(r, a) {

	if (fp4_is_zero(a[2])) {
		let k = fp4_new();
		let t = fp4_new();

		fp4_sqr(k, a[0]);
		fp4_mul(k, k, a[0]);
		fp4_sqr_v(t, a[1]);
		fp4_mul(t, t, a[1]);
		fp4_add(k, k, t);
		fp4_inv(k, k);

		fp4_sqr(r[2], a[1]);
		fp4_mul(r[2], r[2], k);

		fp4_mul(r[1], a[0], a[1]);
		fp4_mul(r[1], r[1], k);
		fp4_neg(r[1], r[1]);

		fp4_sqr(r[0], a[0]);
		fp4_mul(r[0], r[0], k);

	} else {
		let t0 = fp4_new();
		let t1 = fp4_new();
		let t2 = fp4_new();
		let t3 = fp4_new();

		fp4_sqr(t0, a[1]);
		fp4_mul(t1, a[0], a[2]);
		fp4_sub(t0, t0, t1);

		fp4_mul(t1, a[0], a[1]);
		fp4_sqr_v(t2, a[2]);
		fp4_sub(t1, t1, t2);

		fp4_sqr(t2, a[0]);
		fp4_mul_v(t3, a[1], a[2]);
		fp4_sub(t2, t2, t3);

		fp4_sqr(t3, t1);
		fp4_mul(r[0], t0, t2);
		fp4_sub(t3, t3, r[0]);
		fp4_inv(t3, t3);
		fp4_mul(t3, a[2], t3);

		fp4_mul(r[0], t2, t3);

		fp4_mul(r[1], t1, t3);
		fp4_neg(r[1], r[1]);

		fp4_mul(r[2], t0, t3);
	}
}


function fp12_pow(r, a, k) {
	k %= SM9_P;
	if (k == 0n) {
		fp12_set_one(r);
		return;
	}

	let t = fp12_new();
	let kbits = k.toString(2);

	fp12_copy(t, a);
	for (let i = 1; i < kbits.length; i++) {
		fp12_sqr(t, t);
		if (kbits[i] == 1) {
			fp12_mul(t, t, a);
		}
	}
	fp12_copy(r, t);
}

function fp2_conjugate(r, a) {
	r[0] = a[0];
	r[1] = fp_neg(a[1]);
}

function fp2_frobenius(r, a) {
	return fp2_conjugate(r, a);
}

function fp4_frobenius(r, a) {
	const beta = [
		0x6c648de5dc0a3f2cf55acc93ee0baf159f9d411806dc5177f5b21fd3da24d011n,
		0n];
	fp2_conjugate(r[0], a[0]);
	fp2_conjugate(r[1], a[1]);
	fp2_mul(r[1], r[1], beta);
}

function fp4_conjugate(r, a) {
	fp2_copy(r[0], a[0]);
	fp2_neg(r[1], a[1]);
}

function fp4_frobenius2(r, a) {
	return fp4_conjugate(r, a);
}

function fp4_frobenius3(r, a) {
	const beta = [
		0x6c648de5dc0a3f2cf55acc93ee0baf159f9d411806dc5177f5b21fd3da24d011n,
		0n];
	fp2_conjugate(r[0], a[0]);
	fp2_conjugate(r[1], a[1]);
	fp2_mul(r[1], r[1], beta);
	fp2_neg(r[1], r[1]);
}

function fp12_frobenius(r, x) {
	const alpha1 = 0x3f23ea58e5720bdb843c6cfa9c08674947c5c86e0ddd04eda91d8354377b698bn;
	const alpha2 = 0xf300000002a3a6f2780272354f8b78f4d5fc11967be65334n;
	const alpha3 = 0x6c648de5dc0a3f2cf55acc93ee0baf159f9d411806dc5177f5b21fd3da24d011n;
	const alpha4 = 0xf300000002a3a6f2780272354f8b78f4d5fc11967be65333n;
	const alpha5 = 0x2d40a38cf6983351711e5f99520347cc57d778a9f8ff4c8a4c949c7fa2a96686n;

	let xa = x[0];
	let xb = x[1];
	let xc = x[2];
	let ra = fp4_new();
	let rb = fp4_new();
	let rc = fp4_new();

	fp2_conjugate(ra[0], xa[0]);
	fp2_conjugate(ra[1], xa[1]);
	fp2_mul_fp(ra[1], ra[1], alpha3);

	fp2_conjugate(rb[0], xb[0]);
	fp2_mul_fp(rb[0], rb[0], alpha1);
	fp2_conjugate(rb[1], xb[1]);
	fp2_mul_fp(rb[1], rb[1], alpha4);

	fp2_conjugate(rc[0], xc[0]);
	fp2_mul_fp(rc[0], rc[0], alpha2);
	fp2_conjugate(rc[1], xc[1]);
	fp2_mul_fp(rc[1], rc[1], alpha5);

	fp12_set(r, ra, rb, rc);
}

function fp12_frobenius2(r, x) {
	const alpha2 = 0xf300000002a3a6f2780272354f8b78f4d5fc11967be65334n;
	const alpha4 = 0xf300000002a3a6f2780272354f8b78f4d5fc11967be65333n;

	let a = fp4_new();
	let b = fp4_new();
	let c = fp4_new();

	fp4_conjugate(a, x[0]);
	fp4_conjugate(b, x[1]);
	fp4_mul_fp(b, b, alpha2);
	fp4_conjugate(c, x[2]);
	fp4_mul_fp(c, c, alpha4);

	fp4_copy(r[0], a);
	fp4_copy(r[1], b);
	fp4_copy(r[2], c);
}

function fp12_frobenius3(r, x) {
	const beta = [
		0x6c648de5dc0a3f2cf55acc93ee0baf159f9d411806dc5177f5b21fd3da24d011n,
		0n];

	let ra = fp4_new();
	let rb = fp4_new();
	let rc = fp4_new();

	let xa = x[0];
	let xb = x[1];
	let xc = x[2];

	fp2_conjugate(ra[0], xa[0]);
	fp2_conjugate(ra[1], xa[1]);
	fp2_mul(ra[1], ra[1], beta);
	fp2_neg(ra[1], ra[1]);

	fp2_conjugate(rb[0], xb[0]);
	fp2_mul(rb[0], rb[0], beta);
	fp2_conjugate(rb[1], xb[1]);

	fp2_conjugate(rc[0], xc[0]);
	fp2_neg(rc[0], rc[0]);
	fp2_conjugate(rc[1], xc[1]);
	fp2_mul(rc[1], rc[1], beta);

	fp4_copy(r[0], ra);
	fp4_copy(r[1], rb);
	fp4_copy(r[2], rc);
}

function fp12_frobenius6(r, x) {
	let a = fp4_new();
	let b = fp4_new();
	let c = fp4_new();

	fp4_copy(a, x[0]);
	fp4_copy(b, x[1]);
	fp4_copy(c, x[2]);

	fp4_conjugate(a, a);
	fp4_conjugate(b, b);
	fp4_neg(b, b);
	fp4_conjugate(c, c);

	fp4_copy(r[0], a);
	fp4_copy(r[1], b);
	fp4_copy(r[2], c);
}

function point_new() {
	let R = {
		X : 1n,
		Y : 1n,
		Z : 0n,
	}
	return R;
}

function point_set_hex(R, s) {
	R.X = fp_from_hex(s[0]);
	R.Y = fp_from_hex(s[1]);
	R.Z = fp_one();
}

function point_from_hex(s) {
	let R = point_new();
	point_set_hex(R, s);
	return R;
}

function point_copy(R, P) {
	R.X = P.X;
	R.Y = P.Y;
	R.Z = P.Z;
}

function point_is_at_infinity(P) {
	return P.Z == 0n;
}

function point_set_infinity(R) {
	R.X = 1n;
	R.Y = 1n;
	R.Z = 0n;
}

function point_get_affine(R, P) {
	point_copy(R, P);
	if (R.Z == 0 || R.Z == 1) {
		return;
	}
	R.Z = fp_inv(R.Z);
	R.Y = fp_mul(R.Y, R.Z);
	R.Z = fp_sqr(R.Z);
	R.X = fp_mul(R.X, R.Z);
	R.Y = fp_mul(R.Y, R.Z);
	R.Z = 1n;
}

function point_equ(P, Q) {
	let t1 = fp_sqr(P.Z);
	let t2 = fp_sqr(Q.Z);
	let t3 = fp_mul(P.X, t2);
	let t4 = fp_mul(Q.X, t1);
	if (t3 != t4) {
		return false;
	}
	t1 = fp_mul(t1, P.Z);
	t2 = fp_mul(t2, Q.Z);
	t3 = fp_mul(P.Y, t2);
	t4 = fp_mul(Q.Y, t1);
	return t3 == t4;
}

function point_is_on_curve(P) {
	let t0 = fp_new();
	let t1 = fp_new();
	let t2 = fp_new();

	if (fp_is_one(P.Z)) {
		t0 = fp_sqr(P.Y);
		t1 = fp_sqr(P.X);
		t1 = fp_mul(t1, P.X);
		t1 = fp_add(t1, 5n);
	} else {
		t0 = fp_sqr(P.X);
		t0 = fp_mul(t0, P.X);
		t1 = fp_sqr(P.Z);
		t2 = fp_sqr(t1);
		t1 = fp_mul(t1, t2);
		t1 = fp_mul(t1, 5n);
		t1 = fp_add(t0, t1);
		t0 = fp_sqr(P.Y);
	}

	return fp_equ(t0, t1);
}

function point_double(R, P) {
	if (point_is_at_infinity(P)) {
		return point_copy(R, P);
	}
	let X1 = P.X;
	let Y1 = P.Y;
	let Z1 = P.Z;
	let T1 = fp_new();
	let T2 = fp_new();
	let T3 = fp_new();
	let X3 = fp_new();
	let Y3 = fp_new();
	let Z3 = fp_new();

	T2 = fp_sqr(X1);
	T2 = fp_tri(T2);
	Y3 = fp_dbl(Y1);
	Z3 = fp_mul(Y3, Z1);
	Y3 = fp_sqr(Y3);
	T3 = fp_mul(Y3, X1);
	Y3 = fp_sqr(Y3);
	Y3 = fp_div2(Y3);
	X3 = fp_sqr(T2);
	T1 = fp_dbl(T3);
	X3 = fp_sub(X3, T1);
	T1 = fp_sub(T3, X3);
	T1 = fp_mul(T1, T2);
	Y3 = fp_sub(T1, Y3);

	R.X = X3;
	R.Y = Y3;
	R.Z = Z3;
}

function point_add(R, P, Q) {
	if (point_is_at_infinity(Q)) {
		point_copy(R, P);
		return;
	}
	if (point_is_at_infinity(P)) {
		point_copy(R, Q);
		return;
	}

	let X1 = P.X;
	let Y1 = P.Y;
	let Z1 = P.Z;
	let x2 = Q.X;
	let y2 = Q.Y;
	let T1 = 0n;
	let T2 = 0n;
	let T3 = 0n;
	let T4 = 0n;
	let X3 = 0n;
	let Y3 = 0n;
	let Z3 = 0n;

	T1 = fp_sqr(Z1);
	T2 = fp_mul(T1, Z1);
	T1 = fp_mul(T1, x2);
	T2 = fp_mul(T2, y2);
	T1 = fp_sub(T1, X1);
	T2 = fp_sub(T2, Y1);
	if (T1 == 0n) {
		if (T2 == 0n) {
			return point_double(R, Q);
		} else {
			return point_set_infinity(R);
		}
	}
	Z3 = fp_mul(Z1, T1);
	T3 = fp_sqr(T1);
	T4 = fp_mul(T3, T1);
	T3 = fp_mul(T3, X1);
	T1 = fp_dbl(T3);
	X3 = fp_sqr(T2);
	X3 = fp_sub(X3, T1);
	X3 = fp_sub(X3, T4);
	T3 = fp_sub(T3, X3);
	T3 = fp_mul(T3, T2);
	T4 = fp_mul(T4, Y1);
	Y3 = fp_sub(T3, T4);

	R.X = X3;
	R.Y = Y3;
	R.Z = Z3;
}

function point_sub(R, P, Q) {
	let T = point_new();
	point_neg(T, Q);
	point_add(R, P, T);
}

function point_neg(R, P) {
	R.X = P.X;
	R.Y = fp_neg(P.Y);
	R.Z = P.Z;
}

function point_mul(R, k, P) {
	let Q = point_new();
	let kbits = k.toString(2);
	for (let i = 0; i < kbits.length; i++) {
		point_double(Q, Q);
		if (kbits[i] == 1) {
			point_add(Q, Q, P);
		}
	}
	point_copy(R, Q);
}

function point_mul_G(R, k) {
	point_mul(R, k, SM9_P1)
}

function twist_point_new() {
	let R = {
		X : fp2_new(),
		Y : fp2_new(),
		Z : fp2_new(),
	};
	fp2_set_one(R.X);
	fp2_set_one(R.Y);
	fp2_set_zero(R.Z);
	return R;
}

function twist_point_set_hex(R, s) {
	fp2_set_hex(R.X, s.slice(0, 2));
	fp2_set_hex(R.Y, s.slice(2, 4));
	fp2_set_one(R.Z);
}

function twist_point_from_hex(s) {
	let R = twist_point_new();
	twist_point_set_hex(R, s);
	return R;
}

function twist_point_copy(R, P) {
	fp2_copy(R.X, P.X);
	fp2_copy(R.Y, P.Y);
	fp2_copy(R.Z, P.Z);
}

function twist_point_is_at_infinity(P) {
	return fp2_is_zero(P.Z);
}

function twist_point_set_infinity(R) {
	fp2_set_one(R.X);
	fp2_set_one(R.Y);
	fp2_set_zero(R.Z);
}

function twist_point_get_affine(R, P) {
	twist_point_copy(R, P);
	if (fp2_is_zero(R.Z) || fp2_is_one(R.Z)) {
		return;
	}
	fp2_inv(R.Z, R.Z);
	fp2_mul(R.Y, R.Y, R.Z);
	fp2_sqr(R.Z, R.Z);
	fp2_mul(R.X, R.X, R.Z);
	fp2_mul(R.Y, R.Y, R.Z);
	fp2_set_one(R.Z);
}

function twist_point_equ(P, Q) {
	let t1 = fp2_new();
	let t2 = fp2_new();
	let t3 = fp2_new();
	let t4 = fp2_new();

	fp2_sqr(t1, P.Z);
	fp2_sqr(t2, Q.Z);
	fp2_mul(t3, P.X, t2);
	fp2_mul(t4, Q.X, t1);
	if (!fp2_equ(t3, t4)) {
		return false;
	}
	fp2_mul(t1, t1, P.Z);
	fp2_mul(t2, t2, Q.Z);
	fp2_mul(t3, P.Y, t2);
	fp2_mul(t4, Q.Y, t1);
	return fp2_equ(t3, t4);
}

function twist_point_is_on_curve(P) {
	let t0 = fp2_new();
	let t1 = fp2_new();
	let t2 = fp2_new();

	if (fp2_is_one(P.Z)) {
		fp2_sqr(t0, P.Y);
		fp2_sqr(t1, P.X);
		fp2_mul(t1, t1, P.X);
		fp2_add(t1, t1, [0n, 5n]);
	} else {
		fp2_sqr(t0, P.X);
		fp2_mul(t0, t0, P.X);
		fp2_sqr(t1, P.Z);
		fp2_sqr(t2, t1);
		fp2_mul(t1, t1, t2);
		fp2_mul(t1, t1, [0n, 5n]);
		fp2_add(t1, t0, t1);
		fp2_sqr(t0, P.Y);
	}

	return fp2_equ(t0, t1);
}

function twist_point_sub(R, P, Q) {
	let T = twist_point_new();
	twist_point_neg(T, Q);
	twist_point_add(R, P, T);
}

function twist_point_neg(R, P) {
	fp2_copy(R.X, P.X);
	fp2_neg(R.Y, P.Y);
	fp2_copy(R.Z, P.Z);
}

function twist_point_double(R, P) {
	if (twist_point_is_at_infinity(P)) {
		return twist_point_copy(R, P);
	}
	let X1 = P.X;
	let Y1 = P.Y;
	let Z1 = P.Z;
	let T1 = fp2_new();
	let T2 = fp2_new();
	let T3 = fp2_new();
	let X3 = fp2_new();
	let Y3 = fp2_new();
	let Z3 = fp2_new();

	fp2_sqr(T2, X1);
	fp2_tri(T2, T2);
	fp2_dbl(Y3, Y1);
	fp2_mul(Z3, Y3, Z1);
	fp2_sqr(Y3, Y3);
	fp2_mul(T3, Y3, X1);
	fp2_sqr(Y3, Y3);
	fp2_div2(Y3, Y3);
	fp2_sqr(X3, T2);
	fp2_dbl(T1, T3);
	fp2_sub(X3, X3, T1);
	fp2_sub(T1, T3, X3);
	fp2_mul(T1, T1, T2);
	fp2_sub(Y3, T1, Y3);

	fp2_copy(R.X, X3);
	fp2_copy(R.Y, Y3);
	fp2_copy(R.Z, Z3);
}

function twist_point_add(R, P, Q) {
	if (twist_point_is_at_infinity(Q)) {
		twist_point_copy(R, P);
		return;
	}
	if (twist_point_is_at_infinity(P)) {
		twist_point_copy(R, Q);
		return;
	}

	let X1 = P.X;
	let Y1 = P.Y;
	let Z1 = P.Z;
	let x2 = Q.X;
	let y2 = Q.Y;
	let T1 = fp2_new();
	let T2 = fp2_new();
	let T3 = fp2_new();
	let T4 = fp2_new();
	let X3 = fp2_new();
	let Y3 = fp2_new();
	let Z3 = fp2_new();

	fp2_sqr(T1, Z1);
	fp2_mul(T2, T1, Z1);
	fp2_mul(T1, T1, x2);
	fp2_mul(T2, T2, y2);
	fp2_sub(T1, T1, X1);
	fp2_sub(T2, T2, Y1);
	if (fp2_is_zero(T1)) {
		if (fp2_is_zero(T2)) {
			return twist_point_double(R, Q);
		} else {
			return twist_point_set_infinity(R);
		}
	}
	fp2_mul(Z3, Z1, T1);
	fp2_sqr(T3, T1);
	fp2_mul(T4, T3, T1);
	fp2_mul(T3, T3, X1);
	fp2_dbl(T1, T3);
	fp2_sqr(X3, T2);
	fp2_sub(X3, X3, T1);
	fp2_sub(X3, X3, T4);
	fp2_sub(T3, T3, X3);
	fp2_mul(T3, T3, T2);
	fp2_mul(T4, T4, Y1);
	fp2_sub(Y3, T3, T4);

	fp2_copy(R.X, X3);
	fp2_copy(R.Y, Y3);
	fp2_copy(R.Z, Z3);
}

function twist_point_add_full(R, P, Q) {
	if (twist_point_is_at_infinity(Q)) {
		twist_point_copy(R, P);
		return;
	}
	if (twist_point_is_at_infinity(P)) {
		twist_point_copy(R, Q);
		return;
	}

	let X1 = P.X;
	let Y1 = P.Y;
	let Z1 = P.Z;
	let X2 = Q.X;
	let Y2 = Q.Y;
	let Z2 = Q.Z;
	let T1 = fp2_new();
	let T2 = fp2_new();
	let T3 = fp2_new();
	let T4 = fp2_new();
	let T5 = fp2_new();
	let T6 = fp2_new();
	let T7 = fp2_new();
	let T8 = fp2_new();

	fp2_sqr(T1, Z1);
	fp2_sqr(T2, Z2);
	fp2_mul(T3, X2, T1);
	fp2_mul(T4, X1, T2);
	fp2_add(T5, T3, T4);
	fp2_sub(T3, T3, T4);
	fp2_mul(T1, T1, Z1);
	fp2_mul(T1, T1, Y2);
	fp2_mul(T2, T2, Z2);
	fp2_mul(T2, T2, Y1);
	fp2_add(T6, T1, T2);
	fp2_sub(T1, T1, T2);

	if (fp2_is_zero(T1) && fp2_is_zero(T3)) {
		return twist_point_double(R, P);
	}
	if (fp2_is_zero(T1) && fp2_is_zero(T6)) {
		return twist_point_set_infinity(R);
	}

	fp2_sqr(T6, T1);
	fp2_mul(T7, T3, Z1);
	fp2_mul(T7, T7, Z2);
	fp2_sqr(T8, T3);
	fp2_mul(T5, T5, T8);
	fp2_mul(T3, T3, T8);
	fp2_mul(T4, T4, T8);
	fp2_sub(T6, T6, T5);
	fp2_sub(T4, T4, T6);
	fp2_mul(T1, T1, T4);
	fp2_mul(T2, T2, T3);
	fp2_sub(T1, T1, T2);

	fp2_copy(R.X, T6);
	fp2_copy(R.Y, T1);
	fp2_copy(R.Z, T7);
}

function twist_point_mul(R, k, P) {
	let Q = twist_point_new();
	let kbits = k.toString(2);
	for (let i = 0; i < kbits.length; i++) {
		twist_point_double(Q, Q);
		if (kbits[i] == 1) {
			twist_point_add(Q, Q, P);
		}
	}
	twist_point_copy(R, Q);
}

function twist_point_mul_G(R, k) {
	twist_point_mul(R, k, SM9_P2);
}

function eval_g_tangent(num, den, P, Q) {
	let XP = P.X;
	let YP = P.Y;
	let ZP = P.Z;
	let xQ = Q.X;
	let yQ = Q.Y;
	let a0 = num[0][0];
	let a1 = num[0][1];
	let a4 = num[2][0];
	let b1 = den[0][1];
	let t0 = fp2_new();
	let t1 = fp2_new();
	let t2 = fp2_new();

	fp12_set_zero(num);
	fp12_set_zero(den);

	fp2_sqr(t0, ZP);
	fp2_mul(t1, t0, ZP);
	fp2_mul(b1, t1, YP);

	fp2_mul_fp(t2, b1, yQ);
	fp2_neg(a1, t2);

	fp2_sqr(t1, XP);
	fp2_mul(t0, t0, t1);
	fp2_mul_fp(t0, t0, xQ);
	fp2_tri(t0, t0);
	fp2_div2(a4, t0);

	fp2_mul(t1, t1, XP);
	fp2_tri(t1, t1);
	fp2_div2(t1, t1);
	fp2_sqr(t0, YP);
	fp2_sub(a0, t0, t1);
}

function eval_g_line(num, den, T, P, Q) {
	let XT = T.X;
	let YT = T.Y;
	let ZT = T.Z;
	let XP = P.X;
	let YP = P.Y;
	let ZP = P.Z;
	let xQ = Q.X;
	let yQ = Q.Y;
	let a0 = num[0][0];
	let a1 = num[0][1];
	let a4 = num[2][0];
	let b1 = den[0][1];
	let T0 = fp2_new();
	let T1 = fp2_new();
	let T2 = fp2_new();
	let T3 = fp2_new();
	let T4 = fp2_new();

	fp12_set_zero(num);
	fp12_set_zero(den);

	fp2_sqr(T0, ZP);
	fp2_mul(T1, T0, XT);
	fp2_mul(T0, T0, ZP);
	fp2_sqr(T2, ZT);
	fp2_mul(T3, T2, XP);
	fp2_mul(T2, T2, ZT);
	fp2_mul(T2, T2, YP);
	fp2_sub(T1, T1, T3);
	fp2_mul(T1, T1, ZT);
	fp2_mul(T1, T1, ZP);
	fp2_mul(T4, T1, T0);
	fp2_copy(b1, T4);
	fp2_mul(T1, T1, YP);
	fp2_mul(T3, T0, YT);
	fp2_sub(T3, T3, T2);
	fp2_mul(T0, T0, T3);
	fp2_mul_fp(T0, T0, xQ);
	fp2_copy(a4, T0);
	fp2_mul(T3, T3, XP);
	fp2_mul(T3, T3, ZP);
	fp2_sub(T1, T1, T3);
	fp2_copy(a0, T1);
	fp2_mul_fp(T2, T4, yQ);
	fp2_neg(T2, T2);
	fp2_copy(a1, T2);
}

function twist_point_pi1(R, P) {
	const c = 0x3f23ea58e5720bdb843c6cfa9c08674947c5c86e0ddd04eda91d8354377b698bn;
	fp2_conjugate(R.X, P.X);
	fp2_conjugate(R.Y, P.Y);
	fp2_conjugate(R.Z, P.Z);
	fp2_mul_fp(R.Z, R.Z, c);

}

function twist_point_pi2(R, P) {
	const c = 0xf300000002a3a6f2780272354f8b78f4d5fc11967be65334n;
	fp2_copy(R.X, P.X);
	fp2_copy(R.Y, P.Y);
	fp2_mul_fp(R.Z, P.Z, c);
}

function twist_point_neg_pi2(R, P) {
	const c = 0xf300000002a3a6f2780272354f8b78f4d5fc11967be65334n;
	fp2_copy(R.X, P.X);
	fp2_neg(R.Y, P.Y);
	fp2_mul_fp(R.Z, P.Z, c);
}

function final_exponent_hard_part(r, f) {
	const a2 = 0xd8000000019062ed0000b98b0cb27659n;
	const a3 = 0x2400000000215d941n;

	let t0 = fp12_new();
	let t1 = fp12_new();
	let t2 = fp12_new();
	let t3 = fp12_new();

	fp12_pow(t0, f, a3);
	fp12_inv(t0, t0);
	fp12_frobenius(t1, t0);
	fp12_mul(t1, t0, t1);

	fp12_mul(t0, t0, t1);
	fp12_frobenius(t2, f);
	fp12_mul(t3, t2, f);
	fp12_pow(t3, t3, 9n);

	fp12_mul(t0, t0, t3);
	fp12_pow(t3, f, 4n);
	fp12_mul(t0, t0, t3);
	fp12_sqr(t2, t2);
	fp12_mul(t2, t2, t1);
	fp12_frobenius2(t1, f);
	fp12_mul(t1, t1, t2);

	fp12_pow(t2, t1, a2);
	fp12_mul(t0, t2, t0);
	fp12_frobenius3(t1, f);
	fp12_mul(t1, t1, t0);

	fp12_copy(r, t1);
}

function final_exponent(r, f) {
	let t0 = fp12_new();
	let t1 = fp12_new();

	fp12_frobenius6(t0, f);
	fp12_inv(t1, f);
	fp12_mul(t0, t0, t1);
	fp12_frobenius2(t1, t0);
	fp12_mul(t0, t0, t1);
	final_exponent_hard_part(t0, t0);

	fp12_copy(r, t0);
}

function sm9_pairing(r, Q, P) {
	const abits = '00100000000000000000000000000000000000010000101011101100100111110';

	let T = twist_point_new();
	let Q1 = twist_point_new();
	let Q2 = twist_point_new();

	let f_num = fp12_new();
	let f_den = fp12_new();
	let g_num = fp12_new();
	let g_den = fp12_new();

	twist_point_copy(T, Q);

	fp12_set_one(f_num);
	fp12_set_one(f_den);

	for (let i = 0; i < abits.length; i++) {

		fp12_sqr(f_num, f_num);
		fp12_sqr(f_den, f_den);
		eval_g_tangent(g_num, g_den, T, P);
		fp12_mul(f_num, f_num, g_num);
		fp12_mul(f_den, f_den, g_den);

		twist_point_double(T, T);

		if (abits[i] == 1) {
			eval_g_line(g_num, g_den, T, Q, P);
			fp12_mul(f_num, f_num, g_num);
			fp12_mul(f_den, f_den, g_den);
			twist_point_add(T, T, Q);
		}
	}

	twist_point_pi1(Q1, Q);
	twist_point_neg_pi2(Q2, Q);

	eval_g_line(g_num, g_den, T, Q1, P);
	fp12_mul(f_num, f_num, g_num);
	fp12_mul(f_den, f_den, g_den);
	twist_point_add_full(T, T, Q1);

	eval_g_line(g_num, g_den, T, Q2, P);
	fp12_mul(f_num, f_num, g_num);
	fp12_mul(f_den, f_den, g_den);
	twist_point_add_full(T, T, Q2);

	fp12_inv(f_den, f_den);
	fp12_mul(r, f_num, f_den);

	final_exponent(r, r);
}

function pairing_test() {

	let r = fp12_new();
	const g = [
		"aab9f06a4eeba4323a7833db202e4e35639d93fa3305af73f0f071d7d284fcfb",
		"84b87422330d7936eaba1109fa5a7a7181ee16f2438b0aeb2f38fd5f7554e57a",
		"4c744e69c4a2e1c8ed72f796d151a17ce2325b943260fc460b9f73cb57c9014b",
		"b3129a75d31d17194675a1bc56947920898fbf390a5bf5d931ce6cbb3340f66d",
		"93634f44fa13af76169f3cc8fbea880adaff8475d5fd28a75deb83c44362b439",
		"1604a3fcfa9783e667ce9fcb1062c2a5c6685c316dda62de0548baa6ba30038b",
		"5a1ae172102efd95df7338dbc577c66d8d6c15e0a0158c7507228efb078f42a6",
		"67e0e0c2eed7a6993dce28fe9aa2ef56834307860839677f96685f2b44d0911f",
		"a01f2c8bee81769609462c69c96aa923fd863e209d3ce26dd889b55e2e3873db",
		"38bffe40a22d529a0c66124b2c308dac9229912656f62b4facfced408e02380f",
		"28b3404a61908f5d6198815c99af1990c8af38655930058c28c21bb539ce0000",
		"4e378fb5561cd0668f906b731ac58fee25738edf09cadc7a29c0abc0177aea6d"];

	sm9_pairing(r, SM9_Ppubs, SM9_P1);
	console.log("test pairing: ", fp12_equ(r, fp12_from_hex(g)));
}
pairing_test();

