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


const SM2_P = [
	0xffff, 0xffff, 0xffff, 0xffff,
	0x0000, 0x0000, 0xffff, 0xffff,
	0xffff, 0xffff, 0xffff, 0xffff,
	0xffff, 0xffff, 0xfffe, 0xffff,
];

const SM2_B = [
	0x0e93, 0x4d94, 0xbd41, 0xddbc,
	0x8f92, 0x15ab, 0x89f5, 0xf397,
	0x09a7, 0xcf65, 0x9e4b, 0x4d5a,
	0x5e34, 0x9d9f, 0xfa9e, 0x28e9,
];

const SM2_G = {
	X : [
	0x74c7, 0x334c, 0x4589, 0x715a,
	0x0be1, 0xf266, 0x0bbf, 0x8fe3,
	0xc994, 0x6a39, 0x0446, 0x5f99,
	0x8119, 0x1f19, 0xae2c, 0x32c4],

	Y : [
	0xf0a0, 0x2139, 0x32e5, 0x02df,
	0x4740, 0xc62a, 0x877c, 0xd0a9,
	0x2153, 0x6b69, 0xcee3, 0x59bd,
	0x779c, 0xf4f6, 0x36a2, 0xbc37],

	Z: [
	1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
};

const SM2_N = [
	0x4123, 0x39d5, 0xf409, 0x53bb,
	0x052b, 0x21c6, 0xdf6b, 0x7203,
	0xffff, 0xffff,	0xffff,	0xffff,
	0xffff,	0xffff,	0xfffe,	0xffff,
];

function bn_new() {
	return [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
}

function bn_free(a) {
	bn_set_zero(a);
	delete a;
}

function bn_is_zero(a) {
	for (var i = 0; i < 16; i++) {
		if (a[i] != 0)
			return 0;
	}
	return 1;
}

function bn_is_one(a) {
	if (a[0] != 1)
		return 0;
	for (var i = 1; i < 16; i++) {
		if (a[i] != 0)
			return 0;
	}
	return 1;
}

function bn_to_bytes(a, buf, offset) {
	for (var i = 15; i >= 0; i--) {
		buf[offset++] = Math.floor(a[i]/256);
		buf[offset++] = a[i] % 256;
	}
}

function bn_set_bytes(a, buf, offset) {
	for (var i = 15; i >= 0; i--) {
		a[i] = buf[offset++] * 256;
		a[i] += buf[offset++];
	}
}

function bn_cmp(a, b) {
	for (var i = 15; i >= 0; i--) {
		if (a[i] > b[i])
			return 1;
		if (a[i] < b[i])
			return -1;
	}
	return 0;
}

function bn_set_word(a, word) {
	a[0] = word;
	for (var i = 1; i < 16; i++) {
		a[i] = 0;
	}
}

function bn_set_zero(a) {
	bn_set_word(a, 0);
}

function bn_set_one(a) {
	bn_set_word(a, 1);
}

function bn_copy(r, a) {
	for (var i = 0; i < 16; i++) {
		r[i] = a[i];
	}
}

function bn_to_bits(a) {
	var bits = new Array(256);
	for (var i = 0; i < 16; i++) {
		var w = a[i];
		for (var j = 0; j < 16; j++) {
			bits[i*16 + j] = w % 2;
			w = Math.floor(w/2);
		}
	}
	return bits.reverse();
}

function bn_add(r, a, b) {
	r[0] = a[0] + b[0];
	for (var i = 1; i < 16; i++) {
		r[i] = a[i] + b[i] + Math.floor(r[i-1] / 65536);
	}
	for (var i = 0; i < 15; i++) {
		r[i] %= 65536;
	}
}

function bn_sub(r, a, b) {
	var borrow = 0;
	for (var i = 0; i < 16; i++) {
		r[i] = a[i] - b[i] - borrow;
		borrow = 0;
		if (r[i] < 0) {
			r[i] += 65536;
			borrow = 1;
		}
	}
}

function fp_add(r, a, b) {
	bn_add(r,  a, b);
	if (bn_cmp(r, SM2_P) >= 0) {
		return bn_sub(r, r, SM2_P);
	}
}

function fp_sub(r, a, b) {
	if (bn_cmp(a, b) >= 0) {
		bn_sub(r, a, b);
	} else {
		// FIXME:  remove t,
		// it need there is no fp_sub(b, a, b)
		// which is used in point_double()
		var t = bn_new();
		bn_add(t, a, SM2_P);
		bn_sub(r, t, b);
	}
}

function fp_dbl(r, a) {
	return fp_add(r, a, a);
}

function fp_tri(r, a) {
	var t = bn_new();
	fp_dbl(t, a);
	fp_add(r, t, a);
}

function fp_div2(r, a) {
	bn_copy(r, a);
	if (r[0] % 2) {
		bn_add(r, r, SM2_P);
	}

	var i;
	for (i = 0; i < 15; i++) {
		r[i] = Math.floor(r[i] / 2);
		r[i] += (r[i + 1] % 2) * 32768;
	}
	r[i] = Math.floor(r[i] / 2);
}

function fp_neg(r, a) {
	if (bn_is_zero(a)) {
		bn_set_zero(r);
	} else {
		bn_sub(r, SM2_P, a);
	}
}

function fp_mul(r, a, b) {
	var ab = [
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	]
	for (var i = 0; i < 16; i++) {
		for (var j = 0; j < 16; j++) {
			ab[i + j] += a[i] * b[j];
		}
	}
	for (var i = 0; i < 31; i++) {
		ab[i + 1] += Math.floor(ab[i] / 65536);
		ab[i] = ab[i] % 65536;
	}
	s = ab.slice(16, 32);

	r[ 0] = ab[ 0] + s[0] + s[ 2] + s[ 4] + s[ 6] + s[ 8] + 2 * (s[10] + s[12] + s[14]);
	r[ 1] = ab[ 1] + s[1] + s[ 3] + s[ 5] + s[ 7] + s[ 9] + 2 * (s[11] + s[13] + s[15]);
	r[ 2] = ab[ 2] + s[2] + s[ 4] + s[ 6] + s[ 8] + s[10] + 2 * (s[12] + s[14]);
	r[ 3] = ab[ 3] + s[3] + s[ 5] + s[ 7] + s[ 9] + s[11] + 2 * (s[13] + s[15]);
	r[ 4] = ab[ 4];
	r[ 5] = ab[ 5];
	r[ 6] = ab[ 6] + s[0] + s[ 6] + s[ 8] + s[12] + s[14] + 2 * s[10];
	r[ 7] = ab[ 7] + s[1] + s[ 7] + s[ 9] + s[13] + s[15] + 2 * s[11];
	r[ 8] = ab[ 8] + s[2] + s[ 8] + s[10] + s[14]         + 2 * s[12];
	r[ 9] = ab[ 9] + s[3] + s[ 9] + s[11] + s[15]         + 2 * s[13];
	r[10] = ab[10] + s[4] + s[10] + s[12]                 + 2 * s[14];
	r[11] = ab[11] + s[5] + s[11] + s[13]                 + 2 * s[15];
	r[12] = ab[12] + s[6] + s[12] + s[14];
	r[13] = ab[13] + s[7] + s[13] + s[15];
	r[14] = ab[14] + s[0] + s[ 2] + s[ 4] + s[ 6] + s[14] + 2 * (s[8] + s[10] + s[12] + s[14]);
	r[15] = ab[15] + s[1] + s[ 3] + s[ 5] + s[ 7] + s[15] + 2 * (s[9] + s[11] + s[13] + s[15]);

	for (var i = 0; i < 15; i++) {
		r[i + 1] += Math.floor(r[i] / 65536);
		r[i] %= 65536
	}

	var d = [0,0,0,0,s[0]+s[2]+s[10]+s[12],s[1]+s[3]+s[11]+s[13],0,0,0,0,0,0,0,0,0,0];
	for (var i = 0; i < 15; i++) {
		d[i + 1] += Math.floor(d[i] / 65536);
		d[i] %= 65536
	}

	bn_sub(r, r, d);

	while (bn_cmp(r, SM2_P) >= 0) {
		bn_sub(r, r, SM2_P);
	}
}

function fp_sqr(r, a) {
	fp_mul(r, a, a);
}

function fp_inv(r, a) {
	var a1 = bn_new();
	var a2 = bn_new();
	var a3 = bn_new();
	var a4 = bn_new();
	var a5 = bn_new();

	fp_sqr(a1, a);
	fp_mul(a2, a1, a);
	fp_sqr(a3, a2);
	fp_sqr(a3, a3);
	fp_mul(a3, a3, a2);
	fp_sqr(a4, a3);
	fp_sqr(a4, a4);
	fp_sqr(a4, a4);
	fp_sqr(a4, a4);
	fp_mul(a4, a4, a3);
	fp_sqr(a5, a4);
	for (i = 1; i < 8; i++)
		fp_sqr(a5, a5);
	fp_mul(a5, a5, a4);
	for (i = 0; i < 8; i++)
		fp_sqr(a5, a5);
	fp_mul(a5, a5, a4);
	for (i = 0; i < 4; i++)
		fp_sqr(a5, a5);
	fp_mul(a5, a5, a3);
	fp_sqr(a5, a5);
	fp_sqr(a5, a5);
	fp_mul(a5, a5, a2);
	fp_sqr(a5, a5);
	fp_mul(a5, a5, a);
	fp_sqr(a4, a5);
	fp_mul(a3, a4, a1);
	fp_sqr(a5, a4);
	for (i = 1; i< 31; i++)
		fp_sqr(a5, a5);
	fp_mul(a4, a5, a4);
	fp_sqr(a4, a4);
	fp_mul(a4, a4, a);
	fp_mul(a3, a4, a2);
	for (i = 0; i < 33; i++)
		fp_sqr(a5, a5);
	fp_mul(a2, a5, a3);
	fp_mul(a3, a2, a3);
	for (i = 0; i < 32; i++)
		fp_sqr(a5, a5);
	fp_mul(a2, a5, a3);
	fp_mul(a3, a2, a3);
	fp_mul(a4, a2, a4);
	for (i = 0; i < 32; i++)
		fp_sqr(a5, a5);
	fp_mul(a2, a5, a3);
	fp_mul(a3, a2, a3);
	fp_mul(a4, a2, a4);
	for (i = 0; i < 32; i++)
		fp_sqr(a5, a5);
	fp_mul(a2, a5, a3);
	fp_mul(a3, a2, a3);
	fp_mul(a4, a2, a4);
	for (i = 0; i < 32; i++)
		fp_sqr(a5, a5);
	fp_mul(a2, a5, a3);
	fp_mul(a3, a2, a3);
	fp_mul(a4, a2, a4);
	for (i = 0; i < 32; i++)
		fp_sqr(a5, a5)
	fp_mul(r, a4, a5);

	bn_free(a1);
	bn_free(a2);
	bn_free(a3);
	bn_free(a4);
	bn_free(a5);
}

function sm2_point_new() {
	var point = {
		X : [1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
		Y : [1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
		Z : [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
	}
	return point;
}

function sm2_point_free(P) {
	bn_set_zero(P.X);
	bn_set_zero(P.Y);
	bn_set_zero(P.Z);
	delete P;
}

function sm2_point_copy(R, P) {
	bn_copy(R.X, P.X);
	bn_copy(R.Y, P.Y);
	bn_copy(R.Z, P.Z);
}

function sm2_point_is_at_infinity(P) {
	return bn_is_zero(P.Z);
}

function sm2_point_set_infinity(R) {
	bn_set_one(R.X);
	bn_set_one(R.Y);
	bn_set_zero(R.Z);
}

function sm2_point_get_affine(R, P) {
	sm2_point_copy(R, P);
	if (bn_is_zero(R.Z) || bn_is_one(R.Z))
		return;
	fp_inv(R.Z, R.Z);
	fp_mul(R.Y, R.Y, R.Z);
	fp_sqr(R.Z, R.Z);
	fp_mul(R.X, R.X, R.Z);
	fp_mul(R.Y, R.Y, R.Z);
	bn_set_one(R.Z);
}

function sm2_point_set_bytes(P, buf, offset) {
	bn_set_bytes(P.X, buf, offset);
	bn_set_bytes(P.Y, buf, offset + 32);
	bn_set_one(P.Z);
}

function sm2_point_to_bytes(P, buf, offset) {
	var A = sm2_point_new();
	sm2_point_get_affine(A, P);
	bn_to_bytes(A.X, buf, offset);
	bn_to_bytes(A.Y, buf, offset + 32);
}

function sm2_point_is_on_curve(P) {
	var t0 = bn_new();
	var t1 = bn_new();
	var t2 = bn_new();

	if (bn_is_one(P.Z)) {
		fp_sqr(t0, P.Y);
		fp_add(t0, t0, P.X);
		fp_add(t0, t0, P.X);
		fp_add(t0, t0, P.X);
		fp_sqr(t1, P.X);
		fp_mul(t1, t1, P.X);
		fp_add(t1, t1, SM2_B);
	} else {
		fp_sqr(t0, P.Y);
		fp_sqr(t1, P.Z);
		fp_sqr(t2, t1);
		fp_mul(t1, t1, t2);
		fp_mul(t1, t1, SM2_B);
		fp_mul(t2, t2, P.X);
		fp_add(t0, t0, t2);
		fp_add(t0, t0, t2);
		fp_add(t0, t0, t2);
		fp_sqr(t2, P.X);
		fp_mul(t2, t2, P.X);
		fp_add(t1, t1, t2);
	}

	return (bn_cmp(t0, t1) == 0);
}

function sm2_point_neg(R, P) {
	bn_copy(R.X, P.X);
	fp_neg(R.Y, P.Y);
	bn_copy(R.Z, P.Z);
}

function sm2_point_double(R, P) {
	if (sm2_point_is_at_infinity(P)) {
		return sm2_point_copy(R, P);
	}
	var X1 = P.X;
	var Y1 = P.Y;
	var Z1 = P.Z;
	var T1 = bn_new();
	var T2 = bn_new();
	var T3 = bn_new();
	var X3 = bn_new();
	var Y3 = bn_new();
	var Z3 = bn_new();

	fp_sqr(T1, Z1);
	fp_sub(T2, X1, T1);
	fp_add(T1, X1, T1);
	fp_mul(T2, T2, T1);
	fp_tri(T2, T2);
	fp_dbl(Y3, Y1);
	fp_mul(Z3, Y3, Z1);
	fp_sqr(Y3, Y3);
	fp_mul(T3, Y3, X1);
	fp_sqr(Y3, Y3);
	fp_div2(Y3, Y3);
	fp_sqr(X3, T2);
	fp_dbl(T1, T3);
	fp_sub(X3, X3, T1);
	fp_sub(T1, T3, X3);
	fp_mul(T1, T1, T2);
	fp_sub(Y3, T1, Y3);

	bn_copy(R.X, X3);
	bn_copy(R.Y, Y3);
	bn_copy(R.Z, Z3);
}

function sm2_point_add(R, P, Q) {
	if (sm2_point_is_at_infinity(Q)) {
		sm2_point_copy(R, P);
		return;
	}
	if (sm2_point_is_at_infinity(P)) {
		sm2_point_copy(R, Q);
		return;
	}

	var X1 = P.X;
	var Y1 = P.Y;
	var Z1 = P.Z;
	var x2 = Q.X;
	var y2 = Q.Y;
	var T1 = bn_new();
	var T2 = bn_new();
	var T3 = bn_new();
	var T4 = bn_new();
	var X3 = bn_new();
	var Y3 = bn_new();
	var Z3 = bn_new();

	fp_sqr(T1, Z1);
	fp_mul(T2, T1, Z1);
	fp_mul(T1, T1, x2);
	fp_mul(T2, T2, y2);
	fp_sub(T1, T1, X1);
	fp_sub(T2, T2, Y1);
	if (bn_is_zero(T1)) {
		if (bn_is_zero(T2)) {
			return sm2_point_double(R, Q);
		} else {
			return sm2_point_set_infinity(R);
		}
	}
	fp_mul(Z3, Z1, T1);
	fp_sqr(T3, T1);
	fp_mul(T4, T3, T1);
	fp_mul(T3, T3, X1);
	fp_dbl(T1, T3);
	fp_sqr(X3, T2);
	fp_sub(X3, X3, T1);
	fp_sub(X3, X3, T4);
	fp_sub(T3, T3, X3);
	fp_mul(T3, T3, T2);
	fp_mul(T4, T4, Y1);
	fp_sub(Y3, T3, T4);

	bn_copy(R.X, X3);
	bn_copy(R.Y, Y3);
	bn_copy(R.Z, Z3);
}

function sm2_point_mul(R, k, P) {
	var bits = bn_to_bits(k);
	var Q = sm2_point_new();

	for (var i = 0; i < bits.length; i++) {
		sm2_point_double(Q, Q);

		if (bits[i] == 1) {
			sm2_point_add(Q, Q, P);
		}
	}
	sm2_point_copy(R, Q);
}

function sm2_point_mul_G(R, k) {
	return sm2_point_mul(R, k, SM2_G);
}


function sm2_sig_new() {
	var sig = {
		r: bn_new(),
		s: bn_new(),
	};
	return sig;
}

function sm2_do_verify(dgst, sig, P) {

	if (dgst.length < 32
		|| bn_is_zero(sig.r)
		|| bn_cmp(sig.r, SM2_N) >= 0
		|| bn_is_zero(sig.s)
		|| bn_cmp(sig.s, SM2_N) >= 0) {
		return false;
	}

	var e = bn_new();

	bn_set_bytes(e, dgst, 0);
	if (bn_cmp(e, SM2_N) >= 0) {
		bn_sub(e, e, SM2_N);
	}

	var t = bn_new();
	bn_add(t, sig.r, sig.s);
	if (bn_cmp(t, SM2_N) == 0) {
		return false;
	}

	var Q1 = sm2_point_new();
	var Q2 = sm2_point_new();

	sm2_point_mul_G(Q1, s1);
	sm2_point_mul(Q2, t, P);
	sm2_point_add(Q1, Q1, Q2);
	sm2_point_get_affine(Q1, Q1);

	bn_add(e, e, Q1.X);
	if (bn_cmp(e, SM2_N)) {
		bn_sub(e, e, SM2_N);
	}
	if (bn_cmp(e, SM2_N)) {
		bn_sub(e, e, SM2_N);
	}

	return bn_cmp(e, sig.r) == 0;
}

function sm2_point_test() {

	var P = sm2_point_new();

	/*
	sm2_point_double(P, SM2_G);
	sm2_point_double(P, P);
	sm2_point_add(P, P, SM2_G);
	sm2_point_get_affine(P, P);
	console.log(P);
	*/

	var k = bn_new();
	bn_set_word(k, 11);

	console.log("mul");
	sm2_point_mul(P, SM2_B, SM2_G);
	sm2_point_get_affine(P, P);

	console.log(P.X);
	console.log(P.Y);
	console.log(P.Z);
}
