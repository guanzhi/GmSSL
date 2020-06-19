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


function sm4_memcpy(dst, dst_offset, src, src_offset, len) {
	while (len--) {
		dst[dst_offset++] = src[src_offset++];
	}
}

function SM4_GETU32(data, offset) {
	return ((data[offset] << 24)
		| (data[offset + 1] << 16)
		| (data[offset + 2] << 8)
		| data[offset + 3]) >>> 0;
}

function SM4_PUTU32(data, offset, value) {
	data[offset + 3] = (value & 0xff) >>> 0;
	value >>>= 8;
	data[offset + 2] = (value & 0xff) >>> 0;
	value >>>= 8;
	data[offset + 1] = (value & 0xff) >>> 0;
	value >>>= 8;
	data[offset] = (value & 0xff) >>> 0;
}

const SM4_KEY_LENGTH = 16
const SM4_BLOCK_SIZE = 16
const SM4_IV_LENGTH = SM4_BLOCK_SIZE
const SM4_NUM_ROUNDS = 32

const SM4_S = [
	0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7,
	0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
	0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3,
	0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
	0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a,
	0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
	0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95,
	0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
	0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
	0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
	0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b,
	0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
	0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2,
	0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
	0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
	0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
	0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5,
	0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
	0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55,
	0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
	0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
	0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
	0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f,
	0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
	0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f,
	0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
	0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
	0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
	0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e,
	0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
	0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20,
	0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
];

const SM4_FK = [
	0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc,
];

const SM4_CK = [
	0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
	0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
	0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
	0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
	0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
	0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
	0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
	0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
];

function SM4_ROL32(x, n) {
	return ((x << n) | (x >>> (32 - n))) >>> 0;
}

function SM4_S32(A) {
	return (
		(SM4_S[A >>> 24] << 24) ^
		(SM4_S[(A >>> 16) & 0xff] << 16) ^
		(SM4_S[(A >>> 8) & 0xff] << 8) ^
		(SM4_S[A & 0xff])) >>> 0;
}

function SM4_L32(x) {
	return (
		x ^
		SM4_ROL32(x, 2) ^
		SM4_ROL32(x, 10) ^
		SM4_ROL32(x, 18) ^
		SM4_ROL32(x, 24)) >>> 0;
}

function SM4_L32_(x) {
	return (
		x ^
		SM4_ROL32(x, 13) ^
		SM4_ROL32(x, 23)) >>> 0;
}


function sm4_key_new() {
	var key = {
		rk: new Array(SM4_NUM_ROUNDS),
	};
	return key;
}

function sm4_key_free(key) {
	for (var i = 0; i < SM4_NUM_ROUNDS; i++) {
		key.rk[i] = 0;
	}
	delete key;
}

function sm4_set_encrypt_key(key, user_key) {
	var x0, x1, x2, x3, x4;
	x0 = SM4_GETU32(user_key,  0) ^ SM4_FK[0];
	x1 = SM4_GETU32(user_key,  4) ^ SM4_FK[1];
	x2 = SM4_GETU32(user_key,  8) ^ SM4_FK[2];
	x3 = SM4_GETU32(user_key, 12) ^ SM4_FK[3];
	key.rk[ 0] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[ 0]))) >>> 0;
	key.rk[ 1] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[ 1]))) >>> 0;
	key.rk[ 2] = x1 = (x2 ^ SM4_L32_(SM4_S32(x3 ^ x4 ^ x0 ^ SM4_CK[ 2]))) >>> 0;
	key.rk[ 3] = x2 = (x3 ^ SM4_L32_(SM4_S32(x4 ^ x0 ^ x1 ^ SM4_CK[ 3]))) >>> 0;
	key.rk[ 4] = x3 = (x4 ^ SM4_L32_(SM4_S32(x0 ^ x1 ^ x2 ^ SM4_CK[ 4]))) >>> 0;
	key.rk[ 5] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[ 5]))) >>> 0;
	key.rk[ 6] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[ 6]))) >>> 0;
	key.rk[ 7] = x1 = (x2 ^ SM4_L32_(SM4_S32(x3 ^ x4 ^ x0 ^ SM4_CK[ 7]))) >>> 0;
	key.rk[ 8] = x2 = (x3 ^ SM4_L32_(SM4_S32(x4 ^ x0 ^ x1 ^ SM4_CK[ 8]))) >>> 0;
	key.rk[ 9] = x3 = (x4 ^ SM4_L32_(SM4_S32(x0 ^ x1 ^ x2 ^ SM4_CK[ 9]))) >>> 0;
	key.rk[10] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[10]))) >>> 0;
	key.rk[11] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[11]))) >>> 0;
	key.rk[12] = x1 = (x2 ^ SM4_L32_(SM4_S32(x3 ^ x4 ^ x0 ^ SM4_CK[12]))) >>> 0;
	key.rk[13] = x2 = (x3 ^ SM4_L32_(SM4_S32(x4 ^ x0 ^ x1 ^ SM4_CK[13]))) >>> 0;
	key.rk[14] = x3 = (x4 ^ SM4_L32_(SM4_S32(x0 ^ x1 ^ x2 ^ SM4_CK[14]))) >>> 0;
	key.rk[15] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[15]))) >>> 0;
	key.rk[16] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[16]))) >>> 0;
	key.rk[17] = x1 = (x2 ^ SM4_L32_(SM4_S32(x3 ^ x4 ^ x0 ^ SM4_CK[17]))) >>> 0;
	key.rk[18] = x2 = (x3 ^ SM4_L32_(SM4_S32(x4 ^ x0 ^ x1 ^ SM4_CK[18]))) >>> 0;
	key.rk[19] = x3 = (x4 ^ SM4_L32_(SM4_S32(x0 ^ x1 ^ x2 ^ SM4_CK[19]))) >>> 0;
	key.rk[20] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[20]))) >>> 0;
	key.rk[21] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[21]))) >>> 0;
	key.rk[22] = x1 = (x2 ^ SM4_L32_(SM4_S32(x3 ^ x4 ^ x0 ^ SM4_CK[22]))) >>> 0;
	key.rk[23] = x2 = (x3 ^ SM4_L32_(SM4_S32(x4 ^ x0 ^ x1 ^ SM4_CK[23]))) >>> 0;
	key.rk[24] = x3 = (x4 ^ SM4_L32_(SM4_S32(x0 ^ x1 ^ x2 ^ SM4_CK[24]))) >>> 0;
	key.rk[25] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[25]))) >>> 0;
	key.rk[26] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[26]))) >>> 0;
	key.rk[27] = x1 = (x2 ^ SM4_L32_(SM4_S32(x3 ^ x4 ^ x0 ^ SM4_CK[27]))) >>> 0;
	key.rk[28] = x2 = (x3 ^ SM4_L32_(SM4_S32(x4 ^ x0 ^ x1 ^ SM4_CK[28]))) >>> 0;
	key.rk[29] = x3 = (x4 ^ SM4_L32_(SM4_S32(x0 ^ x1 ^ x2 ^ SM4_CK[29]))) >>> 0;
	key.rk[30] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[30]))) >>> 0;
	key.rk[31] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[31]))) >>> 0;
	x0 = x1 = x3 = x3 = x4 = 0;
}

function sm4_set_decrypt_key(key, user_key) {
	var x0, x1, x2, x3, x4;
	x0 = SM4_GETU32(user_key,  0) ^ SM4_FK[0];
	x1 = SM4_GETU32(user_key,  4) ^ SM4_FK[1];
	x2 = SM4_GETU32(user_key,  8) ^ SM4_FK[2];
	x3 = SM4_GETU32(user_key, 12) ^ SM4_FK[3];
	key.rk[31] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[ 0]))) >>> 0;
	key.rk[30] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[ 1]))) >>> 0;
	key.rk[29] = x1 = (x2 ^ SM4_L32_(SM4_S32(x3 ^ x4 ^ x0 ^ SM4_CK[ 2]))) >>> 0;
	key.rk[28] = x2 = (x3 ^ SM4_L32_(SM4_S32(x4 ^ x0 ^ x1 ^ SM4_CK[ 3]))) >>> 0;
	key.rk[27] = x3 = (x4 ^ SM4_L32_(SM4_S32(x0 ^ x1 ^ x2 ^ SM4_CK[ 4]))) >>> 0;
	key.rk[26] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[ 5]))) >>> 0;
	key.rk[25] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[ 6]))) >>> 0;
	key.rk[24] = x1 = (x2 ^ SM4_L32_(SM4_S32(x3 ^ x4 ^ x0 ^ SM4_CK[ 7]))) >>> 0;
	key.rk[23] = x2 = (x3 ^ SM4_L32_(SM4_S32(x4 ^ x0 ^ x1 ^ SM4_CK[ 8]))) >>> 0;
	key.rk[22] = x3 = (x4 ^ SM4_L32_(SM4_S32(x0 ^ x1 ^ x2 ^ SM4_CK[ 9]))) >>> 0;
	key.rk[21] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[10]))) >>> 0;
	key.rk[20] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[11]))) >>> 0;
	key.rk[19] = x1 = (x2 ^ SM4_L32_(SM4_S32(x3 ^ x4 ^ x0 ^ SM4_CK[12]))) >>> 0;
	key.rk[18] = x2 = (x3 ^ SM4_L32_(SM4_S32(x4 ^ x0 ^ x1 ^ SM4_CK[13]))) >>> 0;
	key.rk[17] = x3 = (x4 ^ SM4_L32_(SM4_S32(x0 ^ x1 ^ x2 ^ SM4_CK[14]))) >>> 0;
	key.rk[16] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[15]))) >>> 0;
	key.rk[15] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[16]))) >>> 0;
	key.rk[14] = x1 = (x2 ^ SM4_L32_(SM4_S32(x3 ^ x4 ^ x0 ^ SM4_CK[17]))) >>> 0;
	key.rk[13] = x2 = (x3 ^ SM4_L32_(SM4_S32(x4 ^ x0 ^ x1 ^ SM4_CK[18]))) >>> 0;
	key.rk[12] = x3 = (x4 ^ SM4_L32_(SM4_S32(x0 ^ x1 ^ x2 ^ SM4_CK[19]))) >>> 0;
	key.rk[11] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[20]))) >>> 0;
	key.rk[10] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[21]))) >>> 0;
	key.rk[ 9] = x1 = (x2 ^ SM4_L32_(SM4_S32(x3 ^ x4 ^ x0 ^ SM4_CK[22]))) >>> 0;
	key.rk[ 8] = x2 = (x3 ^ SM4_L32_(SM4_S32(x4 ^ x0 ^ x1 ^ SM4_CK[23]))) >>> 0;
	key.rk[ 7] = x3 = (x4 ^ SM4_L32_(SM4_S32(x0 ^ x1 ^ x2 ^ SM4_CK[24]))) >>> 0;
	key.rk[ 6] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[25]))) >>> 0;
	key.rk[ 5] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[26]))) >>> 0;
	key.rk[ 4] = x1 = (x2 ^ SM4_L32_(SM4_S32(x3 ^ x4 ^ x0 ^ SM4_CK[27]))) >>> 0;
	key.rk[ 3] = x2 = (x3 ^ SM4_L32_(SM4_S32(x4 ^ x0 ^ x1 ^ SM4_CK[28]))) >>> 0;
	key.rk[ 2] = x3 = (x4 ^ SM4_L32_(SM4_S32(x0 ^ x1 ^ x2 ^ SM4_CK[29]))) >>> 0;
	key.rk[ 1] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[30]))) >>> 0;
	key.rk[ 0] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[31]))) >>> 0;
	x0 = x1 = x3 = x3 = x4 = 0;
}

function sm4_encrypt(inbuf, in_offset, outbuf, out_offset, key) {
	var x0, x1, x2, x3, x4;
	x0 = SM4_GETU32(inbuf, in_offset);
	x1 = SM4_GETU32(inbuf, in_offset + 4);
	x2 = SM4_GETU32(inbuf, in_offset + 8);
	x3 = SM4_GETU32(inbuf, in_offset + 12);
	x4 = x0 ^ SM4_L32(SM4_S32(x1 ^ x2 ^ x3 ^ key.rk[0]));
	x0 = x1 ^ SM4_L32(SM4_S32(x2 ^ x3 ^ x4 ^ key.rk[1]));
	x1 = x2 ^ SM4_L32(SM4_S32(x3 ^ x4 ^ x0 ^ key.rk[2]));
	x2 = x3 ^ SM4_L32(SM4_S32(x4 ^ x0 ^ x1 ^ key.rk[3]));
	x3 = x4 ^ SM4_L32(SM4_S32(x0 ^ x1 ^ x2 ^ key.rk[4]));
	x4 = x0 ^ SM4_L32(SM4_S32(x1 ^ x2 ^ x3 ^ key.rk[5]));
	x0 = x1 ^ SM4_L32(SM4_S32(x2 ^ x3 ^ x4 ^ key.rk[6]));
	x1 = x2 ^ SM4_L32(SM4_S32(x3 ^ x4 ^ x0 ^ key.rk[7]));
	x2 = x3 ^ SM4_L32(SM4_S32(x4 ^ x0 ^ x1 ^ key.rk[8]));
	x3 = x4 ^ SM4_L32(SM4_S32(x0 ^ x1 ^ x2 ^ key.rk[9]));
	x4 = x0 ^ SM4_L32(SM4_S32(x1 ^ x2 ^ x3 ^ key.rk[10]));
	x0 = x1 ^ SM4_L32(SM4_S32(x2 ^ x3 ^ x4 ^ key.rk[11]));
	x1 = x2 ^ SM4_L32(SM4_S32(x3 ^ x4 ^ x0 ^ key.rk[12]));
	x2 = x3 ^ SM4_L32(SM4_S32(x4 ^ x0 ^ x1 ^ key.rk[13]));
	x3 = x4 ^ SM4_L32(SM4_S32(x0 ^ x1 ^ x2 ^ key.rk[14]));
	x4 = x0 ^ SM4_L32(SM4_S32(x1 ^ x2 ^ x3 ^ key.rk[15]));
	x0 = x1 ^ SM4_L32(SM4_S32(x2 ^ x3 ^ x4 ^ key.rk[16]));
	x1 = x2 ^ SM4_L32(SM4_S32(x3 ^ x4 ^ x0 ^ key.rk[17]));
	x2 = x3 ^ SM4_L32(SM4_S32(x4 ^ x0 ^ x1 ^ key.rk[18]));
	x3 = x4 ^ SM4_L32(SM4_S32(x0 ^ x1 ^ x2 ^ key.rk[19]));
	x4 = x0 ^ SM4_L32(SM4_S32(x1 ^ x2 ^ x3 ^ key.rk[20]));
	x0 = x1 ^ SM4_L32(SM4_S32(x2 ^ x3 ^ x4 ^ key.rk[21]));
	x1 = x2 ^ SM4_L32(SM4_S32(x3 ^ x4 ^ x0 ^ key.rk[22]));
	x2 = x3 ^ SM4_L32(SM4_S32(x4 ^ x0 ^ x1 ^ key.rk[23]));
	x3 = x4 ^ SM4_L32(SM4_S32(x0 ^ x1 ^ x2 ^ key.rk[24]));
	x4 = x0 ^ SM4_L32(SM4_S32(x1 ^ x2 ^ x3 ^ key.rk[25]));
	x0 = x1 ^ SM4_L32(SM4_S32(x2 ^ x3 ^ x4 ^ key.rk[26]));
	x1 = x2 ^ SM4_L32(SM4_S32(x3 ^ x4 ^ x0 ^ key.rk[27]));
	x2 = x3 ^ SM4_L32(SM4_S32(x4 ^ x0 ^ x1 ^ key.rk[28]));
	x3 = x4 ^ SM4_L32(SM4_S32(x0 ^ x1 ^ x2 ^ key.rk[29]));
	x4 = x0 ^ SM4_L32(SM4_S32(x1 ^ x2 ^ x3 ^ key.rk[30]));
	x0 = x1 ^ SM4_L32(SM4_S32(x2 ^ x3 ^ x4 ^ key.rk[31]));
	SM4_PUTU32(outbuf, out_offset, x0);
	SM4_PUTU32(outbuf, out_offset + 4, x4);
	SM4_PUTU32(outbuf, out_offset + 8, x3);
	SM4_PUTU32(outbuf, out_offset + 12, x2);
}

function sm4_decrypt(inbuf, in_offset, outbuf, out_offset, key) {
	return sm4_encrypt(inbuf, in_offset, outbuf, out_offset, key);
}

function sm4_test() {
	const user_key = [
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	];
	const rk = [
		0xf12186f9, 0x41662b61, 0x5a6ab19a, 0x7ba92077,
		0x367360f4, 0x776a0c61, 0xb6bb89b3, 0x24763151,
		0xa520307c, 0xb7584dbd, 0xc30753ed, 0x7ee55b57,
		0x6988608c, 0x30d895b7, 0x44ba14af, 0x104495a1,
		0xd120b428, 0x73b55fa3, 0xcc874966, 0x92244439,
		0xe89e641f, 0x98ca015a, 0xc7159060, 0x99e1fd2e,
		0xb79bd80c, 0x1d2115b0, 0x0e228aeb, 0xf1780c81,
		0x428d3654, 0x62293496, 0x01cf72e5, 0x9124a012,
	];
	const plaintext = [
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	];
	const ciphertext = [
		0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
		0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46,
	];
	const ciphertext2 = [
		0x59, 0x52, 0x98, 0xc7, 0xc6, 0xfd, 0x27, 0x1f,
		0x04, 0x02, 0xf8, 0x04, 0xc3, 0x3d, 0x3f, 0x66,
	];

	var key = sm4_key_new();
	var buf = new Array(SM4_BLOCK_SIZE);

	sm4_set_encrypt_key(key, user_key);

	for (var i = 0; i < SM4_NUM_ROUNDS; i++) {
		if (key.rk[i] != rk[i]) {
			console.log("sm4_set_encrypt_key failed");
			return 0;
		}
	}

	sm4_encrypt(plaintext, 0, buf, 0, key);

	console.log("sm4 test1");
	for (var i = 0; i < SM4_BLOCK_SIZE; i++) {
		if (buf[i] != ciphertext[i]) {
			console.log("sm4_encrypt failed");
			return 0;
		}
	}

	sm4_memcpy(buf, 0, plaintext, 0, SM4_BLOCK_SIZE);

	console.log("sm4 test2");
	for (var i = 0; i < 1000000; i++) {
		sm4_encrypt(buf, 0, buf, 0, key);
	}

	for (var i = 0; i < SM4_BLOCK_SIZE; i++) {
		if (buf[i] != ciphertext2[i]) {
			console.log("sm4_encrypt 1000000 failed");
			return 0;
		}
	}

	sm4_set_decrypt_key(key, user_key);
	sm4_encrypt(ciphertext, 0, buf, 0, key);

	for (var i = 0; i < SM4_BLOCK_SIZE; i++) {
		if (buf[i] != plaintext[i]) {
			console.log("sm4_decrypt failed");
			return 0;
		}
	}

	sm4_key_free(key);
	return 1;
}
