/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <gmssl/hex.h>
#include <gmssl/error.h>
#include <gmssl/sm2_z256.h>



static int sm2_z256_equ_hex(const uint64_t a[4], const char *hex)
{
	uint64_t b[4];
	sm2_z256_from_hex(b, hex);
	return (sm2_z256_cmp(a, b) == 0);
}


int sm2_z256_mont_equ_hex(const uint64_t a[4], const char *hex)
{
	uint64_t a_[4];
	uint64_t b[4];

	sm2_z256_from_mont(a_, a);
	sm2_z256_from_hex(b, hex);
	return (sm2_z256_cmp(a_, b) == 0);
}

static int test_sm2_z256_add(void)
{
	char *hex_x = "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7";
	char *hex_y = "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0";
	char *hex_add_x_y = "eefbe4cf140ff8b5b956d329d5a2eae8608c933cb89053217439786e54866567";
	char *hex_2y = "786e6d45e9ecef38b37b9dc6d6d242a7a1530ef98c548e8005be65ca4273e140";

	uint64_t x[4];
	uint64_t y[4];
	uint64_t r[4];
	uint64_t c;

	sm2_z256_from_hex(x, hex_x);
	sm2_z256_from_hex(y, hex_y);

	c = sm2_z256_add(r, x, y);
	if (c != 0 || sm2_z256_equ_hex(r, hex_add_x_y) != 1) {
		error_print();
		return -1;
	}

	c = sm2_z256_add(r, y, y);
	if (c != 1 || sm2_z256_equ_hex(r, hex_2y) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_z256_sub(void)
{
	char *hex_x = "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7";
	char *hex_y = "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0";
	char *hex_sub_x_y = "768d77892a23097d05db3562fed0a840bf3984432c3bc4a16e7b12a412128427";
	char *hex_sub_y_x = "89728876d5dcf682fa24ca9d012f57bf40c67bbcd3c43b5e9184ed5beded7bd9";
	uint64_t x[4];
	uint64_t y[4];
	uint64_t r[4];
	uint64_t c;

	sm2_z256_from_hex(x, hex_x);
	sm2_z256_from_hex(y, hex_y);

	c = sm2_z256_sub(r, x, y);
	if (c != 1 || sm2_z256_equ_hex(r, hex_sub_x_y) != 1) {
		error_print();
		return -1;
	}

	c = sm2_z256_sub(r, y, x);
	if (c != 0 || sm2_z256_equ_hex(r, hex_sub_y_x) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_z256_mul(void)
{
	char *hex_x = "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7";
	char *hex_y = "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0";
	char *hex_mul_x_y =
		"255362ffa019467e48add0ebbe29d15e82fab48f15592867dbdab16dde8d0673"
		"dd4057dd755d04ff86dad43f0ecaf69ddccd043ba61f523ebe51b0ee64928c60";

	uint64_t x[4];
	uint64_t y[4];
	uint64_t r[8];

	sm2_z256_from_hex(x, hex_x);
	sm2_z256_from_hex(y, hex_y);

	sm2_z256_mul(r, x, y);

	if (sm2_z256_equ_hex(r + 4, hex_mul_x_y) != 1
		|| sm2_z256_equ_hex(r, hex_mul_x_y + 64) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_z256_cmp(void)
{
	char *hex_x = "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7";
	char *hex_y = "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0";

	uint64_t x[4];
	uint64_t y[4];

	sm2_z256_from_hex(x, hex_x);
	sm2_z256_from_hex(y, hex_y);

	if (sm2_z256_cmp(x, y) != -1
		|| sm2_z256_cmp(x, x) != 0
		|| sm2_z256_cmp(y, y) != 0
		|| sm2_z256_cmp(y, x) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_z256_modp_add(void)
{
	char *hex_x = "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7";
	char *hex_y = "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0";
	char *hex_modp_add_x_y = "eefbe4cf140ff8b5b956d329d5a2eae8608c933cb89053217439786e54866567";
	char *hex_neg_x = "cd3b51d2e0e67ee6a066fbb995c6366b701cf43f0d99f41f8ea5ba76ccb38b38";
	char *hex_p_sub_1 = "fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffe";
	char *hex_2 = "0000000000000000000000000000000000000000000000000000000000000002";
	char *hex_1 = "0000000000000000000000000000000000000000000000000000000000000001";
	char *hex_0 = "0000000000000000000000000000000000000000000000000000000000000000";
	char *hex_modp_2y = "786e6d46e9ecef38b37b9dc6d6d242a7a1530efa8c548e7f05be65ca4273e141";

	uint64_t x[4];
	uint64_t y[4];
	uint64_t r[4];

	sm2_z256_from_hex(x, hex_x);
	sm2_z256_from_hex(y, hex_y);

	// x + y < p
	sm2_z256_modp_add(r, x, y);
	if (sm2_z256_equ_hex(r, hex_modp_add_x_y) != 1) {
		error_print();
		return -1;
	}

	// x + y > 2^256
	sm2_z256_modp_add(r, y, y);
	if (sm2_z256_equ_hex(r, hex_modp_2y) != 1) {
		error_print();
		return -1;
	}

	// x + y = p
	sm2_z256_from_hex(r, hex_neg_x);
	sm2_z256_modp_add(r, r, x);
	if (sm2_z256_equ_hex(r, hex_0) != 1) {
		error_print();
		return -1;
	}

	// p < x + y < 2^256
	sm2_z256_from_hex(x, hex_p_sub_1);
	sm2_z256_from_hex(y, hex_2);
	sm2_z256_modp_add(r, x, y);
	if (sm2_z256_equ_hex(r, hex_1) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_z256_modp_sub(void)
{
	char *hex_x = "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7";
	char *hex_y = "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0";
	char *hex_modp_sub_x_y = "768d77882a23097d05db3562fed0a840bf3984422c3bc4a26e7b12a412128426";
	char *hex_modp_sub_y_x = "89728876d5dcf682fa24ca9d012f57bf40c67bbcd3c43b5e9184ed5beded7bd9";
	char *hex_0 = "0000000000000000000000000000000000000000000000000000000000000000";

	uint64_t x[4];
	uint64_t y[4];
	uint64_t r[4];

	sm2_z256_from_hex(x, hex_x);
	sm2_z256_from_hex(y, hex_y);

	sm2_z256_modp_sub(r, x, y);
	if (sm2_z256_equ_hex(r, hex_modp_sub_x_y) != 1) {
		error_print();
		return -1;
	}

	sm2_z256_modp_sub(r, y, x);
	if (sm2_z256_equ_hex(r, hex_modp_sub_y_x) != 1) {
		error_print();
		return -1;
	}

	sm2_z256_modp_sub(r, x, x);
	if (sm2_z256_equ_hex(r, hex_0) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_z256_modp_div_by_2(void)
{
	char *hex_x = "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7";
	char *hex_y = "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0";
	char *hex_modp_x_div_2 = "996257158f8cc08cafcc8223351ce4ca47f185df793305f138ad22c499a63a63";
	char *hex_modp_y_div_2 = "5e1b9b517a7b3bce2cdee771b5b490a9e854c3be631523a0016f9972909cf850";

	uint64_t x[4];
	uint64_t y[4];
	uint64_t r[4];

	sm2_z256_from_hex(x, hex_x);
	sm2_z256_from_hex(y, hex_y);

	sm2_z256_modp_div_by_2(r, x);
	if (sm2_z256_equ_hex(r, hex_modp_x_div_2) != 1) {
		error_print();
		return -1;
	}

	sm2_z256_modp_div_by_2(r, y);
	if (sm2_z256_equ_hex(r, hex_modp_y_div_2) != 1) {
		error_print();
		return -1;
	}

	printf("%s ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_z256_modp_mul(void)
{
	char *hex_x = "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7";
	char *hex_y = "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0";
	char *hex_modp_mul_x_y = "edd7e745bdc4630ccfa1da1057033a525346dbf202f082f3c431349991ace76a";
	char *hex_0 = "0000000000000000000000000000000000000000000000000000000000000000";

	uint64_t x[4];
	uint64_t y[4];
	uint64_t r[4];

	sm2_z256_from_hex(x, hex_x);
	sm2_z256_from_hex(y, hex_y);

	sm2_z256_to_mont(x, x);
	sm2_z256_to_mont(y, y);
	sm2_z256_mont_mul(r, x, y);
	sm2_z256_from_mont(r, r);

	if (sm2_z256_equ_hex(r, hex_modp_mul_x_y) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_z256_modp_inv(void)
{
	char *hex_x = "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7";
	char *hex_y = "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0";
	char *hex_modp_inv_x = "053b878fb82e213c17e554b9a574b7bd31775222704b7fd9c7d6f8441026cd80";
	char *hex_modp_inv_y = "7adc850505c462b280f710414ab54e922551dbc97eefbc04e99cb743624c729f";
	char *hex_0 = "0000000000000000000000000000000000000000000000000000000000000000";
	char *hex_1 = "0000000000000000000000000000000000000000000000000000000000000001";

	uint64_t x[4];
	uint64_t y[4];
	uint64_t r[4];

	sm2_z256_from_hex(x, hex_x);
	sm2_z256_from_hex(y, hex_y);

	sm2_z256_to_mont(x, x);
	sm2_z256_mont_inv(r, x);
	sm2_z256_from_mont(r ,r);
	if (sm2_z256_equ_hex(r, hex_modp_inv_x) != 1) {
		error_print();
		return -1;
	}

	sm2_z256_to_mont(y, y);
	sm2_z256_mont_inv(r, y);
	sm2_z256_from_mont(r ,r);
	if (sm2_z256_equ_hex(r, hex_modp_inv_y) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}



static const uint64_t SM2_Z256_MONT_X[4] = {
	0x61328990f418029e, 0x3e7981eddca6c050, 0xd6a1ed99ac24c3c3, 0x91167a5ee1c13b05,
};

static const uint64_t SM2_Z256_MONT_Y[4] = {
	0xc1354e593c2d0ddd, 0xc1f5e5788d3295fa, 0x8d4cfb066e2a48f8, 0x63cd65d481d735bd,
};

static int test_sm2_z256_point_get_affine(void)
{
	const char *hex_x = "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7";
	const char *hex_y = "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0";
	SM2_Z256_POINT P;
	uint64_t x[4];
	uint64_t y[4];

	sm2_z256_copy(P.X, SM2_Z256_MONT_X);
	sm2_z256_copy(P.Y, SM2_Z256_MONT_Y);
	sm2_z256_copy(P.Z, SM2_Z256_MONT_ONE);

	sm2_z256_point_get_affine(&P, x, y);

	if (sm2_z256_equ_hex(x, hex_x) != 1 || sm2_z256_equ_hex(y, hex_y) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_z256_point_dbl(void)
{
	char *hex_x_2G = "56cefd60d7c87c000d58ef57fa73ba4d9c0dfa08c08a7331495c2e1da3f2bd52";
	char *hex_y_2G = "31b7e7e6cc8189f668535ce0f8eaf1bd6de84c182f6c8e716f780d3a970a23c3";
	SM2_Z256_POINT P;
	uint64_t x[4];
	uint64_t y[4];

	sm2_z256_copy(P.X, SM2_Z256_MONT_X);
	sm2_z256_copy(P.Y, SM2_Z256_MONT_Y);
	sm2_z256_copy(P.Z, SM2_Z256_MONT_ONE);

	sm2_z256_point_dbl(&P, &P);
	sm2_z256_point_get_affine(&P, x, y);

	if (sm2_z256_equ_hex(x, hex_x_2G) != 1 || sm2_z256_equ_hex(y, hex_y_2G) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;

}

static int test_sm2_z256_point_add_affine(void)
{
	char *hex_x_3G = "a97f7cd4b3c993b4be2daa8cdb41e24ca13f6bd945302244e26918f1d0509ebf";
	char *hex_y_3G = "530b5dd88c688ef5ccc5cec08a72150f7c400ee5cd045292aaacdd037458f6e6";
	SM2_Z256_POINT P;
	SM2_Z256_POINT Q;
	uint64_t x[4];
	uint64_t y[4];

	sm2_z256_copy(P.X, SM2_Z256_MONT_X);
	sm2_z256_copy(P.Y, SM2_Z256_MONT_Y);
	sm2_z256_copy(P.Z, SM2_Z256_MONT_ONE);

	sm2_z256_point_dbl(&Q, &P);
	sm2_z256_point_add_affine(&Q, &Q, (SM2_Z256_POINT_AFFINE *)&P);
	sm2_z256_point_get_affine(&Q, x, y);

	if (sm2_z256_equ_hex(x, hex_x_3G) != 1 || sm2_z256_equ_hex(y, hex_y_3G) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_z256_point_add(void)
{
	char *hex_x_5G = "c749061668652e26040e008fdd5eb77a344a417b7fce19dba575da57cc372a9e";
	char *hex_y_5G = "f2df5db2d144e9454504c622b51cf38f5006206eb579ff7da6976eff5fbe6480";
	SM2_Z256_POINT G;
	SM2_Z256_POINT P;
	SM2_Z256_POINT Q;
	SM2_Z256_POINT R;
	uint64_t x[4];
	uint64_t y[4];

	sm2_z256_copy(G.X, SM2_Z256_MONT_X);
	sm2_z256_copy(G.Y, SM2_Z256_MONT_Y);
	sm2_z256_copy(G.Z, SM2_Z256_MONT_ONE);

	// P = 2*G
	sm2_z256_point_dbl(&P, &G);

	// Q = 3*G
	sm2_z256_point_add_affine(&Q, &P, (SM2_Z256_POINT_AFFINE *)&G);

	// R = P + Q
	sm2_z256_point_add(&R, &P, &Q);

	sm2_z256_point_get_affine(&R, x, y);

	if (sm2_z256_equ_hex(x, hex_x_5G) != 1 || sm2_z256_equ_hex(y, hex_y_5G) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_z256_get_booth(void)
{
	char *hex_a = "7a648a77d0cbe0b9ee841433be0c132aa98f6757da70a18c74999774fa587762";

	// window_size = 7, len(booth) = (256 + 6)/7 = 7
	int booth_a[37] = {
		-30, -17, -30, -45, -48, -17, -26, -51, -11, 25, 6, 5, 39, -5, -42, 52,
		15, -45, 43, 25, -63, -62, -16, 26, 20, 8, 58, -49, 12, -4, 51, -24, -8,
		21, 18, -45, 8
	};
	uint64_t a[4];
	int i = 0;

	sm2_z256_from_hex(a, hex_a);

	for (i = 0; i < 37; i++) {
		if (sm2_z256_get_booth(a, 7, i) != booth_a[i]) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_z256_point_mul_generator(void)
{
	char *hex_b = "28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93";
	char *hex_x = "528470bc74a6ebc663c06fc4cfa1b630d1e9d4a80c0a127b47f73c324c46c0ba";
	char *hex_y = "832cf9c5a15b997e60962b4cf6e2c9cee488faaec98d20599d323d4cabfc1bf4";

	uint64_t b[4];
	SM2_Z256_POINT P;
	uint64_t x[4];
	uint64_t y[4];

	sm2_z256_from_hex(b, hex_b);
	sm2_z256_point_mul_generator(&P, b);
	sm2_z256_point_get_affine(&P, x, y);

	if (sm2_z256_equ_hex(x, hex_x) != 1 || sm2_z256_equ_hex(y, hex_y) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}


static int test_sm2_z256_point_mul(void)
{
	char *hex_b = "28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93";
	char *hex_x = "528470bc74a6ebc663c06fc4cfa1b630d1e9d4a80c0a127b47f73c324c46c0ba";
	char *hex_y = "832cf9c5a15b997e60962b4cf6e2c9cee488faaec98d20599d323d4cabfc1bf4";

	uint64_t b[4];
	SM2_Z256_POINT G;
	SM2_Z256_POINT P;
	uint64_t x[4];
	uint64_t y[4];

	sm2_z256_from_hex(b, hex_b);

	sm2_z256_copy(G.X, SM2_Z256_MONT_X);
	sm2_z256_copy(G.Y, SM2_Z256_MONT_Y);
	sm2_z256_copy(G.Z, SM2_Z256_MONT_ONE);

	sm2_z256_point_mul(&P, &G, b);
	sm2_z256_point_get_affine(&P, x, y);

	if (sm2_z256_equ_hex(x, hex_x) != 1 || sm2_z256_equ_hex(y, hex_y) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (test_sm2_z256_add() != 1) { error_print(); return -1; }
	if (test_sm2_z256_sub() != 1) { error_print(); return -1; }
	if (test_sm2_z256_mul() != 1) { error_print(); return -1; }
	if (test_sm2_z256_cmp() != 1) { error_print(); return -1; }
	if (test_sm2_z256_modp_add() != 1) { error_print(); return -1; }
	if (test_sm2_z256_modp_sub() != 1) { error_print(); return -1; }
	if (test_sm2_z256_modp_mul() != 1) { error_print(); return -1; }
	if (test_sm2_z256_modp_inv() != 1) { error_print(); return -1; }
	if (test_sm2_z256_modp_div_by_2() != 1) { error_print(); return -1; }
	if (test_sm2_z256_get_booth() != 1) { error_print(); return -1; }
	if (test_sm2_z256_point_get_affine() != 1) { error_print(); return -1; }
	if (test_sm2_z256_point_dbl() != 1) { error_print(); return -1; }
	if (test_sm2_z256_point_add_affine() != 1) { error_print(); return -1; }
	if (test_sm2_z256_point_add() != 1) { error_print(); return -1; }
	if (test_sm2_z256_point_mul_generator() != 1) { error_print(); return -1; }
	if (test_sm2_z256_point_mul() != 1) { error_print(); return -1; }

	printf("%s all tests passed\n", __FILE__);
	return 0;
}

