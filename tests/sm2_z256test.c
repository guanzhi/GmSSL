/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
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
#include <gmssl/sm2_z256.h>
#include <gmssl/sm3.h>
#include <gmssl/hex.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>


// TODO:		
static int test_sm2_z256_point_at_infinity(void)
{
	return 1;
}


enum {
	OP_ADD,
	OP_DBL,
	OP_TRI,
	OP_SUB,
	OP_NEG,
	OP_HAF,
	OP_MUL,
	OP_SQR,
	OP_EXP,
	OP_INV,
};

#define TEST_COUNT 10

static int test_sm2_z256_rshift(void)
{
	uint64_t r[4];
	uint64_t a[4];
	uint64_t b[4];
	unsigned int i;

	sm2_z256_rand_range(a, sm2_z256_order());

	sm2_z256_rshift(r, a, 0);
	sm2_z256_copy(b, a);
	if (sm2_z256_cmp(r, b) != 0) {
		error_print();
		return -1;
	}

	sm2_z256_rshift(r, a, 63);
	for (i = 0; i < 63; i++) {
		sm2_z256_rshift(a, a, 1);
	}
	if (sm2_z256_cmp(r, a) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_z256_from_bytes(void)
{
	const uint8_t be[32] = {
		0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
		0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,
	};

	// TODO: choose both `to_bytes` and `from_bytes`		

	sm2_z256_t a;
	uint8_t buf[32];

	sm2_z256_from_bytes(a, be);
	sm2_z256_to_bytes(a, buf);

	if (memcmp(buf, be, sizeof(be)) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_z256_modp_mont_sqrt(void)
{
	uint64_t a[4];
	uint64_t neg_a[4];
	uint64_t mont_a[4];
	uint64_t mont_sqr_a[4];
	uint64_t mont_a_[4];
	uint64_t a_[4];
	int i;

	for (i = 0; i < 6; i++) {
		sm2_z256_rand_range(a, sm2_z256_order());
		sm2_z256_modp_neg(neg_a, a);

		sm2_z256_modp_to_mont(a, mont_a);
		sm2_z256_modp_mont_sqr(mont_sqr_a, mont_a);
		sm2_z256_modp_mont_sqrt(mont_a_, mont_sqr_a);
		sm2_z256_modp_from_mont(a_, mont_a_);

		// a_ = sqrt(a^2), a_ should be a or -a
		if (sm2_z256_cmp(a_, a) != 0 && sm2_z256_cmp(a_, neg_a) != 0) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_z256_modp(void)
{
	struct {
		char *label;
		int op;
		char *r;
		char *a;
		char *b;
	} tests[] = {
		{
		"x + y (mod p)", OP_ADD,
		"eefbe4cf140ff8b5b956d329d5a2eae8608c933cb89053217439786e54866567",
		"32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7",
		"bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0",
		},
		{
		"2*y (mod p)", OP_DBL,
		"786e6d46e9ecef38b37b9dc6d6d242a7a1530efa8c548e7f05be65ca4273e141",
		"bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0",
		NULL,
		},
		{
		"3*y (mod p)", OP_TRI,
		"34a5a3eadee366d50d396caa423b63fb71fc9678527ed5be089d98af63add1e2",
		"bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0",
		NULL,
		},
		{
		"x - y (mod p)", OP_SUB,
		"768d77882a23097d05db3562fed0a840bf3984422c3bc4a26e7b12a412128426",
		"32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7",
		"bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0",
		},
		{
		"y - x (mod p)", OP_SUB,
		"89728876d5dcf682fa24ca9d012f57bf40c67bbcd3c43b5e9184ed5beded7bd9",
		"bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0",
		"32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7",
		},
		{
		"-x (mod p)", OP_NEG,
		"cd3b51d2e0e67ee6a066fbb995c6366b701cf43f0d99f41f8ea5ba76ccb38b38",
		"32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7",
		NULL,
		},
		{
		"x/2 (mod p)", OP_HAF,
		"996257158f8cc08cafcc8223351ce4ca47f185df793305f138ad22c499a63a63",
		"32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7",
		NULL,
		},
		{
		"y/2 (mod p)", OP_HAF,
		"5e1b9b517a7b3bce2cdee771b5b490a9e854c3be631523a0016f9972909cf850",
		"bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0",
		NULL,
		},
		{
		"x * y (mod p)", OP_MUL,
		"edd7e745bdc4630ccfa1da1057033a525346dbf202f082f3c431349991ace76a",
		"32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7",
		"bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0",
		},
		{
		"x^2 (mod p)", OP_SQR,
		"f4e2cca0bcfd67fba8531eebff519e4cb3d47f9fe8c5eff5151f4c497ec99fbf",
		"32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7",
		NULL,
		},
		{
		"x^y (mod p)", OP_EXP,
		"8cafd11b1a0d2072b82911ba87e0d376103a1be5986fce91d8d297b758f68146",
		"32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7",
		"bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0",
		},
		{
		"x^-1 (mod p)", OP_INV,
		"053b878fb82e213c17e554b9a574b7bd31775222704b7fd9c7d6f8441026cd80",
		"32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7",
		NULL,
		},
	};

	uint64_t r[4];
	uint64_t a[4];
	uint64_t b[4];
	uint64_t c[4];
	size_t i;

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {

		sm2_z256_from_hex(r, tests[i].r);
		sm2_z256_from_hex(a, tests[i].a);
		if (tests[i].b) {
			sm2_z256_from_hex(b, tests[i].b);
		}

		switch (tests[i].op) {
		case OP_ADD:
			sm2_z256_modp_add(c, a, b);
			break;
		case OP_DBL:
			sm2_z256_modp_dbl(c, a);
			break;
		case OP_TRI:
			sm2_z256_modp_tri(c, a);
			break;
		case OP_SUB:
			sm2_z256_modp_sub(c, a, b);
			break;
		case OP_NEG:
			sm2_z256_modp_neg(c, a);
			break;
		case OP_HAF:
			sm2_z256_modp_haf(c, a);
			break;
		case OP_MUL:
			sm2_z256_modp_to_mont(a, a);
			sm2_z256_modp_to_mont(b, b);
			sm2_z256_modp_mont_mul(c, a, b);
			sm2_z256_modp_from_mont(c, c);
			break;
		case OP_SQR:
			sm2_z256_modp_to_mont(a, a);
			sm2_z256_modp_mont_sqr(c, a);
			sm2_z256_modp_from_mont(c, c);
			break;
		case OP_EXP:
			sm2_z256_modp_to_mont(a, a);
			sm2_z256_modp_mont_exp(c, a, b);
			sm2_z256_modp_from_mont(c, c);
			break;
		case OP_INV:
			sm2_z256_modp_to_mont(a, a);
			sm2_z256_modp_mont_inv(c, a);
			sm2_z256_modp_from_mont(c, c);
			break;
		default:
			error_print();
			return -1;
		}

		if (sm2_z256_cmp(r, c) != 0) {

			fprintf(stderr, "%s: error\n", __FUNCTION__);
			fprintf(stderr, "    %s\n", tests[i].label);
			sm2_z256_print(stderr, 0, 8, "err", c);
			fprintf(stderr, "        ret: %s\n", tests[i].r);
			fprintf(stderr, "        op1: %s\n", tests[i].a);
			if (tests[i].b) {
				fprintf(stderr, "        op2: %s\n", tests[i].b);
			}

			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_z256_modn(void)
{
	struct {
		char *label;
		int op;
		char *r;
		char *a;
		char *b;
	} tests[] = {
		{
		"x + y (mod n)", OP_ADD,
		"eefbe4cf140ff8b5b956d329d5a2eae8608c933cb89053217439786e54866567",
		"32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7",
		"bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0",
		},
		{
		"x - y (mod n)", OP_SUB,
		"768d77882a23097d05db3562fed0a840313d63ae4e01c9ccc23706ad4be7c54a",
		"32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7",
		"bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0",
		},
		{
		"y - x (mod n)", OP_SUB,
		"89728876d5dcf682fa24ca9d012f57bf40c67bbcd3c43b5e9184ed5beded7bd9",
		"bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0",
		"32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7",
		},
		{
		"-x (mod n)", OP_NEG,
		"cd3b51d2e0e67ee6a066fbb995c6366ae220d3ab2f5ff949e261ae800688cc5c",
		"32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7",
		NULL,
		},
		{
		"x * y (mod n)", OP_MUL,
		"cf7296d5cbf0b64bb5e9a11b294962e9c779b41c038e9c8d815234a0df9d6623",
		"32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7",
		"bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0",
		},
		{
		"x^2 (mod n)", OP_SQR,
		"82d3d1b296d3a3803888b7ffc78f23eca824e7ec8d7ddaf231ffb0d256a19da2",
		"32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7",
		NULL,
		},
		{
		"x^y (mod n)", OP_EXP,
		"0cf4df7e76d7d49ff23b94853a98aba1e36e9ca0358acbf23a3bbda406f46df3",
		"32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7",
		"bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0",
		},
		{
		"x^-1 (mod n)", OP_INV,
		"96340ec8b80f44e9b345a706bdb5c9e3ab8a6474a5cb4e0d4645dbaecf1cf03d",
		"32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7",
		NULL,
		},
	};

	uint64_t r[4];
	uint64_t a[4];
	uint64_t b[4];
	uint64_t c[4];
	size_t i;

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {

		sm2_z256_from_hex(r, tests[i].r);
		sm2_z256_from_hex(a, tests[i].a);
		if (tests[i].b) {
			sm2_z256_from_hex(b, tests[i].b);
		}

		switch (tests[i].op) {
		case OP_ADD:
			sm2_z256_modn_add(c, a, b);
			break;
		case OP_SUB:
			sm2_z256_modn_sub(c, a, b);
			break;
		case OP_NEG:
			sm2_z256_modn_neg(c, a);
			break;
		case OP_MUL:
			sm2_z256_modn_mul(c, a, b);
			break;
		case OP_SQR:
			sm2_z256_modn_sqr(c, a);
			break;
		case OP_EXP:
			sm2_z256_modn_exp(c, a, b);
			break;
		case OP_INV:
			sm2_z256_modn_inv(c, a);
			break;
		default:
			error_print();
			return -1;
		}

		if (sm2_z256_cmp(r, c) != 0) {

			fprintf(stderr, "%s: error\n", __FUNCTION__);
			fprintf(stderr, "    %s\n", tests[i].label);
			sm2_z256_print(stderr, 0, 8, "err", c);
			fprintf(stderr, "        ret: %s\n", tests[i].r);
			fprintf(stderr, "        op1: %s\n", tests[i].a);
			if (tests[i].b) {
				fprintf(stderr, "        op2: %s\n", tests[i].b);
			}

			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_z256_point_is_on_curve(void)
{

	struct {
		char *label;
		char *mont_X;
		char *mont_Y;
		char *mont_Z;
	} tests[] = {
		{
		"Point at Infinity (1:1:0)",
		"0000000100000000000000000000000000000000ffffffff0000000000000001", // mont(1)
		"0000000100000000000000000000000000000000ffffffff0000000000000001", // mont(1)
		"0000000000000000000000000000000000000000000000000000000000000000", // 0
		},
		/*
		{
		"Point at Infinity (X:Y:0) invalid format (might fail)",
		"0000000000000000000000000000000000000000000000000000000000000002", // 2
		"0000000000000000000000000000000000000000000000000000000000000003", // 3
		"0000000000000000000000000000000000000000000000000000000000000000", // 0
		},
		*/
		{
		"Affine Point [1]G with Montgomery Coordinates",
		"91167a5ee1c13b05d6a1ed99ac24c3c33e7981eddca6c05061328990f418029e", // mont(x)
		"63cd65d481d735bd8d4cfb066e2a48f8c1f5e5788d3295fac1354e593c2d0ddd", // mont(y)
		"0000000100000000000000000000000000000000ffffffff0000000000000001", // mont(1)
		},
		{
		"Jacobian Point [2]G with Montgomery Coordinates",
		"398874c476a3b1f77aef3e862601440903243d78d5b614a62eda8381e63c48d6",
		"1fbbdfdddaf4fd475a86a7ae64921d4829f04a88f6cf4dc128385681c1a73e40",
		"c79acba903ae6b7b1a99f60cdc5491f183ebcaf11a652bf5826a9cb2785a1bba",
		},
	};

	SM2_Z256_POINT P;
	size_t i;

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {

		sm2_z256_from_hex(P.X, tests[i].mont_X);
		sm2_z256_from_hex(P.Y, tests[i].mont_Y);
		sm2_z256_from_hex(P.Z, tests[i].mont_Z);

		if (sm2_z256_point_is_on_curve(&P) != 1) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_z256_point_get_xy(void)
{
	struct {
		char *label;
		char *mont_X;
		char *mont_Y;
		char *mont_Z;
		char *x;
		char *y;
	} tests[] = {
		{
		"Point at Infinity (1:1:0)",
		"0000000100000000000000000000000000000000ffffffff0000000000000001", // mont(1)
		"0000000100000000000000000000000000000000ffffffff0000000000000001", // mont(1)
		"0000000000000000000000000000000000000000000000000000000000000000", // 0
		"0000000000000000000000000000000000000000000000000000000000000000", // 0
		"0000000000000000000000000000000000000000000000000000000000000000", // 0
		},
		{
		"Affine Point [1]G with Montgomery Coordinates",
		"91167a5ee1c13b05d6a1ed99ac24c3c33e7981eddca6c05061328990f418029e", // mont(x)
		"63cd65d481d735bd8d4cfb066e2a48f8c1f5e5788d3295fac1354e593c2d0ddd", // mont(y)
		"0000000100000000000000000000000000000000ffffffff0000000000000001", // mont(1)
		"32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7", // x
		"bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0", // y
		},
		{
		"Jacobian Point [2]G with Montgomery Coordinates",
		"398874c476a3b1f77aef3e862601440903243d78d5b614a62eda8381e63c48d6",
		"1fbbdfdddaf4fd475a86a7ae64921d4829f04a88f6cf4dc128385681c1a73e40",
		"c79acba903ae6b7b1a99f60cdc5491f183ebcaf11a652bf5826a9cb2785a1bba",
		"56cefd60d7c87c000d58ef57fa73ba4d9c0dfa08c08a7331495c2e1da3f2bd52",
		"31b7e7e6cc8189f668535ce0f8eaf1bd6de84c182f6c8e716f780d3a970a23c3",
		},
	};

	SM2_Z256_POINT P;
	uint64_t x[4];
	uint64_t y[4];
	size_t i;

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {

		sm2_z256_from_hex(P.X, tests[i].mont_X);
		sm2_z256_from_hex(P.Y, tests[i].mont_Y);
		sm2_z256_from_hex(P.Z, tests[i].mont_Z);

		if (sm2_z256_point_get_xy(&P, x, NULL) < 0) {
			error_print();
			return -1;
		}

		if (sm2_z256_equ_hex(x, tests[i].x) != 1) {
			error_print();
			return -1;
		}

		sm2_z256_point_get_xy(&P, x, y);
		if (sm2_z256_equ_hex(y, tests[i].y) != 1) {
			error_print();
			return -1;
		}
	};

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_z256_point_from_x_bytes(void)
{
	struct {
		char *label;
		char *xy;
		int y_is_odd;
	} tests[] = {
		{
		"G (y is even)",
		"32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7"
		"bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0",
		0,
		},
		{
		"2G (y is odd)",
		"56cefd60d7c87c000d58ef57fa73ba4d9c0dfa08c08a7331495c2e1da3f2bd52"
		"31b7e7e6cc8189f668535ce0f8eaf1bd6de84c182f6c8e716f780d3a970a23c3",
		1,
		},
	};

	SM2_Z256_POINT P;
	uint8_t x_bytes[32];
	size_t i, len;

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {

		hex_to_bytes(tests[i].xy, 64, x_bytes, &len);

		sm2_z256_point_from_x_bytes(&P, x_bytes, tests[i].y_is_odd);

		if (sm2_z256_point_equ_hex(&P, tests[i].xy) != 1) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_z256_point_add_conjugate(void)
{
	char *hex_G =
		"32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7"
		"bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0";
	char *hex_negG =
		"32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7"
		"43c8c95c0b098863a642311c9496deac2f56788239d5b8c0fd20cd1adec60f5f";

	SM2_Z256_POINT R;
	SM2_Z256_POINT P;
	SM2_Z256_POINT Q;

	sm2_z256_point_from_hex(&P, hex_G);
	sm2_z256_point_from_hex(&Q, hex_negG);
	sm2_z256_point_add(&R, &P, &Q);

	sm2_z256_print(stderr, 0, 0, "R.X", R.X);
	sm2_z256_print(stderr, 0, 0, "R.Y", R.Y);
	sm2_z256_print(stderr, 0, 0, "R.Z", R.Z);

	// P + (-P) = (0:0:0)
	/*
	//FIXME:				 
	if (!sm2_z256_is_zero(R.X)
		|| !sm2_z256_is_zero(R.Y)) {
		error_print();
		return -1;
	}
	*/

	if (!sm2_z256_is_zero(R.Z)) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

// TODO: check O + O == O
static int test_sm2_z256_point_dbl_infinity(void)
{
	SM2_Z256_POINT P_infinity;
	SM2_Z256_POINT R;

	sm2_z256_point_set_infinity(&P_infinity);
	sm2_z256_point_dbl(&R, &P_infinity);
	sm2_z256_print(stderr, 0, 0, "ret", R.X);

	if (!sm2_z256_point_is_at_infinity(&R)) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}


static int test_sm2_z256_point_ops(void)
{
	char *hex_G =
		"32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7"
		"bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0";
	char *hex_2G =
		"56cefd60d7c87c000d58ef57fa73ba4d9c0dfa08c08a7331495c2e1da3f2bd52"
		"31b7e7e6cc8189f668535ce0f8eaf1bd6de84c182f6c8e716f780d3a970a23c3";
	char *hex_3G =
		"a97f7cd4b3c993b4be2daa8cdb41e24ca13f6bd945302244e26918f1d0509ebf"
		"530b5dd88c688ef5ccc5cec08a72150f7c400ee5cd045292aaacdd037458f6e6";
	char *hex_negG =
		"32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7"
		"43c8c95c0b098863a642311c9496deac2f56788239d5b8c0fd20cd1adec60f5f";
	char *hex_10G =
		"d3f94862519621c121666061f65c3e32b2d0d065cd219e3284a04814db522756"
		"4b9030cf676f6a742ebd57d146dca428f6b743f64d1482d147d46fb2bab82a14";
	char *hex_bG =
		"528470bc74a6ebc663c06fc4cfa1b630d1e9d4a80c0a127b47f73c324c46c0ba"
		"832cf9c5a15b997e60962b4cf6e2c9cee488faaec98d20599d323d4cabfc1bf4";
	char *hex_10 =
		"000000000000000000000000000000000000000000000000000000000000000A";
	char *hex_b =
		"28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93";

	struct {
		char *label;
		int op;
		char *R;
		char *k;
		char *A;
		char *B;
	} tests[] = {
		{"[2]G", OP_DBL, hex_2G, NULL, hex_G, NULL,},
		{"[2]G + G", OP_ADD, hex_3G, NULL, hex_2G, hex_G,},
		{"[3]G - G", OP_SUB, hex_2G, NULL, hex_3G, hex_G,},
		{"-G", OP_NEG, hex_negG, NULL, hex_G, NULL,},
		{"[10]G", OP_MUL, hex_10G, hex_10, hex_G, NULL,},
		{"[b]G", OP_MUL, hex_bG, hex_b, hex_G, NULL,},
	};

	size_t i;

	SM2_Z256_POINT P;
	SM2_Z256_POINT R;
	uint64_t k[4];
	SM2_Z256_POINT A;
	SM2_Z256_POINT B;


	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {

		sm2_z256_point_from_hex(&R, tests[i].R);
		if (tests[i].k) {
			sm2_z256_from_hex(k, tests[i].k);
		}

		sm2_z256_point_from_hex(&A, tests[i].A);
		if (tests[i].B) {
			sm2_z256_point_from_hex(&B, tests[i].B);
		}

		switch (tests[i].op) {
		case OP_ADD:
			sm2_z256_point_add(&P, &A, &B);
			break;
		case OP_DBL:
			sm2_z256_point_dbl(&P, &A);
			sm2_z256_print(stderr, 0, 0, "X", P.X);
			sm2_z256_print(stderr, 0, 0, "Y", P.Y);
			sm2_z256_print(stderr, 0, 0, "Z", P.Z);
			break;
		case OP_SUB:
			sm2_z256_point_sub(&P, &A, &B);
			break;
		case OP_NEG:
			sm2_z256_point_neg(&P, &A);
			break;
		case OP_MUL:
			sm2_z256_point_mul(&P, k, &A);
			break;
		default:
			error_print();
			return -1;
		}

		if (sm2_z256_point_equ_hex(&P, tests[i].R) != 1) {

			fprintf(stderr, "%s\n", tests[i].label);
			sm2_z256_point_print(stderr, 0, 4, "R", &P);
			fprintf(stderr, "   R: %s\n", tests[i].R);
			fprintf(stderr, "   k: %s\n", tests[i].k);
			fprintf(stderr, "   A: %s\n", tests[i].A);
			fprintf(stderr, "   B: %s\n", tests[i].B);

			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_z256_point_mul_generator(void)
{
	struct {
		char *label;
		char *k;
		char *kG;
	} tests[] = {
		{
		"[0]G",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0000000000000000000000000000000000000000000000000000000000000000"
		"0000000000000000000000000000000000000000000000000000000000000000",
		},
		{
		"[1]G",
		"0000000000000000000000000000000000000000000000000000000000000001",
		"32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"
		"BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
		},
		{
		"[2]G",
		"0000000000000000000000000000000000000000000000000000000000000002",
		"56CEFD60D7C87C000D58EF57FA73BA4D9C0DFA08C08A7331495C2E1DA3F2BD52"
		"31B7E7E6CC8189F668535CE0F8EAF1BD6DE84C182F6C8E716F780D3A970A23C3",
		},
		{
		"[3]G",
		"0000000000000000000000000000000000000000000000000000000000000003",
		"A97F7CD4B3C993B4BE2DAA8CDB41E24CA13F6BD945302244E26918F1D0509EBF"
		"530B5DD88C688EF5CCC5CEC08A72150F7C400EE5CD045292AAACDD037458F6E6",
		},
		{
		"[4]G",
		"0000000000000000000000000000000000000000000000000000000000000004",
		"C239507105C683242A81052FF641ED69009A084AD5CC937DB21646CD34A0CED5"
		"B1BF7EC4080F3C8735F1294AC0DB19686BEE2E96AB8C71FB7A253666CB66E009",
		},
		{
		"[5]G",
		"0000000000000000000000000000000000000000000000000000000000000005",
		"C749061668652E26040E008FDD5EB77A344A417B7FCE19DBA575DA57CC372A9E"
		"F2DF5DB2D144E9454504C622B51CF38F5006206EB579FF7DA6976EFF5FBE6480",
		},
		{
		"[6]G",
		"0000000000000000000000000000000000000000000000000000000000000006",
		"0927AFB57D93483BBB17C93E71F22A3105FF8856A66016892C8B1A1A3C4B0D30"
		"150C6B1AB4D1FC7EAC1C0EF6EBF2664581ADF1F0855A064DD572103000088F63",
		},
		{
		"[7]G",
		"0000000000000000000000000000000000000000000000000000000000000007",
		"DDF092555409C19DFDBE86A75C139906A80198337744EE78CD27E384D9FCAF15"
		"847D18FFB38E87065CD6B6E9C12D2922037937707D6A49A2223B949657E52BC1",
		},
		{
		"[x]G",
		"32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
		"782E1941B8A8C802543BC831E19F3548235C94A9C42AAD1EA8952CEAAECF12BA"
		"EEE0D9A6939E87F3B47A85863F873B324B9859136E2BF3235E17B3270164202D",
		},
		{
		"[y]G",
		"BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
		"1000165E3FFF85F1DFFFB3AA1DF9F5E62B9A86A9A2927B4FF1AC16D19FEFF330"
		"3116F22B65320DD3B7F73DCF4A4028063A9BE6EFBD1DB0915C72F1EE067C5ECF",
		},
		{
		"[n-1]G",
		"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54122",
		"32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"
		"43C8C95C0B098863A642311C9496DEAC2F56788239D5B8C0FD20CD1ADEC60F5F",
		},
		{
		"[n]G",
		"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
		"0000000000000000000000000000000000000000000000000000000000000000"
		"0000000000000000000000000000000000000000000000000000000000000000",
		},
		{
		"[n+1]G",
		"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54124",
		"32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"
		"BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
		},
		{
		"[2^256 - 1]G",
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
		"B3217D884BC175E6BA6B360EB0E6D4396EAEA725C3D66E87BFA5BEB6C0D3456B"
		"A5199445C54B56602AA60025E1907BFD26B30E867DB6C58A034263AE4A2E27C2",
		},
	};

	uint64_t k[4];
	SM2_Z256_POINT P;
	uint8_t P_bytes[64];
	uint8_t kG_bytes[64];
	size_t i, len;

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {

		sm2_z256_from_hex(k, tests[i].k);
		hex_to_bytes(tests[i].kG, strlen(tests[i].kG), kG_bytes, &len);

		sm2_z256_point_mul_generator(&P, k);
		sm2_z256_point_to_bytes(&P, P_bytes);

		if (memcmp(P_bytes, kG_bytes, 64) != 0) {

			fprintf(stderr, "%s: error\n", __FUNCTION__);
			fprintf(stderr, "    %s\n", tests[i].label);
			fprintf(stderr, "    k: %s\n", tests[i].k);
			fprintf(stderr, "    R: %s\n", tests[i].kG);
			format_bytes(stderr, 0, 4, "P", P_bytes, 64);

			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_z256_point_equ(void)
{
	struct {
		char *label;
		char *mont_X1;
		char *mont_Y1;
		char *mont_Z1;
		char *mont_X2;
		char *mont_Y2;
		char *mont_Z2;
	} tests[] = {
		{
		"Point at Infinity (1:1:0)",
		"0000000100000000000000000000000000000000ffffffff0000000000000001", // mont(1)
		"0000000100000000000000000000000000000000ffffffff0000000000000001", // mont(1)
		"0000000000000000000000000000000000000000000000000000000000000000", // 0
		"0000000100000000000000000000000000000000ffffffff0000000000000001", // mont(1)
		"0000000100000000000000000000000000000000ffffffff0000000000000001", // mont(1)
		"0000000000000000000000000000000000000000000000000000000000000000", // 0
		},
		{
		"[2]2G == 2G + G + G",
		"87b2ca9ded2487c6efdbc69303258763a0b5520fc63cf40154f6c059b945acf2",
		"dc86353bc72db45ebb5b2d03cec4614b164688f19f12dd857fd007e181457b59",
		"050653f8579d1d2d930d7346e31bad56b5a4654d6a9f2c5022434941744ced3a",
		"e8457905838420a51366f7fe174ce34dc3579fefc188f0b5124e7537526ae99e",
		"48c3374ab1d5fde0276bebb81b8ff0baa9805cc2d0f487e18d7b3a4352f4ae21",
		"79f76fd57f22f1e282d64ff809a53f1f729f6b89c6f626b96725a9d05704e681",
		}
	};

	SM2_Z256_POINT P;
	SM2_Z256_POINT Q;
	size_t i;

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {

		sm2_z256_from_hex(P.X, tests[i].mont_X1);
		sm2_z256_from_hex(P.Y, tests[i].mont_Y1);
		sm2_z256_from_hex(P.Z, tests[i].mont_Z1);

		sm2_z256_from_hex(Q.X, tests[i].mont_X2);
		sm2_z256_from_hex(Q.Y, tests[i].mont_Y2);
		sm2_z256_from_hex(Q.Z, tests[i].mont_Z2);

		if (sm2_z256_point_equ(&P, &Q) != 1) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_z256_point_from_hash(void)
{
	SM2_Z256_POINT P;
	uint8_t data[64];
	size_t datalen = sizeof(data);
	int y_is_odd = 1;
	int y_is_even = 0;
	size_t i;

	for (i = 0; i < 5; i++) {

		rand_bytes(data, datalen);

		if (sm2_z256_point_from_hash(&P, data, datalen, y_is_odd) != 1) {
			error_print();
			return -1;
		}
		if (sm2_z256_point_from_hash(&P, data, datalen, y_is_even) != 1) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}


int main(void)
{
	if (test_sm2_z256_rshift() != 1) goto err;

	if (test_sm2_z256_from_bytes() != 1) goto err;


	if (test_sm2_z256_modp() != 1) goto err;
	if (test_sm2_z256_modp_mont_sqrt() != 1) goto err;
	if (test_sm2_z256_modn() != 1) goto err;

	if (test_sm2_z256_point_is_on_curve() != 1) goto err;
	if (test_sm2_z256_point_equ() != 1) goto err;
	if (test_sm2_z256_point_get_xy() != 1) goto err;
	if (test_sm2_z256_point_add_conjugate() != 1) goto err;
	if (test_sm2_z256_point_mul_generator() != 1) goto err;
	if (test_sm2_z256_point_from_hash() != 1) goto err;
	if (test_sm2_z256_point_from_x_bytes() != 1) goto err;


	if (test_sm2_z256_point_dbl_infinity() != 1) goto err;
	if (test_sm2_z256_point_ops() != 1) goto err;

	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
