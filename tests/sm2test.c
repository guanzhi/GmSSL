/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/asn1.h>
#include <gmssl/error.h>
#include <gmssl/sm2.h>
#include <gmssl/pkcs8.h>

#define sm2_print_bn(label,a) sm2_bn_print(stderr,0,0,label,a) // 这个不应该放在这里，应该放在测试文件中


#define hex_fp_add_x_y "eefbe4cf140ff8b5b956d329d5a2eae8608c933cb89053217439786e54866567"
#define hex_fp_sub_x_y "768d77882a23097d05db3562fed0a840bf3984422c3bc4a26e7b12a412128426"
#define hex_fp_sub_y_x "89728876d5dcf682fa24ca9d012f57bf40c67bbcd3c43b5e9184ed5beded7bd9"
#define hex_fp_neg_x   "cd3b51d2e0e67ee6a066fbb995c6366b701cf43f0d99f41f8ea5ba76ccb38b38"
#define hex_fp_mul_x_y "edd7e745bdc4630ccfa1da1057033a525346dbf202f082f3c431349991ace76a"
#define hex_fp_squ_x   "f4e2cca0bcfd67fba8531eebff519e4cb3d47f9fe8c5eff5151f4c497ec99fbf"
#define hex_fp_exp_x_y "8cafd11b1a0d2072b82911ba87e0d376103a1be5986fce91d8d297b758f68146"
#define hex_fp_inv_x   "053b878fb82e213c17e554b9a574b7bd31775222704b7fd9c7d6f8441026cd80"

#define hex_fn_add_x_y "eefbe4cf140ff8b5b956d329d5a2eae8608c933cb89053217439786e54866567"
#define hex_fn_sub_x_y "768d77882a23097d05db3562fed0a840313d63ae4e01c9ccc23706ad4be7c54a"
#define hex_fn_sub_y_x "89728876d5dcf682fa24ca9d012f57bf40c67bbcd3c43b5e9184ed5beded7bd9"
#define hex_fn_neg_x   "cd3b51d2e0e67ee6a066fbb995c6366ae220d3ab2f5ff949e261ae800688cc5c"
#define hex_fn_mul_x_y "cf7296d5cbf0b64bb5e9a11b294962e9c779b41c038e9c8d815234a0df9d6623"
#define hex_fn_sqr_x   "82d3d1b296d3a3803888b7ffc78f23eca824e7ec8d7ddaf231ffb0d256a19da2"
#define hex_fn_exp_x_y "0cf4df7e76d7d49ff23b94853a98aba1e36e9ca0358acbf23a3bbda406f46df3"
#define hex_fn_inv_x   "96340ec8b80f44e9b345a706bdb5c9e3ab8a6474a5cb4e0d4645dbaecf1cf03d"
#define hex_v          "d3da0ef661be97360e1b32f834e6ca5673b1984b22bb420133da05e56ccd59fb"
#define hex_fn_mul_x_v "0375c61e1ed13e460f4b5d462dc5b2c846f36c7b481cd4bed8f7dd55908a6afd"

#define hex_t		"2fbadf57b52dc19e8470bf201cb182e0a4f7fa5e28d356b15da173132b94b325"


int test_sm2_bn(void)
{
	const SM2_JACOBIAN_POINT _G = {
		{
		0x334c74c7, 0x715a4589, 0xf2660be1, 0x8fe30bbf,
		0x6a39c994, 0x5f990446, 0x1f198119, 0x32c4ae2c,
		},
		{
		0x2139f0a0, 0x02df32e5, 0xc62a4740, 0xd0a9877c,
		0x6b692153, 0x59bdcee3, 0xf4f6779c, 0xbc3736a2,
		},
		{
		1, 0, 0, 0, 0, 0, 0, 0,
		},
	};
	const SM2_JACOBIAN_POINT *G = &_G;
	SM2_BN r;
	SM2_BN x;
	SM2_BN y;
	int ok, i = 1;

	char hex[65];

	SM2_BN v = {
		0x6ccd59fb, 0x33da05e5, 0x22bb4201, 0x73b1984b,
		0x34e6ca56, 0x0e1b32f8, 0x61be9736, 0xd3da0ef6,
	};

	SM2_BN t;

	sm2_bn_copy(x, G->X);
	sm2_bn_copy(y, G->Y);

	sm2_bn_from_hex(r, hex_v);
	ok = (sm2_bn_cmp(r, v) == 0);
	printf("sm2 bn test %d %s\n", i++, ok ? "ok" : "failed");
	if (!ok) return -1;

	// fp tests
	sm2_fp_add(r, x, y);
	ok = sm2_bn_equ_hex(r, hex_fp_add_x_y);
	printf("sm2 bn test %d %s\n", i++, ok ? "ok" : "failed");
	if (!ok) return -1;

	sm2_fp_sub(r, x, y);
	ok = sm2_bn_equ_hex(r, hex_fp_sub_x_y);
	printf("sm2 bn test %d %s\n", i++, ok ? "ok" : "failed");
	if (!ok) return -1;

	sm2_fp_mul(r, x, y);
	ok = sm2_bn_equ_hex(r, hex_fp_mul_x_y);
	printf("sm2 bn test %d %s\n", i++, ok ? "ok" : "failed");
	if (!ok) return -1;

	sm2_fp_exp(r, x, y);
	ok = sm2_bn_equ_hex(r, hex_fp_exp_x_y);
	printf("sm2 bn test %d %s\n", i++, ok ? "ok" : "failed");
	if (!ok) return -1;

	sm2_fp_inv(r, x);
	ok = sm2_bn_equ_hex(r, hex_fp_inv_x);
	printf("sm2 bn test %d %s\n", i++, ok ? "ok" : "failed");
	if (!ok) return -1;

	sm2_fp_neg(r, x);
	ok = sm2_bn_equ_hex(r, hex_fp_neg_x);
	printf("sm2 bn test %d %s\n", i++, ok ? "ok" : "failed");
	if (!ok) return -1;

	// fn tests
	sm2_fn_add(r, x, y);
	ok = sm2_bn_equ_hex(r, hex_fn_add_x_y);
	printf("sm2 bn test %d %s\n", i++, ok ? "ok" : "failed");
	if (!ok) return -1;

	sm2_fn_sub(r, x, y);
	ok = sm2_bn_equ_hex(r, hex_fn_sub_x_y);
	printf("sm2 bn test %d %s\n", i++, ok ? "ok" : "failed");
	if (!ok) return -1;

	sm2_fn_sub(r, y, x);
	ok = sm2_bn_equ_hex(r, hex_fn_sub_y_x);
	printf("sm2 bn test %d %s\n", i++, ok ? "ok" : "failed");
	if (!ok) return -1;

	sm2_fn_neg(r, x);
	ok = sm2_bn_equ_hex(r, hex_fn_neg_x);
	printf("sm2 bn test %d %s\n", i++, ok ? "ok" : "failed");
	if (!ok) return -1;

	sm2_fn_mul(r, x, y);
	ok = sm2_bn_equ_hex(r, hex_fn_mul_x_y);
	printf("sm2 bn test %d %s\n", i++, ok ? "ok" : "failed");
	if (!ok) return -1;

	sm2_fn_mul(r, x, v);
	ok = sm2_bn_equ_hex(r, hex_fn_mul_x_v);
	printf("sm2 bn test %d %s\n", i++, ok ? "ok" : "failed");
	if (!ok) return -1;

	sm2_fn_sqr(r, x);
	ok = sm2_bn_equ_hex(r, hex_fn_sqr_x);
	printf("sm2 bn test %d %s\n", i++, ok ? "ok" : "failed");
	if (!ok) return -1;

	sm2_fn_exp(r, x, y);
	ok = sm2_bn_equ_hex(r, hex_fn_exp_x_y);
	printf("sm2 bn test %d %s\n", i++, ok ? "ok" : "failed");
	if (!ok) return -1;

	sm2_fn_inv(r, x);
	ok = sm2_bn_equ_hex(r, hex_fn_inv_x);
	printf("sm2 bn test %d %s\n", i++, ok ? "ok" : "failed");
	if (!ok) return -1;

	SM2_BN tv = {
		0x2b94b325, 0x5da17313, 0x28d356b1, 0xa4f7fa5e,
		0x1cb182e0, 0x8470bf20, 0xb52dc19e, 0x2fbadf57,
	};
	sm2_bn_from_hex(t, hex_t);
	ok = (sm2_bn_cmp(t, tv) == 0);
	if (!ok) return -1;

	sm2_bn_to_hex(t, hex);

	return 1;
}


#define hex_G \
	"32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7" \
	"bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0"
#define hex_2G \
	"56cefd60d7c87c000d58ef57fa73ba4d9c0dfa08c08a7331495c2e1da3f2bd52" \
	"31b7e7e6cc8189f668535ce0f8eaf1bd6de84c182f6c8e716f780d3a970a23c3"
#define hex_3G \
	"a97f7cd4b3c993b4be2daa8cdb41e24ca13f6bd945302244e26918f1d0509ebf" \
	"530b5dd88c688ef5ccc5cec08a72150f7c400ee5cd045292aaacdd037458f6e6"
#define hex_negG \
	"32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7" \
	"43c8c95c0b098863a642311c9496deac2f56788239d5b8c0fd20cd1adec60f5f"
#define hex_10G \
	"d3f94862519621c121666061f65c3e32b2d0d065cd219e3284a04814db522756" \
	"4b9030cf676f6a742ebd57d146dca428f6b743f64d1482d147d46fb2bab82a14"
#define hex_bG \
	"528470bc74a6ebc663c06fc4cfa1b630d1e9d4a80c0a127b47f73c324c46c0ba" \
	"832cf9c5a15b997e60962b4cf6e2c9cee488faaec98d20599d323d4cabfc1bf4"

#define hex_P \
	"504cfe2fae749d645e99fbb5b25995cc6fed70196007b039bdc44706bdabc0d9" \
	"b80a8018eda5f55ddc4b870d7784b7b84e53af02f575ab53ed8a99a3bbe2abc2"
#define hex_2P \
	"a53d20e89312b5243f66aec12ef6471f5911941d86302d5d8337cb70937d65ae" \
	"96953c46815e4259363256ddd6c77fcc33787aeafc6a57beec5833f476dd69e0"

#define hex_tP \
	"02deff2c5b3656ca3f7c7ca9d710ca1d69860c75a9c7ec284b96b8adc50b2936" \
	"b74bcba937e9267fce4ccc069a6681f5b04dcedd9e2794c6a25ddc7856df7145"


int test_sm2_jacobian_point(void)
{
	const SM2_JACOBIAN_POINT _G = {
		{
		0x334c74c7, 0x715a4589, 0xf2660be1, 0x8fe30bbf,
		0x6a39c994, 0x5f990446, 0x1f198119, 0x32c4ae2c,
		},
		{
		0x2139f0a0, 0x02df32e5, 0xc62a4740, 0xd0a9877c,
		0x6b692153, 0x59bdcee3, 0xf4f6779c, 0xbc3736a2,
		},
		{
		1, 0, 0, 0, 0, 0, 0, 0,
		},
	};
	const SM2_BN _B = {
		0x4d940e93, 0xddbcbd41, 0x15ab8f92, 0xf39789f5,
		0xcf6509a7, 0x4d5a9e4b, 0x9d9f5e34, 0x28e9fa9e,
	};
	const SM2_JACOBIAN_POINT *G = &_G;
	SM2_JACOBIAN_POINT _P, *P = &_P;
	SM2_BN k;
	int i = 1, ok;

	uint8_t buf[64];

	printf("sm2_jacobian_point_test\n");

	ok = sm2_jacobian_point_equ_hex(G, hex_G);
	printf("sm2 point test %d %s\n", i++, ok ? "ok" : "failed");
	if (!ok) return -1;

	ok = sm2_jacobian_point_is_on_curve(G);
	printf("sm2 point test %d %s\n", i++, ok ? "ok" : "failed");
	if (!ok) return -1;

	sm2_jacobian_point_dbl(P, G);
	ok = sm2_jacobian_point_equ_hex(P, hex_2G);
	printf("sm2 point test %d %s\n", i++, ok ? "ok" : "failed");
	if (!ok) return -1;

	sm2_jacobian_point_add(P, P, G);
	ok = sm2_jacobian_point_equ_hex(P, hex_3G);
	printf("sm2 point test %d %s\n", i++, ok ? "ok" : "failed");
	if (!ok) return -1;

	sm2_jacobian_point_sub(P, P, G);
	ok = sm2_jacobian_point_equ_hex(P, hex_2G);
	printf("sm2 point test %d %s\n", i++, ok ? "ok" : "failed");
	if (!ok) return -1;

	sm2_jacobian_point_neg(P, G);
	ok = sm2_jacobian_point_equ_hex(P, hex_negG);
	printf("sm2 point test %d %s\n", i++, ok ? "ok" : "failed");
	if (!ok) return -1;

	sm2_bn_set_word(k, 10);
	sm2_jacobian_point_mul(P, k, G);
	ok = sm2_jacobian_point_equ_hex(P, hex_10G);
	printf("sm2 point test %d %s\n", i++, ok ? "ok" : "failed");
	if (!ok) return -1;

	sm2_jacobian_point_mul_generator(P, _B);
	ok = sm2_jacobian_point_equ_hex(P, hex_bG);
	printf("sm2 point test %d %s\n", i++, ok ? "ok" : "failed");
	if (!ok) return -1;

	sm2_jacobian_point_to_bytes(P, buf);
	sm2_jacobian_point_from_hex(P, hex_P);

	return 1;
}

#define hex_d   "5aebdfd947543b713bc0df2c65baaecc5dadd2cab39c6971402daf92c263fad2"
#define hex_e   "c0881c19beec741b9af27cc26493dcc33b05d481bfeab2f3ce9cc056e6ff8400"
#define hex_k   "981325ee1ab171e9d2cffb317181a02957b18a34bca610a6d2f8afcdeb53f6b8"
#define hex_x1  "17d2dfe83f23cce8499bca983950d59f0fd56c4c671dd63c04b27e4e94cfd767"
#define hex_r   "d85afc01fe104103e48e475a9de4b2624adb40ce2708892fd34f3ea57bcf5b67"
#define hex_rd  "a70ba64f9c30e05095f39fe26675114e3f157b2c35191bf6ff06246452f82eb3"
#define hex_di  "3ecfdb51c24b0eecb2d4238d1da8c013b8b575cef14ef43e2ddb7bce740ce9cf"
#define hex_krd "f1077f9d7e8091993cdc5b4f0b0c8eda8a9fee73a952f9db27ae7f72d2310928"
#define hex_s   "006bac5b8057ca829534dfde72a0d7883444a3b9bfe9bcdfb383fb90ed7d9486"


static int test_sm2_point(void)
{
	SM2_POINT P, Q;
	uint8_t k[32] = {0};
	uint8_t buf[65] = {0};
	int i;

	for (i = 1; i < 8; i++) {
		k[31] = (uint8_t)i;

		if (sm2_point_mul_generator(&P, k) != 1
			|| sm2_point_is_on_curve(&P) != 1) {
			error_print();
			return -1;
		}
		format_print(stderr, 0, 0, "k = %d, ", i);
		sm2_point_print(stderr, 0, 0, "k * G", &P);

		memset(buf, 0, sizeof(buf));
		sm2_point_to_compressed_octets(&P, buf);
		format_bytes(stderr, 0, 4, "compressedPoint", buf, 33);
		memset(&Q, 0, sizeof(Q));
		if (sm2_point_from_x(&Q, buf + 1, buf[0]) != 1
			|| memcmp(&P, &Q, sizeof(SM2_POINT)) != 0) {

			sm2_point_print(stderr, 0, 4, "P", &P);
			sm2_point_print(stderr, 0, 4, "Q", &Q);

			error_print();
			return -1;
		}

		memset(buf, 0, sizeof(buf));
		sm2_point_to_uncompressed_octets(&P, buf);
		format_bytes(stderr, 0, 4, "compressedPoint", buf, 65);
		memset(&Q, 0, sizeof(Q));
		if (sm2_point_from_octets(&Q, buf, 65) != 1
			|| memcmp(&P, &Q, sizeof(SM2_POINT)) != 0) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_point_der(void)
{
	SM2_POINT P, Q;
	uint8_t k[32] = {0};
	uint8_t buf[512];
	int i;

	for (i = 1; i < 8; i++) {
		uint8_t *p = buf;
		const uint8_t *cp = buf;
		size_t len = 0;

		k[31] = i;
		memset(&P, 0, sizeof(P));
		memset(&Q, 0, sizeof(Q));

		if (sm2_point_mul_generator(&P, k) != 1
			|| sm2_point_to_der(&P, &p, &len) != 1
			|| format_bytes(stderr, 0, 4, "ECPoint", buf, len) != 1
			|| sm2_point_from_der(&Q, &cp, &len) != 1
			|| asn1_length_is_zero(len) != 1) {
			error_print();
			return -1;
		}
		if (memcmp(&P, &Q, sizeof(SM2_POINT)) != 0) {
			error_print();
			sm2_point_print(stderr, 0, 4, "P", &P);
			sm2_point_print(stderr, 0, 4, "Q", &Q);
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_point_octets(void)
{
	SM2_POINT P, Q;
	uint8_t k[32] = {0};
	uint8_t buf[33];
	int i;

	for (i = 1; i < 8; i++) {
		uint8_t *p = buf;
		const uint8_t *cp = buf;
		size_t len = 0;

		k[31] = i;
		memset(&P, 0, sizeof(P));
		memset(&Q, 0, sizeof(Q));

		if (sm2_point_mul_generator(&P, k) != 1) {
			error_print();
			return -1;
		}
		sm2_point_to_compressed_octets(&P, buf);
		format_bytes(stderr, 0, 4, "compressedPoint", buf, sizeof(buf));
		if (sm2_point_from_octets(&Q, buf, sizeof(buf)) != 1) {
			error_print();
			return -1;
		}
		if (memcmp(&P, &Q, sizeof(SM2_POINT)) != 0) {
			error_print();
			sm2_point_print(stderr, 0, 4, "P", &P);
			sm2_point_print(stderr, 0, 4, "Q", &Q);
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_point_from_x(void)
{
	SM2_POINT P, Q;
	uint8_t k[32] = {0};
	uint8_t buf[33];
	int i;

	for (i = 1; i < 8; i++) {
		uint8_t *p = buf;
		const uint8_t *cp = buf;
		size_t len = 0;

		k[31] = i;
		memset(&P, 0, sizeof(P));
		memset(&Q, 0, sizeof(Q));

		if (sm2_point_mul_generator(&P, k) != 1) {
			error_print();
			return -1;
		}
		sm2_point_to_compressed_octets(&P, buf);
		if (sm2_point_from_x(&Q, buf + 1, buf[0]) != 1) {
			error_print();
			return -1;
		}
		if (memcmp(&P, &Q, sizeof(SM2_POINT)) != 0) {
			error_print();
			sm2_point_print(stderr, 0, 4, "P", &P);
			sm2_point_print(stderr, 0, 4, "Q", &Q);
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_signature(void)
{
	SM2_SIGNATURE sig;
	uint8_t buf[512];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	// MinLen
	memset(&sig, 0x00, sizeof(sig));
	cp = p = buf; len = 0;
	if (sm2_signature_to_der(&sig, &p, &len) != 1) {
		error_print();
		return -1;
	}
	format_print(stderr, 0, 4, "SM2_MIN_SIGNATURE_SIZE: %zu\n", len);
	format_bytes(stderr, 0, 4, "", buf, len);
	sm2_signature_print(stderr, 0, 4, "signature", buf, len);
	if (len != SM2_MIN_SIGNATURE_SIZE) {
		error_print();
		return -1;
	}
	if (sm2_signature_from_der(&sig, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}


	// MaxLen
	memset(&sig, 0x80, sizeof(sig));
	cp = p = buf; len = 0;
	if (sm2_signature_to_der(&sig, &p, &len) != 1) {
		error_print();
		return -1;
	}
	format_print(stderr, 0, 4, "SM2_MAX_SIGNATURE_SIZE: %zu\n", len);
	format_bytes(stderr, 0, 4, "", buf, len);
	sm2_signature_print(stderr, 0, 4, "signature", buf, len);
	if (len != SM2_MAX_SIGNATURE_SIZE) {
		error_print();
		return -1;
	}
	if (sm2_signature_from_der(&sig, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}


	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_sign(void)
{
	int ret;
	SM2_KEY sm2_key;
	SM2_SIGN_CTX sign_ctx;
	uint8_t msg[] = "Hello World!";
	uint8_t sig[SM2_MAX_SIGNATURE_SIZE] = {0};
	size_t siglen;

	if (sm2_key_generate(&sm2_key) != 1) {
		error_print();
		return -1;
	}
	sm2_key_print(stderr, 0, 4, "SM2_KEY", &sm2_key);

	if (sm2_sign_init(&sign_ctx, &sm2_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1
		|| sm2_sign_update(&sign_ctx, msg, sizeof(msg)) != 1
		|| sm2_sign_finish(&sign_ctx, sig, &siglen) != 1) {
		error_print();
		return -1;
	}
	format_bytes(stderr, 0, 4, "signature", sig, siglen);
	sm2_signature_print(stderr, 0, 4, "signature", sig, siglen);

	if (sm2_verify_init(&sign_ctx, &sm2_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1
		|| sm2_verify_update(&sign_ctx, msg, sizeof(msg)) != 1
		|| (ret = sm2_verify_finish(&sign_ctx, sig, siglen)) != 1) {
		error_print();
		return -1;
	}
	format_print(stderr, 0, 4, "verification: %s\n", ret ? "success" : "failed");


	// FIXME: 还应该增加验证不通过的测试
	// 还应该增加底层的参数
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

// 由于当前Ciphertext中椭圆曲线点数据不正确，因此无法通过测试
static int test_sm2_ciphertext(void)
{
	SM2_CIPHERTEXT C;
	uint8_t buf[1024];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	memset(&C, 0, sizeof(SM2_CIPHERTEXT));

	cp = p = buf; len = 0;
	if (sm2_ciphertext_to_der(&C, &p, &len) != 1) {
		error_print();
		return -1;
	}
	format_print(stderr, 0, 4, "SM2_NULL_CIPHERTEXT_SIZE: %zu\n", len);
	format_bytes(stderr, 0, 4, "", buf, len);


	if (sm2_ciphertext_from_der(&C, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}


	// {0, 0, Hash, MinLen}
	C.ciphertext_size = SM2_MIN_PLAINTEXT_SIZE;
	cp = p = buf; len = 0;
	if (sm2_ciphertext_to_der(&C, &p, &len) != 1) {
		error_print();
		return -1;
	}
	format_print(stderr, 0, 4, "SM2_MIN_PLAINTEXT_SIZE: %zu\n", SM2_MIN_PLAINTEXT_SIZE);
	format_print(stderr, 0, 4, "SM2_MIN_CIPHERTEXT_SIZE: %zu\n", len);
	format_bytes(stderr, 0, 4, "", buf, len);
	if (len != SM2_MIN_CIPHERTEXT_SIZE) {
		error_print();
		return -1;
	}
	if (sm2_ciphertext_from_der(&C, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}

	// { 33, 33, Hash, NULL }
	memset(&C, 0x80, sizeof(SM2_POINT));
	cp = p = buf; len = 0;
	if (sm2_ciphertext_to_der(&C, &p, &len) != 1) {
		error_print();
		return -1;
	}
	format_print(stderr, 0, 4, "ciphertext len: %zu\n", len);
	format_bytes(stderr, 0, 4, "", buf, len);
	if (sm2_ciphertext_from_der(&C, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}

	// { 33, 33, Hash, MaxLen }
	C.ciphertext_size = SM2_MAX_PLAINTEXT_SIZE;//SM2_MAX_PLAINTEXT_SIZE;
	cp = p = buf; len = 0;
	if (sm2_ciphertext_to_der(&C, &p, &len) != 1) {
		error_print();
		return -1;
	}
	format_print(stderr, 0, 4, "SM2_MAX_PLAINTEXT_SIZE: %zu\n", SM2_MAX_PLAINTEXT_SIZE);
	format_print(stderr, 0, 4, "SM2_MAX_CIPHERTEXT_SIZE: %zu\n", len);
	format_bytes(stderr, 0, 4, "", buf, len);
	if (len != SM2_MAX_CIPHERTEXT_SIZE) {
		error_print();
		return -1;
	}
	if (sm2_ciphertext_from_der(&C, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}


static int test_sm2_do_encrypt(void)
{
	SM2_KEY sm2_key;
	uint8_t plaintext[] = "Hello World!";
	SM2_CIPHERTEXT ciphertext;

	uint8_t plainbuf[SM2_MAX_PLAINTEXT_SIZE] = {0};
	size_t plainlen = 0;
	int r = 0;

	if (sm2_key_generate(&sm2_key) != 1) {
		error_print();
		return -1;
	}

	if (sm2_do_encrypt(&sm2_key, plaintext, sizeof(plaintext), &ciphertext) != 1
		|| sm2_do_decrypt(&sm2_key, &ciphertext, plainbuf, &plainlen) != 1) {
		error_print();
		return -1;
	}

	if (plainlen != sizeof(plaintext)
		|| memcmp(plainbuf, plaintext, sizeof(plaintext)) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}


static int test_sm2_encrypt(void)
{
	SM2_KEY sm2_key;
	uint8_t msg[SM2_MAX_PLAINTEXT_SIZE];
	uint8_t cbuf[SM2_MAX_CIPHERTEXT_SIZE+100];
	uint8_t mbuf[SM2_MAX_CIPHERTEXT_SIZE];
	size_t lens[] = {
//		0,
		1,
		16,
		SM2_MAX_PLAINTEXT_SIZE,
	};
	size_t clen, mlen;
	int i;

	if (sm2_key_generate(&sm2_key) != 1) {
		error_print();
		return -1;
	}

	for (i = 0; i < sizeof(msg); i++) {
		msg[i] = (uint8_t)i;
	}

	for (i = 0; i < sizeof(lens)/sizeof(lens[0]); i++) {
		format_print(stderr, 0, 0, "test %d\n", i + 1);
		format_bytes(stderr, 0, 4, "plaintext", msg, lens[i]);
		if (sm2_encrypt(&sm2_key, msg, lens[i], cbuf, &clen) != 1) {
			error_print();
			return -1;
		}
		format_bytes(stderr, 0, 4, "ciphertext", cbuf, clen);
		sm2_ciphertext_print(stderr, 0, 4, "Ciphertext", cbuf, clen);
		format_print(stderr, 0, 0, "\n");

		if (sm2_decrypt(&sm2_key, cbuf, clen, mbuf, &mlen) != 1) {
			error_print();
			return -1;
		}
		if (mlen != lens[i]
			|| memcmp(mbuf, msg, lens[i]) != 0) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}



static int test_sm2_private_key(void)
{
	SM2_KEY sm2_key;
	SM2_KEY tmp_key;
	uint8_t buf[SM2_PRIVATE_KEY_BUF_SIZE];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	const uint8_t *d;
	size_t dlen;

	if (sm2_key_generate(&sm2_key) != 1) {
		error_print();
		return -1;
	}
	sm2_key_print(stderr, 0, 4, "SM2_KEY", &sm2_key);

	if (sm2_private_key_to_der(&sm2_key, &p, &len) != 1) {
		error_print();
		return -1;
	}
	format_bytes(stderr, 0, 4, "ECPrivateKey", buf, len);
	format_print(stderr, 0, 4, "#define SM2_PRIVATE_KEY_DEFAULT_SIZE %zu\n", len);
	if (sm2_private_key_from_der(&tmp_key, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}

	if (memcmp(&tmp_key, &sm2_key, sizeof(SM2_KEY)) != 0) {

		sm2_key_print(stderr, 0, 0, "sm2_key", &sm2_key);
		sm2_key_print(stderr, 0, 0, "tmp_key", &tmp_key);


		error_print();
		return -1;
	}

	cp = p = buf; len = 0;
	memset(&tmp_key, 0, sizeof(tmp_key));
	if (sm2_private_key_to_der(&sm2_key, &p, &len) != 1
		|| asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	sm2_private_key_print(stderr, 0, 4, "ECPrivateKey", d, dlen);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_private_key_info(void)
{
	uint8_t buf[512];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	const uint8_t *d;
	size_t dlen;

	SM2_KEY sm2_key;
	SM2_KEY tmp_key;
	const uint8_t *attrs;
	size_t attrs_len;

	if (sm2_key_generate(&sm2_key) != 1) {
		error_print();
		return -1;
	}
	sm2_key_print(stderr, 0, 4, "SM2_KEY", &sm2_key);

	if (sm2_private_key_info_to_der(&sm2_key, &p, &len) != 1) {
		error_print();
		return -1;
	}
	format_bytes(stderr, 0, 4, "PrivateKeyInfo", buf, len);
	format_print(stderr, 0, 4, "sizeof(PrivateKeyInfo): %zu\n", len);
	if (asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	sm2_private_key_info_print(stderr, 0, 4, "PrivateKeyInfo", d, dlen);

	cp = p = buf; len = 0;
	if (sm2_private_key_info_to_der(&sm2_key, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (sm2_private_key_info_from_der(&tmp_key, &attrs, &attrs_len, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1
		|| memcmp(&tmp_key, &sm2_key, sizeof(SM2_KEY)) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_enced_private_key_info(void)
{
	uint8_t buf[512];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;
	const uint8_t *d;
	size_t dlen;

	SM2_KEY sm2_key;
	SM2_KEY tmp_key;
	const uint8_t *attrs;
	size_t attrs_len;
	const char *pass = "Password";

	if (sm2_key_generate(&sm2_key) != 1) {
		error_print();
		return -1;
	}
	sm2_key_print(stderr, 0, 4, "SM2_KEY", &sm2_key);

	if (sm2_private_key_info_encrypt_to_der(&sm2_key, pass, &p, &len) != 1) {
		error_print();
		return -1;
	}
	format_bytes(stderr, 0, 4, "EncryptedPrivateKeyInfo", buf, len);
	format_print(stderr, 0, 4, "sizeof(EncryptedPrivateKeyInfo): %zu\n", len);
	if (asn1_sequence_from_der(&d, &dlen, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	pkcs8_enced_private_key_info_print(stderr, 0, 4, "EncryptedPrivateKeyInfo", d, dlen);


	cp = p = buf; len = 0;
	if (sm2_private_key_info_encrypt_to_der(&sm2_key, pass, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (sm2_private_key_info_decrypt_from_der(&tmp_key, &attrs, &attrs_len, pass, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1
		|| memcmp(&tmp_key, &sm2_key, sizeof(SM2_KEY)) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}


int main(void)
{
	if (test_sm2_bn()  != 1) goto err;
	if (test_sm2_jacobian_point() != 1) goto err;
	if (test_sm2_point() != 1) goto err;
	if (test_sm2_point_octets() != 1) goto err;
	if (test_sm2_point_from_x() != 1) goto err;
	if (test_sm2_point_der() != 1) goto err;
	if (test_sm2_private_key() != 1) goto err;
	if (test_sm2_private_key_info() != 1) goto err;
	if (test_sm2_enced_private_key_info() != 1) goto err;
	if (test_sm2_signature() != 1) goto err;
	if (test_sm2_sign() != 1) goto err;
	//if (test_sm2_ciphertext() != 1) goto err; // 需要正确的Ciphertext数据
	if (test_sm2_do_encrypt() != 1) goto err;
	if (test_sm2_encrypt() != 1) goto err;
	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return -1;
}
