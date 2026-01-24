/*
 *  Copyright 2014-2026 The GmSSL Project. All Rights Reserved.
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
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include <gmssl/secp256r1.h>


static const char *secp256r1_p = "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF";
static const char *secp256r1_b = "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";
static const char *secp256r1_x = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
static const char *secp256r1_y = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
static const char *secp256r1_n = "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551";

static int test_secp256r1(void)
{
	secp256r1_t a;
	secp256r1_t b;
	secp256r1_t r;
	uint8_t buf[32];

	secp256r1_set_zero(a);
	if (!secp256r1_is_zero(a)) {
		error_print();
		return -1;
	}
	secp256r1_to_32bytes(a, buf);
	format_bytes(stderr, 0, 4, "0", buf, sizeof(buf));

	secp256r1_set_one(b);
	if (!secp256r1_is_one(b)) {
		error_print();
		return -1;
	}
	secp256r1_to_32bytes(b, buf);
	format_bytes(stderr, 0, 4, "1", buf, sizeof(buf));

	if (secp256r1_cmp(a, b) >= 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}


// 这个测试是有问题的，mod_add很多情况下是引发进位和借位的！			
static int test_secp256r1_modp(void)
{
	secp256r1_t x;
	secp256r1_t y;
	secp256r1_t r;
	secp256r1_t v;
	uint8_t buf[32];
	size_t len;

	hex_to_bytes("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 64, buf, &len);
	secp256r1_from_32bytes(x, buf);

	hex_to_bytes("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 64, buf, &len);
	secp256r1_from_32bytes(y, buf);

	secp256r1_modp_add(r, x, y);
	hex_to_bytes("bafb14d5df46c1e387a4d22fdfb3df08a2d1b0d8991c926fc05779ae1058148b", 64, buf, &len);
	secp256r1_from_32bytes(v, buf);
	if (secp256r1_cmp(r, v) != 0) {
		error_print();
		return -1;
	}

	secp256r1_modp_dbl(r, x);
	hex_to_bytes("d62fa3e5c258848ff179cdcac74881e4ee06fb025bd66741e942728bb131852c", 64, buf, &len);
	secp256r1_from_32bytes(v, buf);
	if (secp256r1_cmp(r, v) != 0) {
		error_print();
		return -1;
	}

	secp256r1_modp_tri(r, x);
	hex_to_bytes("414775d9a384c6d6ea36b4b02aecc2d7650a788289c19ae2dde3abd189ca47c3", 64, buf, &len);
	secp256r1_from_32bytes(v, buf);
	if (secp256r1_cmp(r, v) != 0) {
		error_print();
		return -1;
	}

	secp256r1_modp_sub(r, x, y);
	hex_to_bytes("1b348f0fe311c2ac69d4fb9ae794a2dc4b354a29c2b9d4d228eaf8dda0d970a1", 64, buf, &len);
	secp256r1_from_32bytes(v, buf);
	if (secp256r1_cmp(r, v) != 0) {

		error_print();
		return -1;
	}

	secp256r1_modp_sub(r, y, x);
	hex_to_bytes("e4cb70ef1cee3d54962b0465186b5d23b4cab5d73d462b2dd71507225f268f5e", 64, buf, &len);
	secp256r1_from_32bytes(v, buf);
	if (secp256r1_cmp(r, v) != 0) {
		error_print();
		return -1;
	}

	secp256r1_modp_neg(r, x);
	hex_to_bytes("94e82e0c1ed3bdb90743191a9c5bbf0d88fc827fd214cc5f0b5ec6ba27673d69", 64, buf, &len);
	secp256r1_from_32bytes(v, buf);
	if (secp256r1_cmp(r, v) != 0) {
		error_print();
		return -1;
	}

	secp256r1_modp_mul(r, x, y);
	hex_to_bytes("823cd15f6dd3c71933565064513a6b2bd183e554c6a08622f713ebbbface98be", 64, buf, &len);
	secp256r1_from_32bytes(v, buf);
	if (secp256r1_cmp(r, v) != 0) {
		error_print();
		return -1;
	}

	secp256r1_modp_sqr(r, x);
	hex_to_bytes("98f6b84d29bef2b281819a5e0e3690d833b699495d694dd1002ae56c426b3f8c", 64, buf, &len);
	secp256r1_from_32bytes(v, buf);
	if (secp256r1_cmp(r, v) != 0) {
		error_print();
		return -1;
	}

	secp256r1_modp_exp(r, x, y);
	hex_to_bytes("2f3db69bc9d93323c351f3e768d332806ad3a7652ea632e89e23312f7b5f9f96", 64, buf, &len);
	secp256r1_from_32bytes(v, buf);
	if (secp256r1_cmp(r, v) != 0) {
		error_print();
		return -1;
	}

	secp256r1_modp_inv(r, x);
	hex_to_bytes("e060cbb088706d5d24936933b69b16ab707d656273744b65664c49e577f35238", 64, buf, &len);
	secp256r1_from_32bytes(v, buf);
	if (secp256r1_cmp(r, v) != 0) {
		error_print();
		return -1;
	}

	secp256r1_modp_inv(r, y);
	hex_to_bytes("fa27a3da2c00618a828f8cd65c1a919effc67bf68b4dbb05bbdaa775c45d4034", 64, buf, &len);
	secp256r1_from_32bytes(v, buf);
	if (secp256r1_cmp(r, v) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}


static int test_secp256r1_modn(void)
{
	secp256r1_t x;
	secp256r1_t y;
	secp256r1_t r;
	secp256r1_t v;
	uint8_t buf[32];
	size_t len;

	hex_to_bytes("d62fa3e5c258848ff179cdcac74881e4ee06fb025bd66741e942728bb131852c", 64, buf, &len);
	secp256r1_from_32bytes(x, buf);

	hex_to_bytes("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 64, buf, &len);
	secp256r1_from_32bytes(y, buf);

	secp256r1_modn_add(r, x, y);
	hex_to_bytes("2612e6c9c073042a8061b91543581ffb5cee33ac1ff0278bc13ee830ec8db1d0", 64, buf, &len);
	secp256r1_from_32bytes(v, buf);
	if (secp256r1_cmp(r, v) != 0) {
		error_print();
		return -1;
	}

	secp256r1_modn_dbl(r, x);
	hex_to_bytes("ac5f47cc84b1091ee2f39b958e9103ca1f26fb5710952ffedecb1a5465ffe507", 64, buf, &len);
	secp256r1_from_32bytes(v, buf);
	if (secp256r1_cmp(r, v) != 0) {
		error_print();
		return -1;
	}

	secp256r1_modn_tri(r, x);
	hex_to_bytes("828eebb347098dadd46d696055d985af5046fbabc553f8bbd453c21d1ace44e2", 64, buf, &len);
	secp256r1_from_32bytes(v, buf);
	if (secp256r1_cmp(r, v) != 0) {
		error_print();
		return -1;
	}

	secp256r1_modn_sub(r, x, y);
	hex_to_bytes("864c6102c43e04f46291e2804b38e3cec238c7aaf0a508731d8c322379723337", 64, buf, &len);
	secp256r1_from_32bytes(v, buf);
	if (secp256r1_cmp(r, v) != 0) {
		error_print();
		return -1;
	}

	secp256r1_modn_sub(r, y, x);
	hex_to_bytes("79b39efc3bc1fb0c9d6e1d7fb4c71c30faae3302b6729611d62d989f82f0f21a", 64, buf, &len);
	secp256r1_from_32bytes(v, buf);
	if (secp256r1_cmp(r, v) != 0) {
		error_print();
		return -1;
	}

	secp256r1_modn_neg(r, x);
	hex_to_bytes("29d05c193da77b710e86323538b77e1acedfffab4b4137430a7758374b31a025", 64, buf, &len);
	secp256r1_from_32bytes(v, buf);
	if (secp256r1_cmp(r, v) != 0) {
		error_print();
		return -1;
	}

	secp256r1_modn_mul(r, x, y);
	hex_to_bytes("2a876a4e5df28cd6c2f3951aa6b65c55e2d6eb1883b463aee5d95035999c9a30", 64, buf, &len);
	secp256r1_from_32bytes(v, buf);
	if (secp256r1_cmp(r, v) != 0) {
		error_print();
		return -1;
	}

	secp256r1_modn_mul(r, y, x);
	hex_to_bytes("2a876a4e5df28cd6c2f3951aa6b65c55e2d6eb1883b463aee5d95035999c9a30", 64, buf, &len);
	secp256r1_from_32bytes(v, buf);
	if (secp256r1_cmp(r, v) != 0) {
		error_print();
		return -1;
	}

	secp256r1_modn_sqr(r, x);
	hex_to_bytes("22f25cab8043b82c9a5a6f0ca72c2122700737b557a11ba95ee80bddf671471f", 64, buf, &len);
	secp256r1_from_32bytes(v, buf);
	if (secp256r1_cmp(r, v) != 0) {
		error_print();
		return -1;
	}

	secp256r1_modn_exp(r, x, y);
	hex_to_bytes("31e8d728b341541057e09242800bcd7321b523284104340f3ac3bedb55b516c7", 64, buf, &len);
	secp256r1_from_32bytes(v, buf);
	if (secp256r1_cmp(r, v) != 0) {
		error_print();
		return -1;
	}

	secp256r1_modn_inv(r, x);
	hex_to_bytes("a546ddb0e12a46eedab8425e77558aa3e56b7fec1d73fd94c03235e2f2298172", 64, buf, &len);
	secp256r1_from_32bytes(v, buf);
	if (secp256r1_cmp(r, v) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}



static int test_secp256r1_point_at_infinity(void)
{
	SECP256R1_POINT P;
	secp256r1_point_set_infinity(&P);

	if (!secp256r1_point_is_at_infinity(&P)) {
		error_print();
		return -1;
	}
	secp256r1_point_print(stderr, 0, 4, "point_at_infinity", &P);

	if (!secp256r1_point_is_on_curve(&P)) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_secp256r1_point_set_xy(void)
{
	SECP256R1_POINT P;
	secp256r1_t x;
	secp256r1_t y;
	secp256r1_t x1;
	secp256r1_t y1;
	uint8_t bytes[32];
	size_t len;

	hex_to_bytes(secp256r1_x, 64, bytes, &len);
	secp256r1_from_32bytes(x, bytes);

	hex_to_bytes(secp256r1_y, 64, bytes, &len);
	secp256r1_from_32bytes(y, bytes);

	if (secp256r1_point_set_xy(&P, x, y) != 1) {
		error_print();
		return -1;
	}

	secp256r1_point_get_xy(&P, x1, y1);

	if (secp256r1_cmp(x, x1) != 0
		|| secp256r1_cmp(y, y1) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_secp256r1_point_is_on_curve(void)
{
	if (secp256r1_point_is_on_curve(&SECP256R1_POINT_G) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}


// 这两个计算是应该分开的！
static int test_secp256r1_point_dbl_add(void)
{
	SECP256R1_POINT P;
	SECP256R1_POINT Q;
	secp256r1_t x;
	secp256r1_t y;
	secp256r1_t x1;
	secp256r1_t y1;
	uint8_t bytes[32];
	size_t len;

	// test 2*G
	secp256r1_point_dbl(&P, &SECP256R1_POINT_G);
	secp256r1_point_get_xy(&P, x, y);

	secp256r1_point_print(stderr, 0, 4, "2*G", &P);

	hex_to_bytes("7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978", 64, bytes, &len);
	secp256r1_from_32bytes(x1, bytes);
	hex_to_bytes("07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1", 64, bytes, &len);
	secp256r1_from_32bytes(y1, bytes);

	if (secp256r1_cmp(x, x1) != 0 || secp256r1_cmp(y, y1) != 0) {
		error_print();
		return -1;
	}

	// test 2*G + G
	secp256r1_point_add(&Q, &P, &SECP256R1_POINT_G);
	secp256r1_point_get_xy(&Q, x, y);

	hex_to_bytes("5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c", 64, bytes, &len);
	secp256r1_from_32bytes(x1, bytes);
	hex_to_bytes("8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032", 64, bytes, &len);
	secp256r1_from_32bytes(y1, bytes);

	if (secp256r1_cmp(x, x1) != 0 || secp256r1_cmp(y, y1) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static const char *secp256r1_x_2G = "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978";
static const char *secp256r1_y_2G = "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1";
static const char *secp256r1_x_3G = "5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c";
static const char *secp256r1_y_3G = "8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032";


static int test_secp256r1_point_mul(void)
{
	SECP256R1_POINT P;
	secp256r1_t x;
	secp256r1_t y;
	secp256r1_t x1;
	secp256r1_t y1;
	secp256r1_t k;
	uint8_t bytes[32] = {0};
	size_t len;

	// k = 3
	bytes[31] = 3;
	secp256r1_from_32bytes(k, bytes);

	secp256r1_point_mul_generator(&P, k);
	secp256r1_point_get_xy(&P, x, y); // 这个必须返回错误啊，否则没办法判断是否为无穷远点呢！

	hex_to_bytes(secp256r1_x_3G, 64, bytes, &len);
	secp256r1_from_32bytes(x1, bytes);
	hex_to_bytes(secp256r1_y_3G, 64, bytes, &len);
	secp256r1_from_32bytes(y1, bytes);

	if (secp256r1_cmp(x, x1) != 0 || secp256r1_cmp(y, y1) != 0) {
		error_print();
		return -1;
	}

	// k = n
	hex_to_bytes(secp256r1_n, 64, bytes, &len);
	secp256r1_from_32bytes(k, bytes);

	secp256r1_point_mul_generator(&P, k);

	if (secp256r1_point_is_at_infinity(&P) != 1) {
		error_print();
		return -1;
	}


	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_secp256r1_point_to_uncompressed_octets(void)
{
	SECP256R1_POINT P;
	uint8_t octets[65];


	secp256r1_point_copy(&P, &SECP256R1_POINT_G);

	if (secp256r1_point_to_uncompressed_octets(&P, octets) != 1) {
		error_print();
		return -1;
	}
	if (secp256r1_point_from_uncompressed_octets(&P, octets) != 1) {
		error_print();
		return -1;
	}


	printf("%s() ok\n", __FUNCTION__);
	return 1;
}


int main(void)
{
	if (test_secp256r1() != 1) goto err;
	if (test_secp256r1_modp() != 1) goto err;
	if (test_secp256r1_modn() != 1) goto err;
	if (test_secp256r1_point_at_infinity() != 1) goto err;
	if (test_secp256r1_point_is_on_curve() != 1) goto err;
	if (test_secp256r1_point_set_xy() != 1) goto err;
	if (test_secp256r1_point_dbl_add() != 1) goto err;
	if (test_secp256r1_point_mul() != 1) goto err;
	if (test_secp256r1_point_to_uncompressed_octets() != 1) goto err;


	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
