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
#include <gmssl/error.h>
#include <gmssl/secp384r1.h>


static const char *secp384r1_p = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF";
static const char *secp384r1_b = "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef";
static const char *secp384r1_x = "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7";
static const char *secp384r1_y = "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f";
static const char *secp384r1_n = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973";
static const char *secp384r1_2x = "08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61";
static const char *secp384r1_2y = "8e80f1fa5b1b3cedb7bfe8dffd6dba74b275d875bc6cc43e904e505f256ab4255ffd43e94d39e22d61501e700a940e80";
static const char *secp384r1_3x = "077a41d4606ffa1464793c7e5fdc7d98cb9d3910202dcd06bea4f240d3566da6b408bbae5026580d02d7e5c70500c831";
static const char *secp384r1_3y = "c995f7ca0b0c42837d0bbe9602a9fc998520b41c85115aa5f7684c0edc111eacc24abd6be4b5d298b65f28600a2f1df1";

static int secp384r1_from_hex(secp384r1_t r, const char *hex)
{
	uint8_t buf[48];
	size_t len;

	if (hex_to_bytes(hex, strlen(hex), buf, &len) != 1 || len != sizeof(buf)) {
		error_print();
		return -1;
	}
	return secp384r1_from_48bytes(r, buf);
}

static int secp384r1_check_hex(const secp384r1_t a, const char *hex)
{
	secp384r1_t v;

	if (secp384r1_from_hex(v, hex) != 1) {
		error_print();
		return -1;
	}
	if (secp384r1_cmp(a, v) != 0) {
		error_print();
		return -1;
	}
	return 1;
}

static int secp384r1_check_point_xy(const SECP384R1_POINT *P, const char *xhex, const char *yhex)
{
	secp384r1_t x;
	secp384r1_t y;

	if (secp384r1_point_get_xy(P, x, y) != 1) {
		error_print();
		return -1;
	}
	if (secp384r1_check_hex(x, xhex) != 1
		|| secp384r1_check_hex(y, yhex) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

static int test_secp384r1(void)
{
	secp384r1_t a;
	secp384r1_t b;
	secp384r1_t p;
	secp384r1_t n;
	uint8_t buf[48];

	if (secp384r1_set_zero(a) != 1 || !secp384r1_is_zero(a)) {
		error_print();
		return -1;
	}
	if (secp384r1_to_48bytes(a, buf) != 1) {
		error_print();
		return -1;
	}
	format_bytes(stderr, 0, 4, "0", buf, sizeof(buf));

	if (secp384r1_set_one(b) != 1 || !secp384r1_is_one(b)) {
		error_print();
		return -1;
	}
	if (secp384r1_to_48bytes(b, buf) != 1) {
		error_print();
		return -1;
	}
	format_bytes(stderr, 0, 4, "1", buf, sizeof(buf));

	if (secp384r1_cmp(a, b) >= 0) {
		error_print();
		return -1;
	}
	if (secp384r1_from_hex(p, secp384r1_p) != 1
		|| secp384r1_from_hex(b, secp384r1_b) != 1
		|| secp384r1_from_hex(n, secp384r1_n) != 1
		|| secp384r1_check_hex(p, secp384r1_p) != 1
		|| secp384r1_check_hex(b, secp384r1_b) != 1
		|| secp384r1_check_hex(n, secp384r1_n) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_secp384r1_modp(void)
{
	secp384r1_t x;
	secp384r1_t y;
	secp384r1_t r;

	if (secp384r1_from_hex(x, secp384r1_x) != 1
		|| secp384r1_from_hex(y, secp384r1_y) != 1) {
		error_print();
		return -1;
	}

	if (secp384r1_modp_add(r, x, y) != 1
		|| secp384r1_check_hex(r, "e09fa86d54b131a6ec505fde85b3899e6711591fb441b01543d172f43844e2f85f63a42bdcd3ab09b4977bb503601916") != 1) goto err;
	if (secp384r1_modp_dbl(r, x) != 1
		|| secp384r1_check_hex(r, "550f94457d160a6f1d638e3de6415ae8dc3a76c5174f3730b3ee83c104a85471aa05e4bc7eaa52d874a8bc6fe4ec156f") != 1) goto err;
	if (secp384r1_modp_tri(r, x) != 1
		|| secp384r1_check_hex(r, "ff975e683ba10fa6ac15555cd962085d4a57b227a2f6d2c90de5c5a186fc7ea9ff08d71a3dff7c44aefd1aa857622026") != 1) goto err;
	if (secp384r1_modp_sub(r, x, y) != 1
		|| secp384r1_check_hex(r, "746febd82864d8c831132e5f608dd14a75291da5630d871b701d10cccc6371784aa2408fa1d6a7cec01140bbe18bfc58") != 1) goto err;
	if (secp384r1_modp_sub(r, y, x) != 1
		|| secp384r1_check_hex(r, "8b901427d79b2737ceecd1a09f722eb58ad6e25a9cf278e48fe2ef33339c8e86b55dbf6f5e2958313feebf451e7403a7") != 1) goto err;
	if (secp384r1_modp_neg(r, x) != 1
		|| secp384r1_check_hex(r, "557835dd4174fac8714e38e10cdf528b91e2c49d74586467a608be1f7dabd5c6aafd0da140aad693c5aba1c88d89f548") != 1) goto err;
	if (secp384r1_modp_mul(r, x, y) != 1
		|| secp384r1_check_hex(r, "332e559389c970313cb29c4b55af5783821971a99c250daf84dc5d3cc441cb0a482e90de9d3ccd96b3c8c48b2ad3f025") != 1) goto err;
	if (secp384r1_modp_sqr(r, x) != 1
		|| secp384r1_check_hex(r, "046af925fa51ac496728217df5bc7c1fc3353aca34a380e1ffd8419fe7b13f6a92e8614fee38a288e2222412aca8b019") != 1) goto err;
	if (secp384r1_modp_exp(r, x, y) != 1
		|| secp384r1_check_hex(r, "e2f876012d77fd16b510933ebb40d33758751272874af587def1858002f128d8fa151410f114c9d8c8ff23f35add99fd") != 1) goto err;
	if (secp384r1_modp_inv(r, x) != 1
		|| secp384r1_check_hex(r, "1ce18121749aa29a393faddf4e55522af8c67dabdfa413aac45da5c5f0781147133e1c96ca2a8234440fbf89e7e96410") != 1) goto err;
	if (secp384r1_modp_inv(r, y) != 1
		|| secp384r1_check_hex(r, "9eee8231a5913c8aac5a8f03b92fee93f6d05a5777cb0bf87063909e7e5682f7a26736b36031e4006ecf009e5f9c8231") != 1) goto err;

	printf("%s() ok\n", __FUNCTION__);
	return 1;
err:
	error_print();
	return -1;
}

static int test_secp384r1_modn(void)
{
	secp384r1_t x;
	secp384r1_t y;
	secp384r1_t r;

	if (secp384r1_from_hex(x, secp384r1_x) != 1
		|| secp384r1_from_hex(y, secp384r1_y) != 1) {
		error_print();
		return -1;
	}

	if (secp384r1_modn_add(r, x, y) != 1
		|| secp384r1_check_hex(r, "e09fa86d54b131a6ec505fde85b3899e6711591fb441b01543d172f43844e2f85f63a42bdcd3ab09b4977bb503601916") != 1) goto err;
	if (secp384r1_modn_dbl(r, x) != 1
		|| secp384r1_check_hex(r, "550f94457d160a6f1d638e3de6415ae8dc3a76c5174f3730ec8b363f1071269151ebd70935f9ab5d87bca3061826ebfb") != 1) goto err;
	if (secp384r1_modn_tri(r, x) != 1
		|| secp384r1_check_hex(r, "ff975e683ba10fa6ac15555cd962085d4a57b227a2f6d2c94682781f92c550c9a6eec966f54ed4c9c211013e8a9cf6b2") != 1) goto err;
	if (secp384r1_modn_sub(r, x, y) != 1
		|| secp384r1_check_hex(r, "746febd82864d8c831132e5f608dd14a75291da5630d871b701d10cccc6371784aa2408fa1d6a7cec01140bbe18bfc58") != 1) goto err;
	if (secp384r1_modn_sub(r, y, x) != 1
		|| secp384r1_check_hex(r, "8b901427d79b2737ceecd1a09f722eb58ad6e25a9cf278e457463cb527d3bc670d77cd22a6d9ffac2cdad8aeeb392d1b") != 1) goto err;
	if (secp384r1_modn_neg(r, x) != 1
		|| secp384r1_check_hex(r, "557835dd4174fac8714e38e10cdf528b91e2c49d745864676d6c0ba171e303a703171b54895b7e0eb297bb325a4f1ebc") != 1) goto err;
	if (secp384r1_modn_mul(r, x, y) != 1
		|| secp384r1_check_hex(r, "2a8e172f52ea8a3f1864714efafb6588d0ed2fc509e9b4502bdd369bdbeeb9019f58804fbe958008223ba8752ead1f2c") != 1) goto err;
	if (secp384r1_modn_sqr(r, x) != 1
		|| secp384r1_check_hex(r, "a067a4d6fd10d2108a2d4649446529d5501f3734e9d5075a68178b74a7fb933b79d068c4f3d6e8585115c859fd9c0bc3") != 1) goto err;
	if (secp384r1_modn_exp(r, x, y) != 1
		|| secp384r1_check_hex(r, "0076a61817d4c4953212e870f68b9333672b79065de7009630493b17ee66d771779850e91be0594e4f0275f876ed8b58") != 1) goto err;
	if (secp384r1_modn_inv(r, x) != 1
		|| secp384r1_check_hex(r, "c0345088d98aa2f119e693230bbfb7a15f02792e7267cb55b3b0da1cb38a1c5d5f05c8d102d5128f524604074c4c8846") != 1) goto err;
	if (secp384r1_modn_inv(r, y) != 1
		|| secp384r1_check_hex(r, "195089baf8f5f0aff5c30a6cbde5b89a548ed7f739d253a675186a655eb60fe5e7973625ab399512e7a68c6b1bc8c167") != 1) goto err;

	printf("%s() ok\n", __FUNCTION__);
	return 1;
err:
	error_print();
	return -1;
}

static int test_secp384r1_mod_zero(void)
{
	secp384r1_t zero;
	secp384r1_t r;

	if (secp384r1_set_zero(zero) != 1) {
		error_print();
		return -1;
	}
	if (secp384r1_modp_neg(r, zero) != 1 || !secp384r1_is_zero(r)) {
		error_print();
		return -1;
	}
	if (secp384r1_modn_neg(r, zero) != 1 || !secp384r1_is_zero(r)) {
		error_print();
		return -1;
	}
	if (secp384r1_modp_inv(r, zero) != -1) {
		error_print();
		return -1;
	}
	if (secp384r1_modn_inv(r, zero) != -1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_secp384r1_point(void)
{
	SECP384R1_POINT P;
	SECP384R1_POINT Q;
	SECP384R1_POINT R;
	secp384r1_t k;
	secp384r1_t n;
	uint8_t octets[97];

	if (secp384r1_point_set_xy(&P, SECP384R1_POINT_G.X, SECP384R1_POINT_G.Y) != 1
		|| secp384r1_point_is_on_curve(&P) != 1) {
		error_print();
		return -1;
	}

	if (secp384r1_point_dbl(&Q, &P) != 1
		|| secp384r1_check_point_xy(&Q, secp384r1_2x, secp384r1_2y) != 1) {
		error_print();
		return -1;
	}
	if (secp384r1_point_add(&R, &P, &Q) != 1
		|| secp384r1_check_point_xy(&R, secp384r1_3x, secp384r1_3y) != 1) {
		error_print();
		return -1;
	}

	if (secp384r1_set_zero(k) != 1) {
		error_print();
		return -1;
	}
	k[0] = 3;
	if (secp384r1_point_mul_generator(&R, k) != 1
		|| secp384r1_check_point_xy(&R, secp384r1_3x, secp384r1_3y) != 1) {
		error_print();
		return -1;
	}
	if (secp384r1_from_hex(n, secp384r1_n) != 1
		|| secp384r1_point_mul_generator(&R, n) != 1
		|| !secp384r1_point_is_at_infinity(&R)) {
		error_print();
		return -1;
	}

	if (secp384r1_point_to_uncompressed_octets(&P, octets) != 1
		|| secp384r1_point_from_uncompressed_octets(&R, octets) != 1
		|| secp384r1_point_equ(&P, &R) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (test_secp384r1() != 1) goto err;
	if (test_secp384r1_modp() != 1) goto err;
	if (test_secp384r1_modn() != 1) goto err;
	if (test_secp384r1_mod_zero() != 1) goto err;
	if (test_secp384r1_point() != 1) goto err;
	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return -1;
}
