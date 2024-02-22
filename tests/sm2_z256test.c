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
#include <gmssl/hex.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>

enum {
	OP_ADD,
	OP_SUB,
	OP_NEG,
	OP_MUL,
	OP_SQR,
	OP_EXP,
	OP_INV,
};

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
		case OP_SUB:
			sm2_z256_modp_sub(c, a, b);
			break;
		case OP_NEG:
			sm2_z256_modp_neg(c, a);
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
			sm2_z256_modn_to_mont(a, a);
			sm2_z256_modn_to_mont(b, b);
			sm2_z256_modn_mont_mul(c, a, b);
			sm2_z256_modn_from_mont(c, c);
			break;
		case OP_SQR:
			sm2_z256_modn_to_mont(a, a);
			sm2_z256_modn_mont_sqr(c, a);
			sm2_z256_modn_from_mont(c, c);
			break;
		case OP_EXP:
			sm2_z256_modn_to_mont(a, a);
			sm2_z256_modn_mont_exp(c, a, b);
			sm2_z256_modn_from_mont(c, c);
			break;
		case OP_INV:
			sm2_z256_modn_to_mont(a, a);
			sm2_z256_modn_mont_inv(c, a);
			sm2_z256_modn_from_mont(c, c);
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
		// k = G.x
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

int main(void)
{
	if (test_sm2_z256_modp() != 1) goto err;
	if (test_sm2_z256_modn() != 1) goto err;
	if (test_sm2_z256_point_mul_generator() != 1) goto err;
	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
