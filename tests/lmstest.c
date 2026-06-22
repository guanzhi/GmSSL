/*
 *  Copyright 2014-2025 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <gmssl/hex.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include <gmssl/lms.h>

static void test_print_elapsed(const char *func, clock_t start)
{
	printf("    %s() elapsed: %.3f seconds\n",
		func, (double)(clock() - start)/CLOCKS_PER_SEC);
}


static int lms_types[] = {
	LMS_SM3_M32_H5,
	LMS_SM3_M32_H5,
	LMS_SM3_M32_H5,
};

static int test_print_consts(void)
{
	format_print(stderr, 0, 4, "sizeof(LMS_PUBLIC_KEY): %zu\n", sizeof(LMS_PUBLIC_KEY));
	format_print(stderr, 0, 4, "LMS_PUBLIC_KEY_SIZE: %zu\n", LMS_PUBLIC_KEY_SIZE);
	format_print(stderr, 0, 4, "LMS_PRIVATE_KEY_SIZE: %zu\n", LMS_PRIVATE_KEY_SIZE);
	format_print(stderr, 0, 4, "sizeof(LMS_SIGNATURE): %zu\n", sizeof(LMS_SIGNATURE));
	format_print(stderr, 0, 4, "LMS_SIGNATURE_MAX_SIZE: %zu\n", LMS_SIGNATURE_MAX_SIZE);
	format_print(stderr, 0, 4, "sizeof(HSS_PUBLIC_KEY): %zu\n", sizeof(HSS_PUBLIC_KEY));
	format_print(stderr, 0, 4, "HSS_PUBLIC_KEY_SIZE: %zu\n", HSS_PUBLIC_KEY_SIZE);
	format_print(stderr, 0, 4, "HSS_PRIVATE_KEY_MAX_SIZE: %zu\n", HSS_PRIVATE_KEY_MAX_SIZE);
	format_print(stderr, 0, 4, "sizeof(HSS_SIGNATURE): %zu\n", sizeof(HSS_SIGNATURE));
	format_print(stderr, 0, 4, "HSS_SIGNATURE_MAX_SIZE: %zu\n", HSS_SIGNATURE_MAX_SIZE);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm3_hss_kat(void)
{
	static const char *sm3_hss_public_key =
		"00000002000000050000000e61a5d57d37f5e46bfb7520806b07a1b83d3bcaed"
		"9914f6c45640986637c1a14e5f7cc64bcc92b47ac318afd894b17544";
	static const char *sm3_hss_signature =
		"00000001000000050000000ed32b56671d7eb98833c49b433c272586bc4a1c8a"
		"8970528ffa04b966f9426eb9ab7e482480399fa6e357c683e14b55bc03989238"
		"3a55e93fa79abee02b261705d55980b4e2ccf6fb8042b17777e0474de1b43748"
		"3ca96302b5a69d2c3a4ab572f7a278014dd095b031a76f2f5fbc25ec30c99881"
		"e5d536bb0c12996ef228c4a1ac62df352dce08b9b04ebbb74ee7a3266d6dc101"
		"c524331025ba41dae0d331262afabafd0beff8e668bd5dd916eafd1274484934"
		"ce506e571cf693eec3fcb34cbbea87ac8b313f93197bf15a0e9bb105d9e37691"
		"e0c57e4a5f615f8dd4ba35c7df9456e9815a143acf4e984cb023455125b51243"
		"ecd3485858e5ebd7d2ffb3c889f53b7c59135e9f872932b12a521868301538bf"
		"4cffecca900735806b929aec2cc5d6da8b9a91e5cf8e2c38189af5b92a8c5648"
		"ae860a767190c306c460834ca476d129e263d3f62804d88d9d077c5deef80418"
		"3467e158ad7c5a179dc0088ff80d296c659f3203c77a2e06df15efcda01cf675"
		"bbaed0b9e3cba4726d758fec71523374c3e6a007fe286706eb46abb9267caeb2"
		"140ce421714908793563dd8d910880b382941affdd38d3a9add3dac360f72a21"
		"627f7f0f173e9ad493d1a97ceae63249c4bcb7d871d8b17286ab2c91271096be"
		"aba1e8798eb61a6ad18f246e0ecb38bebce0927523baa98c72c288645aaaf61c"
		"19330fe351e7fb4c5e622679acc7f15b92d424682d34555e8afa859ec293b3ac"
		"788375f0e8a6951bb4b916d14470f908115e66c424f1acbea399aef6fa00f0e3"
		"ff319e3a8a296681b7630ccc9b0da1617a75e5eb0480e5e06e7f164c42b58394"
		"f870b658031a3de596101d5e7e71b3a6523c594233bd00b2c170e81ff93e94b0"
		"bca9f9043aab415cd330b566eaa2535b6e42607b979515db5a99b90064560119"
		"96fec95a36031c4fd9136cda176fa658d54b96f7a6d80908d65e145217d7009f"
		"d2f0fb96fb45dbdbf33f49e739ae7bc7f7e0531d179e1b15b0ca1d3c345540fe"
		"cb3591f60e72e9fa9c3f7d85e2d1856f9baaee3af90f14d105b3be98b7c3900e"
		"1e4709d7698b031c2b40fc114ab13745eef2dfbc8eec730a21ee3f2e8affad5e"
		"807f022bd7091a00ca55d6affbb5310c866c4bf16805ecf4a1f910e3334de46f"
		"45e354d27dccd5310d2db6396bc357e3947a9897440cd849c0bd520c55a6dc05"
		"8be5f0444d49ab6dbcc3c642d372d21ea51440c5ad3907a854b4129f55c05f21"
		"da6f33227ceb80d158b334416a34e7d42bf5ecb3ceb06a7260bbd3d1f3603709"
		"ce7f9df8c8d977085e013fa6f2d48c4ec703d6f25d6614728d20db85aaa2a2a6"
		"a520b977c35ee862e1679348e16fc474a78006fc5689c91ad18953406f01e0c3"
		"5ad9aadd7a96695c989620ce16bb8334a808af2ba3a7a23c2f53867044eb09fc"
		"0c756d837d4cbe3408e2ccce21c8e786fe4fb292b6197e1346669774d3a9eedf"
		"a8e5ddb2910ecef28521540243dfcae28ee5cd6d0a569a7ad664cbfefb52bfcf"
		"d09e66db110cc2bdcfa6909f3f5998f7cc2d7a5c11c146cce13f72c698a8b138"
		"651e9ad1541442f36e51e09a0000000528a7d2e5292ffaa18483fe7f0d6db429"
		"238d3809ee778f6da4aaf28e77ba6ff939e8b2b0f3fe300beea139543ad25004"
		"307de7ca1344c8645d8a8ee9629373868df046e1d4df456ad9cf5857d9ad868a"
		"77633abf7de96279f84e2cf1166863a459638c92bd5617191ff96a912cc314e3"
		"a430ad746f427ea60c3d1171e2034c67af8b1e5323b82a57dcdbd92ce21d3999"
		"86d36d10f4ab2725ee808d2a654e1554000000050000000ed2f14ff6346af964"
		"569f7d6cb880a1b6a3dfee7a6eb6bb4eceb552326e159d57b27f0c98bc513d3b"
		"8746311d1d57ad6e0000000a0000000e0703c491e7558b35011ece3592eaa5da"
		"4d918786771233e8353bc4f62323185ca6181777500d72b576c54d3b7c800664"
		"9fdf6cc3d0251c138bed161ae9866dc12fd4f4c8002b29631dedfe72a08567ac"
		"b0cb8d4c8189f4c64db40707196d49a0a738ac6575b662156b8d3825a19ab18f"
		"10f93b6ee46d4f31f4295a68f51d4ae778ab3dd99020c8cb8e187e2f7cec0fb8"
		"5cb888481d379faa8d1cd0e63e525e394d1256b12ee2cee8a6a4a80999ec7b3e"
		"35b6d9b660b12e071f105f9fca56909d7bf25dc173fcd5ba6ea3ec138157f524"
		"dea1ac0a679524f0f3a27129e90b7e09b41c178b8344a59333c963665ea28f9d"
		"bca379ea6d98c216453810e150edb8c2404cc2c92804eb348f929e0d6ab0c5df"
		"731ba8f346034d391a1beffc13b257039d1a653a83767e2b2ccb450cbc4c3e76"
		"1f76a3b94b58b2a846e01344c716a6beada874e34a8a46cdd4ee3b328ba797c8"
		"d8aef40fd8b27ee57a45d0d25e1d6091504472a261c7de6fb1f3e47d7495edd2"
		"1760200a7c5c91205116e09d0565437b4813dd7b316ec01625945ebeb81800b0"
		"7742abfa06998638e9a9e95cf09b0cca5e45234a9dc62f8983ddbd77efd737d5"
		"b97c72cf7f7f1b33b7473c7dfc249b4001a05b71213eeb2305f0b79f047ab1f9"
		"349a4fcada42523d0b6c4f994671cea38fdcea663ec725dbff73b2b3f0f4c037"
		"8878a0d85d6fecf954ca9a4e97d3a1f219f324e7785f83a402af499bd852bac6"
		"5bef42aa13fd8f564003e96268618b1082611885548344b6bcacb04a23123ea4"
		"8b3902d5ff10b0d9bd6006257102c78f4cd2d60fbc49e3b173ba13e559ecb2e4"
		"f10fcb33bb571fdc3440964b8613a2a763c0cf7860c75580c716bbf88a6c3bff"
		"ff632ab66d3861f7fd3e0255147feb21fcd1a6742788dd56d4b820d4206b9dbc"
		"b4b045b95cd587f02e317e986f6e86caa709e5aac8da44321fd38e50b4ff1386"
		"e4e02887b6c961e633a16da4729bf6172e40a865f163e3610e4352aa15b177ac"
		"35545aa7783c4fde3724a2151312b1901dd37a161f619033914ddb330d7783e0"
		"e1e3b7c71d2c6da820af348644a3ea479fca0075974eec4b780ceb6dbacb8164"
		"6f3f8d604d9f56b90e31b174f80ae1e450f3ac29663667c6ebaf090b13d6f60d"
		"7541f988271efe00241160072b8d6667e5d4546ab40036af88aef5c9553957b3"
		"3962cbd31b946fbf66dac1a2c477421590d17eea8c4c4900385847c116a4b2f9"
		"453b3246542951bf377895912d4de8fd6ba7255c1ac065359b629cd58d51c767"
		"81f6f2e8f2b3c61b4c6adaab90c937823c81fb70046136a457122134f340542e"
		"92207aa84b1623330a2378bcbeb3ff0b85204acc8d2507ddc0912da70284de24"
		"2f28aec0f69d6aa43d2d44cb6a8ae837a3936c2181ec26ae9ed18461620d7487"
		"d76f5bbf4b5e69317d7a5cd016dc7ab00d9ef0a3825350db64ddb9d2610fd273"
		"1758f7e9fff621e9e0927f1f91b9f2c5e5a3bcaea6e25319cddc6cc7e515826a"
		"e0c77a214fed5f64d17e02b0408c8a9e4fe8929c8d92d5f837410814cff8a534"
		"789a1dbee2ecd59afe7cb4924472d001000000055809ff98d4366c45f6903e86"
		"ba7eefeafdda04ff2ad295313688efefea69839460746b64bd308dbc590fef12"
		"0d3c02707215b122202ffc9fb8d602e563485f75e78f9e2684cf5fce9e3480db"
		"8dd35a03dde4186c6eb9c6bfa4bb19c6d6c28e7b2d1fa4164d83caffd498085c"
		"fa6616cacd7d44c6b700cbb0f6ec377d31fe9096e1b7b9bb773c8271423e4bbb"
		"09613e7a026511948a67acd77e54031b62df1cbb";
	static const char *msg =
		"54686520706f77657273206e6f742064656c65676174656420746f2074686520"
		"556e69746564205374617465732062792074686520436f6e737469747574696f"
		"6e2c206e6f722070726f6869626974656420627920697420746f207468652053"
		"74617465732c2061726520726573657276656420746f20746865205374617465"
		"7320726573706563746976656c792c206f7220746f207468652070656f706c65"
		"2e0a"; // MUST NOT use strlen(msg), which will not count the last 0x0a
	HSS_KEY key;
	HSS_SIGNATURE sig;
	HSS_SIGN_CTX ctx;
	uint8_t pub[HSS_PUBLIC_KEY_SIZE];
	uint8_t sigbuf[HSS_SIGNATURE_MAX_SIZE];
	uint8_t data[162];
	const uint8_t *cp;
	size_t len;

	hex_to_bytes(sm3_hss_public_key, strlen(sm3_hss_public_key), pub, &len);
	if (len != HSS_PUBLIC_KEY_SIZE) {
		error_print();
		return -1;
	}
	cp = pub;
	if (hss_public_key_from_bytes(&key, &cp, &len) != 1 || len != 0) {
		error_print();
		return -1;
	}

	hex_to_bytes(sm3_hss_signature, strlen(sm3_hss_signature), sigbuf, &len);
	cp = sigbuf;
	if (hss_signature_from_bytes(&sig, &cp, &len) != 1 || len != 0) {
		error_print();
		return -1;
	}

	hex_to_bytes(msg, strlen(msg), data, &len);

	if (hss_verify_init_ex(&ctx, &key, &sig) != 1) {
		error_print();
		return -1;
	}
	if (hss_verify_update(&ctx, data, len) != 1) {
		error_print();
		return -1;
	}
	if (hss_verify_finish(&ctx) != 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}


static int test_sm3_lmots(void)
{
	lms_sm3_digest_t seed = {0}; // TODO: change to test vector
	uint8_t I[16] = {0};
	int q = 0;
	lms_sm3_digest_t dgst = {0};
	lms_sm3_digest_t x[34];
	lms_sm3_digest_t y[34];
	lms_sm3_digest_t pub;
	lms_sm3_digest_t pub2;

	lmots_derive_secrets(seed, I, q, x); // TODO: compare results with test vector
	lmots_secrets_to_public_hash(I, q, x, pub); // TODO: compare results with test vector

	lmots_compute_signature(I, q, dgst, x, y); // TODO: compare results with test vector
	lmots_signature_to_public_hash(I, q, y, dgst, pub2);

	if (memcmp(pub, pub2, 32) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_lms_derive_merkle_root(void)
{
	lms_sm3_digest_t seed = {0}; // TODO: change to test vector
	uint8_t I[16] = {0};
	int h = 5;
	int n = 1<<h;
	lms_sm3_digest_t *tree = NULL;
	lms_sm3_digest_t root;

	if (!(tree = (lms_sm3_digest_t *)malloc(sizeof(lms_sm3_digest_t)*(2*n - 1)))) {
		error_print();
		return -1;
	}

	lms_derive_merkle_tree(seed, I, h, tree);
	lms_derive_merkle_root(seed, I, h, root);

	if (memcmp(tree[0], root, 32) != 0) {
		free(tree);
		error_print();
		return -1;
	}
	free(tree);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_lms_key_generate(void)
{
	LMS_KEY lms_key;
	int lms_type = lms_types[0];
	clock_t start = clock();

	if (lms_key_generate(&lms_key, lms_type) != 1) {
		error_print();
		return -1;
	}
	lms_private_key_print(stdout, 0, 0, "lms_private_key", &lms_key);

	test_print_elapsed(__FUNCTION__, start);
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_lms_key_to_bytes(void)
{
	LMS_KEY key;
	int lms_type = lms_types[0];

	uint8_t buf[sizeof(LMS_KEY) * 2];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len;


	if (lms_key_generate(&key, lms_type) != 1) {
		error_print();
		return -1;
	}

	p = buf;
	len = 0;
	if (lms_public_key_to_bytes(&key, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (len != LMS_PUBLIC_KEY_SIZE) {
		error_print();
		return -1;
	}

	if (lms_private_key_to_bytes(&key, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (len != LMS_PUBLIC_KEY_SIZE + LMS_PRIVATE_KEY_SIZE) {
		error_print();
		return -1;
	}

	cp = buf;
	if (lms_public_key_from_bytes(&key, &cp, &len) != 1) {
		error_print();
		return -1;
	}
	lms_public_key_print(stdout, 0, 4, "lms_public_key", &key);

	if (lms_private_key_from_bytes(&key, &cp, &len) != 1) {
		error_print();
		return -1;
	}
	lms_private_key_print(stdout, 0, 4, "lms_private_key", &key);
	if (len != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_lms_signature_size(void)
{
	int lms_types[] = {
		LMS_SM3_M32_H5,
		LMS_SM3_M32_H10,
		LMS_SM3_M32_H15,
		LMS_SM3_M32_H20,
		LMS_SM3_M32_H25,
	};
	size_t siglens[] = {
		1292,
		1452,
		1612,
		1772,
		1932,
	};
	size_t siglen;
	size_t i;

	for (i = 0; i < sizeof(lms_types)/sizeof(lms_types[0]); i++) {
		if (lms_signature_size(lms_types[i], &siglen) != 1) {
			error_print();
			return -1;
		}
		if (siglen != siglens[i]) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_hss_signature_size(void)
{
	int lms_types[] = {
		LMS_SM3_M32_H5,
		LMS_SM3_M32_H10,
		LMS_SM3_M32_H15,
		LMS_SM3_M32_H20,
		LMS_SM3_M32_H25,
	};
	size_t siglens[] = {
		4 + 1292,
		4 + 1292 + LMS_PUBLIC_KEY_SIZE*1 + 1452,
		4 + 1292 + LMS_PUBLIC_KEY_SIZE*2 + 1452 + 1612,
		4 + 1292 + LMS_PUBLIC_KEY_SIZE*3 + 1452 + 1612 + 1772,
		4 + 1292 + LMS_PUBLIC_KEY_SIZE*4 + 1452 + 1612 + 1772 + 1932,
	};
	size_t siglen;
	size_t i;

	for (i = 0; i < sizeof(lms_types)/sizeof(lms_types[0]); i++) {

		if (hss_signature_size(lms_types, i+1, &siglen) != 1) {
			error_print();
			return -1;
		}

		fprintf(stderr, "%zu %zu\n", siglens[i], siglen);



		if (siglen != siglens[i]) {
			error_print();
		//	return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_lms_sign(void)
{
	int lms_type = lms_types[0];
	LMS_KEY key;
	LMS_SIGN_CTX ctx;
	uint8_t msg[200];
	uint8_t sig[LMS_SIGNATURE_MAX_SIZE];
	size_t siglen;
	int ret;
	clock_t start = clock();

	if (lms_key_generate(&key, lms_type) != 1) {
		error_print();
		return -1;
	}

	memset(&ctx, 0, sizeof(ctx));
	memset(sig, 0, sizeof(sig));

	if (lms_sign_init(&ctx, &key) != 1) {
		error_print();
		return -1;
	}
	if (lms_sign_update(&ctx, msg, 100) != 1) {
		error_print();
		return -1;
	}
	if (lms_sign_update(&ctx, msg + 100, 100) != 1) {
		error_print();
		return -1;
	}
	if (lms_sign_finish(&ctx, sig, &siglen) != 1) {
		error_print();
		return -1;
	}

	if (1) {
		LMS_SIGNATURE signature;
		const uint8_t *cp = sig;
		size_t len = siglen;

		if (lms_signature_from_bytes(&signature, &cp, &len) != 1) {
			error_print();
			return -1;
		}
		lms_signature_print_ex(stderr, 0, 4, "lms_signature", &signature);
		if (len) {
			error_print();
			return -1;
		}
	}

	memset(&ctx, 0, sizeof(ctx));

	if (lms_verify_init(&ctx, &key, sig, siglen) != 1) {
		error_print();
		return -1;
	}
	if (lms_verify_update(&ctx, msg, 100) != 1) {
		error_print();
		return -1;
	}
	if (lms_verify_update(&ctx, msg + 100, 100) != 1) {
		error_print();
		return -1;
	}
	if ((ret = lms_verify_finish(&ctx)) != 1) {
		error_print();
		return -1;
	}

	test_print_elapsed(__FUNCTION__, start);
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_lms_max_sigs(void)
{
	int lms_type = LMS_SM3_M32_H5;
	int height = 5;
	LMS_KEY key;
	LMS_SIGN_CTX ctx;
	int i;

	if (lms_key_generate(&key, lms_type) != 1) {
		error_print();
		return -1;
	}

	key.q = 1 << height;

	if (lms_sign_init(&ctx, &key) == 1) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_hss_key_generate(void)
{
	HSS_KEY key;
	clock_t start = clock();

	if (hss_key_generate(&key, lms_types, sizeof(lms_types)/sizeof(lms_types[0])) != 1) {
		error_print();
		return -1;
	}

	hss_public_key_print(stdout, 0, 4, "hss_public_key", &key);
	hss_private_key_print(stdout, 0, 4, "hss_key", &key);

	test_print_elapsed(__FUNCTION__, start);
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}



static int test_hss_key_update_level1(void)
{
	HSS_KEY key;

	memset(&key, 0, sizeof(HSS_KEY));

	key.levels = 1;
	key.lms_key[0].public_key.lms_type = LMS_SM3_M32_H25;
	key.lms_key[0].public_key.lmots_type = LMOTS_SM3_N32_W8;
	key.lms_key[0].q = (1 << 25);

	// out of keys
	if (hss_key_update(&key) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_hss_key_update_level2(void)
{
	int lms_types[] = {
		LMS_SM3_M32_H5,
		LMS_SM3_M32_H5,
	};
	HSS_KEY key;
	int i;

	if (hss_key_generate(&key, lms_types, 2) != 1) {
		error_print();
		return -1;
	}
	key.lms_key[1].q = 32;

	// update 1
	if (hss_key_update(&key) != 1) {
		error_print();
		return -1;
	}
	if (key.lms_key[0].q != 2
		|| key.lms_sig[0].q != 1
		|| key.lms_key[1].q != 0) {
		error_print();
		return -1;
	}

	// update 2
	key.lms_key[1].q = 32;
	if (hss_key_update(&key) != 1) {
		error_print();
		return -1;
	}
	if (key.lms_key[0].q != 3
		|| key.lms_sig[0].q != 2
		|| key.lms_key[1].q != 0) {
		error_print();
		return -1;
	}

	// update 31
	key.lms_key[0].q = 31;
	key.lms_key[1].q = 32;
	if (hss_key_update(&key) != 1) {
		error_print();
		return -1;
	}
	if (key.lms_key[0].q != 32
		|| key.lms_sig[0].q != 31
		|| key.lms_key[1].q != 0) {
		error_print();
		return -1;
	}

	// update 32, key space exhausted, return 0
	key.lms_key[1].q = 32;
	if (hss_key_update(&key) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}



static int test_hss_key_update_level5(void)
{
	int lms_types[] = {
		LMS_SM3_M32_H5,
		LMS_SM3_M32_H5,
		LMS_SM3_M32_H5,
		LMS_SM3_M32_H5,
		LMS_SM3_M32_H5,
	};
	HSS_KEY key;
	int i;

	if (hss_key_generate(&key, lms_types, 5) != 1) {
		error_print();
		return -1;
	}
	if (key.lms_key[0].q != 1
		|| key.lms_sig[0].q != 0
		|| key.lms_key[1].q != 1
		|| key.lms_sig[1].q != 0
		|| key.lms_key[2].q != 1
		|| key.lms_sig[2].q != 0
		|| key.lms_key[3].q != 1
		|| key.lms_sig[3].q != 0
		|| key.lms_key[4].q != 0) {
		error_print();
		return -1;
	}


	// level-4 update
	key.lms_key[4].q = 32;
	if (hss_key_update(&key) != 1) {
		error_print();
		return -1;
	}
	if (key.lms_key[0].q != 1
		|| key.lms_sig[0].q != 0
		|| key.lms_key[1].q != 1
		|| key.lms_sig[1].q != 0
		|| key.lms_key[2].q != 1
		|| key.lms_sig[2].q != 0
		|| key.lms_key[3].q != 2
		|| key.lms_sig[3].q != 1
		|| key.lms_key[4].q != 0) {
		error_print();
		return -1;
	}

	// level-4 to level-2 update
	key.lms_key[0].q = 1;
	key.lms_sig[0].q = 0;
	key.lms_key[1].q = 3;
	key.lms_sig[1].q = 2;
	key.lms_key[2].q = 32;
	key.lms_sig[2].q = 31;
	key.lms_key[3].q = 32;
	key.lms_sig[3].q = 31;
	key.lms_key[4].q = 32;
	if (hss_key_update(&key) != 1) {
		error_print();
		return -1;
	}
	if (key.lms_key[0].q != 1
		|| key.lms_sig[0].q != 0
		|| key.lms_key[1].q != 4
		|| key.lms_sig[1].q != 3
		|| key.lms_key[2].q != 1
		|| key.lms_sig[2].q != 0
		|| key.lms_key[3].q != 1
		|| key.lms_sig[3].q != 0
		|| key.lms_key[4].q != 0) {
		error_print();
		return -1;
	}

	// level-4 to level-1 update
	key.lms_key[0].q = 1;
	key.lms_sig[0].q = 0;
	key.lms_key[1].q = 32;
	key.lms_sig[1].q = 31;
	key.lms_key[2].q = 32;
	key.lms_sig[2].q = 31;
	key.lms_key[3].q = 32;
	key.lms_sig[3].q = 31;
	key.lms_key[4].q = 32;
	if (hss_key_update(&key) != 1) {
		error_print();
		return -1;
	}
	if (key.lms_key[0].q != 2
		|| key.lms_sig[0].q != 1
		|| key.lms_key[1].q != 1
		|| key.lms_sig[1].q != 0
		|| key.lms_key[2].q != 1
		|| key.lms_sig[2].q != 0
		|| key.lms_key[3].q != 1
		|| key.lms_sig[3].q != 0
		|| key.lms_key[4].q != 0) {
		error_print();
		return -1;
	}

	// out of keys
	key.lms_key[0].q = 32;
	key.lms_sig[0].q = 31;
	key.lms_key[1].q = 32;
	key.lms_sig[1].q = 31;
	key.lms_key[2].q = 32;
	key.lms_sig[2].q = 31;
	key.lms_key[3].q = 32;
	key.lms_sig[3].q = 31;
	key.lms_key[4].q = 32;
	if (hss_key_update(&key) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_hss_key_to_bytes(void)
{
	HSS_KEY key;

	uint8_t buf[HSS_PUBLIC_KEY_SIZE + sizeof(HSS_KEY)];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len;

	if (hss_key_generate(&key,
		lms_types, sizeof(lms_types)/sizeof(lms_types[0])) != 1) {
		error_print();
		return -1;
	}

	p = buf;
	len = 0;
	if (hss_public_key_to_bytes(&key, &p, &len) != 1) {
		error_print();
		return -1;
	}
	if (len != HSS_PUBLIC_KEY_SIZE) {
		error_print();
		return -1;
	}

	if (hss_private_key_to_bytes(&key, &p, &len) != 1) {
		error_print();
		return -1;
	}

	cp = buf;
	if (hss_public_key_from_bytes(&key, &cp, &len) != 1) {
		error_print();
		return -1;
	}
	hss_public_key_print(stdout, 0, 4, "lms_public_key", &key);

	if (hss_private_key_from_bytes(&key, &cp, &len) != 1) {
		error_print();
		return -1;
	}
	hss_private_key_print(stdout, 0, 4, "lms_private_key", &key);
	if (len != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_hss_sign_level1(void)
{
	int levels = 1;
	HSS_KEY key;
	HSS_SIGN_CTX ctx;
	HSS_SIGNATURE sig;
	uint8_t msg[200];
	uint8_t buf[sizeof(HSS_SIGNATURE)];
	size_t len;
	clock_t start = clock();

	if (hss_key_generate(&key, lms_types, levels) != 1) {
		error_print();
		return -1;
	}

	if (hss_sign_init(&ctx, &key) != 1) {
		error_print();
		return -1;
	}
	if (hss_sign_update(&ctx, msg, sizeof(msg)) != 1) {
		error_print();
		return -1;
	}
	if (hss_sign_finish(&ctx, buf, &len) != 1) {
		error_print();
		return -1;
	}

	if (hss_verify_init(&ctx, &key, buf, len) != 1) {
		error_print();
		return -1;
	}
	if (hss_verify_update(&ctx, msg, sizeof(msg)) != 1) {
		error_print();
		return -1;
	}
	if (hss_verify_finish(&ctx) != 1) {
		error_print();
		return -1;
	}

	test_print_elapsed(__FUNCTION__, start);
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_hss_sign_level2(void)
{
	int levels = 2;
	HSS_KEY key;
	HSS_SIGN_CTX ctx;
	HSS_SIGNATURE sig;
	uint8_t msg[200];
	uint8_t buf[sizeof(HSS_SIGNATURE)];
	size_t len;
	clock_t start = clock();

	if (hss_key_generate(&key, lms_types, levels) != 1) {
		error_print();
		return -1;
	}
	hss_private_key_print(stderr, 0, 4, "hss_key", &key);


	if (hss_sign_init(&ctx, &key) != 1) {
		error_print();
		return -1;
	}
	if (hss_sign_update(&ctx, msg, sizeof(msg)) != 1) {
		error_print();
		return -1;
	}
	if (hss_sign_finish(&ctx, buf, &len) != 1) {
		error_print();
		return -1;
	}
	hss_signature_print(stderr, 0, 4, "hss_signature", buf, len);


	if (hss_verify_init(&ctx, &key, buf, len) != 1) {
		error_print();
		return -1;
	}
	if (hss_verify_update(&ctx, msg, sizeof(msg)) != 1) {
		error_print();
		return -1;
	}
	if (hss_verify_finish(&ctx) != 1) {
		error_print();
		return -1;
	}

	test_print_elapsed(__FUNCTION__, start);
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_hss_sign(void)
{
	HSS_KEY key;
	HSS_SIGN_CTX ctx;
	HSS_SIGNATURE sig;
	uint8_t msg[200];
	uint8_t buf[sizeof(HSS_SIGNATURE)];
	size_t len;
	clock_t start = clock();

	if (hss_key_generate(&key, lms_types, sizeof(lms_types)/sizeof(lms_types[0])) != 1) {
		error_print();
		return -1;
	}
	hss_private_key_print(stderr, 0, 4, "hss_key", &key);


	if (hss_sign_init(&ctx, &key) != 1) {
		error_print();
		return -1;
	}
	if (hss_sign_update(&ctx, msg, sizeof(msg)) != 1) {
		error_print();
		return -1;
	}
	if (hss_sign_finish(&ctx, buf, &len) != 1) {
		error_print();
		return -1;
	}
	hss_signature_print(stderr, 0, 4, "hss_signature", buf, len);


	if (hss_verify_init(&ctx, &key, buf, len) != 1) {
		error_print();
		return -1;
	}
	if (hss_verify_update(&ctx, msg, sizeof(msg)) != 1) {
		error_print();
		return -1;
	}
	if (hss_verify_finish(&ctx) != 1) {
		error_print();
		return -1;
	}

	test_print_elapsed(__FUNCTION__, start);
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

/*
static int test_hss_public_key_algor(void)
{
	int lms_types[] = {
		LMS_SM3_M32_H5
	};
	HSS_KEY key;
	uint8_t buf[512];
	const uint8_t *cp;
	uint8_t *p;
	size_t len;


	if (hss_key_generate(&key, lms_types, sizeof(lms_types)/sizeof(lms_types[0])) != 1) {
		error_print();
		return -1;
	}

	cp = p = buf;
	len = 0;
	if (hss_public_key_to_der(&key, &p, &len) != 1) {
		error_print();
		return -1;
	}
	fprintf(stderr, "HSS-LMS-HashSig-PublicKey ::= OCTET STRING\n");
	fprintf(stderr, "hss_public_key der size = %zu\n", len);
	memset(&key, 0, sizeof(HSS_KEY));
	if (hss_public_key_from_der(&key, &cp, &len) != 1) {
		error_print();
		return -1;
	}
	if (len) {
		error_print();
		return -1;
	}


	cp = p = buf;
	len = 0;
	if (hss_public_key_algor_to_der(&p, &len) != 1) {
		error_print();
		return -1;
	}
	if (hss_public_key_algor_from_der(&cp, &len) != 1) {
		error_print();
		return -1;
	}
	if (len) {
		error_print();
		return -1;
	}


	cp = p = buf;
	len = 0;
	if (hss_public_key_info_to_der(&key, &p, &len) != 1) {
		error_print();
		return -1;
	}
	fprintf(stderr, "HSSPublicKeyInfo DER size = %zu\n", len);
	memset(&key, 0, sizeof(HSS_KEY));
	if (hss_public_key_info_from_der(&key, &cp, &len) != 1) {
		error_print();
		return -1;
	}
	if (len) {
		error_print();
		return -1;
	}


	printf("%s() ok\n", __FUNCTION__);
	return 1;

}
*/

int main(void)
{
	if (test_print_consts() != 1) goto err;
	if (test_sm3_hss_kat() != 1) goto err;
	if (test_sm3_lmots() != 1) goto err;
	if (test_lms_derive_merkle_root() != 1) goto err;
	if (test_lms_key_generate() != 1) goto err;
	if (test_lms_key_to_bytes() != 1) goto err;
	if (test_lms_signature_size() != 1) goto err;
	if (test_lms_sign() != 1) goto err;
	if (test_lms_max_sigs() != 1) goto err;
	if (test_hss_key_generate() != 1) goto err;
	if (test_hss_key_to_bytes() != 1) goto err;
	if (test_hss_key_update_level1() != 1) goto err;
	if (test_hss_key_update_level2() != 1) goto err;
	if (test_hss_key_update_level5() != 1) goto err;
	if (test_hss_signature_size() != 1) goto err;
	if (test_hss_sign_level1() != 1) goto err;
	if (test_hss_sign_level2() != 1) goto err;
	if (test_hss_sign() != 1) goto err;
//	if (test_hss_public_key_algor() != 1) goto err;

	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
