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
#include <gmssl/hex.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include <gmssl/lms.h>


static int lms_types[] = {
	LMS_HASH256_M32_H5,
	LMS_HASH256_M32_H5,
	LMS_HASH256_M32_H5,
};


#if defined(ENABLE_LMS_CROSSCHECK) && defined(ENABLE_SHA2)
static int test_rfc8554_test1(void)
{
	size_t i;

	// HSS Public key
	int levels = 2;
	int lms_type = LMS_SHA256_M32_H5;
	int lmots_type = LMOTS_SHA256_N32_W8;
	char *I = "61a5d57d37f5e46bfb7520806b07a1b8";
	char *K = "50650e3b31fe4a773ea29a07f09cf2ea30e579f0df58ef8e298da0434cb2b878";

	// Message
	char *msg =
		"54686520706f77657273206e6f742064656c65676174656420746f2074686520"
		"556e69746564205374617465732062792074686520436f6e737469747574696f"
		"6e2c206e6f722070726f6869626974656420627920697420746f207468652053"
		"74617465732c2061726520726573657276656420746f20746865205374617465"
		"7320726573706563746976656c792c206f7220746f207468652070656f706c65"
		"2e0a"; // MUST NOT use strlen(msg), which will not count the last 0x0a

	// Signature
	int Nspk = 1;

	int sig0_q = 5;
	int sig0_lmots_type = LMOTS_SHA256_N32_W8;
	char *sig0_C =
		"d32b56671d7eb98833c49b433c272586"
		"bc4a1c8a8970528ffa04b966f9426eb9";
	char *sig0_y[34] = {
		"965a25bfd37f196b9073f3d4a232feb69128ec45146f86292f9dff9610a7bf95",
		"a64c7f60f6261a62043f86c70324b7707f5b4a8a6e19c114c7be866d488778a0",
		"e05fd5c6509a6e61d559cf1a77a970de927d60c70d3de31a7fa0100994e162a2",
		"582e8ff1b10cd99d4e8e413ef469559f7d7ed12c838342f9b9c96b83a4943d16",
		"81d84b15357ff48ca579f19f5e71f18466f2bbef4bf660c2518eb20de2f66e3b",
		"14784269d7d876f5d35d3fbfc7039a462c716bb9f6891a7f41ad133e9e1f6d95",
		"60b960e7777c52f060492f2d7c660e1471e07e72655562035abc9a701b473ecb",
		"c3943c6b9c4f2405a3cb8bf8a691ca51d3f6ad2f428bab6f3a30f55dd9625563",
		"f0a75ee390e385e3ae0b906961ecf41ae073a0590c2eb6204f44831c26dd768c",
		"35b167b28ce8dc988a3748255230cef99ebf14e730632f27414489808afab1d1",
		"e783ed04516de012498682212b07810579b250365941bcc98142da13609e9768",
		"aaf65de7620dabec29eb82a17fde35af15ad238c73f81bdb8dec2fc0e7f93270",
		"1099762b37f43c4a3c20010a3d72e2f606be108d310e639f09ce7286800d9ef8",
		"a1a40281cc5a7ea98d2adc7c7400c2fe5a101552df4e3cccfd0cbf2ddf5dc677",
		"9cbbc68fee0c3efe4ec22b83a2caa3e48e0809a0a750b73ccdcf3c79e6580c15",
		"4f8a58f7f24335eec5c5eb5e0cf01dcf4439424095fceb077f66ded5bec73b27",
		"c5b9f64a2a9af2f07c05e99e5cf80f00252e39db32f6c19674f190c9fbc506d8",
		"26857713afd2ca6bb85cd8c107347552f30575a5417816ab4db3f603f2df56fb",
		"c413e7d0acd8bdd81352b2471fc1bc4f1ef296fea1220403466b1afe78b94f7e",
		"cf7cc62fb92be14f18c2192384ebceaf8801afdf947f698ce9c6ceb696ed70e9",
		"e87b0144417e8d7baf25eb5f70f09f016fc925b4db048ab8d8cb2a661ce3b57a",
		"da67571f5dd546fc22cb1f97e0ebd1a65926b1234fd04f171cf469c76b884cf3",
		"115cce6f792cc84e36da58960c5f1d760f32c12faef477e94c92eb75625b6a37",
		"1efc72d60ca5e908b3a7dd69fef0249150e3eebdfed39cbdc3ce9704882a2072",
		"c75e13527b7a581a556168783dc1e97545e31865ddc46b3c957835da252bb732",
		"8d3ee2062445dfb85ef8c35f8e1f3371af34023cef626e0af1e0bc017351aae2",
		"ab8f5c612ead0b729a1d059d02bfe18efa971b7300e882360a93b025ff97e9e0",
		"eec0f3f3f13039a17f88b0cf808f488431606cb13f9241f40f44e537d302c64a",
		"4f1f4ab949b9feefadcb71ab50ef27d6d6ca8510f150c85fb525bf25703df720",
		"9b6066f09c37280d59128d2f0f637c7d7d7fad4ed1c1ea04e628d221e3d8db77",
		"b7c878c9411cafc5071a34a00f4cf07738912753dfce48f07576f0d4f94f42c6",
		"d76f7ce973e9367095ba7e9a3649b7f461d9f9ac1332a4d1044c96aefee67676",
		"401b64457c54d65fef6500c59cdfb69af7b6dddfcb0f086278dd8ad0686078df",
		"b0f3f79cd893d314168648499898fbc0ced5f95b74e8ff14d735cdea968bee74",
	};
	int sig0_lms_type = LMS_SHA256_M32_H5;
	char *sig0_path[5] = {
		"d8b8112f9200a5e50c4a262165bd342cd800b8496810bc716277435ac376728d",
		"129ac6eda839a6f357b5a04387c5ce97382a78f2a4372917eefcbf93f63bb591",
		"12f5dbe400bd49e4501e859f885bf0736e90a509b30a26bfac8c17b5991c157e",
		"b5971115aa39efd8d564a6b90282c3168af2d30ef89d51bf14654510a12b8a14",
		"4cca1848cf7da59cc2b3d9d0692dd2a20ba3863480e25b1b85ee860c62bf5136",
	};

	int pub0_lms_type = LMS_SHA256_M32_H5;
	int pub0_lmots_type = LMOTS_SHA256_N32_W8;
	char *pub0_I = "d2f14ff6346af964569f7d6cb880a1b6";
	char *pub0_K = "6c5004917da6eafe4d9ef6c6407b3db0e5485b122d9ebe15cda93cfec582d7ab";

	int sig1_q = 0x0a;
	int sig1_lmots_type = LMOTS_SHA256_N32_W8;
	char *sig1_C = "0703c491e7558b35011ece3592eaa5da4d918786771233e8353bc4f62323185c";
	char *sig1_y[34] = {
		"95cae05b899e35dffd717054706209988ebfdf6e37960bb5c38d7657e8bffeef",
		"9bc042da4b4525650485c66d0ce19b317587c6ba4bffcc428e25d08931e72dfb",
		"6a120c5612344258b85efdb7db1db9e1865a73caf96557eb39ed3e3f426933ac",
		"9eeddb03a1d2374af7bf77185577456237f9de2d60113c23f846df26fa942008",
		"a698994c0827d90e86d43e0df7f4bfcdb09b86a373b98288b7094ad81a0185ac",
		"100e4f2c5fc38c003c1ab6fea479eb2f5ebe48f584d7159b8ada03586e65ad9c",
		"969f6aecbfe44cf356888a7b15a3ff074f771760b26f9c04884ee1faa329fbf4",
		"e61af23aee7fa5d4d9a5dfcf43c4c26ce8aea2ce8a2990d7ba7b57108b47dabf",
		"beadb2b25b3cacc1ac0cef346cbb90fb044beee4fac2603a442bdf7e507243b7",
		"319c9944b1586e899d431c7f91bcccc8690dbf59b28386b2315f3d36ef2eaa3c",
		"f30b2b51f48b71b003dfb08249484201043f65f5a3ef6bbd61ddfee81aca9ce6",
		"0081262a00000480dcbc9a3da6fbef5c1c0a55e48a0e729f9184fcb1407c3152",
		"9db268f6fe50032a363c9801306837fafabdf957fd97eafc80dbd165e435d0e2",
		"dfd836a28b354023924b6fb7e48bc0b3ed95eea64c2d402f4d734c8dc26f3ac5",
		"91825daef01eae3c38e3328d00a77dc657034f287ccb0f0e1c9a7cbdc828f627",
		"205e4737b84b58376551d44c12c3c215c812a0970789c83de51d6ad787271963",
		"327f0a5fbb6b5907dec02c9a90934af5a1c63b72c82653605d1dcce51596b3c2",
		"b45696689f2eb382007497557692caac4d57b5de9f5569bc2ad0137fd47fb47e",
		"664fcb6db4971f5b3e07aceda9ac130e9f38182de994cff192ec0e82fd6d4cb7",
		"f3fe00812589b7a7ce515440456433016b84a59bec6619a1c6c0b37dd1450ed4",
		"f2d8b584410ceda8025f5d2d8dd0d2176fc1cf2cc06fa8c82bed4d944e71339e",
		"ce780fd025bd41ec34ebff9d4270a3224e019fcb444474d482fd2dbe75efb203",
		"89cc10cd600abb54c47ede93e08c114edb04117d714dc1d525e11bed8756192f",
		"929d15462b939ff3f52f2252da2ed64d8fae88818b1efa2c7b08c8794fb1b214",
		"aa233db3162833141ea4383f1a6f120be1db82ce3630b3429114463157a64e91",
		"234d475e2f79cbf05e4db6a9407d72c6bff7d1198b5c4d6aad2831db61274993",
		"715a0182c7dc8089e32c8531deed4f7431c07c02195eba2ef91efb5613c37af7",
		"ae0c066babc69369700e1dd26eddc0d216c781d56e4ce47e3303fa73007ff7b9",
		"49ef23be2aa4dbf25206fe45c20dd888395b2526391a724996a44156beac8082",
		"12858792bf8e74cba49dee5e8812e019da87454bff9e847ed83db07af3137430",
		"82f880a278f682c2bd0ad6887cb59f652e155987d61bbf6a88d36ee93b6072e6",
		"656d9ccbaae3d655852e38deb3a2dcf8058dc9fb6f2ab3d3b3539eb77b248a66",
		"1091d05eb6e2f297774fe6053598457cc61908318de4b826f0fc86d4bb117d33",
		"e865aa805009cc2918d9c2f840c4da43a703ad9f5b5806163d7161696b5a0adc",
	};
	int sig1_lms_type = LMS_SHA256_M32_H5;
	char *sig1_path[5] = {
		"d5c0d1bebb06048ed6fe2ef2c6cef305b3ed633941ebc8b3bec9738754cddd60",
		"e1920ada52f43d055b5031cee6192520d6a5115514851ce7fd448d4a39fae2ab",
		"2335b525f484e9b40d6a4a969394843bdcf6d14c48e8015e08ab92662c05c6e9",
		"f90b65a7a6201689999f32bfd368e5e3ec9cb70ac7b8399003f175c40885081a",
		"09ab3034911fe125631051df0408b3946b0bde790911e8978ba07dd56c73e7ee",
	};

	HSS_KEY key;
	HSS_SIGNATURE sig;
	LMS_SIGNATURE *lms_sig;
	LMS_PUBLIC_KEY *lms_pub;
	size_t len;

	// hss public key
	memset(&key, 0, sizeof(key));
	key.levels = levels;
	lms_pub = &key.lms_key[0].public_key;
	lms_pub->lms_type = lms_type;
	lms_pub->lmots_type = lmots_type;
	hex_to_bytes(I, strlen(I), lms_pub->I, &len);
	hex_to_bytes(K, strlen(K), lms_pub->root, &len);

	// hss signature
	memset(&sig, 0, sizeof(sig));
	sig.num_signed_public_keys = Nspk;

	// sig[0]
	lms_sig = &sig.signed_public_keys[0].lms_sig;
	lms_sig->q = sig0_q;
	lms_sig->lmots_sig.lmots_type = sig0_lmots_type;
	hex_to_bytes(sig0_C, 64, lms_sig->lmots_sig.C, &len);
	for (i = 0; i < 34; i++) {
		hex_to_bytes(sig0_y[i], 64, lms_sig->lmots_sig.y[i], &len);
	}
	lms_sig->lms_type = sig0_lms_type;
	for (i = 0; i < 5; i++) {
		hex_to_bytes(sig0_path[i], 64, lms_sig->path[i], &len);
	}

	// pub[0]
	lms_pub = &sig.signed_public_keys[0].lms_public_key;
	lms_pub->lms_type = pub0_lms_type;
	lms_pub->lmots_type = pub0_lmots_type;
	hex_to_bytes(pub0_I, 32, lms_pub->I, &len);
	hex_to_bytes(pub0_K, 64, lms_pub->root, &len);

	// sig[1]
	lms_sig = &sig.msg_lms_sig;
	lms_sig->q = sig1_q;
	lms_sig->lmots_sig.lmots_type = sig1_lmots_type;
	hex_to_bytes(sig1_C, 64, lms_sig->lmots_sig.C, &len);
	for (i = 0; i < 34; i++) {
		hex_to_bytes(sig1_y[i], 64, lms_sig->lmots_sig.y[i], &len);
	}
	lms_sig->lms_type = sig1_lms_type;
	for (i = 0; i < 5; i++) {
		hex_to_bytes(sig1_path[i], 64, lms_sig->path[i], &len);
	}

	hss_public_key_print(stderr, 0, 0, "hss_public_key", &key);

	hss_signature_print_ex(stderr, 0, 0, "hss_signature", &sig);


	HSS_SIGN_CTX ctx;
	uint8_t data[162];

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
#endif


static int test_sm3_lmots(void)
{
	hash256_t seed = {0}; // TODO: change to test vector
	uint8_t I[16] = {0};
	int q = 0;
	hash256_t dgst = {0};
	hash256_t x[34];
	hash256_t y[34];
	hash256_t pub;
	hash256_t pub2;

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
	hash256_t seed = {0}; // TODO: change to test vector
	uint8_t I[16] = {0};
	int h = 5;
	int n = 1<<h;
	hash256_t *tree = NULL;
	hash256_t root;

	if (!(tree = (hash256_t *)malloc(sizeof(hash256_t)*(2*n - 1)))) {
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

	if (lms_key_generate(&lms_key, lms_type) != 1) {
		error_print();
		return -1;
	}
	//lms_key_print(stdout, 0, 0, "lms_key", &lms_key);

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
	lms_key_print(stdout, 0, 4, "lms_public_key", &key);

	if (lms_private_key_from_bytes(&key, &cp, &len) != 1) {
		error_print();
		return -1;
	}
	lms_key_print(stdout, 0, 4, "lms_private_key", &key);
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
		LMS_HASH256_M32_H5,
		LMS_HASH256_M32_H10,
		LMS_HASH256_M32_H15,
		LMS_HASH256_M32_H20,
		LMS_HASH256_M32_H25,
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
		LMS_HASH256_M32_H5,
		LMS_HASH256_M32_H10,
		LMS_HASH256_M32_H15,
		LMS_HASH256_M32_H20,
		LMS_HASH256_M32_H25,
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

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_lms_max_sigs(void)
{
	int lms_type = LMS_HASH256_M32_H5;
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

	if (hss_key_generate(&key, lms_types, sizeof(lms_types)/sizeof(lms_types[0])) != 1) {
		error_print();
		return -1;
	}

	hss_public_key_print(stdout, 0, 4, "hss_public_key", &key);
	hss_key_print(stdout, 0, 4, "hss_key", &key);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}



static int test_hss_key_update_level1(void)
{
	HSS_KEY key;

	memset(&key, 0, sizeof(HSS_KEY));

	key.levels = 1;
	key.lms_key[0].public_key.lms_type = LMS_HASH256_M32_H25;
	key.lms_key[0].public_key.lmots_type = LMOTS_HASH256_N32_W8;
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
		LMS_HASH256_M32_H5,
		LMS_HASH256_M32_H5,
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
		LMS_HASH256_M32_H5,
		LMS_HASH256_M32_H5,
		LMS_HASH256_M32_H5,
		LMS_HASH256_M32_H5,
		LMS_HASH256_M32_H5,
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
	hss_key_print(stdout, 0, 4, "lms_private_key", &key);
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

	if (hss_key_generate(&key, lms_types, levels) != 1) {
		error_print();
		return -1;
	}
	hss_key_print(stderr, 0, 4, "hss_key", &key);


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

	if (hss_key_generate(&key, lms_types, sizeof(lms_types)/sizeof(lms_types[0])) != 1) {
		error_print();
		return -1;
	}
	hss_key_print(stderr, 0, 4, "hss_key", &key);


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

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_hss_public_key_algor(void)
{
	int lms_types[] = {
		LMS_HASH256_M32_H5
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


int main(void)
{
#if defined(ENABLE_LMS_CROSSCHECK) && defined(ENABLE_SHA2)
	if (test_rfc8554_test1() != 1) goto err;
#endif
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
	if (test_hss_public_key_algor() != 1) goto err;

	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
