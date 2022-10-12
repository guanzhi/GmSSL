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
#include <gmssl/aes.h>
#include <gmssl/hex.h>
#include <gmssl/error.h>


int test_aes(void)
{
	AES_KEY aes_key;

	/* test 1 */
	uint8_t key128[16] = {
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
	};
	uint32_t rk128[4 * 11] = {
		0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c,
		0xa0fafe17, 0x88542cb1, 0x23a33939, 0x2a6c7605,
		0xf2c295f2, 0x7a96b943, 0x5935807a, 0x7359f67f,
		0x3d80477d, 0x4716fe3e, 0x1e237e44, 0x6d7a883b,
		0xef44a541, 0xa8525b7f, 0xb671253b, 0xdb0bad00,
		0xd4d1c6f8, 0x7c839d87, 0xcaf2b8bc, 0x11f915bc,
		0x6d88a37a, 0x110b3efd, 0xdbf98641, 0xca0093fd,
		0x4e54f70e, 0x5f5fc9f3, 0x84a64fb2, 0x4ea6dc4f,
		0xead27321, 0xb58dbad2, 0x312bf560, 0x7f8d292f,
		0xac7766f3, 0x19fadc21, 0x28d12941, 0x575c006e,
		0xd014f9a8, 0xc9ee2589, 0xe13f0cc8, 0xb6630ca6,
	};

	/* test 2 */
	uint8_t key192[24] = {
		0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
		0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
		0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
	};
	uint32_t rk192[4 * 13] = {
		0x8e73b0f7, 0xda0e6452, 0xc810f32b, 0x809079e5,
		0x62f8ead2, 0x522c6b7b, 0xfe0c91f7, 0x2402f5a5,
		0xec12068e, 0x6c827f6b, 0x0e7a95b9, 0x5c56fec2,
		0x4db7b4bd, 0x69b54118, 0x85a74796, 0xe92538fd,
		0xe75fad44, 0xbb095386, 0x485af057, 0x21efb14f,
		0xa448f6d9, 0x4d6dce24, 0xaa326360, 0x113b30e6,
		0xa25e7ed5, 0x83b1cf9a, 0x27f93943, 0x6a94f767,
		0xc0a69407, 0xd19da4e1, 0xec1786eb, 0x6fa64971,
		0x485f7032, 0x22cb8755, 0xe26d1352, 0x33f0b7b3,
		0x40beeb28, 0x2f18a259, 0x6747d26b, 0x458c553e,
		0xa7e1466c, 0x9411f1df, 0x821f750a, 0xad07d753,
		0xca400538, 0x8fcc5006, 0x282d166a, 0xbc3ce7b5,
		0xe98ba06f, 0x448c773c, 0x8ecc7204, 0x01002202,
	};

	/* test 3 */
	uint8_t key256[32] = {
		0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
		0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
		0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
		0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
	};
	uint32_t rk256[4 * 15] = {
		0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781,
		0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4,
		0x9ba35411, 0x8e6925af, 0xa51a8b5f, 0x2067fcde,
		0xa8b09c1a, 0x93d194cd, 0xbe49846e, 0xb75d5b9a,
		0xd59aecb8, 0x5bf3c917, 0xfee94248, 0xde8ebe96,
		0xb5a9328a, 0x2678a647, 0x98312229, 0x2f6c79b3,
		0x812c81ad, 0xdadf48ba, 0x24360af2, 0xfab8b464,
		0x98c5bfc9, 0xbebd198e, 0x268c3ba7, 0x09e04214,
		0x68007bac, 0xb2df3316, 0x96e939e4, 0x6c518d80,
		0xc814e204, 0x76a9fb8a, 0x5025c02d, 0x59c58239,
		0xde136967, 0x6ccc5a71, 0xfa256395, 0x9674ee15,
		0x5886ca5d, 0x2e2f31d7, 0x7e0af1fa, 0x27cf73c3,
		0x749c47ab, 0x18501dda, 0xe2757e4f, 0x7401905a,
		0xcafaaae3, 0xe4d59b34, 0x9adf6ace, 0xbd10190d,
		0xfe4890d1, 0xe6188d0b, 0x046df344, 0x706c631e,
	};

	/* test 4 */
	unsigned char in1[16] = {
		0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
		0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
	};
	unsigned char out1[16] = {
		0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
		0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32,
	};

	unsigned char buf[16] = {0};

	printf("aes test 1 ");
	aes_set_encrypt_key(&aes_key, key128, sizeof(key128));
	if (memcmp(&aes_key, rk128, sizeof(rk128)) != 0) {
		printf("failed\n");
		return -1;
	} else {
		printf("ok\n");
	}

	printf("aes test 2 ");
	aes_set_encrypt_key(&aes_key, key192, sizeof(key192));
	if (memcmp(&aes_key, rk192, sizeof(rk192)) != 0) {
		printf("failed\n");
		return -1;
	} else {
		printf("ok\n");
	}

	printf("aes test 3 ");
	aes_set_encrypt_key(&aes_key, key256, sizeof(key256));
	if (memcmp(&aes_key, rk256, sizeof(rk256)) != 0) {
		printf("failed\n");
		return -1;
	} else {
		printf("ok\n");
	}

	printf("aes test 4 ");
	aes_set_encrypt_key(&aes_key, key128, sizeof(key128));
	aes_encrypt(&aes_key, in1, buf);
	if (memcmp(buf, out1, sizeof(out1)) != 0) {
		printf("failed\n");
		return -1;
	} else {
		printf("ok\n");
	}

	printf("aes test 5 ");
	aes_set_decrypt_key(&aes_key, key128, sizeof(key128));
	aes_decrypt(&aes_key, buf, buf);
	if (memcmp(buf, in1, sizeof(in1)) != 0) {
		printf("failed\n");
		return -1;
	} else {
		printf("ok\n");
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int test_aes_ctr(void)
{
	// NIST SP 800-38A F.5.1
	char *hex_key = "2b7e151628aed2a6abf7158809cf4f3c";
	char *hex_ctr = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
	char *hex_msg = "6bc1bee22e409f96e93d7e117393172a"
			"ae2d8a571e03ac9c9eb76fac45af8e51"
			"30c81c46a35ce411e5fbc1191a0a52ef"
			"f69f2445df4f9b17ad2b417be66c3710";
	char *hex_out = "874d6191b620e3261bef6864990db6ce"
			"9806f66b7970fdff8617187bb9fffdff"
			"5ae4df3edbd5d35e5b4f09020db03eab"
			"1e031dda2fbe03d1792170a0f3009cee";

	AES_KEY aes_key;
	uint8_t key[32];
	uint8_t ctr[16];
	uint8_t msg[64];
	uint8_t out[64];
	uint8_t buf[64];
	size_t keylen, ctrlen, msglen, outlen, buflen;

	hex_to_bytes(hex_key, strlen(hex_key), key, &keylen);
	hex_to_bytes(hex_ctr, strlen(hex_ctr), ctr, &ctrlen);
	hex_to_bytes(hex_msg, strlen(hex_msg), msg, &msglen);
	hex_to_bytes(hex_out, strlen(hex_out), out, &outlen);

	aes_set_encrypt_key(&aes_key, key, keylen);
	aes_ctr_encrypt(&aes_key, ctr, msg, msglen, buf);
	buflen = msglen;

	printf("aes ctr test 1 ");
	if (memcmp(buf, out, outlen) != 0) {
		printf("failed\n");
		format_bytes(stdout, 0, 0, "aes_ctr(msg) = ", buf, buflen);
		format_bytes(stdout, 0, 0, "            != ", out, outlen);
		return -1;
	} else {
		printf("ok\n");
	}

	printf("aes ctr test 2 ");
	hex_to_bytes(hex_ctr, strlen(hex_ctr), ctr, &ctrlen);
	aes_ctr_decrypt(&aes_key, ctr, buf, buflen, buf);
	if (memcmp(buf, msg, msglen) != 0) {
		printf("failed\n");
		format_bytes(stdout, 0, 0, "msg = ", msg, msglen);
		format_bytes(stdout, 0, 0, "    = ", buf, buflen);
		return -1;
	} else {
		printf("ok\n");
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}


struct {
	char *K;
	char *P;
	char *A;
	char *IV;
	char *C;
	char *T;
} aes_gcm_tests[] = {
	// test 1
	{
		"00000000000000000000000000000000",
		"",
		"",
		"000000000000000000000000",
		"",
		"58e2fccefa7e3061367f1d57a4e7455a",
	},
	// test 2
	{
		"00000000000000000000000000000000",
		"00000000000000000000000000000000",
		"",
		"000000000000000000000000",
		"0388dace60b6a392f328c2b971b2fe78",
		"ab6e47d42cec13bdf53a67b21257bddf",
	},
	// test 3
	{
		"feffe9928665731c6d6a8f9467308308",
		"d9313225f88406e5a55909c5aff5269a"
		"86a7a9531534f7da2e4c303d8a318a72"
		"1c3c0c95956809532fcf0e2449a6b525"
		"b16aedf5aa0de657ba637b391aafd255",
		"",
		"cafebabefacedbaddecaf888",
		"42831ec2217774244b7221b784d0d49c"
		"e3aa212f2c02a4e035c17e2329aca12e"
		"21d514b25466931c7d8f6a5aac84aa05"
		"1ba30b396a0aac973d58e091473f5985",
		"4d5c2af327cd64a62cf35abd2ba6fab4",
	},
	// test 4
	{
		"feffe9928665731c6d6a8f9467308308",
		"d9313225f88406e5a55909c5aff5269a"
		"86a7a9531534f7da2e4c303d8a318a72"
		"1c3c0c95956809532fcf0e2449a6b525"
		"b16aedf5aa0de657ba637b39",
		"feedfacedeadbeeffeedfacedeadbeef"
		"abaddad2",
		"cafebabefacedbaddecaf888",
		"42831ec2217774244b7221b784d0d49c"
		"e3aa212f2c02a4e035c17e2329aca12e"
		"21d514b25466931c7d8f6a5aac84aa05"
		"1ba30b396a0aac973d58e091",
		"5bc94fbc3221a5db94fae95ae7121a47",
	},
	// test 5
	{
		"feffe9928665731c6d6a8f9467308308",
		"d9313225f88406e5a55909c5aff5269a"
		"86a7a9531534f7da2e4c303d8a318a72"
		"1c3c0c95956809532fcf0e2449a6b525"
		"b16aedf5aa0de657ba637b39",
		"feedfacedeadbeeffeedfacedeadbeef"
		"abaddad2",
		"cafebabefacedbad",
		"61353b4c2806934a777ff51fa22a4755"
		"699b2a714fcdc6f83766e5f97b6c7423"
		"73806900e49f24b22b097544d4896b42"
		"4989b5e1ebac0f07c23f4598",
		"3612d2e79e3b0785561be14aaca2fccb",
	},
	// test 6
	{
		"feffe9928665731c6d6a8f9467308308",
		"d9313225f88406e5a55909c5aff5269a"
		"86a7a9531534f7da2e4c303d8a318a72"
		"1c3c0c95956809532fcf0e2449a6b525"
		"b16aedf5aa0de657ba637b39",
		"feedfacedeadbeeffeedfacedeadbeef"
		"abaddad2",
		"9313225df88406e555909c5aff5269aa"
		"6a7a9538534f7da1e4c303d2a318a728"
		"c3c0c95156809539fcf0e2429a6b5254"
		"16aedbf5a0de6a57a637b39b",
		"8ce24998625615b603a033aca13fb894"
		"be9112a5c3a211a8ba262a3cca7e2ca7"
		"01e4a9a4fba43c90ccdcb281d48c7c6f"
		"d62875d2aca417034c34aee5",
		"619cc5aefffe0bfa462af43c1699d050",
	},
	// test 7
	{
		"00000000000000000000000000000000"
		"0000000000000000",
		"",
		"",
		"000000000000000000000000",
		"",
		"cd33b28ac773f74ba00ed1f312572435",
	},
};

int test_aes_gcm(void)
{
	int err = 0;
	uint8_t K[32];
	uint8_t P[64];
	uint8_t A[32];
	uint8_t IV[64];
	uint8_t C[64];
	uint8_t T[16];
	size_t Klen, Plen, Alen, IVlen, Clen, Tlen;

	AES_KEY aes_key;
	uint8_t out[64];
	uint8_t tag[16];
	uint8_t buf[64];
	int i;

	for (i = 0; i < sizeof(aes_gcm_tests)/sizeof(aes_gcm_tests[0]); i++) {
		hex_to_bytes(aes_gcm_tests[i].K, strlen(aes_gcm_tests[i].K), K, &Klen);
		hex_to_bytes(aes_gcm_tests[i].P, strlen(aes_gcm_tests[i].P), P, &Plen);
		hex_to_bytes(aes_gcm_tests[i].A, strlen(aes_gcm_tests[i].A), A, &Alen);
		hex_to_bytes(aes_gcm_tests[i].IV, strlen(aes_gcm_tests[i].IV), IV, &IVlen);
		hex_to_bytes(aes_gcm_tests[i].C, strlen(aes_gcm_tests[i].C), C, &Clen);
		hex_to_bytes(aes_gcm_tests[i].T, strlen(aes_gcm_tests[i].T), T, &Tlen);

		aes_set_encrypt_key(&aes_key, K, Klen);
		aes_gcm_encrypt(&aes_key, IV, IVlen, A, Alen, P, Plen, out, Tlen, tag);

		printf("aes gcm test %d ", i + 1);
		if (aes_gcm_decrypt(&aes_key, IV, IVlen, A, Alen, out, Plen, tag, Tlen, buf) != 1
			|| memcmp(buf, P, Plen) != 0) {
			printf("failed\n");
			format_print(stdout, 0, 2, "K = %s\n", aes_gcm_tests[i].K);
			format_print(stdout, 0, 2, "P = %s\n", aes_gcm_tests[i].P);
			format_print(stdout, 0, 2, "A = %s\n", aes_gcm_tests[i].A);
			format_print(stdout, 0, 2, "IV = %s\n", aes_gcm_tests[i].IV);
			format_print(stdout, 0, 2, "C = %s\n", aes_gcm_tests[i].C);
			format_bytes(stdout, 0, 2, "  = ", out, Plen);
			format_print(stdout, 0, 2, "T = %s\n", aes_gcm_tests[i].T);
			format_bytes(stdout, 0, 2, "  = ", tag, Tlen);
			return -1;
		} else {
			printf("ok\n");
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (test_aes() != 1) goto err;
	if (test_aes_ctr() != 1) goto err;
	if (test_aes_gcm() != 1) goto err;
	printf("%s all tests passed!\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
