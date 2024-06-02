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
#include <time.h>
#include <gmssl/sm4.h>
#include <gmssl/hex.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>


static int test_sm4_ctr(void)
{
	SM4_KEY sm4_key;
	uint8_t key[16] = {0};
	uint8_t ctr[16];
	uint8_t buf1[30] = {0};
	uint8_t buf2[30] = {0};
	uint8_t buf3[30] = {0};

	sm4_set_encrypt_key(&sm4_key, key);
	memset(ctr, 0, sizeof(ctr));
	sm4_ctr_encrypt(&sm4_key, ctr, buf1, sizeof(buf1), buf2);

	memset(ctr, 0, sizeof(ctr));
	sm4_ctr_encrypt(&sm4_key, ctr, buf2, sizeof(buf2), buf3);

	if (memcmp(buf1, buf3, sizeof(buf3)) != 0) {
		fprintf(stderr, "%s %d: error\n", __FILE__, __LINE__);
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm4_ctr_test_vectors(void)
{
	struct {
		char *label;
		char *key;
		char *iv;
		char *plaintext;
		char *ciphertext;
	} tests[] = {
		{
		"openssl-1",
		"0123456789abcdeffedcba9876543210",
		"0123456789abcdeffedcba9876543210",
		"aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccccccccccddddddddddddddddeeeeeeeeeeeeeeeeffffffffffffffffeeeeeeeeeeeeeeeeaaaaaaaaaaaaaaaa",
		"c2b4759e78ac3cf43d0852f4e8d5f9fd7256e8a5fcb65a350ee00630912e44492a0b17e1b85b060d0fba612d8a95831638b361fd5ffacd942f081485a83ca35d",
		},
		{
		"draft-ribose-cfrg-sm4-10 example-1",
		"0123456789abcdeffedcba9876543210",
		"000102030405060708090a0b0c0d0e0f",
		"aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccccccccccddddddddddddddddeeeeeeeeeeeeeeeeffffffffffffffffaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb",
		"ac3236cb970cc20791364c395a1342d1a3cbc1878c6f30cd074cce385cdd70c7f234bc0e24c11980fd1286310ce37b926e02fcd0faa0baf38b2933851d824514",
		},
		{
		"draft-ribose-cfrg-sm4-10 example-2",
		"fedcba98765432100123456789abcdef",
		"000102030405060708090a0b0c0d0e0f",
		"aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccccccccccddddddddddddddddeeeeeeeeeeeeeeeeffffffffffffffffaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb",
		"5dcccd25b95ab07417a08512ee160e2f8f661521cbbab44cc87138445bc29e5c0ae0297205d62704173b21239b887f6c8cb5b800917a2488284bde9e16ea2906",
		},
	};

	uint8_t key[16];
	size_t key_len;
	uint8_t iv[16];
	size_t iv_len;
	uint8_t *plaintext;
	size_t plaintext_len;
	uint8_t *ciphertext;
	size_t ciphertext_len;

	SM4_KEY sm4_key;
	uint8_t *encrypted;
	uint8_t *decrypted;
	size_t i;

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {

		if ((plaintext = (uint8_t *)malloc(strlen(tests[i].plaintext)/2)) == NULL) {
			error_print();
			return -1;
		}
		if ((ciphertext = (uint8_t *)malloc(strlen(tests[i].ciphertext)/2)) == NULL) {
			error_print();
			return -1;
		}

		hex_to_bytes(tests[i].key, strlen(tests[i].key), key, &key_len);
		hex_to_bytes(tests[i].iv, strlen(tests[i].iv), iv, &iv_len);
		hex_to_bytes(tests[i].plaintext, strlen(tests[i].plaintext), plaintext, &plaintext_len);
		hex_to_bytes(tests[i].ciphertext, strlen(tests[i].ciphertext), ciphertext, &ciphertext_len);

		if ((encrypted = (uint8_t *)malloc(ciphertext_len)) == NULL) {
			error_print();
			return -1;
		}
		if ((decrypted = (uint8_t *)malloc(plaintext_len)) == NULL) {
			error_print();
			return -1;
		}

		sm4_set_encrypt_key(&sm4_key, key);
		sm4_ctr_encrypt(&sm4_key, iv, plaintext, plaintext_len, encrypted);

		if (memcmp(encrypted, ciphertext, ciphertext_len) != 0) {
			error_print();
			return -1;
		}

		//sm4_set_encrypt_key(&sm4_key, key);
		hex_to_bytes(tests[i].iv, strlen(tests[i].iv), iv, &iv_len);
		sm4_ctr_encrypt(&sm4_key, iv, ciphertext, ciphertext_len, decrypted);

		if (memcmp(decrypted, plaintext, plaintext_len) != 0) {
			error_print();
			return -1;
		}

		free(plaintext);
		free(ciphertext);
		free(encrypted);
		free(decrypted);
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm4_ctr_with_carray(void)
{
	const char *hex_key =	"0123456789ABCDEFFEDCBA9876543210";
	const char *hex_ctr =	"0000000000000000000000000000FFFF";
	const char *hex_in  =	"AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB"
				"CCCCCCCCCCCCCCCCDDDDDDDDDDDD";
	const char *hex_out =	"7EA678F9F0CBE2000917C63D4E77B4C8"
				"6E4E8532B0046E4AC1E97DA8B831";

	SM4_KEY sm4_key;
	uint8_t key[16] = {0};
	uint8_t ctr[16];
	uint8_t buf1[30] = {0};
	uint8_t buf2[30] = {0};
	uint8_t buf3[30] = {0};

	size_t keylen, ctrlen, inlen, outlen;

	hex_to_bytes(hex_key, strlen(hex_key), key, &keylen);
	hex_to_bytes(hex_ctr, strlen(hex_ctr), ctr, &ctrlen);
	hex_to_bytes(hex_in, strlen(hex_in), buf1, &inlen);
	hex_to_bytes(hex_out, strlen(hex_out), buf3, &outlen);

	sm4_set_encrypt_key(&sm4_key, key);

	sm4_ctr_encrypt(&sm4_key, ctr, buf1, sizeof(buf1), buf2);

	if (memcmp(buf2, buf3, sizeof(buf3)) != 0) {
		error_print();
		return -1;
	}

	hex_to_bytes(hex_ctr, strlen(hex_ctr), ctr, &ctrlen);
	sm4_ctr_encrypt(&sm4_key, ctr, buf3, sizeof(buf3), buf2);

	if (memcmp(buf2, buf1, sizeof(buf1)) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm4_ctr_iv_overflow(void)
{
	struct {
		char *label;
		char *key;
		char *iv;
		char *plaintext;
		char *ciphertext;
	} tests[] = {
		{
		"8-bit overflow",
		"0123456789abcdeffedcba9876543210",
		"000000000000000000000000000000ff",
		"abcdefghijklmnopkrstuvwxyz123456",
		"0c52aa1703982654be4a61a73beecefa688c23b123d5ac77b3d6c495f2f1399f",
		},
		{
		"32-bit overflow",
		"0123456789abcdeffedcba9876543210",
		"000000000000000000000000ffffffff",
		"abcdefghijklmnopkrstuvwxyz123456",
		"77569603146f352a68f2a2060ef5869f34cd12f510f4b598cfed42984f33e0c0",
		},
		{
		"64-bit overflow",
		"0123456789abcdeffedcba9876543210",
		"0000000000000000ffffffffffffffff",
		"abcdefghijklmnopkrstuvwxyz123456",
		"024ffdc1b9b510f6968205b42f6dd15505e5e399e54b08aae25a9298dc9590a1",
		},
		{
		"128-bit overflow",
		"0123456789abcdeffedcba9876543210",
		"ffffffffffffffffffffffffffffffff",
		"abcdefghijklmnopkrstuvwxyz123456",
		"0973cc1a6c15038fef912ea230f40f804d05871f7cb755b4ee2f022268e0971c",
		},
	};


	uint8_t key[16];
	uint8_t iv[16];
	uint8_t plaintext[32];
	uint8_t ciphertext[32];

	SM4_KEY sm4_key;
	uint8_t encrypted[32];
	size_t len, i;

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {

		hex_to_bytes(tests[i].key, strlen(tests[i].key), key, &len);
		hex_to_bytes(tests[i].iv, strlen(tests[i].iv), iv, &len);
		memcpy(plaintext, tests[i].plaintext, strlen(tests[i].plaintext));
		hex_to_bytes(tests[i].ciphertext, strlen(tests[i].ciphertext), ciphertext, &len);

		sm4_set_encrypt_key(&sm4_key, key);
		sm4_ctr_encrypt(&sm4_key, iv, plaintext, sizeof(plaintext), encrypted);

		if (memcmp(encrypted, ciphertext, sizeof(ciphertext)) != 0) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

/*
 * NOTE:
 * There is an compiler bug on Tencent Cloud/Windows Server 2022/Visual Studio 2022 and GitHub CI Windows env.
 * When calling memcpy(ctr, iv, sizeof(iv)) multiple times. The compiler might omit the memcpy()
 * As `ctr` has been changed by sm4_ctr_encrypt() and the reset to `iv` is not working, the test will fail.
 */
static int test_sm4_ctr_ctx(void)
{
	SM4_KEY sm4_key;
	SM4_CTR_CTX enc_ctx;
	SM4_CTR_CTX dec_ctx;

	uint8_t key[16];
	uint8_t iv[16];
	uint8_t ctr[16];
	uint8_t mbuf[16];
	uint8_t cbuf[16];
	uint8_t pbuf[32];
	size_t mlen = 0;
	size_t clen = 0;
	size_t plen = 0;
	size_t len;

	rand_bytes(key, sizeof(key));
	rand_bytes(iv, sizeof(iv));

	mlen = sizeof(mbuf);
	rand_bytes(mbuf, mlen);

	if (sm4_ctr_encrypt_init(&enc_ctx, key, iv) != 1
		|| sm4_ctr_encrypt_update(&enc_ctx, mbuf, mlen, cbuf, &clen) != 1
		|| sm4_ctr_encrypt_finish(&enc_ctx, cbuf + clen, &len) != 1) {
		error_print();
		return -1;
	}
	clen += len;

	// check ciphertext
	sm4_set_encrypt_key(&sm4_key, key);
	memcpy(ctr, iv, sizeof(iv)); // ctr is a variable
	sm4_ctr_encrypt(&sm4_key, ctr, mbuf, mlen, pbuf); // NOTE: sm4_ctr_encrypt() change ctr value

	if (memcmp(cbuf, pbuf, clen) != 0) {
		error_print();
		return -1;
	}

	// check decrypt
	if (sm4_ctr_encrypt_init(&dec_ctx, key, iv) != 1
		|| sm4_ctr_encrypt_update(&dec_ctx, cbuf, clen, pbuf, &plen) != 1
		|| sm4_ctr_encrypt_finish(&dec_ctx, pbuf + plen, &len) != 1) {
		error_print();
		return -1;
	}
	plen += len;

	if (plen != mlen || memcmp(pbuf, mbuf, mlen) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm4_ctr_ctx_multi_updates(void)
{
	SM4_KEY sm4_key;
	SM4_CTR_CTX enc_ctx;
	SM4_CTR_CTX dec_ctx;

	uint8_t key[16];
	uint8_t iv[16];
	uint8_t ctr[16];
	uint8_t mbuf[16 * 10];
	uint8_t cbuf[16 * 11];
	uint8_t pbuf[16 * 11];
	size_t mlen = 0;
	size_t clen = 0;
	size_t plen = 0;

	uint8_t *in;
	uint8_t *out;
	size_t len;
	size_t lens[] = { 1,5,17,80 };

	int i;

	rand_bytes(key, sizeof(key));
	rand_bytes(iv, sizeof(iv));

	rand_bytes(mbuf, sizeof(mbuf));

	if (sm4_ctr_encrypt_init(&enc_ctx, key, iv) != 1) {
		error_print();
		return -1;
	}
	in = mbuf;
	out = cbuf;
	mlen = 0;
	clen = 0;
	for (i = 0; i < sizeof(lens)/sizeof(lens[0]); i++) {
		if (sm4_ctr_encrypt_update(&enc_ctx, in, lens[i], out, &len) != 1) {
			error_print();
			return -1;
		}
		in += lens[i];
		mlen += lens[i];
		if (mlen > sizeof(mbuf)) {
			// invalid lens[] values, reset the test data
			error_print();
			return -1;
		}
		out += len;
		clen += len;
	}
	if (sm4_ctr_encrypt_finish(&enc_ctx, out, &len) != 1) {
		error_print();
		return -1;
	}
	clen += len;

	// check ciphertest
	sm4_set_encrypt_key(&sm4_key, key);
	memcpy(ctr, iv, sizeof(iv));
	sm4_ctr_encrypt(&sm4_key, ctr, mbuf, mlen, pbuf);
	if (memcmp(pbuf, cbuf, mlen) != 0) {
		error_print();
		return -1;
	}

	// check decrypt
	if (sm4_ctr_encrypt_init(&dec_ctx, key, iv) != 1) {
		error_print();
		return -1;
	}
	plen = 0;
	in = cbuf;
	out = pbuf;
	for (i = 0; i < sizeof(lens)/sizeof(lens[0]); i++) {
		if (sm4_ctr_encrypt_update(&dec_ctx, in, lens[i], out, &len) != 1) {
			error_print();
			return -1;
		}
		in += lens[i];
		clen -= lens[i];
		out += len;
		plen += len;
	}
	if (sm4_ctr_encrypt_update(&dec_ctx, in, clen, out, &len) != 1) {
		error_print();
		return -1;
	}
	out += len;
	plen += len;
	if (sm4_ctr_encrypt_finish(&dec_ctx, out, &len) != 1) {
		error_print();
		return -1;
	}
	plen += len;

	if (plen != mlen || memcmp(pbuf, mbuf, mlen) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (test_sm4_ctr() != 1) goto err;
	if (test_sm4_ctr_test_vectors() != 1) goto err;
	if (test_sm4_ctr_with_carray() != 1) goto err;
	if (test_sm4_ctr_iv_overflow() != 1) goto err;
	if (test_sm4_ctr_ctx() != 1) goto err;
	if (test_sm4_ctr_ctx_multi_updates() != 1) goto err;
	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
