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
#include <gmssl/sm4.h>
#include <gmssl/hex.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>


static int test_sm4_cbc(void)
{
	SM4_KEY sm4_key;
	const uint8_t key[16] = {0};
	const uint8_t civ[16] = {0};
	uint8_t iv[16];
	uint8_t buf1[32] = {0};
	uint8_t buf2[32] = {0};
	uint8_t buf3[32] = {0};

	sm4_set_encrypt_key(&sm4_key, key);
	memcpy(iv, civ, 16);
	sm4_cbc_encrypt_blocks(&sm4_key, iv, buf1, 2, buf2);

	sm4_set_decrypt_key(&sm4_key, key);
	memcpy(iv, civ, 16);
	sm4_cbc_decrypt_blocks(&sm4_key, iv, buf2, 2, buf3);

	if (memcmp(buf1, buf3, sizeof(buf3)) != 0) {
		fprintf(stderr, "%s %d: error\n", __FILE__, __LINE__);
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm4_cbc_test_vectors(void)
{
	struct {
		char *mode;
		char *key;
		char *iv;
		char *plaintext;
		char *ciphertext;
	} tests[] = {
		{
		"openssl-1",
		"0123456789abcdeffedcba9876543210",
		"0123456789abcdeffedcba9876543210",
		"0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210",
		"2677f46b09c122cc975533105bd4a22af6125f7275ce552c3a2bbcf533de8a3b",
		},
		{
		"openssl-2",
		"0123456789abcdeffedcba9876543210",
		"0123456789abcdeffedcba9876543210",
		"0123456789abcdeffedcba98765432100123456789abcdeffedcba98765432100123456789abcdeffedcba98765432100123456789abcdeffedcba98765432100123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210",
		"2677f46b09c122cc975533105bd4a22af6125f7275ce552c3a2bbcf533de8a3bfff5a4f208092c0901ba02d5772977369915e3fa2356c9f4eb6460ecc457e7f8e3cfa3deebfe9883e3a48bcf7c4a11aa3ec9e0d317c5d319be72a5cdddec640c",
		},
		{
		"openssl-3",
		"0123456789abcdeffedcba9876543210",
		"0123456789abcdeffedcba9876543210",
		"0123456789abcdeffedcba98765432100123456789abcdeffedcba98765432100123456789abcdeffedcba98765432100123456789abcdeffedcba98765432100123456789abcdeffedcba98765432100123456789abcdeffedcba98765432100123456789abcdeffedcba98765432100123456789abcdeffedcba98765432100123456789abcdeffedcba98765432100123456789abcdeffedcba98765432100123456789abcdeffedcba98765432100123456789abcdeffedcba98765432100123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210",
		"2677f46b09c122cc975533105bd4a22af6125f7275ce552c3a2bbcf533de8a3bfff5a4f208092c0901ba02d5772977369915e3fa2356c9f4eb6460ecc457e7f8e3cfa3deebfe9883e3a48bcf7c4a11aa3ec9e0d317c5d319be72a5cdddec640c6fc70bfa3ddaafffdd7c09b2774dcb2cec29f0c6f0b6773e985b3e395e924238505a8f120d9ca84de5c3cf7e45f097b14b3a46c5b1068669982a5c1f5f61be291b984f331d44ffb2758f771672448fc957fa1416c446427a41e25d5524a2418b9d96b2f17582f0f1aa9c204c6807f54f7b6833c5f00856659ddabc245936868c",
		},
	};

	SM4_KEY sm4_key;
	uint8_t key[16];
	uint8_t iv[16];
	size_t key_len;
	size_t iv_len;
	uint8_t *plaintext;
	size_t plaintext_len;
	uint8_t *ciphertext;
	size_t ciphertext_len;
	uint8_t *encrypted;
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

		sm4_set_encrypt_key(&sm4_key, key);
		hex_to_bytes(tests[i].iv, strlen(tests[i].iv), iv, &iv_len);
		sm4_cbc_encrypt_blocks(&sm4_key, iv, plaintext, plaintext_len/16, encrypted);

		if (memcmp(encrypted, ciphertext, ciphertext_len) != 0) {
			error_print();
			return -1;
		}

		free(plaintext);
		free(ciphertext);
		free(encrypted);
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm4_cbc_padding(void)
{
	SM4_KEY enc_key;
	SM4_KEY dec_key;
	uint8_t key[16] = {0};
	uint8_t iv[16] = {0};
	uint8_t buf1[64];
	uint8_t buf2[128];
	uint8_t buf3[128];
	size_t len1, len2, len3;

	sm4_set_encrypt_key(&enc_key, key);
	sm4_set_decrypt_key(&dec_key, key);

	len1 = 0;
	sm4_cbc_padding_encrypt(&enc_key, iv, buf1, len1, buf2, &len2);
	sm4_cbc_padding_decrypt(&dec_key, iv, buf2, len2, buf3, &len3);
	if (len1 != len3 || memcmp(buf1, buf3, len3) != 0) {
		fprintf(stderr, "%s %d: error\n", __FILE__, __LINE__);
		return -1;
	}

	len1 = 7;
	sm4_cbc_padding_encrypt(&enc_key, iv, buf1, len1, buf2, &len2);
	sm4_cbc_padding_decrypt(&dec_key, iv, buf2, len2, buf3, &len3);
	if (len1 != len3 || memcmp(buf1, buf3, len3) != 0) {
		fprintf(stderr, "%s %d: error\n", __FILE__, __LINE__);
		return -1;
	}

	len1 = 16;
	sm4_cbc_padding_encrypt(&enc_key, iv, buf1, len1, buf2, &len2);
	sm4_cbc_padding_decrypt(&dec_key, iv, buf2, len2, buf3, &len3);
	if (len1 != len3 || memcmp(buf1, buf3, len3) != 0) {
		fprintf(stderr, "%s %d: error\n", __FILE__, __LINE__);
		return -1;
	}

	len1 = 33;
	sm4_cbc_padding_encrypt(&enc_key, iv, buf1, len1, buf2, &len2);
	sm4_cbc_padding_decrypt(&dec_key, iv, buf2, len2, buf3, &len3);
	if (len1 != len3 || memcmp(buf1, buf3, len3) != 0) {
		fprintf(stderr, "%s %d: error\n", __FILE__, __LINE__);
		return -1;
	}

	len1 = sizeof(buf1);
	sm4_cbc_padding_encrypt(&enc_key, iv, buf1, len1, buf2, &len2);
	sm4_cbc_padding_decrypt(&dec_key, iv, buf2, len2, buf3, &len3);
	if (len1 != len3 || memcmp(buf1, buf3, len3) != 0) {
		fprintf(stderr, "%s %d: error\n", __FILE__, __LINE__);
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm4_cbc_ctx(void)
{
	SM4_KEY sm4_key;
	SM4_CBC_CTX enc_ctx;
	SM4_CBC_CTX dec_ctx;

	uint8_t key[16];
	uint8_t iv[16];
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



	// first test

	mlen = 16;
	rand_bytes(mbuf, mlen);

	if (sm4_cbc_encrypt_init(&enc_ctx, key, iv) != 1
		|| sm4_cbc_encrypt_update(&enc_ctx, mbuf, mlen, cbuf, &clen) != 1
		|| sm4_cbc_encrypt_finish(&enc_ctx, cbuf + clen, &len) != 1) {
		error_print();
		return -1;
	}
	clen += len;

	// check ciphertext
	sm4_set_encrypt_key(&sm4_key, key);
	sm4_cbc_padding_encrypt(&sm4_key, iv, mbuf, mlen, pbuf, &plen);
	if (clen != plen || memcmp(cbuf, pbuf, plen) != 0) {
		error_print();
		return -1;
	}

	// check decrypt
	if (sm4_cbc_decrypt_init(&dec_ctx, key, iv) != 1
		|| sm4_cbc_decrypt_update(&dec_ctx, cbuf, clen, pbuf, &plen) != 1
		|| sm4_cbc_decrypt_finish(&dec_ctx, pbuf + plen, &len) != 1) {
		error_print();
		return -1;
	}
	plen += len;
	if (plen != mlen || memcmp(pbuf, mbuf, mlen) != 0) {
		error_print();
		return -1;
	}


	// second test

	rand_bytes(mbuf, sizeof(mbuf));

	if (sm4_cbc_encrypt_init(&enc_ctx, key, iv) != 1) {
		error_print();
		return -1;
	}
	in = mbuf;
	out = cbuf;
	mlen = 0;
	clen = 0;
	for (i = 0; i < sizeof(lens)/sizeof(lens[0]); i++) {
		if (sm4_cbc_encrypt_update(&enc_ctx, in, lens[i], out, &len) != 1) {
			error_print();
			return -1;
		}
		in += lens[i];
		mlen += lens[i];
		out += len;
		clen += len;

	}
	if (sm4_cbc_encrypt_finish(&enc_ctx, out, &len) != 1) {
		error_print();
		return -1;
	}
	clen += len;

	// check ciphertest
	sm4_cbc_padding_encrypt(&sm4_key, iv, mbuf, mlen, pbuf, &plen);
	if (plen != clen || memcmp(pbuf, cbuf, clen) != 0) {
		error_print();
		return -1;
	}

	// check decrypt
	if (sm4_cbc_decrypt_init(&dec_ctx, key, iv) != 1) {
		error_print();
		return -1;
	}
	plen = 0;
	in = cbuf;
	out = pbuf;
	for (i = 0; i < sizeof(lens)/sizeof(lens[0]); i++) {
		if (sm4_cbc_decrypt_update(&dec_ctx, in, lens[i], out, &len) != 1) {
			error_print();
			return -1;
		}
		in += lens[i];
		clen -= lens[i];
		out += len;
		plen += len;
	}
	if (sm4_cbc_decrypt_update(&dec_ctx, in, clen, out, &len) != 1) {
		error_print();
		return -1;
	}
	out += len;
	plen += len;
	if (sm4_cbc_decrypt_finish(&dec_ctx, out, &len) != 1) {
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
	if (test_sm4_cbc() != 1) goto err;
	if (test_sm4_cbc_test_vectors() != 1) goto err;
	if (test_sm4_cbc_padding() != 1) goto err;
	if (test_sm4_cbc_ctx() != 1) goto err;
	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
