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
#include "sm4_ccmtest.h"


static int test_sm4_ccm(void)
{
	SM4_KEY sm4_key;
	uint8_t key[16];
	uint8_t iv[SM4_CCM_MAX_IV_SIZE];
	size_t ivlen[] = { SM4_CCM_MIN_IV_SIZE, SM4_CCM_MIN_IV_SIZE + 1, SM4_CCM_MAX_IV_SIZE };
	uint8_t aad[32];
	size_t aadlen[] = {0, 8, 16, 20, 32 };
	uint8_t plaintext[64];
	size_t len[] = { 4, 16, 36, 64 };
	uint8_t encrypted[sizeof(plaintext)];
	uint8_t decrypted[sizeof(plaintext)];
	uint8_t mac[SM4_CCM_MAX_TAG_SIZE];
	size_t maclen[] = { SM4_CCM_MIN_TAG_SIZE, SM4_CCM_MAX_TAG_SIZE };
	size_t i;

	rand_bytes(key, sizeof(key));
	rand_bytes(iv, sizeof(iv));
	rand_bytes(aad, sizeof(aad));
	rand_bytes(plaintext, sizeof(plaintext));

	sm4_set_encrypt_key(&sm4_key, key);

	for (i = 0; i < sizeof(ivlen)/sizeof(ivlen[0]); i++) {

		if (sm4_ccm_encrypt(&sm4_key, iv, ivlen[i],  aad, sizeof(aad),
			plaintext, sizeof(plaintext), encrypted, sizeof(mac), mac) != 1) {
			error_print();
			return -1;
		}

		if (sm4_ccm_decrypt(&sm4_key, iv, ivlen[i], aad, sizeof(aad),
			encrypted, sizeof(encrypted), mac, sizeof(mac), decrypted) != 1) {
			error_print();
			return -1;
		}

		if (memcmp(decrypted, plaintext, sizeof(plaintext)) != 0) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm4_ccm_test_vectors(void)
{
	struct {
		char *label;
		char *key;
		char *iv;
		char *aad;
		char *tag;
		char *plaintext;
		char *ciphertext;
	} tests[] = {
		{
		"rfc8998",
		"0123456789abcdeffedcba9876543210",
		"00001234567800000000abcd",
		"feedfacedeadbeeffeedfacedeadbeefabaddad2",
		"16842d4fa186f56ab33256971fa110f4",
		"aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccccccccccddddddddddddddddeeeeeeeeeeeeeeeeffffffffffffffffeeeeeeeeeeeeeeeeaaaaaaaaaaaaaaaa",
		"48af93501fa62adbcd414cce6034d895dda1bf8f132f042098661572e7483094fd12e518ce062c98acee28d95df4416bed31a2f04476c18bb40c84a74b97dc5b",
		},
	};

	uint8_t key[16];
	size_t key_len;
	uint8_t iv[16];
	size_t iv_len;
	uint8_t *aad;
	size_t aad_len;
	uint8_t tag[16];
	size_t tag_len;
	uint8_t *plaintext;
	size_t plaintext_len;
	uint8_t *ciphertext;
	size_t ciphertext_len;

	SM4_KEY sm4_key;
	uint8_t *encrypted;
	uint8_t *decrypted;
	uint8_t mac[16];
	size_t i;

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {

		if ((aad = (uint8_t *)malloc(strlen(tests[i].aad)/2)) == NULL) {
			error_print();
			return -1;
		}
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
		hex_to_bytes(tests[i].aad, strlen(tests[i].aad), aad, &aad_len);
		hex_to_bytes(tests[i].tag, strlen(tests[i].tag), tag, &tag_len);
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
		if (sm4_ccm_encrypt(&sm4_key, iv, iv_len, aad, aad_len,
			plaintext, plaintext_len, encrypted, tag_len, mac) != 1) {
			error_print();
			return -1;
		}
		if (memcmp(encrypted, ciphertext, ciphertext_len) != 0) {
			error_print();
			return -1;
		}
		if (memcmp(mac, tag, tag_len) != 0) {
			error_print();
			return -1;
		}

		//sm4_set_encrypt_key(&sm4_key, key); // same as ccm_encrypt
		if (sm4_ccm_decrypt(&sm4_key, iv, iv_len, aad, aad_len,
			ciphertext, ciphertext_len, tag, tag_len, decrypted) != 1) {
			error_print();
			return -1;
		}
		if (memcmp(decrypted, plaintext, plaintext_len) != 0) {
			error_print();
			return -1;
		}

		free(aad);
		free(plaintext);
		free(ciphertext);
		free(encrypted);
		free(decrypted);
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}


static int test_sm4_ccm_wycheproof(void)
{
	size_t i;

	for (i = 0; i < sizeof(test_sm4_ccm_vectors)/sizeof(test_sm4_ccm_vectors[0]); i++) {
		const TEST_SM4_CCM_VECTOR *tv = &test_sm4_ccm_vectors[i];
		SM4_KEY sm4_key;
		uint8_t key[16];
		uint8_t iv[268];
		uint8_t aad[513];
		uint8_t msg[513];
		uint8_t ct[513];
		uint8_t tag[16];
		uint8_t out[513];
		uint8_t dec[513];
		uint8_t mac[16];
		size_t keylen, ivlen, aadlen, msglen, ctlen, taglen;
		int enc_ret, dec_ret;

		if (hex_to_bytes(tv->key, strlen(tv->key), key, &keylen) != 1
			|| hex_to_bytes(tv->iv, strlen(tv->iv), iv, &ivlen) != 1
			|| hex_to_bytes(tv->aad, strlen(tv->aad), aad, &aadlen) != 1
			|| hex_to_bytes(tv->msg, strlen(tv->msg), msg, &msglen) != 1
			|| hex_to_bytes(tv->ct, strlen(tv->ct), ct, &ctlen) != 1
			|| hex_to_bytes(tv->tag, strlen(tv->tag), tag, &taglen) != 1) {
			error_print();
			return -1;
		}
		if (keylen != SM4_KEY_SIZE) {
			error_print();
			return -1;
		}
		if (taglen > sizeof(mac)
			|| msglen > sizeof(out)
			|| ctlen > sizeof(dec)) {
			error_print();
			return -1;
		}

		sm4_set_encrypt_key(&sm4_key, key);
		enc_ret = sm4_ccm_encrypt(&sm4_key, iv, ivlen, aad, aadlen, msg, msglen, out, taglen, mac);
		dec_ret = sm4_ccm_decrypt(&sm4_key, iv, ivlen, aad, aadlen, ct, ctlen, tag, taglen, dec);

		if (tv->result == TEST_RESULT_VALID) {
			if (enc_ret != 1 || dec_ret != 1
				|| ctlen != msglen
				|| memcmp(out, ct, ctlen) != 0
				|| memcmp(mac, tag, taglen) != 0
				|| memcmp(dec, msg, msglen) != 0) {
				error_print();
				return -1;
			}
		} else {
			if (dec_ret == 1) {
				error_print();
				return -1;
			}
			fprintf(stderr, "    error output above is part of the negative test\n");
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int speed_sm4_ccm_encrypt(void)
{
	SM4_KEY sm4_key;
	uint8_t key[16] = {0};
	uint8_t iv[12];
	uint8_t aad[16];
	uint8_t tag[16];
	uint32_t buf[1024];
	clock_t begin, end;
	double seconds;
	int i;

	sm4_set_encrypt_key(&sm4_key, key);

	for (i = 0; i < 4096; i++) {
		sm4_ccm_encrypt(&sm4_key, iv, sizeof(iv), aad, sizeof(aad), (uint8_t *)buf, sizeof(buf), (uint8_t *)buf, 16, tag);
	}
	begin = clock();
	for (i = 0; i < 4096; i++) {
		sm4_ccm_encrypt(&sm4_key, iv, sizeof(iv), aad, sizeof(aad), (uint8_t *)buf, sizeof(buf), (uint8_t *)buf, 16, tag);
	}
	end = clock();

	seconds = (double)(end - begin)/ CLOCKS_PER_SEC;
	fprintf(stderr, "%s: %f MiB per second\n", __FUNCTION__, 16/seconds);

	return 1;
}

int main(void)
{
	if (test_sm4_ccm() != 1) goto err;
	if (test_sm4_ccm_test_vectors() != 1) goto err;
	if (test_sm4_ccm_wycheproof() != 1) goto err;
#if ENABLE_TEST_SPEED
	if (speed_sm4_ccm_encrypt() != 1) goto err;
#endif
	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
