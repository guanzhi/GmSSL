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


static int test_sm4_ofb(void)
{
	SM4_KEY sm4_key;
	uint8_t key[16];
	uint8_t iv[16];

	size_t len[] = { 4, 16, 16+2, 32, 48+8 };
	uint8_t plaintext[48+8];
	uint8_t encrypted[sizeof(plaintext)];
	uint8_t decrypted[sizeof(plaintext)];
	size_t i;

	rand_bytes(key, sizeof(key));
	rand_bytes(iv, sizeof(iv));
	rand_bytes(plaintext, sizeof(plaintext));

	sm4_set_encrypt_key(&sm4_key, key);

	for (i = 0; i < sizeof(len)/sizeof(len[0]); i++) {
		uint8_t state_iv[16];

		memcpy(state_iv, iv, sizeof(iv));
		sm4_ofb_encrypt(&sm4_key, state_iv, plaintext, len[i], encrypted);

		memcpy(state_iv, iv, sizeof(iv));
		sm4_ofb_encrypt(&sm4_key, state_iv, encrypted, len[i], decrypted);

		if (memcmp(decrypted, plaintext, len[i]) != 0) {
			error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm4_ofb_ctx(void)
{
	SM4_OFB_CTX ctx;
	uint8_t key[16];
	uint8_t iv[16];
	size_t inlen[] = { 2, 14, 32, 4, 18 };
	uint8_t plaintext[2 + 14 + 32 + 4 + 18];
	uint8_t encrypted[sizeof(plaintext) + 16];
	uint8_t decrypted[sizeof(plaintext) + 16];
	size_t plaintext_len = 0;
	size_t encrypted_len = 0;
	size_t decrypted_len = 0;
	uint8_t *in, *out;
	size_t len;
	size_t i;

	rand_bytes(key, sizeof(key));
	rand_bytes(iv, sizeof(iv));
	rand_bytes(plaintext, sizeof(plaintext));


	// encrypt

	if (sm4_ofb_encrypt_init(&ctx, key, iv) != 1) {
		error_print();
		return -1;
	}

	in = plaintext;
	out = encrypted;

	for (i = 0; i < sizeof(inlen)/sizeof(inlen[0]); i++) {
		if (sm4_ofb_encrypt_update(&ctx, in, inlen[i], out, &len) != 1) {
			error_print();
			return -1;
		}
		in += inlen[i];
		out += len;
		plaintext_len += inlen[i];
		encrypted_len += len;
	}

	if (sm4_ofb_encrypt_finish(&ctx, out, &len) != 1) {
		error_print();
		return -1;
	}
	encrypted_len += len;

	if (encrypted_len != plaintext_len) {
		error_print();
		return -1;
	}

	// decrypt

	if (sm4_ofb_encrypt_init(&ctx, key, iv) != 1) {
		error_print();
		return -1;
	}

	in = encrypted;
	out = decrypted;

	for (i = 0; i < sizeof(inlen)/sizeof(inlen[0]); i++) {
		if (sm4_ofb_encrypt_update(&ctx, in, inlen[i], out, &len) != 1) {
			error_print();
			return -1;
		}
		in += inlen[i];
		out += len;
		decrypted_len += len;
	}

	if (sm4_ofb_encrypt_finish(&ctx, out, &len) != 1) {
		error_print();
		return -1;
	}
	decrypted_len += len;

	if (decrypted_len != plaintext_len) {
		error_print();
		return -1;
	}
	if (memcmp(decrypted, plaintext, plaintext_len) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (test_sm4_ofb() != 1) goto err;
	if (test_sm4_ofb_ctx() != 1) goto err;
	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
