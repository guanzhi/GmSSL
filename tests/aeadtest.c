/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <gmssl/hex.h>
#include <gmssl/rand.h>
#include <gmssl/aead.h>
#include <gmssl/error.h>


static int test_aead_sm4_cbc_sm3_hmac(void)
{
	SM4_CBC_SM3_HMAC_CTX aead_ctx;
	uint8_t key[16 + 32];
	uint8_t iv[16];
	uint8_t aad[29];
	uint8_t plain[71];
	size_t plainlen = sizeof(plain);
	uint8_t cipher[256];
	size_t cipherlen = 0;
	uint8_t buf[256];
	size_t buflen = 0;

	size_t lens[] = { 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37 };
	uint8_t *in = plain;
	uint8_t *out = cipher;
	size_t inlen, outlen;
	size_t i;

	rand_bytes(key, sizeof(key));
	rand_bytes(iv, sizeof(iv));
	rand_bytes(aad, sizeof(aad));
	rand_bytes(plain, plainlen);

	if (sm4_cbc_sm3_hmac_encrypt_init(&aead_ctx, key, sizeof(key), iv, sizeof(iv), aad, sizeof(aad)) != 1) {
		error_print();
		return -1;
	}
	for (i = 0; plainlen; i++) {
		assert(i < sizeof(lens)/sizeof(lens[0]));

		inlen = plainlen < lens[i] ? plainlen  : lens[i];
		if (sm4_cbc_sm3_hmac_encrypt_update(&aead_ctx, in, inlen, out, &outlen) != 1) {
			error_print();
			return -1;
		}
		in += inlen;
		plainlen -= inlen;
		out += outlen;
		cipherlen += outlen;
	}
	if (sm4_cbc_sm3_hmac_encrypt_finish(&aead_ctx, out, &outlen) != 1) {
		error_print();
		return -1;
	}
	out += outlen;
	cipherlen += outlen;

	format_bytes(stdout, 0, 4, "plaintext ", plain, sizeof(plain));
	format_bytes(stdout, 0, 4, "ciphertext", cipher, cipherlen);

	{
		SM4_KEY sm4_key;
		SM3_HMAC_CTX sm3_hmac_ctx;
		uint8_t tmp[256];
		size_t tmplen;

		sm4_set_encrypt_key(&sm4_key, key);
		if (sm4_cbc_padding_encrypt(&sm4_key, iv, plain, sizeof(plain), tmp, &tmplen) != 1) {
			error_print();
			return -1;
		}

		sm3_hmac_init(&sm3_hmac_ctx, key + 16, 32);
		sm3_hmac_update(&sm3_hmac_ctx, aad, sizeof(aad));
		sm3_hmac_update(&sm3_hmac_ctx, tmp, tmplen);
		sm3_hmac_finish(&sm3_hmac_ctx, tmp + tmplen);
		tmplen += 32;

		format_bytes(stdout, 0, 4, "ciphertext", tmp, tmplen);

		if (cipherlen != tmplen
			|| memcmp(cipher, tmp, tmplen) != 0) {
			error_print();
			return -1;
		}
	}

	in = cipher;
	out = buf;

	if (sm4_cbc_sm3_hmac_decrypt_init(&aead_ctx, key, sizeof(key), iv, sizeof(iv), aad, sizeof(aad)) != 1) {
		error_print();
		return -1;
	}
	for (i = sizeof(lens)/sizeof(lens[0]) - 1; cipherlen; i--) {
		inlen = cipherlen < lens[i] ? cipherlen : lens[i];

		if (sm4_cbc_sm3_hmac_decrypt_update(&aead_ctx, in, inlen, out, &outlen) != 1) {
			error_print();
			return -1;
		}
		in += inlen;
		cipherlen -= inlen;
		out += outlen;
		buflen += outlen;
	}
	if (sm4_cbc_sm3_hmac_decrypt_finish(&aead_ctx, out, &outlen) != 1) {
		error_print();
		return -1;
	}
	out += outlen;
	buflen += outlen;

	format_bytes(stdout, 0, 4, "plaintext ", buf, buflen);

	if (buflen != sizeof(plain)) {
		error_print();
		return -1;
	}
	if (memcmp(buf, plain, sizeof(plain)) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_aead_sm4_ctr_sm3_hmac(void)
{
	SM4_CTR_SM3_HMAC_CTX aead_ctx;
	uint8_t key[16 + 32];
	uint8_t iv[16];
	uint8_t aad[29];
	uint8_t plain[71];
	size_t plainlen = sizeof(plain);
	uint8_t cipher[256];
	size_t cipherlen = 0;
	uint8_t buf[256];
	size_t buflen = 0;

	size_t lens[] = { 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37 };
	uint8_t *in = plain;
	uint8_t *out = cipher;
	size_t inlen, outlen;
	size_t i;

	rand_bytes(key, sizeof(key));
	rand_bytes(iv, sizeof(iv));
	rand_bytes(aad, sizeof(aad));
	rand_bytes(plain, plainlen);

	if (sm4_ctr_sm3_hmac_encrypt_init(&aead_ctx, key, sizeof(key), iv, sizeof(iv), aad, sizeof(aad)) != 1) {
		error_print();
		return -1;
	}
	for (i = 0; plainlen; i++) {
		assert(i < sizeof(lens)/sizeof(lens[0]));

		inlen = plainlen < lens[i] ? plainlen  : lens[i];
		if (sm4_ctr_sm3_hmac_encrypt_update(&aead_ctx, in, inlen, out, &outlen) != 1) {
			error_print();
			return -1;
		}
		in += inlen;
		plainlen -= inlen;
		out += outlen;
		cipherlen += outlen;
	}
	if (sm4_ctr_sm3_hmac_encrypt_finish(&aead_ctx, out, &outlen) != 1) {
		error_print();
		return -1;
	}
	out += outlen;
	cipherlen += outlen;

	format_bytes(stdout, 0, 4, "plaintext ", plain, sizeof(plain));
	format_bytes(stdout, 0, 4, "ciphertext", cipher, cipherlen);

	{
		SM4_KEY sm4_key;
		uint8_t ctr[16];
		SM3_HMAC_CTX sm3_hmac_ctx;
		uint8_t tmp[256];
		size_t tmplen;

		sm4_set_encrypt_key(&sm4_key, key);
		memcpy(ctr, iv, 16);

		sm4_ctr_encrypt(&sm4_key, ctr, plain, sizeof(plain), tmp);
		tmplen = sizeof(plain);

		sm3_hmac_init(&sm3_hmac_ctx, key + 16, 32);
		sm3_hmac_update(&sm3_hmac_ctx, aad, sizeof(aad));
		sm3_hmac_update(&sm3_hmac_ctx, tmp, tmplen);
		sm3_hmac_finish(&sm3_hmac_ctx, tmp + tmplen);
		tmplen += 32;

		format_bytes(stdout, 0, 4, "ciphertext", tmp, tmplen);

		if (cipherlen != tmplen
			|| memcmp(cipher, tmp, tmplen) != 0) {
			error_print();
			return -1;
		}
	}


	in = cipher;
	out = buf;

	if (sm4_ctr_sm3_hmac_decrypt_init(&aead_ctx, key, sizeof(key), iv, sizeof(iv), aad, sizeof(aad)) != 1) {
		error_print();
		return -1;
	}
	for (i = sizeof(lens)/sizeof(lens[0]) - 1; cipherlen; i--) {
		inlen = cipherlen < lens[i] ? cipherlen : lens[i];

		if (sm4_ctr_sm3_hmac_decrypt_update(&aead_ctx, in, inlen, out, &outlen) != 1) {
			error_print();
			return -1;
		}
		in += inlen;
		cipherlen -= inlen;
		out += outlen;
		buflen += outlen;

	}
	if (sm4_ctr_sm3_hmac_decrypt_finish(&aead_ctx, out, &outlen) != 1) {
		error_print();
		return -1;
	}
	out += outlen;
	buflen += outlen;

	format_bytes(stdout, 0, 4, "plaintext ", buf, buflen);

	if (buflen != sizeof(plain)) {
		error_print();
		return -1;
	}
	if (memcmp(buf, plain, sizeof(plain)) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_aead_sm4_gcm(void)
{
	SM4_GCM_CTX aead_ctx;
	uint8_t key[16];
	uint8_t iv[16];
	uint8_t aad[29];
	uint8_t plain[71];
	size_t plainlen = sizeof(plain);
	uint8_t cipher[256];
	size_t cipherlen = 0;
	uint8_t buf[256];
	size_t buflen = 0;

	size_t lens[] = { 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37 };
	uint8_t *in = plain;
	uint8_t *out = cipher;
	size_t inlen, outlen;
	size_t i;

	rand_bytes(key, sizeof(key));
	rand_bytes(iv, sizeof(iv));
	rand_bytes(aad, sizeof(aad));
	rand_bytes(plain, plainlen);

	if (sm4_gcm_encrypt_init(&aead_ctx, key, sizeof(key), iv, sizeof(iv), aad, sizeof(aad), GHASH_SIZE) != 1) {
		error_print();
		return -1;
	}
	for (i = 0; plainlen; i++) {
		assert(i < sizeof(lens)/sizeof(lens[0]));

		inlen = plainlen < lens[i] ? plainlen  : lens[i];
		if (sm4_gcm_encrypt_update(&aead_ctx, in, inlen, out, &outlen) != 1) {
			error_print();
			return -1;
		}
		in += inlen;
		plainlen -= inlen;
		out += outlen;
		cipherlen += outlen;
	}
	if (sm4_gcm_encrypt_finish(&aead_ctx, out, &outlen) != 1) {
		error_print();
		return -1;
	}
	out += outlen;
	cipherlen += outlen;

	format_bytes(stdout, 0, 4, "plaintext ", plain, sizeof(plain));
	format_bytes(stdout, 0, 4, "ciphertext", cipher, cipherlen);

	{
		SM4_KEY sm4_key;
		uint8_t tmp[256];
		size_t tmplen;

		sm4_set_encrypt_key(&sm4_key, key);

		if (sm4_gcm_encrypt(&sm4_key, iv, sizeof(iv), aad, sizeof(aad), plain, sizeof(plain),
			tmp, GHASH_SIZE, tmp + sizeof(plain)) != 1) {
			error_print();
			return -1;
		}
		tmplen = sizeof(plain) + GHASH_SIZE;

		format_bytes(stdout, 0, 4, "ciphertext", tmp, tmplen);

		if (cipherlen != tmplen
			|| memcmp(cipher, tmp, tmplen) != 0) {
			error_print();
			return -1;
		}
	}

	in = cipher;
	out = buf;

	if (sm4_gcm_decrypt_init(&aead_ctx, key, sizeof(key), iv, sizeof(iv), aad, sizeof(aad), GHASH_SIZE) != 1) {
		error_print();
		return -1;
	}
	for (i = sizeof(lens)/sizeof(lens[0]) - 1; cipherlen; i--) {
		inlen = cipherlen < lens[i] ? cipherlen : lens[i];

		if (sm4_gcm_decrypt_update(&aead_ctx, in, inlen, out, &outlen) != 1) {
			error_print();
			return -1;
		}
		in += inlen;
		cipherlen -= inlen;
		out += outlen;
		buflen += outlen;

	}
	if (sm4_gcm_decrypt_finish(&aead_ctx, out, &outlen) != 1) {
		error_print();
		return -1;
	}
	out += outlen;
	buflen += outlen;

	format_bytes(stdout, 0, 4, "plaintext ", buf, buflen);

	if (buflen != sizeof(plain)) {
		error_print();
		return -1;
	}
	if (memcmp(buf, plain, sizeof(plain)) != 0) {
		error_print();
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void)
{
	if (test_aead_sm4_cbc_sm3_hmac() != 1) { error_print(); return -1; }
	if (test_aead_sm4_ctr_sm3_hmac() != 1) { error_print(); return -1; }
	if (test_aead_sm4_gcm() != 1) { error_print(); return -1; }
	printf("%s all tests passed!\n", __FILE__);
	return 0;
}
